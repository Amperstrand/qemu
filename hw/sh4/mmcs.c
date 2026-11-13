/*
 * Mitsubishi Outlander 2014 MMCS E12 head unit (SH7777-class, WinCE5/SH4)
 *
 * Memory map reconstructed from the unit's own firmware corpus
 * (see car-research: docs/PROVEN-EXECUTION-DEMO.md, OAL MMIO census):
 *   phys 0x08000000  SDRAM 128 MB   (P1 0x88000000: MLD loads at 0x88900000,
 *                                    framebuffer 0x88B00000 800x480 RGB565)
 *   phys 0x10800000  XIP NOR flash  (P1 0x90800000: WinCE OS image, records
 *                                    0x90800000-0x96CE8E2C, entry 0x908066b0)
 *   phys 0x00000000  boot ROM stub  (jump to OS entry, mask-ROM role)
 *   0xFFxxxxxxx      SH4-family on-chip registers (INTC/TMU/RTC/SCIF/PFC via
 *                    sh7750 model; SH7777-specific regions as unimplemented
 *                    stubs so guest accesses are logged, µEmu-style)
 */
#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "cpu.h"
#include "hw/sysbus.h"
#include "hw/sh4/sh.h"
#include "hw/sh4/sh7777.h"
#include "sysemu/reset.h"
#include "sysemu/runstate.h"
#include "sysemu/sysemu.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"
#include "hw/irq.h"
#include "hw/loader.h"
#include "exec/address-spaces.h"
#include "hw/char/serial.h"
#include "qemu/datadir.h"
#include "hw/misc/unimp.h"

#define MMCS_SDRAM_BASE 0x08000000
#define MMCS_SDRAM_SIZE 0x8800000  /* 0x08000000..0x10800000: kernel RAM 0x88600000-0x90700000 (ROMHDR) + margin */
#define MMCS_FLASH_BASE 0x10800000
#define MMCS_FLASH_SIZE (128 * MiB)
#define MMCS_ENTRY      0x908066b0   /* kernel entry from image first record */

/* MMIO census regions (64K buckets) not covered by the sh7750 model —
 * logged as unimplemented so the OAL's dialogue with missing hardware is
 * visible instead of silent. */
static const struct { hwaddr base; const char *name; } mmcs_unimpl[] = {
    { 0xFF000000, "sh7777-intc2" },
    { 0xFF200000, "sh7777-dmac1" },
    { 0xFF400000, "sh7777-dmac2" },
    { 0xFF700000, "sh7777-ffb" },
    { 0xFFB00000, "sh7777-usb" },
    { 0xFFC70000, "sh7777-rtc" },
    { 0xFFDF0000, "sh7777-tmu-extra" },
    { 0xFFE10000, "sh7777-pfc" },
    { 0xFFE20000, "sh7777-port" },
    { 0xFFE70000, "sh7777-cpg" },
    { 0xFFF70000, "sh7777-ubc" },
    { 0xFFFE0000, "sh7777-sdram-ctrl" },
    { 0xFFFF0000, "sh7777-cpu-idi" },
    { 0xA8060000, "unit-ext" },
    { 0xA9D80000, "unit-ext2" },
};

/* MMCS syscon: two polled regions the OAL hits during boot.
 * 0xFFC08000: counter block — reads return written values EXCEPT +0xF4,
 *             a free-running up-counter (64Hz-ish) so delay/poll loops
 *             complete instead of timing out forever.
 * 0xFA00000:  status block — plain read-back storage. */
static uint32_t syscon_c080[64];
static uint64_t mmcs_syscon_c080_read(void *opaque, hwaddr addr, unsigned size)
{
    if (addr == 0xf4) {
        return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 16000000; /* ~62.5 Hz tick */
    }
    if (addr / 4 < 64) {
        return syscon_c080[addr / 4];
    }
    return 0;
}
static void mmcs_syscon_c080_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    if (addr / 4 < 64) {
        syscon_c080[addr / 4] = val;
    }
}
static const MemoryRegionOps mmcs_syscon_c080_ops = {
    .read = mmcs_syscon_c080_read,
    .write = mmcs_syscon_c080_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4, .valid.max_access_size = 4,
};

/* deterministic post-boot RAM dump (env MMCS_DUMP=<seconds>):
 * writes the ROMHDR copy-entry destinations + RAMStart to /tmp for
 * verifying kernel-side ROM→RAM copies. */
static void mmcs_dump_ram(void *opaque)
{
    static const struct { hwaddr pa; const char *fn; } dumps[] = {
        { 0x08602000, "/tmp/copy0.bin" },
        { 0x0862c000, "/tmp/copy1.bin" },
        { 0x0867a000, "/tmp/copy2.bin" },
        { 0x08600000, "/tmp/ramstart.bin" },
        { 0x08602848, "/tmp/waittable.bin" },
        { 0x08602800, "/tmp/waitctx.bin" },
        { 0x0867b200, "/tmp/apiset.bin" },
    };
    uint8_t buf[0x1000];
    if (getenv("MMCS_MLD")) {
        cpu_physical_memory_read(0x0B000000, buf, 16);
        FILE *g = fopen("/tmp/mldresult.bin", "wb");
        if (g) { fwrite(buf, 1, 16, g); fclose(g); }
        fprintf(stderr, "MMCS: MLD result word = 0x%08x\n",
                (unsigned)(buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24));
        return;
    }
    for (unsigned i = 0; i < ARRAY_SIZE(dumps); i++) {
        cpu_physical_memory_read(dumps[i].pa, buf, sizeof buf);
        FILE *f = fopen(dumps[i].fn, "wb");
        if (f) { fwrite(buf, 1, sizeof buf, f); fclose(f); }
    }
    fprintf(stderr, "MMCS: RAM dump written\n");
}

static void mmcs_init(MachineState *machine)
{
    SuperHCPU *cpu;
    MemoryRegion *sdram, *flash, *bootrom;
    uint8_t *boot_stub;

    cpu = SUPERH_CPU(cpu_create(machine->cpu_type));

    /* SDRAM at 0x08000000 (unit RAM window; covers MLD + framebuffer) */
    sdram = g_new(MemoryRegion, 1);
    memory_region_init_ram(sdram, NULL, "mmcs.sdram", MMCS_SDRAM_SIZE,
                           &error_fatal);
    memory_region_add_subregion(get_system_memory(), MMCS_SDRAM_BASE, sdram);

    /* second RAM window: the kernel probes phys 0x04000000-0x047FFFFF during
     * RAM discovery (write/read test at 0x47FFFF8 seen in boot traces) */
    {
        MemoryRegion *ram2 = g_new(MemoryRegion, 1);
        memory_region_init_ram(ram2, NULL, "mmcs.ram2", 8 * MiB, &error_fatal);
        memory_region_add_subregion(get_system_memory(), 0x04000000, ram2);
    }

    /* MLD acceptance-test mode (env MMCS_MLD=1): skip the OS boot entirely —
     * map the loader RAM image, our payload, and the test stub at phys 0.
     * MMCS_PAYLOAD = container file (mapped at phys 0x0A000000),
     * MMCS_STUB    = assembled stub binary (mapped at phys 0, is the boot). */
    if (getenv("MMCS_MLD")) {
        MemoryRegion *mr;
        const char *pay = getenv("MMCS_PAYLOAD") ?: "/dev/null";
        const char *stub = getenv("MMCS_STUB") ?: "/dev/null";
        mr = g_new(MemoryRegion, 1);
        memory_region_init_ram(mr, NULL, "mld.loader", 0x100000, &error_fatal);
        memory_region_add_subregion(get_system_memory(), 0x08900000, mr);
        if (load_image_targphys("/tmp/mld-mem.bin", 0x08900000, 0x100000) < 0) {
            error_report("MMCS_MLD: cannot load /tmp/mld-mem.bin");
            exit(1);
        }
        mr = g_new(MemoryRegion, 1);
        memory_region_init_ram(mr, NULL, "mld.payload", 0x100000, &error_fatal);
        memory_region_add_subregion(get_system_memory(), 0x0A000000, mr);
        load_image_targphys(pay, 0x0A000000, 0x100000);
        mr = g_new(MemoryRegion, 1);
        memory_region_init_ram(mr, NULL, "mld.stub", 0x1000, &error_fatal);
        memory_region_add_subregion(get_system_memory(), 0, mr);
        if (load_image_targphys(stub, 0, 0x1000) < 0) {
            error_report("MMCS_MLD: cannot load stub %s", stub);
            exit(1);
        }
        memory_region_set_readonly(mr, true);
        /* debug SCIF below still wires; skip kernel flash/bootrom path */
        sh7750_init(cpu, get_system_memory());
        {
            DeviceState *dev = qdev_new(TYPE_SH_SERIAL);
            SysBusDevice *sb = SYS_BUS_DEVICE(dev);
            dev->id = g_strdup("mmcs-dbg-scif");
            qdev_prop_set_chr(dev, "chardev", serial_hd(2));
            qdev_prop_set_uint8(dev, "features", SH_SERIAL_FEAT_SCIF);
            sysbus_realize_and_unref(sb, &error_fatal);
            sysbus_mmio_map(sb, 0, 0xffe40000);
        }
        {
            const char *ds = getenv("MMCS_DUMP");
            if (ds) {
                QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_dump_ram, NULL);
                timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + atoi(ds) * 1000);
            }
        }
        return;
    }

    /* XIP flash window at 0x10800000: -pflash/-device loader fills it, or a
     * raw file via firmware property; default: load machine->firmware if set */
    flash = g_new(MemoryRegion, 1);
    memory_region_init_ram(flash, NULL, "mmcs.flash", MMCS_FLASH_SIZE,
                           &error_fatal);
    if (machine->firmware) {
        char *fn = qemu_find_file(QEMU_FILE_TYPE_BIOS, machine->firmware);
        if (!fn || load_image_targphys(fn, MMCS_FLASH_BASE,
                                       MMCS_FLASH_SIZE) < 0) {
            error_report("could not load firmware '%s'", machine->firmware);
            exit(1);
        }
        g_free(fn);
    }
    memory_region_set_readonly(flash, true);   /* RO after load */
    memory_region_add_subregion(get_system_memory(), MMCS_FLASH_BASE, flash);

    /* Classic SH4 on-chip devices: INTC, TMU, RTC, SCIF serial, DMAC, CPG */
    sh7750_init(cpu, get_system_memory());

    /* SH7777 devices: CMT/DMA block, INTC banks, CPG (PLL lock) */
    {
        sh7777_init(NULL);   /* cpu_irq wired later if needed */
    }

    /* The kernel addresses on-chip regs P4-style (0xFFxxxxxx). qemu's INTC
     * IPRs already live there; the TMU/RTC only exist at 0x1Fxxxxxx physical
     * — alias them to their P4 addresses or the kernel's writes vanish. */
    {
        struct { hwaddr p4, phys; const char *name; } p4map[] = {
            { 0xFFD80000, 0x1FD80000, "mmcs.tmu-p4" },
            { 0xFFC80000, 0x1FC80000, "mmcs.rtc-p4" },
        };
        for (unsigned i = 0; i < ARRAY_SIZE(p4map); i++) {
            MemoryRegionSection sec = memory_region_find(get_system_memory(),
                                                         p4map[i].phys, 4);
            if (sec.mr && sec.mr != get_system_memory()) {
                MemoryRegion *al = g_new(MemoryRegion, 1);
                memory_region_init_alias(al, NULL, p4map[i].name, sec.mr, 0,
                                         0x100);
                memory_region_add_subregion_overlap(get_system_memory(),
                                                    p4map[i].p4, al, 0);
            }
        }
    }

    /* MMCS debug SCIF: the kernel's OAL emits its banner on the SCIF channel
     * at 0xFFE40000 (SCFSR poll at +0x10 — identified from the boot trace and
     * the SUBCPU_SCIF driver's channel table). Third QEMU serial = stdio. */
    {
        DeviceState *dev = qdev_new(TYPE_SH_SERIAL);
        dev->id = g_strdup("mmcs-dbg-scif");
        SysBusDevice *sb = SYS_BUS_DEVICE(dev);
        qdev_prop_set_chr(dev, "chardev", serial_hd(2));
        qdev_prop_set_uint8(dev, "features", SH_SERIAL_FEAT_SCIF);
        sysbus_realize_and_unref(sb, &error_fatal);
        sysbus_mmio_map(sb, 0, 0xffe40000);
    }

    /* census regions as logged stubs */
    for (unsigned i = 0; i < ARRAY_SIZE(mmcs_unimpl); i++) {
        create_unimplemented_device(mmcs_unimpl[i].name,
                                    mmcs_unimpl[i].base, 0x10000);
    }

    /* OAL channel structs: the walker at 0x9080db40 validates a signature
     * struct at each channel base (0xF40000..0xFC0000): value/~value pairs
     * at +48/+52 and +56/+60, and +92 == ~(sum of dwords [+0..+88]).
     * Defaults = valid signature, entry[0] = -1 ("no device"). */
    {
        static const hwaddr chan_bases[5] = { 0xF40000, 0xF60000, 0xF80000,
                                              0xFA0000, 0xFC0000 };
        for (unsigned c = 0; c < 5; c++) {
            MemoryRegion *mr = g_new(MemoryRegion, 1);
            uint32_t *m;
            memory_region_init_ram(mr, NULL, g_strdup_printf("mmcs.chan%d", c), 0x1000, &error_fatal);
            m = memory_region_get_ram_ptr(mr);
            memset(m, 0, 0x1000);
            m[0] = 0xffffffff;          /* entry[0] = -1: no device (experiment 1 made no difference) */
            m[12] = 0;                  /* +48 */
            m[13] = 0xffffffff;         /* +52 = ~m[12] */
            m[14] = 0;                  /* +56 */
            m[15] = 0xffffffff;         /* +60 = ~m[14] */
            m[23] = 0;                  /* +92 = ~(sum m[0..22]) = ~0xffffffff = 0 */
            memory_region_add_subregion(get_system_memory(), chan_bases[c], mr);
        }
    }

    /* polled syscon regions (see ops above) */
    {
        MemoryRegion *mr = g_new(MemoryRegion, 1);
        memory_region_init_io(mr, NULL, &mmcs_syscon_c080_ops, NULL,
                              "mmcs.syscon-c080", 0x1000);
        memory_region_add_subregion(get_system_memory(), 0xFFC08000, mr);
    }

    /* Boot ROM stub at physical 0: mask-ROM role, jumps to the OS entry.
     * Reset PC on SH4 is 0xA0000000 (P2 mirror of physical 0). */
    bootrom = g_new(MemoryRegion, 1);
    memory_region_init_ram(bootrom, NULL, "mmcs.bootrom", 0x1000, &error_fatal);
    boot_stub = memory_region_get_ram_ptr(bootrom);
    /* mov.l @(0,pc),r0 ; jmp @r0 ; .long 0x908066b0 (pool at pc+4) */
    boot_stub[0] = 0x00; boot_stub[1] = 0xD0;   /* mov.l @(0,pc),r0  */
    boot_stub[2] = 0x2B; boot_stub[3] = 0x40;   /* jmp @r0           */
    boot_stub[4] = 0xb0; boot_stub[5] = 0x66;   /* 0x908066b0        */
    boot_stub[6] = 0x80; boot_stub[7] = 0x90;
    memory_region_set_readonly(bootrom, true);
    memory_region_add_subregion(get_system_memory(), 0, bootrom);

    /* optional deterministic RAM dump after MMCS_DUMP seconds */
    {
        const char *ds = getenv("MMCS_DUMP");
        if (ds) {
            QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_dump_ram, NULL);
            timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + atoi(ds) * 1000);
        }
    }
}

static void mmcs_machine_init(MachineClass *mc)
{
    mc->desc = "Mitsubishi MMCS E12 head unit (SH7777-class WinCE5)";
    mc->init = mmcs_init;
    mc->is_default = false;
    mc->default_cpu_type = TYPE_SH7751R_CPU;
    mc->no_parallel = 1;
}

DEFINE_MACHINE("mmcs", mmcs_machine_init)
