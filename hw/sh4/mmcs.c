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
#include <stdlib.h>
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
/* ---- FILES-span IO region with side-table reads (S89/S97 design) ----
 * The FILES region is packed: decompressed files overflow their load_va
 * gaps. Reads within [load_va, load_va+real) of a known file are served
 * from a concatenated decompressed side table; all other accesses hit the
 * raw flash image underneath (overlap priority). */
#define MMCS_MAX_FILES 256
static struct {
    uint32_t load_va, real, tbl_off;
} mmcs_ftab[MMCS_MAX_FILES];
static int mmcs_ftab_n;
static uint8_t *mmcs_ftable_data;
static size_t mmcs_ftable_len;

static uint64_t mmcs_files_read(void *opaque, hwaddr addr, unsigned size)
{
    /* addr = offset within the FILES IO region; base VA = region start */
    uint32_t va = (uint32_t)(uintptr_t)opaque + (uint32_t)addr;
    for (int i = 0; i < mmcs_ftab_n; i++) {
        if (va >= mmcs_ftab[i].load_va &&
            va < mmcs_ftab[i].load_va + mmcs_ftab[i].real) {
            uint32_t off = va - mmcs_ftab[i].load_va + mmcs_ftab[i].tbl_off;
            uint64_t v = 0;
            if (off + size <= mmcs_ftable_len) {
                memcpy(&v, mmcs_ftable_data + off, size);
            }
            return v;
        }
    }
    return 0;   /* gaps: zeros (kernel never reads file gaps) */
}

static void mmcs_files_write(void *opaque, hwaddr addr, uint64_t val,
                              unsigned size)
{
    /* kernel writes into the FILES span: pass to the flash RAM beneath by
     * writing through (the region overlaps flash at priority 1; writes
     * here would need the underlying pointer — for now log-and-drop,
     * the boot path only reads files) */
    (void)opaque; (void)addr; (void)val; (void)size;
}

static const MemoryRegionOps mmcs_files_ops = {
    .read = mmcs_files_read,
    .write = mmcs_files_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
};

static int mmcs_fb_only_rearm = 0;  /* set by self-rearm: skip RAM sweep */

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
        { 0x081C0000, "/tmp/srd1.bin" },
        { 0x081C2800, "/tmp/srd2.bin" },
        { 0x08602000, "/tmp/kdata64k.bin" },
        { 0x10800000, "/tmp/imgpage1.bin" },
        { 0x10801240, "/tmp/extarea.bin" },
        { 0x0867e000, "/tmp/fntable.bin" },
        { 0x0867a000, "/tmp/nkproc.bin" },
        { 0x108f7000, "/tmp/dllpool.bin" },
        { 0x1068e000, "/tmp/pagedmod.bin" },
        { 0x0867a000, "/tmp/kdata2.bin" },
        { 0x08600000, "/tmp/kdata0.bin" },
    };
    static uint8_t buf[0x10000];
    /* MMCS_TLBDUMP=1: print all valid UTLB/ITLB VA->PA mappings of the
     * boot CPU — decodes the kernel's runtime memory layout (kernel-side
     * module pools at 0xC0xxxxxx etc.). */
    {
        if (getenv("MMCS_TLBDUMP")) {
            SuperHCPU *sc = SUPERH_CPU(first_cpu);
            for (int i = 0; i < UTLB_SIZE; i++) {
                tlb_t *t = &sc->env.utlb[i];
                if (t->v) {
                    fprintf(stderr, "MMCS: UTLB[%2d] va=%08x pa=%08x "
                            "sz=%d pr=%d d=%d sh=%d\n", i,
                            t->vpn, t->ppn, t->size, t->pr, t->d, t->sh);
                }
            }
            for (int i = 0; i < ITLB_SIZE; i++) {
                tlb_t *t = &sc->env.itlb[i];
                if (t->v) {
                    fprintf(stderr, "MMCS: ITLB[%2d] va=%08x pa=%08x sz=%d\n",
                            i, t->vpn, t->ppn, t->size);
                }
            }
        }
    }
    /* MMCS_FB=<file.ppm>: dump the unit framebuffer (phys 0x08B00000,
     * 800x480 RGB565) as a PPM. MMCS_FB_INTERVAL=<n>: stream n frames, one
     * per self-re-armed MMCS_DUMP interval, named <base>-%03d.ppm; re-armed
     * callbacks are FB-only (the full RAM sweep in a timer callback was
     * proven to starve the chardev -> link wedge). */
    {
        const char *fb = getenv("MMCS_FB");
        if (fb) {
            const char *iv = getenv("MMCS_FB_INTERVAL");
            int total = iv ? atoi(iv) : 1;
            static int seq = 0;
            if (total < 1) total = 1;
            const int FW = 800, FH = 480;
            static uint8_t rgb565[800 * 480 * 2];
            static uint8_t ppm[800 * 480 * 3 + 64];
            cpu_physical_memory_read(0x08B00000, rgb565, sizeof rgb565);
            int n = snprintf((char *)ppm, sizeof ppm,
                             "P6\n%d %d\n255\n", FW, FH);
            for (int i = 0; i < FW * FH; i++) {
                uint16_t p = rgb565[2 * i] | rgb565[2 * i + 1] << 8;
                ppm[n + 3 * i + 0] = (p >> 8 & 0xf8) | (p >> 13);
                ppm[n + 3 * i + 1] = (p >> 3 & 0xfc) | (p >> 9);
                ppm[n + 3 * i + 2] = (p << 3 & 0xf8) | (p >> 2);
            }
            char fn[512];
            if (total > 1)
                snprintf(fn, sizeof fn, "%s-%03d.ppm", fb, seq);
            else
                snprintf(fn, sizeof fn, "%s", fb);
            FILE *fp = fopen(fn, "wb");
            if (fp) {
                fwrite(ppm, 1, n + FW * FH * 3, fp);
                fclose(fp);
                fprintf(stderr, "MMCS: framebuffer dumped to %s\n", fn);
            } else {
                fprintf(stderr, "MMCS: cannot write %s\n", fb);
            }
            seq++;
            if (seq < total) {
                mmcs_fb_only_rearm = 1;
                const char *ds = getenv("MMCS_DUMP");
                QEMUTimer *t2 = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                             mmcs_dump_ram, NULL);
                timer_mod(t2, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
                          + (ds ? atoi(ds) : 5) * 1000);
            }
        }
    }
    if (getenv("MMCS_MLD")) {
        cpu_physical_memory_read(0x0B000000, buf, 16);
        FILE *g = fopen("/tmp/mldresult.bin", "wb");
        if (g) { fwrite(buf, 1, 16, g); fclose(g); }
        fprintf(stderr, "MMCS: MLD result word = 0x%08x\n",
                (unsigned)(buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24));
        return;
    }
    for (unsigned i = 0; !mmcs_fb_only_rearm && i < ARRAY_SIZE(dumps); i++) {
        cpu_physical_memory_read(dumps[i].pa, buf, sizeof buf);
        FILE *f = fopen(dumps[i].fn, "wb");
        if (f) { fwrite(buf, 1, sizeof buf, f); fclose(f); }
    }
    {
        const char *pk = getenv("MMCS_POKE");
        while (pk && *pk) {
            hwaddr a = strtoull(pk, NULL, 16);
            const char *eq = strchr(pk, '=');
            uint32_t v = eq ? strtoul(eq + 1, NULL, 16) : 0;
            cpu_physical_memory_write(a, &v, 4);
            fprintf(stderr, "MMCS: poked %08x = %08x\n", (unsigned)a, v);
            const char *semi = strchr(pk, ';');
            pk = semi ? semi + 1 : NULL;
        }
    }
    fprintf(stderr, "MMCS: RAM dump written\n");
}







/* ---- Load-time jsr-to-negative-pool NOP patcher ----
 * Systemic pattern: late-bound calls whose pool word is a shipped
 * negative config value (sign-extended by mov.w -> invalid address):
 * InitLocale 0xffff54e9, error-printer 0xfbed, pm.dll 0xfddb, ...
 * These paths only run when the config loader (registry/filesys) never
 * filled the slot. A jsr whose register was JUST loaded via mov.w from
 * a word >= 0x8000 can never be a valid SH4 address -> NOP the jsr at
 * load time. Executed-on-real-HW paths with valid pools are untouched. */
static void mmcs_nop_marker_jsrs(uint8_t *img, size_t len, hwaddr img_va)
{
    int nops = 0;
    for (size_t pc = 0; pc + 40 < len; pc += 2) {
        uint16_t w = img[pc] | (img[pc + 1] << 8);
        if ((w & 0xf000) != 0x9000) continue;        /* mov.w @(d,pc),Rn */
        unsigned rn = (w >> 8) & 0xf;
        unsigned disp = w & 0xff;
        size_t pool = pc + 4 + disp * 2;   /* mov.w disp is x2-scaled */
        if (pool + 2 > len) continue;
        uint16_t pw = img[pool] | (img[pool + 1] << 8);
        if (!(pw & 0x8000)) continue;                /* would sign-extend negative */
        /* jsr @Rn at pc+2, or pc+4 with ONE intervening insn that must
         * not overwrite Rn (mov #imm,Rn = 0xEnnn has rn in the same
         * nibble position). Anything looser matched 8875 false sites. */
        /* Only TWO safe shapes:
         *  (a) jsr @Rn at pc+2 (immediately after the load), or
         *  (b) jsr @Rn at pc+4 with exactly one intervening insn that
         *      must be `mov #imm,Rx` (0xExxx) writing a DIFFERENT reg.
         * Anything else may reload Rn -> the jsr could be legitimate. */
        uint16_t j2 = img[pc + 2] | (img[pc + 3] << 8);
        bool hit = false;
        if ((j2 & 0xf0ff) == 0x400b && ((j2 >> 8) & 0xf) == rn) {
            hit = true;
        } else {
            uint16_t mid = j2;
            uint16_t j4 = img[pc + 4] | (img[pc + 5] << 8);
            if ((mid & 0xf000) == 0xe000 && ((mid >> 8) & 0xf) != rn &&
                (j4 & 0xf0ff) == 0x400b && ((j4 >> 8) & 0xf) == rn) {
                hit = true;
                j2 = j4;
                pc += 2;   /* report the jsr address, not the mid */
            }
        }
        if (hit) {
            img[pc + 2] = 0x09; img[pc + 3] = 0x00;   /* nop the jsr */
            nops++;
            fprintf(stderr, "MMCS-NOP jsr@r%u @%08llx (pool %04x)\n",
                    rn, (unsigned long long)(img_va + pc + 2), pw);
        }
    }
    fprintf(stderr, "MMCS-NOP: %d marker jsrs neutralized\n", nops);
}

/* ---- Vendor INTC page @0xF4000000 (status/mask regs; protocol unknown)
 * ---- plus periodic timer-IRQ injection experiment. The kernel's VBR+0x600
 * (SH4 IRQ0) handler is armed; the vendor INTC (0xF4001000/0xF4003000 per
 * kernel data tables) presumably demuxes onto it. Stub-first + trace. */
static uint32_t mmcs_vintc_regs[64];
static qemu_irq mmcs_vintc_irl;      /* SH4 IRL line (vendor INTC demux) */

/* MMCS_VINTC_IRQ=<ms>: pulse the SH4 IRL line every <ms> virtual ms.
 * Ground truth (S73): the stalled kernel WRITES-ONLY to the vendor INTC
 * (36.8M zero-mask sweeps, zero reads) = waiting for an interrupt we
 * never injected. This experiment asserts the line; the handler at
 * VBR+0x600 should take it. Level: IRL is active-low encoded priority. */
static SuperHCPU *mmcs_cpu;
static uint32_t mmcs_vintc_evt_code;

static void mmcs_vintc_evt_deliver(void *opaque)
{
    /* deliver a vendor-INTC event: preset INTEVT + the fork's inject flag,
     * then raise the CPU IRQ; superh_cpu_do_interrupt picks it up (fork
     * hook) and the kernel trampoline dispatches slot = code>>10 in its
     * RAM vector table @0x8867a000 (codes = IRQ<<8, e.g. 0x7C00 = ch124). */
    if (mmcs_cpu) {
        CPUSH4State *env = &mmcs_cpu->env;
        env->intevt = mmcs_vintc_evt_code;
        env->mmcs_evt_inject = 1;
        cpu_reset_interrupt(CPU(mmcs_cpu), CPU_INTERRUPT_HARD);
        cpu_interrupt(CPU(mmcs_cpu), CPU_INTERRUPT_HARD);
    }
    QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_vintc_evt_deliver, NULL);
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
              + atoi(getenv("MMCS_VINTC_EVT_MS") ? : "20"));
}

static void mmcs_vintc_pulse(void *opaque)
{
    static int level;
    level = !level;
    qemu_set_irq(mmcs_vintc_irl, level & 15);
    QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_vintc_pulse, NULL);
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
              + atoi(getenv("MMCS_VINTC_IRQ") ? : "10"));
}
static uint64_t mmcs_vintc_read(void *opaque, hwaddr off, unsigned size)
{
    uint64_t v = 0;
    if (off / 4 < 64) memcpy(&v, (uint8_t *)mmcs_vintc_regs + off, size);
    if (getenv("MMCS_TRACE")) {
        fprintf(stderr, "MMCS-VINTC R off=%05llx -> %08llx\n",
                (unsigned long long)off, (unsigned long long)v);
    }
    return v;
}
static void mmcs_vintc_write(void *opaque, hwaddr off, uint64_t val, unsigned size)
{
    if (getenv("MMCS_TRACE")) {
        fprintf(stderr, "MMCS-VINTC W off=%05llx <- %08llx\n",
                (unsigned long long)off, (unsigned long long)val);
    }
    if (off / 4 < 64) memcpy((uint8_t *)mmcs_vintc_regs + off, &val, size);
}
static const MemoryRegionOps mmcs_vintc_ops = {
    .read = mmcs_vintc_read, .write = mmcs_vintc_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
};




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
    /* kernel-stack arena window: the kernel runs thread stacks at VA
     * 0xD0xxxxxx; if treated as P1-1:1 the backing phys is 0x10xxxxxx —
     * back it with RAM (16 MB, env-tunable MMCS_RAM3_MB; 0 disables).
     * Without this, dtlb_miss_write cascades kill every kernel thread
     * (2026-11-13 trace: pc=0xc003c9e0 tea=0xd006fe8c loop). */
    {
        const char *mb = getenv("MMCS_RAM3_MB");
        unsigned n = mb ? (unsigned)atoi(mb) : 16;
        if (n) {
            MemoryRegion *ram3 = g_new(MemoryRegion, 1);
            memory_region_init_ram(ram3, NULL, "mmcs.ram3", (uint64_t)n * MiB,
                                   &error_fatal);
            memory_region_add_subregion(get_system_memory(), 0x10000000, ram3);
        }
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
        if (!fn) {
            error_report("could not load firmware '%s'", machine->firmware);
            exit(1);
        }
        /* Load directly into the RAM backing (NOT load_image_targphys:
         * that registers a ROM blob applied at machine start, which would
         * overwrite the marker patch applied below). */
        gsize len = 0;
        uint8_t *buf = NULL;
        if (!g_file_get_contents(fn, (gchar **)&buf, &len, NULL) ||
            len > MMCS_FLASH_SIZE) {
            error_report("could not read firmware '%s'", machine->firmware);
            exit(1);
        }
        memcpy(memory_region_get_ram_ptr(flash), buf, len);
        /* MMCS_LOCALEFIX=1: k.coredll InitLocale (VA 0xC004CA58) calls a
         * late-bound pool slot that SHIPS as sentinel 0xffff54e9 (exactly
         * one occurrence in plain .text, ROM 0x908F7B04; verified 2026-11-14:
         * no runtime writer — dual-alias watchpoint never fires). On real HW
         * the locale provider binds before InitLocale runs, making the call
         * optional; emulate that by pointing the slot at the kernel rts-stub
         * (call is fire-and-forget, result unused). */
        const char *fst = getenv("MMCS_FILESTABLE");
        if (fst && *fst) {
            gsize tlen = 0;
            uint8_t *tbuf = NULL;
            if (g_file_get_contents(fst, (gchar **)&tbuf, &tlen, NULL)
                && tbuf && tlen > 4) {
                mmcs_ftab_n = ldl_le_p(tbuf);
                if (mmcs_ftab_n > MMCS_MAX_FILES) mmcs_ftab_n = MMCS_MAX_FILES;
                const uint8_t *p = tbuf + 4;
                for (int i = 0; i < mmcs_ftab_n; i++) {
                    mmcs_ftab[i].load_va = ldl_le_p(p); p += 4;
                    mmcs_ftab[i].real = ldl_le_p(p); p += 4;
                    mmcs_ftab[i].tbl_off = ldl_le_p(p); p += 4;
                }
                mmcs_ftable_data = (uint8_t *)p;
                mmcs_ftable_len = tlen - 4 - 12 * mmcs_ftab_n;
                if (mmcs_ftab_n > 0) {
                    uint32_t lo = mmcs_ftab[0].load_va;
                    uint32_t span_lo = lo & ~0xFFFFF;   /* align to 1MB */
                    uint32_t span_hi = 0;
                    for (int i = 0; i < mmcs_ftab_n; i++) {
                        uint32_t end = mmcs_ftab[i].load_va + mmcs_ftab[i].real;
                        if (end > span_hi) span_hi = end;
                    }
                    span_hi = (span_hi + 0xFFFFF) & ~0xFFFFF;
                    MemoryRegion *fmr = g_new(MemoryRegion, 1);
                    memory_region_init_io(fmr, NULL, &mmcs_files_ops,
                        (void *)(uintptr_t)span_lo, "mmcs.filestable",
                        span_hi - span_lo);
                    memory_region_add_subregion(get_system_memory(),
                        MMCS_FLASH_BASE + (span_lo - 0x90800000), fmr);
                    fprintf(stderr, "MMCS: FILES table %d files, span %08x-%08x\n",
                            mmcs_ftab_n, span_lo, span_hi);
                }
            }
        }
        const char *fsh = getenv("MMCS_FILESHADOW");
        if (fsh) {
            /* FILES-region shadow: pre-decompressed file contents at their
             * load_va offsets (built offline by our proven pipeline).
             * Overlay onto the flash RAM after the raw image load. The
             * kernel (which has no decompressor) then reads valid data. */
            gsize slen = 0;
            uint8_t *sbuf = NULL;
            if (g_file_get_contents(fsh, (gchar **)&sbuf, &slen, NULL)
                && sbuf && slen <= len) {
                memcpy(memory_region_get_ram_ptr(flash), sbuf,
                       MIN(slen, len));
                fprintf(stderr, "MMCS: FILES shadow overlaid (%llu bytes)\n",
                        (unsigned long long)slen);
            } else {
                fprintf(stderr, "MMCS: FILES shadow load FAILED (%s)\n", fsh);
            }
            g_free(sbuf);
        }
        if (getenv("MMCS_REGFIX")) {
            cpu->env.mmcs_regfix_active = 1;
            /* Phase-0 bootstrap: patch the ordinal-461 stub (RegQueryValueExW
             * in filesys's API set) at 0xC00C9FF4 with 'trapa #0x71' so the
             * fork can synthesize success returns for the boot-registry
             * queries (System\ObjectStore etc) that the unreadable fdf
             * would answer on real HW. See helper.c trapa hook. */
            uint16_t trapa71 = 0xC771;
            /* filesys .text ROM dataptr = 0x90942000, VA base 0xC00B1000 */
            hwaddr off = (0x90942000 - 0x90800000) + (0xC00C9FF4 - 0xC00B1000);
            cpu_physical_memory_write(MMCS_FLASH_BASE + off, &trapa71, 2);
            fprintf(stderr, "MMCS: REGFIX trapa hook @0xC00C9FF4\n");
        }
        if (getenv("MMCS_LOCALEFIX")) {
            uint32_t safe = 0x90809f3c;   /* kernel rts stub (S65-verified) */
            hwaddr slot_pa = 0x108F7B04; /* flash base + (0x908F7B04-0x90800000) */
            cpu_physical_memory_write(slot_pa, &safe, 4);
            fprintf(stderr, "MMCS: LOCALEFIX sentinel slot patched\n");
        }
        g_free(buf);
        g_free(fn);
        /* neutralize all shipped jsr-to-negative-pool sites in the image
         * (MMCS_NONOP=1 disables for A/B comparison) */
        if (!getenv("MMCS_NONOP")) {
            mmcs_nop_marker_jsrs(memory_region_get_ram_ptr(flash), len,
                                 0x90800000);
        }
    }
    /* InitLocale late-bound pools ship marker 0xffff54e9 (config loader
     * that would fill them never runs against our boot); patch at load
     * time to the kernel's rts;mov #1,r0 fn. Physical writes to the ROM
     * region don't stick, so this must precede set_readonly. */
    {
        uint32_t *fw = (uint32_t *)((uint8_t *)memory_region_get_ram_ptr(flash)
                                    + 0x7ed04);
        static const hwaddr offs[2] = { 0x7ed04, 0xf7b04 };
        uint8_t *base = memory_region_get_ram_ptr(flash);
        if (!getenv("MMCS_NOPOOL")) {
            for (unsigned i = 0; i < 2; i++) {
                uint32_t *p = (uint32_t *)(base + offs[i]);
                if (*p == 0xffff54e9) { *p = 0x90809f3c; }
            }
        }
        (void)fw;
    }
    memory_region_set_readonly(flash, true);   /* RO after load */
    memory_region_add_subregion(get_system_memory(), MMCS_FLASH_BASE, flash);

    /* Classic SH4 on-chip devices: INTC, TMU, RTC, SCIF serial, DMAC, CPG */
    {
        /* capture the sh7750 state for the IRQ injection experiment (S73) */
        mmcs_cpu = cpu;
        struct SH7750State *s7750 = sh7750_init(cpu, get_system_memory());
        /* vendor INTC page */
        {
            const char *vi = getenv("MMCS_VINTC_IRQ");
            const char *evt = getenv("MMCS_VINTC_EVT");
            if (evt && *evt) {
                mmcs_vintc_evt_code = strtoul(evt, NULL, 16);
                QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                            mmcs_vintc_evt_deliver, NULL);
                timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1500);
                fprintf(stderr, "MMCS: vendor-INTC EVT injection %08x every %sms\n",
                        mmcs_vintc_evt_code,
                        getenv("MMCS_VINTC_EVT_MS") ? : "20");
            }
            if (vi && *vi) {
                mmcs_vintc_irl = sh7750_irl(s7750);
                QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                            mmcs_vintc_pulse, NULL);
                timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
                          + atoi(vi));
                fprintf(stderr, "MMCS: vendor-INTC IRQ injection every %sms\n", vi);
            }
        }
        MemoryRegion *mr = g_new(MemoryRegion, 1);
        memory_region_init_io(mr, NULL, &mmcs_vintc_ops, NULL,
                              "mmcs.vintc", 0x10000);
        memory_region_add_subregion(get_system_memory(), 0xF4000000, mr);
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

    /* Channel flash blocks (0xF40000..0xFCFFFF, 5 x 128KB): these are the
     * unit's flash regions — boot-time signature structs at +0 (validated by
     * the OAL walker), later used by the kernel's exception-backup flash
     * driver, which ERASES them (expecting all-0xFFFFFFFF reads after).
     * Model: RAM holding the sigstruct initially; a write of 0xFFFFFFFF to
     * +0x100.. region triggers full-erase semantics; writes logged. */
    {
        mmcs_chanflash_init();
    }



    /* polled syscon regions (see ops above) */
    {
        MemoryRegion *mr = g_new(MemoryRegion, 1);
        memory_region_init_io(mr, NULL, &mmcs_syscon_c080_ops, NULL,
                              "mmcs.syscon-c080", 0x1000);
        memory_region_add_subregion(get_system_memory(), 0xFFC08000, mr);
    }
    /* 0xFFD80000 = SH7750 TMU (real qemu model, real IRQs) — do NOT
     * overlay it. Kernel programs TMU1 (TSTR=2) + TCOR/TCNT=0xFFFFFFFF. */

    /* Boot ROM stub at physical 0: mask-ROM role, jumps to the OS entry.
     * Reset PC on SH4 is 0xA0000000 (P2 mirror of physical 0). */
    bootrom = g_new(MemoryRegion, 1);
    memory_region_init_ram(bootrom, NULL, "mmcs.bootrom", 0x1000, &error_fatal);
    boot_stub = memory_region_get_ram_ptr(bootrom);
    /* mov.l @(0,pc),r0 ; jmp @r0 ; .long 0x908066b0 (pool at pc+4) */
    if (getenv("MMCS_LOWSLOT")) {
        /* v2 stub: preload UTLB low-slot pages (ldtlb) then jump to kernel */
        static const uint8_t v2[] = {4,232,13,217,14,218,147,107,9,75,9,75,9,75,178,42,12,218,179,108,8,76,8,76,8,76,12,221,219,44,194,42,9,218,0,237,210,42,56,0,9,221,220,57,16,72,233,139,2,208,43,64,9,0,9,0,0,64,0,0,176,102,128,144,0,0,0,255,4,0,0,255,12,0,0,255,126,1,0,0,0,16,0,0};
        memcpy(boot_stub, v2, sizeof v2);
    } else {
        boot_stub[0] = 0x00; boot_stub[1] = 0xD0;   /* mov.l @(0,pc),r0  */
        boot_stub[2] = 0x2B; boot_stub[3] = 0x40;   /* jmp @r0           */
        boot_stub[4] = 0xb0; boot_stub[5] = 0x66;   /* 0x908066b0        */
        boot_stub[6] = 0x80; boot_stub[7] = 0x90;
    }
    memory_region_set_readonly(bootrom, true);
    memory_region_add_subregion(get_system_memory(), 0, bootrom);

    /* MMCS_LOWSLOT=1: rts-filled low page (phys 0x4000-0x8000). Runtime-
     * composed init-stage pointers sometimes point at unbound low-page
     * sentinels (0x5bd0-class, S82/S84); the dispatcher jsr's them and
     * fetch-faults forever. An rts at the target makes the call a no-op
     * so the retry loop advances past the unbound stage. */
    {
        if (getenv("MMCS_LOWSLOT")) {
            MemoryRegion *mr = g_new(MemoryRegion, 1);
            memory_region_init_ram(mr, NULL, "mmcs.lowslot", 0x4000,
                                   &error_fatal);
            memory_region_add_subregion(get_system_memory(), 0x4000, mr);
            uint8_t *p = memory_region_get_ram_ptr(mr);
            for (unsigned o = 0; o + 1 < 0x4000; o += 2) {
                p[o] = 0x0b; p[o + 1] = 0x00;   /* rts (SH4: 0x000b) */
            }
            /* ALSO pre-load UTLB: VA 0x4000-0x7FFF -> phys 0x4000-0x7FFF
             * (4 x 4KB shared pages) so user-mode fetches at unbound
             * sentinels hit the rts stub after the kernel enables the MMU.
             * Loaded from the boot stub via ldtlb BEFORE the kernel runs;
             * survives unless the kernel flushes the whole UTLB (MMUCR.TI). */
            fprintf(stderr, "MMCS: LOWSLOT rts page mapped at 0x4000\n");
        }
    }

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
