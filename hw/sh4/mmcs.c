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
#include "hw/usb.h"
#include "chardev/char.h"
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

/* L18 vendor-INTC access census (defined near the vintc ops below) */
static void mmcs_vi_note(int is_w, hwaddr off, uint32_t val);
static void mmcs_vi_census_dump(void);

/* L21: the write-sticky page-ownership table (block below) */
int mmcs_pgown_fill(CPUSH4State *env, uint32_t address, uint32_t *pa,
                    int prot, int is_store);

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

/* MMCS fork (L26): the [UsbCommonInit] PFC USB handshake — the OTHER
 * polled register block the vendor kernel hits at boot.
 *
 * Decoded 2026-11-17 (L26 park walk): the kernel's USB common init
 * (nk.exe 0x908098c0-lane) writes the PFC USB mux config at
 * 0xFFE70804 (|= 1, then |= 3), then POLLS 0xFFE70808 for
 * (val & 0xC0000000) == 0xC0000000 with a 0x515900-try timeout;
 * on timeout it takes the error lane — the wide-string print
 * '//// [UsbCommonInit] register(USBST=0x%X) check error ////'
 * (ROM 0x90802750) — whose printer-thunk loop (0x90809b40 jsr +
 * 0x90809b48 lds.l @r15+,pr) was the KData-IST-stack ASCII caught
 * by the L26 bp probe, the serial '//\r\n' remnant, and the
 * return-to-garbage deaths that end the kernel launch cascade
 * before filesys's phase chain ever runs. On HW the USBST status
 * bits (+0x808 top two bits) come up once the port pins are muxed
 * (+0x804 low bits) — model exactly that: read-back storage for
 * the block, +0x808 reads OR ((stored+0x804 & 3) << 30).
 * Env MMCS_USBST=1, default off. */
static uint32_t pfc_usb_st[4];
static uint64_t mmcs_pfc_usb_read(void *opaque, hwaddr addr, unsigned size)
{
    if (addr == 0x808) {
        return pfc_usb_st[2] | ((pfc_usb_st[1] & 3) << 30);
    }
    if (addr / 4 < 4) {
        return pfc_usb_st[addr / 4];
    }
    return 0;
}
static void mmcs_pfc_usb_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size)
{
    if (addr / 4 < 4) {
        pfc_usb_st[addr / 4] = (uint32_t)val;
    }
}
static const MemoryRegionOps mmcs_pfc_usb_ops = {
    .read = mmcs_pfc_usb_read,
    .write = mmcs_pfc_usb_write,
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

/* ---- MMCS_SRVPG (L12): servant-window page-in synthesis support ----
 * The relaunched servant's kernel-side k.coredll window pages never get
 * rebuilt in the new process's page tables (see the SRVPG hook in
 * target/sh4/helper.c): the .text is a linear unrelocated image of the
 * ROM module section (mapped read-only straight at the flash), but the
 * .data sections are FILES-compressed in the raw image — their init
 * content must be decompressed via the side table. This allocator
 * hands out seeded demand pages (deduped per VA per boot) from the
 * dedicated mmcs.srvpg RAM at phys 0x26000000. */
static struct { uint32_t va, pa; } mmcs_srvpg_map[1024];
static int mmcs_nsrvpg;
static uint32_t mmcs_srvpg_nxt = 0x26000000;

/* MMCS fork (L17): MMCS_SRVPGTAB sidecar — the servant's TRUE non-XIP
 * section init content. DECODE (L17, ROM TOC parse + the decompressed
 * .data read-back): the L12 seeding path served the .data/.pdata pages
 * from RAW FLASH — the module's .data (psize 0x2da) and .pdata (psize
 * 0x2360) are CE-LZX-COMPRESSED in the image and are NOT covered by the
 * FILES table (module sections, not files; the table span starts at
 * 0x90b07550, the section blobs live at 0x912E4D14/0x944A635C), so the
 * fallback fed COMPRESSED BYTES to the servant as init .data. Every
 * pointer cell in .data was garbage: the woken L16 PNPThread called
 * pc=0x40a61eb0 = the compressed bytes at .data+0x5ec read as a function
 * pointer (the call site 0xc00280e8 "DirectHandleCall": mov.l @r2,r3;
 * jsr @r3 with r2=0xc00835ec — a runtime-bound "direct handle call"
 * cell whose TRUE init value is 0x00000000, filled by the lazy binder
 * FUN_c0028010 from live server handles; the stock mirror = the CE
 * loader's per-instance decompress of compressed sections, loader.c
 * PageInFromRAM-class — the pass that never ran for our synthesized
 * mapping). The kernel's own pager DOES decompress them on HW (the
 * live launch-1 window byte-verified: RTTI strings at .data+8 match
 * the decompressed blob). Sidecar = scripts/emul/build_srvpg_table.py
 * (proven corpus pipeline): v1 'SRP1' {n,{va,size,off,flags},blob} =
 * k.coredll's non-XIP sections; v2 'SRP2' {n,{va,size,rom,flags,off,
 * pad},blob} = EVERY kernel-side-DLL (C0-window) section of the ROM
 * TOC — the manifest MMCS_IATFIX services the whole window with. */
#define MMCS_SRVT_MAX 640
static struct {
    uint32_t va, size, rom, flags, off;   /* off 0xffffffff = XIP text */
} mmcs_srvt[MMCS_SRVT_MAX];
static int mmcs_nsrvt;
static uint8_t *mmcs_srvt_blob;
static size_t mmcs_srvt_blob_len;
/* the generalized window service is armed (MMCS_IATFIX=1 + SRVPGTAB
 * loaded + SRVPG scratch RAM present) — consumed by the tlb_fill hook
 * in target/sh4/helper.c */
int mmcs_iatfix_on;

/* MMCS fork (L22): MMCS_C0ARM=1 — arm the C0-window module service
 * (SRVPG .text/.data + IATFIX manifest) for the KERNEL-side servant
 * lane. Decoded 2026-11-17 (L22): the S141 post-prgInit death — the
 * k.coredll api-set/handle-table walk, statically the stock loader.c
 * import/export machinery (c003c354 DoImports-loop / c003ca10
 * ResolveImpOrd / c003c8e4 AddrFromEat, forwarder '.'-parse) — dies
 * because EVERY C0-window miss in these boots is refused with the
 * launch latch CLOSED: mmcs_ilkfix_user_seen only ever sets on USER-
 * mode events (KData 0x5000 fault / user arena write), but this
 * image's servants run entirely KERNEL-side (filesys relaunch lane)
 * so the latch never fires (L22DBG: every unserviced miss has
 * ilk=0, srvpg=1, iatfix=1 — e.g. the death triple: fetch
 * va=c003c3dc acc=0 pr=c003c39e, IAT store va=c0012000 acc=2,
 * export-dir read va=c0076470 acc=0 pr=90836a66 = the kernel's own
 * KernelInit2 module walk). The C0 window holds REAL module pages
 * (manifest XIP .text = flash bytes, non-XIP = decompressed init
 * content) — serving them to the kernel from first contact is what
 * the real pager does; the L8 early-walk hazard (loader-data holes)
 * was about the KData interlocked page, never this window. Consumed
 * by the SRVPG/IATFIX gates in superh_cpu_tlb_fill. */
int mmcs_c0arm;

/* MMCS fork (L23): MMCS_UWARM=1 — serve KERNEL-mode misses in the
 * CURRENT-PROCESS USER window [0x40000000,0x80000000) from the SRP2
 * manifest's user-window rows. Decoded 2026-11-17 (L23): the kd-class
 * module lane (ROM TOC[4] oalioctl.dll at c0011000, entry c00111f0)
 * runs the stock loader.c import walk (c003ca8a/c003caa0 =
 * ResolveImpOrd's export-dir/EAT loads) against the USER-mode coredll
 * instance — this image is a fully fixed-slot build: coredll.dll's o32
 * rows are absolute (real 0x40011000 XIP ROM 0x90853000, RW sections
 * at 0x40074000+; export dir 0x40066460, EAT/names through
 * 0x4006b000; the oalioctl IAT ships PRE-BOUND to 0x4001xxxx-class
 * user-coredll addresses and DllMain calls those targets). The walk's
 * kernel-mode loads at tea=40066f10/40068628/400696f0 (all inside the
 * 0x40011000 XIP span) were refused by every tlb_fill service (COWFIX
 * shape (b) covers only [40074000,40080000); the C0 lanes stop at
 * 0xC0000000) -> excp 0x040 -> marshalled PSL forward -> servant
 * death loop. On real HW the kernel maps the current process at
 * 0x40000000+ and kernel-mode access to user memory is legal
 * (PerformCallBack/marshalling semantics) — serving the manifest rows
 * (XIP .text from flash RO+X, non-XIP from the decompressed blob RW
 * per the L22 PE-bit decode) is what the real pager installs. The
 * oalioctl DllMain itself is fail-soft BY DESIGN (returns TRUE
 * unconditionally, mov #1,r0 in the rts delay slot) — the retail
 * no-debugger unit takes exactly this path with the window mapped;
 * the death was only the missing mapping, never a debugger-transport
 * need. Consumed by the UWARM gate in superh_cpu_tlb_fill; needs
 * MMCS_IATFIX + MMCS_SRVPGTAB (the user rows ship in the SRP2 table
 * since build_srvpg_table.py L23). */
int mmcs_uwarm;

#define MMCS_SRVPG_ROM_BASE 0x90800000

/* L25: the SRP2 manifest's rom field is the FULL ROM VA of the section
 * content (build_srvpg_table.py: rom = the o32 dataptr, 0x908xxxxx-class),
 * NOT a flash-relative offset. Both manifest consumers used to compute
 * MMCS_FLASH_BASE + rom, landing at ~0xA10CA000 — an unmapped phys that
 * reads zeros. That zero page then satisfied the oalioctl import-
 * descriptor walk (desc[0]==0 => "no imports" => fake DoImports success)
 * and got softmmu-cached as the c0011000 .text backing, so the later
 * DllMain-entry fetch at c00111f0 read word 0x0000 => illegal 0x180 =>
 * the trampoline "returns 0" => LoadOneLibraryPart2's failure-bit path
 * frees the module and returns NULL => the resolver derefs [0+0x38]
 * (the S144 death). Normalize any rom value (full ROM VA, legacy
 * flash-relative, or raw phys) to its flash phys backing. */
static inline hwaddr mmcs_rom_pa(uint32_t rom)
{
    if (rom >= MMCS_FLASH_BASE
        && rom < MMCS_FLASH_BASE + MMCS_FLASH_SIZE) {
        return rom;                        /* already flash-relative */
    }
    if (rom >= MMCS_SRVPG_ROM_BASE) {
        return MMCS_FLASH_BASE + (hwaddr)(rom - MMCS_SRVPG_ROM_BASE);
    }
    return rom;                            /* raw phys below the ROM base */
}

static const struct { uint32_t va, sz, rom; } mmcs_srvpg_secs[] = {
    /* k.coredll servant .data sections (realaddr manifest, verified
     * against the live window: 0xc004dba2/0xc002f0a0 pages byte-equal
     * their ROM images). */
    { 0xC0083000, 0x8A8,  0x912E4D14 },  /* files-compressed */
    { 0xC0084000, 0x4BA8, 0x944A635C },  /* files-compressed */
    { 0xC0089000, 0x13114, 0x9092E000 }, /* raw in image */
};

/* section of the loaded manifest covering `va` (NULL if none) */
static const void *mmcs_srvt_find(uint32_t va)
{
    for (int i = 0; i < mmcs_nsrvt; i++) {
        if (va >= mmcs_srvt[i].va && va < mmcs_srvt[i].va + mmcs_srvt[i].size) {
            return &mmcs_srvt[i];
        }
    }
    return NULL;
}

/* MMCS fork (L28): MMCS_FSVT — the k.coredll api-set CELL rescue
 * (hooks in target/sh4/helper.c do_interrupt). The kernel-side coredll
 * calls kernel APIs through runtime-bound .data cells — [c00835c0] the
 * FILESYS set, [c0083600] the WIN32 set — which ship 0 in the SRP2
 * blob and never get bound in emulation (the synthetic servant launch
 * skips the HW bind lane, and the loader's CopyRegions re-zeroes any
 * seed-time patch), so the thunk derefs fault at NULL+0xXX and the
 * vendor exception march killed every servant relaunch. The rescue
 * drives the derefs at REGISTER level (immune to the backing
 * flip-flop): the FS thunks jump straight to fsdmgr's FSINT_*
 * kernel-direct implementations (RegisterAFSName c02c8c60,
 * RegisterAFSEx c02c8ca4, DeregisterAFS c02c8db0, DeregisterAFSName
 * c02c8e50 — same ABI, identified from fsdmgr.functions.json; the tea
 * of the fault = the method offset), the WIN32 thunks re-base on the
 * ROM methods table 0x90821028 (CINFO 'Wn32' @90821848, cMethods 130:
 * CreateAPISet +0x08, GetLastError +0x178), and unmapped FS offsets
 * land here — on a 4KB all-stub table (slot -> `mov #-1,r0; rts`, the
 * guarded failure path). */
#define MMCS_FSVT_PAGE   0x1F020000u
#define MMCS_FSVT_P1     0x9F020000u
#define MMCS_FSVT_STUB   (MMCS_FSVT_P1 + 0xF00u)
static int mmcs_fsvt_armed;

/* Consumed by the do_interrupt FSVT hook in target/sh4/helper.c: the
 * all-stub fallback table's P1 address (0 when FSVT is not armed). */
uint32_t mmcs_fsvt_p1(void);
uint32_t mmcs_fsvt_p1(void)
{
    return mmcs_fsvt_armed ? MMCS_FSVT_P1 : 0;
}

static bool mmcs_srvpg_seed_page(uint32_t page, uint8_t *out)
{
    /* L17: manifest first — true decompressed init content */
    const void *sec = mmcs_srvt_find(page);
    if (sec) {
        const struct { uint32_t va, size, rom, flags, off; } *s = sec;
        if (s->off != 0xffffffffu) {
            uint32_t o = page - s->va;
            uint32_t n = MIN(0x1000u, s->size - o);
            if (s->off + n <= mmcs_srvt_blob_len) {
                memset(out, 0, 0x1000);
                memcpy(out, mmcs_srvt_blob + s->off, n);
                return true;
            }
        } else if (page >= s->va && page < s->va + ((s->size + 0xFFF) & ~0xFFFu)) {
            /* XIP section: serve the flash bytes (the manifest's rom
             * pointer; both are page-aligned, verified at build) */
            cpu_physical_memory_read(
                mmcs_rom_pa(s->rom) + (page - s->va), out, 0x1000);
            return true;
        }
    }
    /* legacy path: FILES side table, raw flash fallback */
    uint32_t rom = 0;
    for (unsigned i = 0; i < ARRAY_SIZE(mmcs_srvpg_secs); i++) {
        if (page >= mmcs_srvpg_secs[i].va
            && page < mmcs_srvpg_secs[i].va + mmcs_srvpg_secs[i].sz) {
            rom = mmcs_srvpg_secs[i].rom + (page - mmcs_srvpg_secs[i].va);
            break;
        }
    }
    if (!rom) {
        return false;
    }
    for (unsigned o = 0; o < 0x1000; o++) {
        uint32_t rva = rom + o;
        uint8_t b = 0;
        bool hit = false;
        for (int f = 0; f < mmcs_ftab_n; f++) {
            if (rva >= mmcs_ftab[f].load_va
                && rva < mmcs_ftab[f].load_va + mmcs_ftab[f].real) {
                uint32_t off = rva - mmcs_ftab[f].load_va
                               + mmcs_ftab[f].tbl_off;
                if (off < mmcs_ftable_len) {
                    b = mmcs_ftable_data[off];
                }
                hit = true;
                break;
            }
        }
        if (!hit) {
            cpu_physical_memory_read(
                MMCS_FLASH_BASE + (rva - MMCS_SRVPG_ROM_BASE), &b, 1);
        }
        out[o] = b;
    }
    return true;
}

/* MMCS fork (L17): MMCS_IATFIX — service a kernel-mode miss in the
 * kernel-side-DLL (C0) window from the loaded manifest. Called from the
 * tlb_fill hook in target/sh4/helper.c (the SRVPG generalization):
 * an XIP .text section page maps the flash ROM bytes read-only (the
 * real kernel-side mapping: fsdmgr .text 0xc02c1000 <-> ROM 0x90a82000,
 * byte-identical to what the kernel pager installs on HW); a non-XIP
 * section page seeds the mmcs.srvpg scratch with the DECOMPRESSED init
 * content (RW for writable sections, RO for rsrc/pdata-class). Returns
 * the backing phys page (0 = not covered / out of scratch); *rw
 * receives the write permission. */
hwaddr mmcs_iatfix_page_pa(uint32_t va, bool *rw, bool kernel_side);
hwaddr mmcs_iatfix_page_pa(uint32_t va, bool *rw, bool kernel_side)
{
    const void *sec = mmcs_srvt_find(va & ~0xFFFu);
    if (!sec) {
        return 0;
    }
    const struct { uint32_t va, size, rom, flags, off; } *s = sec;
    if (s->off == 0xffffffffu) {
        *rw = false;
        return mmcs_rom_pa(s->rom) + ((va & ~0xFFFu) - s->va);
    }
    /* non-XIP: deduped seeded scratch (the shared module instance copy).
     * RW decode (L22 fix): the SRP2 manifest flags field is the o32/PE
     * section characteristics (build_srvpg_table.py passes them through
     * raw) — writable = IMAGE_SCN_MEM_WRITE 0x80000000 (e.g. the IAT
     * sections c0012000 flags=c0300040, c00ce000 flags=c0002040).
     * The old `flags & 0x80` read never matched any manifest row
     * (0x80 is not a PE bit) so EVERY non-XIP section was served RO
     * and the loader's IAT stores bounced (the L22 death class after
     * the latch opened). Keep the 0x80 term for any legacy SRP1
     * table that used a host-side bit.
     *
     * L25: for the KERNEL-SIDE window (the C0ARM/IATFIX service) a
     * decompressed instance page is plain kernel RAM on HW — the
     * loader's own CopyRegions writes the section content through
     * the C0 VA (measured: pc=0x90837734 storing filesys's
     * c00d7000 blob instance, o32 flags 0x40002040 = no write bit),
     * and later reloc/IAT write-backs land there too. Only the XIP
     * flash pages stay RO there. User-window (UWARM) instances keep
     * the o32 decode (real user-mode protection). */
    bool row_rw = kernel_side
                  || !!(s->flags & 0x80000000u) || !!(s->flags & 0x80u);
    for (int i = 0; i < mmcs_nsrvpg; i++) {
        if (mmcs_srvpg_map[i].va == (va & ~0xFFFu)) {
            *rw = row_rw;
            return mmcs_srvpg_map[i].pa;
        }
    }
    if (mmcs_nsrvpg >= ARRAY_SIZE(mmcs_srvpg_map)
        || mmcs_srvpg_nxt + 0x1000 > 0x26400000) {
        fprintf(stderr, "MMCS: IATFIX scratch exhausted (n=%d)\n",
                mmcs_nsrvpg);
        return 0;
    }
    uint32_t pa = mmcs_srvpg_nxt;
    static uint8_t page[0x1000];
    if (!mmcs_srvpg_seed_page(va & ~0xFFFu, page)) {
        return 0;
    }
    cpu_physical_memory_write(pa, page, 0x1000);
    mmcs_srvpg_map[mmcs_nsrvpg].va = va & ~0xFFFu;
    mmcs_srvpg_map[mmcs_nsrvpg].pa = pa;
    mmcs_nsrvpg++;
    mmcs_srvpg_nxt += 0x1000;
    if (getenv("MMCS_SRVPGLOG")) {
        static int nil;
        if (nil++ < 96) {
            fprintf(stderr, "MMCS: IATFIX module page-in va=%08x "
                    "-> pa=%08x (n=%d)\n", va & ~0xFFFu, pa, mmcs_nsrvpg);
        }
    }
    *rw = row_rw;
    return pa;
}

/* Servant .data VA -> scratch phys page seeded with the module's init
 * content (L17: decompressed sidecar when MMCS_SRVPGTAB is loaded,
 * FILES side table / raw flash otherwise). Returns 0 when out of pages
 * or the VA is unknown.
 * Prototype consumed by target/sh4/helper.c (SRVPG hook). */
hwaddr mmcs_srvpg_data_pa(uint32_t va);
hwaddr mmcs_srvpg_data_pa(uint32_t va)
{
    va &= ~0xFFFu;
    for (int i = 0; i < mmcs_nsrvpg; i++) {
        if (mmcs_srvpg_map[i].va == va) {
            return mmcs_srvpg_map[i].pa;
        }
    }
    if (mmcs_nsrvpg >= ARRAY_SIZE(mmcs_srvpg_map)
        || mmcs_srvpg_nxt + 0x1000 > 0x26400000) {
        return 0;
    }
    uint32_t pa = mmcs_srvpg_nxt;
    static uint8_t page[0x1000];
    if (!mmcs_srvpg_seed_page(va, page)) {
        return 0;
    }
    cpu_physical_memory_write(pa, page, 0x1000);
    mmcs_srvpg_map[mmcs_nsrvpg].va = va;
    mmcs_srvpg_map[mmcs_nsrvpg].pa = pa;
    mmcs_nsrvpg++;
    mmcs_srvpg_nxt += 0x1000;
    if (getenv("MMCS_SRVPGLOG")) {
        static int nsl;
        if (nsl++ < 64) {
            fprintf(stderr, "MMCS: SRVPG servant .data page-in va=%08x "
                    "-> pa=%08x (n=%d)\n", va, pa, mmcs_nsrvpg);
        }
    }
    return pa;
}

/* ---- MMCS_PGOWN (L21): the write-sticky page-ownership table ----
 * THE VANISHING-WRITE DEFECT (S140, A/B-proven twice): the fdf hive
 * apply, the prgInit flags|=4 (cell 0xd00bfe4c) and the AutoLoad
 * sticky RegSetValueExW all land, execute, and are GONE one 7Hz pass
 * later. AUDIT of every host-side page-serving path (SRVPG/SRVPGTAB/
 * FILEVIEW/COWFIX/HBZERO/IATFIX): each one dedupes VA->PA per boot, so
 * none of them re-seeds a page IT owns — the amnesia is the other half
 * of the demand-pager model: the services only engage on FAULTS. The
 * moment the guest kernel authors its own mapping for the same VA
 * (demand-zero stack pages, hive buffer re-VirtualAlloc per pass, the
 * pager rebuilding servant-window entries), get_physical_address
 * resolves the FRESH guest page and the fault services step aside —
 * the written scratch content is orphaned = "serves fresh zeroed pages
 * on remap". (One latent re-seed also fixed by the same table: the
 * COWFIX dedup key is va & ~(entry size-1), unstable across faults
 * with different guest entry sizes — a re-keyed allocation seeds a
 * fresh zero page; a PINNED entry overrides it at fill time.)
 * FIX: one shared ownership table consulted at the single choke point
 * where QEMU installs softmmu translations (the tlb_set_page sites in
 * target/sh4/helper.c::superh_cpu_tlb_fill). A writable mapping in a
 * managed window registers CLEAN and is installed WITHOUT PAGE_WRITE;
 * the first store's permission bounce re-enters tlb_fill (the guest
 * translation itself grants write, so no guest exception is raised),
 * promotes the entry to PINNED with the page the store lands on, and
 * re-installs RW. From then on the pinned phys page IS the backing:
 * any later guest-authored remap of the VA is overridden to serve the
 * pinned copy = "first write pins the page content; later faults
 * serve the pinned copy". Keying (the COWFIX fidelity question, per
 * the L8-L14 audit's per-process obligation):
 *   per-ASID  — user windows [0x00800000,0x40000000) (heap arena) and
 *               [0x40000000,0x80000000) (coredll .data class): the
 *               real pager gives every process a fresh private copy;
 *               relaunches of a DIFFERENT process must not see the
 *               dead one's dirty pages (ASID recycle aliases are the
 *               documented bound of this model).
 *   shared    — [0xC0000000,0xC1000000) the kernel-side-DLL (C0)
 *               window: k.coredll/filesys/fsdmgr .data are process-
 *               COMMON (one kernel-side instance system-wide; servant
 *               relaunch keeps the module loaded on real HW), so the
 *               loader data is intentionally shared; the kernel stack
 *               arena [0xD0000000,0xDC000000) (kernel address space,
 *               stacks observed marching UP +0x10000/launch, never
 *               reused); and the KData page VA 0x5000 (one global
 *               struct). Sub-floor stack pages (0xD0000000-0xD0600000)
 *               only register once the launches are live — mirrors the
 *               FILEVIEW latch so the early IRQ-init walk's low-arena
 *               writes stay untouched.
 * P1/P2/P4 windows are excluded: their translation is identity by
 * construction, the backing never changes, pins would be no-ops.
 * Read-only mappings (XIP text) never register: writes to them must
 * keep violating (fidelity), and ROM content cannot be written anyway. */
#define MMCS_PGOWN_BITS 17
#define MMCS_PGOWN_SLOTS (1u << MMCS_PGOWN_BITS)
#define MMCS_PGOWN_ASID_SHARED 0x100   /* sentinel key (PTEH ASID is 8-bit) */
struct mmcs_pgown_ent {
    uint32_t va;       /* 4K page VA (0 = empty slot) */
    uint32_t asid;     /* key ASID (shared windows: the sentinel) */
    uint32_t pa;       /* registered/pinned backing phys page */
    uint32_t pinned;   /* 0 = clean (never written), 1 = pinned */
    uint32_t nremap;   /* remap-overrides served (diagnostics) */
};
static struct mmcs_pgown_ent mmcs_pgown[MMCS_PGOWN_SLOTS];
static int mmcs_pgown_armed;
static uint32_t mmcs_pgown_nins, mmcs_pgown_npin, mmcs_pgown_novr;

/* helper.c's launch-phase latch (the first USER-mode KData fault = the
 * PSL launches are live) — sub-floor stack registration gate */
extern bool mmcs_ilkfix_user_seen;

static int mmcs_pgown_class(uint32_t page)
{
    if (page == 0x5000) {
        return 2;                                   /* KData page */
    }
    if (page >= 0x00800000 && page < 0x40000000) {
        return 1;                                   /* user heap arena */
    }
    if (page >= 0x40000000 && page < 0x80000000) {
        return 1;                                   /* user .data (COWFIX) */
    }
    if (page >= 0xC0000000 && page < 0xC1000000) {
        return 2;                                   /* kernel-side DLL window */
    }
    if (page >= 0xD0000000 && page < 0xDC000000) {
        return 2;                                   /* kernel stack arena */
    }
    return 0;
}

static struct mmcs_pgown_ent *mmcs_pgown_find(uint32_t page, uint32_t asid)
{
    uint32_t h = ((page >> 12) * 2654435761u + asid * 40503u)
                 & (MMCS_PGOWN_SLOTS - 1);
    for (unsigned i = 0; i < MMCS_PGOWN_SLOTS; i++) {
        struct mmcs_pgown_ent *e = &mmcs_pgown[(h + i)
                                               & (MMCS_PGOWN_SLOTS - 1)];
        if (!e->va || (e->va == page && e->asid == asid)) {
            return e->va ? e : NULL;
        }
    }
    return NULL;
}

static struct mmcs_pgown_ent *mmcs_pgown_insert(uint32_t page, uint32_t asid,
                                                uint32_t pa)
{
    struct mmcs_pgown_ent *e = mmcs_pgown_find(page, asid);
    if (e) {
        return e;                    /* lost a race within one fill: reuse */
    }
    uint32_t h = ((page >> 12) * 2654435761u + asid * 40503u)
                 & (MMCS_PGOWN_SLOTS - 1);
    for (unsigned i = 0; i < MMCS_PGOWN_SLOTS; i++) {
        struct mmcs_pgown_ent *s = &mmcs_pgown[(h + i)
                                               & (MMCS_PGOWN_SLOTS - 1)];
        if (!s->va) {
            s->va = page;
            s->asid = asid;
            s->pa = pa;
            s->pinned = 0;
            s->nremap = 0;
            mmcs_pgown_nins++;
            return s;
        }
    }
    static bool warned;
    if (!warned) {
        warned = true;
        fprintf(stderr, "MMCS-PGOWN: table full - persistence passthrough\n");
    }
    return NULL;
}

/* The choke point: consult/modify the ownership table for one 4K page
 * about to be installed into the softmmu TLB. *pa may be overridden
 * (pinned entries force their backing); the returned prot strips
 * PAGE_WRITE for clean entries so the first store bounces back here
 * and pins the page it lands on. Called from every tlb_set_page site
 * in superh_cpu_tlb_fill (the ret==MMU_OK main path covers everything
 * the do_interrupt services install as guest UTLB entries, plus every
 * guest-kernel-authored remap). Passthrough (prot unchanged) when not
 * armed, outside the managed windows, for read-only mappings, or when
 * the table is full. */
int mmcs_pgown_fill(CPUSH4State *env, uint32_t address, uint32_t *pa,
                    int prot, int is_store)
{
    static int haslog = -1;
    static int havetrace;
    static uint32_t traceva;
    if (haslog < 0) {
        haslog = getenv("MMCS_PGOWNLOG") != NULL;
        const char *tv = getenv("MMCS_PGOWN_TRACE_VA");
        havetrace = tv && *tv;
        traceva = tv ? (uint32_t)strtoul(tv, NULL, 16) : 0;
    }
    if (havetrace && (address & ~0xFFFu) == traceva) {
        static int ntr;
        if (ntr++ < 64) {
            fprintf(stderr, "MMCS-PGOWN-TRACE fill va=%08x store=%d "
                    "prot=%d pa=%08x cls-latch(user_seen)=%d armed=%d\n",
                    (unsigned)address, is_store, prot, *pa,
                    (int)mmcs_ilkfix_user_seen, mmcs_pgown_armed);
        }
    }
    if (!mmcs_pgown_armed) {
        return prot;
    }
    uint32_t page = address & ~0xFFFu;
    int cls = mmcs_pgown_class(page);
    if (!cls) {
        return prot;
    }
    if (cls == 2 && page >= 0xD0000000 && page < 0xD0600000
        && !mmcs_ilkfix_user_seen) {
        return prot;    /* sub-floor stacks: launches-live latch only */
    }
    uint32_t key = (cls == 2) ? MMCS_PGOWN_ASID_SHARED
                              : (env->pteh & PTEH_ASID_MASK);
    struct mmcs_pgown_ent *e = mmcs_pgown_find(page, key);
    if (!e) {
        if (!(prot & PAGE_WRITE)) {
            return prot;               /* RO mapping: nothing to pin */
        }
        e = mmcs_pgown_insert(page, key, *pa);
        if (!e) {
            return prot;
        }
        if (haslog && mmcs_pgown_nins <= 32) {
            fprintf(stderr, "MMCS-PGOWN: reg va=%08x asid=%02x -> pa=%08x "
                    "(clean)\n", page, key, *pa);
        }
        return prot & ~PAGE_WRITE;
    }
    if (e->pinned) {
        if (*pa != e->pa) {
            e->nremap++;
            mmcs_pgown_novr++;
            if (haslog && mmcs_pgown_novr <= 32) {
                fprintf(stderr, "MMCS-PGOWN: OVERRIDE va=%08x asid=%02x "
                        "guest pa=%08x -> pinned pa=%08x\n",
                        page, key, *pa, e->pa);
            }
        }
        *pa = e->pa;
        return prot;
    }
    if (is_store && (prot & PAGE_WRITE)) {
        e->pinned = 1;
        e->pa = *pa;          /* pin the page this store lands on */
        mmcs_pgown_npin++;
        if (haslog && mmcs_pgown_npin <= 32) {
            fprintf(stderr, "MMCS-PGOWN: PIN va=%08x asid=%02x -> pa=%08x\n",
                    page, key, *pa);
        }
        return prot;
    }
    if (*pa != e->pa) {
        e->pa = *pa;          /* clean remap: the guest mapping is
                               * authoritative until the first write */
    }
    return prot & ~PAGE_WRITE;
}

static void mmcs_pgown_census(void)
{
    if (!mmcs_pgown_armed) {
        return;
    }
    fprintf(stderr, "MMCS-PGOWN: registered=%u pinned=%u remap-overrides=%u "
            "launch-latch=%d\n",
            mmcs_pgown_nins, mmcs_pgown_npin, mmcs_pgown_novr,
            (int)mmcs_ilkfix_user_seen);
    int shown = 0;
    for (unsigned i = 0; i < MMCS_PGOWN_SLOTS && shown < 24; i++) {
        struct mmcs_pgown_ent *e = &mmcs_pgown[i];
        if (e->va && e->pinned && e->nremap) {
            fprintf(stderr, "  pinned va=%08x asid=%02x pa=%08x "
                    "overrides=%u\n", e->va, e->asid, e->pa, e->nremap);
            shown++;
        }
    }
}

/* ---- Framebuffer console (MMCS_FBCON=1): live screen via QEMU display ---- */
#include "ui/console.h"
static QemuConsole *mmcs_con;

static void mmcs_fbcon_refresh(void *opaque)
{
    if (mmcs_con) {
        dpy_gfx_update_full(mmcs_con);
    }
}

static const GraphicHwOps mmcs_fbcon_ops = {
    .gfx_update = mmcs_fbcon_refresh,
};

static void mmcs_fbcon_init(MemoryRegion *sdram_mr)
{
    mmcs_con = graphic_console_init(NULL, 0, &mmcs_fbcon_ops, NULL);
    uint8_t *fb = memory_region_get_ram_ptr(sdram_mr)
                  + (0x08B00000 - MMCS_SDRAM_BASE);
    DisplaySurface *s = qemu_create_displaysurface_from(
        800, 480, PIXMAN_r5g6b5, 800 * 2, fb);
    dpy_gfx_replace_surface(mmcs_con, s);
    fprintf(stderr, "MMCS: framebuffer console live (800x480 RGB565)\n");
}

static int mmcs_fb_only_rearm = 0;  /* set by self-rearm: skip RAM sweep */

/* ---- MMCS_JITFIX: break the WinCE JIT-debugger name in kernel RAM ----
 * L9 decode: the last remaining per-boot fault (a servant's second-chance
 * RaiseException(0xC0000005, NONCONTINUABLE) after a failed kernel-side
 * 0xfffffdff-class call) engages the CE5 JIT path (schedule.c
 * UserExceptionFilter: pDebugger from HKLM\Debug\JITDebugger — the REAL
 * registry now answers "JitDbgrEXE.exe"): CreateProcess(JitDbgrEXE.exe)
 * succeeds (relfsd serves \Windows from the FILES table — first USER EXE
 * launch from the ROM FS), then the system DEADLOCKS: the faulting thread
 * loops ProcGetCode/STILL_ACTIVE waiting for the debugger attach while the
 * debugger parks on an INFINITE wait. On real HW servants don't fault, so
 * the JIT path never runs; our fault is an emulation gap. This fix breaks
 * the UTF-16 name in kernel RAM ('J'->'X') so CreateProcess fails and the
 * exception path takes the normal thread-death route. Bounded: sweeps
 * guest RAM every 2 s (virtual), stops after 128 patches or 120 s. */
static int mmcs_jitfix_hits;

static void mmcs_jitfix_sweep(void *opaque)
{
    /* UTF-16LE of the registry-configured JIT debugger name */
    static const char jit_name[] = "JitDbgrEXE.exe";
    static const struct { hwaddr lo, hi; } ranges[] = {
        { 0x08600000, 0x0B000000 },  /* kernel pool + filesys heaps */
        { 0x10000000, 0x10800000 },  /* kernel-stack arena backing */
    };
    uint8_t pat[32];
    int patlen = 0;
    for (const char *p = jit_name; *p; p++) {
        pat[patlen++] = (uint8_t)*p;
        pat[patlen++] = 0;
    }
    for (unsigned r = 0; r < ARRAY_SIZE(ranges); r++) {
        static uint8_t chunk[0x10000];
        const hwaddr lo = ranges[r].lo, hi = ranges[r].hi;
        for (hwaddr pa = lo; pa < hi && mmcs_jitfix_hits < 128;
             pa += sizeof chunk - patlen) {
            hwaddr n = MIN((hwaddr)sizeof chunk, hi - pa);
            cpu_physical_memory_read(pa, chunk, n);
            const uint8_t *hit = chunk;
            while (mmcs_jitfix_hits < 128) {
                hit = memmem(hit, n - (hit - chunk), pat, patlen);
                if (!hit) {
                    break;
                }
                hwaddr ha = pa + (hit - chunk);
                uint8_t broken = 'X';
                cpu_physical_memory_write(ha, &broken, 1);
                fprintf(stderr, "MMCS-JITFIX: JIT debugger name broken at "
                        "phys %08" HWADDR_PRIx "\n", ha);
                mmcs_jitfix_hits++;
                hit += patlen;
            }
        }
    }
    if (mmcs_jitfix_hits < 128
        && qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) < 120000) {
        QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_jitfix_sweep,
                                    NULL);
        timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 2000);
    } else {
        fprintf(stderr, "MMCS-JITFIX: done (%d patches)\n",
                mmcs_jitfix_hits);
    }
}


static void mmcs_dump_ram(void *opaque)
{
    /* L21: the page-ownership census at dump time */
    mmcs_pgown_census();
    /* L18: the vendor-INTC census snapshot at dump time */
    mmcs_vi_census_dump();
    /* MMCS_FINDPAT=<hexbytes>: scan unit RAM (0x08000000..0x10800000) for a
     * byte pattern at dump time and log phys hits — content-based phys
     * discovery for structures whose page tables were fault-aborted. */
    const char *fpat = getenv("MMCS_FINDPAT");
    if (fpat) {
        size_t plen = strlen(fpat) / 2;
        uint8_t pat[64];
        for (size_t i = 0; i < plen && i < sizeof pat; i++) {
            unsigned b; sscanf(fpat + i * 2, "%2x", &b); pat[i] = b;
        }
        uint8_t win[0x10000];
        for (hwaddr pa = 0x08000000; pa < 0x10800000; pa += sizeof win) {
            cpu_physical_memory_read(pa, win, sizeof win);
            for (size_t o = 0; o + plen <= sizeof win; o++) {
                if (!memcmp(win + o, pat, plen)) {
                    fprintf(stderr, "MMCS-FINDPAT hit phys %08llx\n",
                            (unsigned long long)(pa + o));
                }
            }
        }
    }

    static const struct { hwaddr pa; uint32_t len; const char *fn; } dumps[] = {
        { 0x08602000, 0x10000, "/tmp/copy0.bin" },
        { 0x0862c000, 0x10000, "/tmp/copy1.bin" },
        { 0x0867a000, 0x10000, "/tmp/copy2.bin" },
        { 0x08600000, 0x10000, "/tmp/ramstart.bin" },
        { 0x08602848, 0x10000, "/tmp/waittable.bin" },
        { 0x08602800, 0x10000, "/tmp/waitctx.bin" },
        { 0x0867b200, 0x10000, "/tmp/apiset.bin" },
        { 0x081C0000, 0x10000, "/tmp/srd1.bin" },
        { 0x081C2800, 0x10000, "/tmp/srd2.bin" },
        { 0x08602000, 0x10000, "/tmp/kdata64k.bin" },
        { 0x10800000, 0x10000, "/tmp/imgpage1.bin" },
        { 0x10801240, 0x10000, "/tmp/extarea.bin" },
        { 0x0867e000, 0x10000, "/tmp/fntable.bin" },
        { 0x0867a000, 0x10000, "/tmp/nkproc.bin" },
        { 0x108f7000, 0x10000, "/tmp/dllpool.bin" },
        { 0x1068e000, 0x10000, "/tmp/pagedmod.bin" },
        { 0x0867a000, 0x10000, "/tmp/kdata2.bin" },
        { 0x08600000, 0x10000, "/tmp/kdata0.bin" },
        /* FILEVIEW scratch (servant heap backing, phys 0x20000000): the
         * park-state heap-content analysis target (S129). 64MB dump; the
         * scan keeps only nonzero 4K pages. */
        { 0x20000000, 16 * 1024 * 1024, "/tmp/fileview.bin" },
        /* SRVPG .data window (servant .data seeded scratch, phys 0x26000000):
         * the list heads the coredll walker consumes live here (S129). */
        { 0x26000000, 4 * 1024 * 1024, "/tmp/srvpg.bin" },
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
        if (dumps[i].len > sizeof buf) {
            /* large region: stream it */
            FILE *f = fopen(dumps[i].fn, "wb");
            if (f) {
                uint8_t *big = g_malloc(dumps[i].len);
                cpu_physical_memory_read(dumps[i].pa, big, dumps[i].len);
                fwrite(big, 1, dumps[i].len, f);
                g_free(big);
                fclose(f);
            }
            continue;
        }
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

/* env-gate helper: on when set to anything except "0" (repo convention:
 * scripts pass VAR=0 for the A/B off-arm) */
static int mmcs_env_on(const char *name)
{
    const char *v = getenv(name);
    return v && *v && strcmp(v, "0") != 0;
}

void mmcs_inject_evt(uint32_t evt);

/* MMCS fork (L13): inject a vendor-INTC event into the CPU — the shared
 * engine behind the MMCS_VINTC_EVT injector and the MMCS_TICK timer-tick
 * delivery (mmcs_tick_deliver below). Presets INTEVT + the fork's inject
 * flag, then raises the CPU IRQ; superh_cpu_do_interrupt picks it up
 * (fork hook) and the kernel trampoline @0x90822f80 dispatches
 *   handler = *(u32*)(0x8867a000 + (evt>>3))   [BYTE offset, no scaling]
 * i.e. slot dword = evt>>5 = id+16 for HookInterrupt id, so
 *   EVT = 0x200 + id*0x20   (stock shexcept.src InterruptExceptionHandler
 * arithmetic; S75/S76's "IRQ<<8, slot=code>>10" decode was WRONG - all
 * S77 sweep codes landed outside the 0x800-byte table). Proven live:
 * evt 0xAE0->slot87->0x9080caec (SDHI0 thunk, IISR chain[23]),
 * evt 0xB00->slot88->0x9080cb08 (SDHI1, chain[24]),
 * evt 0x3E0->slot31->0x9080ce70 (vendor-INTC ch ISR, sysintr 34).
 * Waking a sleep-halted CPU works: superh_cpu_has_work is
 * CPU_INTERRUPT_HARD, so cpu_handle_halt clears cs->halted. */
void mmcs_inject_evt(uint32_t evt)
{
    if (mmcs_cpu) {
        CPUSH4State *env = &mmcs_cpu->env;
        static int n;
        env->intevt = evt;
        env->mmcs_evt_inject = 1;
        cpu_reset_interrupt(CPU(mmcs_cpu), CPU_INTERRUPT_HARD);
        cpu_interrupt(CPU(mmcs_cpu), CPU_INTERRUPT_HARD);
        if (getenv("MMCS_TMUDEBUG") && n++ < 64) {
            fprintf(stderr, "MMCS-TMU: inject evt=%03x halted=%d intevt=%03x\n",
                    evt, CPU(mmcs_cpu)->halted, env->intevt);
        }
    }
}

/* MMCS fork (L15): MMCS_RINGNOP — unblock the uHAL exception-ring
 * producer. DECODE (hermes S128 + this lane): FUN_9080755c's space check
 * `fill = ring[12]-ring[8]; if (fill < r6) goto 0x908075dc` blocks the
 * 43-byte exception-text write when nothing consumes the ring (the real
 * consumer = the KD/sub-CPU relay lane, unmodeled); the caller retries
 * forever = the L15 park. FIX SHAPE: NOP the `bf 0x908075dc` at kernel
 * VA 0x90807572 (guest XIP window, phys 0x10807572; QEMU writes the RAM
 * backing directly — no guest protections involved). The ring then wraps
 * (a debug log overwriting itself = faithful-enough emulation; strictly
 * better than return-synthesis: no pr/context hazards). Additive, env-
 * gated, delayed arm like TICK/HDEVT (default 140s virtual). */
static void mmcs_ringnop_arm(void *opaque)
{
    const uint16_t nops[1] = { 0x0009 };
    /* the bf at 0x90807572 is ONE 16-bit slot; patch both it and the
     * preceding cmp delay-slot alignment is unnecessary — single nop */
    cpu_physical_memory_write(0x10807572, (void *)nops, 2);
    fprintf(stderr, "MMCS: RINGNOP patched kernel ring space-check "
            "@0x90807572 (bf -> nop)\n");
}

/* MMCS fork (L13): MMCS_TICK=1 — deliver the vendor scheduler tick.
 * DECODE (L13, gdb park-walk of the deterministic post-kill park): the
 * system parks in the kernel idle loop `sleep` @0x908089fc with the TMU0
 * configured (TSTR=0x03, TCOR0=0x2b62 = OALTimerInit(1,0x2b62,0), TCR0
 * UNIE=1) but its underflow IRQ NEVER reaches the CPU: the vendor
 * SH7777 OAL programs no sh7750-compatible IPRA (reads 0 = TUNI0 masked
 * forever; the real unit routes timers through the vendor INTC at
 * 0xF4000000), so nothing wakes the halted CPU and CurMSec/SleepList
 * freeze — every timeout-based notify (the relaunch KillThread
 * owner-wait @0x9082954c: Sleep(500) doubling to a 30000 cap waiting
 * for pProc+0xC4 to drop to the 0x80000000 marker) parks forever.
 * The vendor dispatch table (@0x8867a000, handler = *(u32*)(base +
 * (evt>>3))) holds the timer ISR 0x90809d78 (the S91 timer-ISR
 * epilogue: clears TMU TCSR, cur-thread bookkeeping, scheduler yield)
 * at slot 0x8867a088 => EVT 0x440 (id 18 = the stock TUNI2 vector).
 * FIX: a 1ms QEMU_CLOCK_VIRTUAL timer (the JITFIX/DUMP timer class —
 * these fire reliably at the park, unlike the tmu012 ptimer whose
 * callback starves behind the halted vCPU) delivers EVT 0x440 through
 * the shared injector; the kernel trampoline @0x90822f80 dispatches
 * the ISR natively, the tick advances, sleepers expire, the notify
 * fires. Delayed start (MMCS_TICK_DELAY, default 12s, the
 * early-injection-derails-init rule from the VINTC experiments). */
/* MMCS fork (L14): MMCS_HDEVT=1 — deliver the event-set for the parked
 * boot thread's last wait. DECODE (L14, full-boot Z2 write-watchpoints on
 * the waiter's event object + park walks + the stock-source mirror): the
 * deterministic post-kill park leaves exactly ONE interesting waiter —
 * the boot-stack kernel-only thread 0x906ff024 (kstk 0xd001ff00, THE
 * first boot stack) blocked INFINITE in the vendor DoWait loop
 * (0x90837cf6: re-issues KCall(0x90828244) = the old-CE BlockWithHelper
 * while thread->wait-state bit 0x4000 is set) on the kernel EVENT object
 * 0x906dc234 — an EVNT-class named event "hd.dll" (handle 0x8400, HDATA
 * @0x906dc2d0 = {phys-self, lock, ref, pci="EVNT"@0x90822040, pvObj,
 * hValue 0x00010002}), created at t~3s by 0x908361xx in the vendor
 * KernelInit2 debug-harness lane (right after a "CeLog.dll"-named event;
 * the stock mirror = kwin32.c KernelInit2: LoadKernelLibrary("hd.dll")/
 * osaxst0/1/kd.dll, g_pHdEvent = the HDSTUB-client handshake event).
 * The wait-block (0xd001fd98, on the waiter's kstack: {obj, next=self,
 * prev=self, .., pTh=0x906ff024}) is the event's only proxy. NOTHING
 * ever sets the event: a Z2 write-watch on the object for the whole boot
 * saw ZERO writes after the block at t=16s — and no OAL ISR references
 * it: the live 24-slot dispatch-table census shows only status-gated
 * multi-source ISRs and unconditional-sysintr stubs (0x240->19, 0x540->
 * 18, 0x780->33, 0x5a0->43, 0x640->57...), all of which pend+drain
 * anonymously through PendEvents1 @0x886798b8 (the stock IntrEvents[]
 * holds ONLY the OAL's own sysintr-34 stub at KData+0x208; registering
 * our event into IntrEvents[6]+pend+bResched drains without a wake —
 * the vendor drain has no stock EventModIntr walk). The feeder on real
 * HW = the hd.dll client's own completion (or a boot config that skips
 * the harness); in emulation it never comes.
 * FIX: synthesize the set through 100% vendor code — a one-shot (BQL
 * virtual timer, default MMCS_HDEVT_DELAY=140s = post-park) writes a
 * small SH4 stub to the KILLSTK page (P2 0xBF00F000, kernel-executable,
 * clear of both the sh7750 INTC register window at the region bottom and
 * the kill stack top 0xBF00FF00; requires MMCS_KILLSTK) that calls the
 * vendor event-set walker 0x90827f68(pEvent=0x906dc234, EVENT_SET=3)
 * (both the EVNT m2 wrapper 0x9083fff0 — which decodes a HANDLE arg —
 * and the internal DoEventMod 0x9083fe94 — which KCall()s the walker —
 * fault when invoked from interrupt context; the walker itself runs
 * with interrupts masked exactly like an ISR body),
 * rewires an EMPTY dispatch-table slot (evt 0x200 -> slot dword
 * @0x8867a040, RAM), then chains the delivery through the NEXT ticks
 * (mmcs_hdevt_pending: a free-running injection races the 1ms tick's
 * intevt overwrite — the tick callback is the proven delivery path).
 * The waiter should wake with WAIT_OBJECT_0 and KernelInit2 continues.
 *
 * MMCS fork (L15): complete the wake — the L14 stub delivered only the
 * FIRST half of the vendor EventModify(EVENT_SET): the walker
 * 0x90827f68 (= the stock EventModIntr, sched.c:1538) detaches the
 * proxy, wCount++s and flips the waiter state16 0x62 -> 0x63
 * (NEEDSRUN, `wInfo |= 3`), returning pTh — but the stock
 * SC_EventModify (sched.c:1643-44) then does
 * `if (hWake) KCall(MakeRunIfNeeded, hWake)`, and THAT half (the
 * run-queue insert) never ran, so the vendor scheduler had no runnable
 * thread to pick and the waiter stayed parked at NEEDSRUN. DECODE
 * (L15, re_tools disasm + park walks, all mirroring stock sched.c):
 *  - MakeRunIfNeeded 0x908278e8: guard state16&3==3, then (state&0x20
 *    -> RunqDequeue 0x90826308 = the sleep-list unlink — the parked
 *    waiter has the +0x148 sleep link 0x9069c2f8) + wCount++, then
 *    MakeRun 0x90825ee4.
 *  - MakeRun 0x90825ee4 = stock MakeRun (sched.c:709) instruction for
 *    instruction: bSuspendCnt(+14) check, state16=(s&~3)|1 RUNNABLE,
 *    cprio(+65), enqueue RunList@0x8867efa0 {+0 pRunnable,
 *    +8+4*(cprio/8) pHashThread[]}, thread links +324/+328 (list) and
 *    +340/+344 (hash ring), tail: when !pth or higher prio, the
 *    long-store *(KDataPtr+0x88)=1 with KDataPtr=*0x8867ed64=
 *    0x88679800 (park-verified) — i.e. the "resched/drain-B" gate
 *    0x88679888, NOT the {drainA-flag,cNest} word 0x88679884 the
 *    interrupt-return trampoline checks (word==0x0101 -> scheduler
 *    entry 0x90822b0a).
 *  - the completion is vendor-native from interrupt context: the
 *    scheduler re-check (0x90822b7e) runs drain A 0x90826f4c (the
 *    IntrEvents/KData-pend walk whose wake path itself calls MakeRun
 *    0x90825ee4 directly from ISR context — proof the vendor does the
 *    run-queue insert there too) and drain B 0x90827148 (gated by the
 *    0x88679888 cell MakeRun sets: quantum bookkeeping + THE PICK that
 *    fills RunList.pth from pRunnable), then switches to *(pth) and
 *    rte-resumes the thread at its saved ctx (thread+0xb0/b4/b8).
 *  - the L14 "walker switches context mid-flight / never returns"
 *    reading was a stub bug: the stale r2 (callee-clobbered to pTh)
 *    sent the marker+retval stores to *(pTh+0) (self-repairing); the
 *    walker returned pTh in r0 all along.
 * FIX: stub v2 — guarded (reads pEvent+0x8 first: re-deliveries on the
 * 10-chained ticks after the arena reaped the event no-op instead of
 * writing the recycled object), calls walker(pEvent, EVENT_SET), saves
 * r0=hWake, reloads r2 (clobber lesson), and calls the vendor's own
 * MakeRunIfNeeded(hWake) — the exact stock SC_EventModify post-flip
 * sequence, minus the KCall wrapper (we are already in the
 * interrupts-masked ISR-equivalent context KCall would create; the
 * vendor's drain A does the same). The idle loop's tick wake ->
 * drain-B pick -> switch completes the resume natively.
 * RESULT (L15 A/B, one-shot @v140s + MMCS_HDEVT_REPEAT ladder):
 * the wake WORKS — marker 0x0d (walker+MakeRunIfNeeded complete),
 * wCount +2 per delivery (20 after the 10-tick chain = every chained
 * delivery resumed the thread), the L14 tick-timer suicide is fixed
 * (ticks survive the delivery: 187K post-delivery ticks; see
 * mmcs_tick_deliver) — and the thread RE-BLOCKS every time BY DESIGN:
 * the parked waiter's caller is an UNCONDITIONAL SERVICE PUMP
 * (0x908382be: loop { KCall(SetPrio-class 0x90826b88); wait on the
 * event at *(*(0x8867ebb4)+0x90); 0x908424d0; 0x90845aec; bra }),
 * i.e. the L14 "last wait" is a kernel service loop (the harness/
 * notify pump), not a boot step — the boot frontier is the OTHER
 * parked waiters (the servant-side threads with waitblocks on
 * 0x9069c6ac/0x906a3598/0x906a3634/0x906dc6e4/0x906dc9fc-class
 * events), each needing its own feeder decoded (L16). */
static const uint8_t mmcs_hdevt_stub[] = {
    0x22, 0x4f,                /* sts.l pr,@-r15 */
    0xe6, 0x2f,                /* mov.l r14,@-r15 */
    0x0f, 0xd4,                /* mov.l .Le,r4 (pEvent 0x906dc234) */
    0x42, 0x50,                /* mov.l @(8,r4),r0 (proxy head) */
    0x08, 0x20,                /* tst r0,r0 */
    0x13, 0x89,                /* bt Lret (already delivered: no-op) */
    0x0a, 0xe1,                /* mov #10,r1 (marker: delivery entered) */
    0x0c, 0xd2,                /* mov.l .Lm,r2 */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0x03, 0xe5,                /* mov #3,r5 (EVENT_SET) */
    0x0c, 0xd3,                /* mov.l .Lw,r3 (0x90827f68 walker) */
    0x0b, 0x43,                /* jsr @r3 */
    0x09, 0x00,                /* nop */
    0x03, 0x6e,                /* mov r0,r14 (hWake = pTh) */
    0x0b, 0xe1,                /* mov #11,r1 (marker: walker returned) */
    0x08, 0xd2,                /* mov.l .Lm,r2 (reload: clobbered) */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0xe8, 0x2e,                /* tst r14,r14 */
    0x06, 0x89,                /* bt Lret */
    0xe3, 0x64,                /* mov r14,r4 */
    0x08, 0xd3,                /* mov.l .Lmri,r3 (0x908278e8 MakeRunIfNeeded) */
    0x0b, 0x43,                /* jsr @r3 */
    0x09, 0x00,                /* nop */
    0x0d, 0xe1,                /* mov #13,r1 (marker: MakeRunIfNeeded done) */
    0x03, 0xd2,                /* mov.l .Lm,r2 */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0xf6, 0x6e,                /* Lret: mov.l @r15+,r14 */
    0x26, 0x4f,                /* lds.l @r15+,pr */
    0x00, 0xe0,                /* mov #0,r0 (SYSINTR_NOP) */
    0x0b, 0x00,                /* rts */
    0x09, 0x00,                /* nop */
    0x09, 0x00,                /* nop (align pad) */
    0x00, 0xff,                /* .Lm: marker cell 0xBF00FF00 (killstk top) */
    0x00, 0xbf,
    0x34, 0xc2,                /* .Le: pEvent 0x906dc234 */
    0x6d, 0x90,
    0x68, 0x7f,                /* .Lw: 0x90827f68 (EventModIntr walker) */
    0x82, 0x90,
    0xe8, 0x78,                /* .Lmri: 0x908278e8 (MakeRunIfNeeded) */
    0x82, 0x90,
};

static int mmcs_hdevt_pending;

static void mmcs_hdevt_fire(void *opaque);

static void mmcs_hdevt_restore(void *opaque)
{
    static const uint32_t zero;
    cpu_physical_memory_write(0x0867a040, &zero, 4);
    fprintf(stderr, "MMCS-HDEVT: dispatch slot evt 0x200 restored\n");
}

static void mmcs_hdevt_trace(void *opaque);

static void mmcs_hdevt_fire(void *opaque)
{
    uint32_t stub_va = 0xBF00F000;
    uint32_t link = 0;
    cpu_physical_memory_read(0x106DC23C, &link, 4);   /* event +0x8 */
    cpu_physical_memory_write(0x1F00F000, mmcs_hdevt_stub,
                              sizeof mmcs_hdevt_stub);
    cpu_physical_memory_write(0x0867a040, &stub_va, 4);
    mmcs_hdevt_pending = 10;    /* chain the next 10 ticks to evt 0x200 */
    fprintf(stderr, "MMCS-HDEVT: stub installed @%08x, slot evt 0x200 "
            "rewired, chained to next ticks (event+8=%08x)\n",
            stub_va, link);
    if (mmcs_env_on("MMCS_HDEVT_TRACE")) {
        QEMUTimer *tr = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_hdevt_trace,
                                     NULL);
        timer_mod(tr, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL));
    }
    QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_hdevt_restore, NULL);
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 100);
    /* MMCS fork (L15): the handshake LADDER — the vendor KernelInit2
     * debug-harness lane waits sequentially ({osaxst1, osaxst0, hd.dll,
     * kd.dll} per the L14 string table), and the arena reuses the
     * 0x906dc234 slot for each successive named event (observed live:
     * "CeLog.dll"->"hd.dll"->the post-wake event, all EVNT-class at
     * the same address with the same HDATA @0x906dc2d0). With
     * MMCS_HDEVT_REPEAT=<ms> the delivery re-arms: each firing wakes
     * whatever waitblock is currently linked on the slot's event; the
     * stub's +0x8 guard makes empty firings no-ops (safe while the
      * woken thread runs its next step). L16 hardening: an empty-string
      * env var (the common `VAR=$X` scripting accident) must NOT arm
      * the repeat — atoi("")=0 makes it a +0ms fire loop (3.5M
      * fires/300s starved every other chained delivery; found live in
      * the first L16 verify run). */
    const char *l16rep = getenv("MMCS_HDEVT_REPEAT");
    if (l16rep && *l16rep && atoi(l16rep) > 0) {
        QEMUTimer *r = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_hdevt_fire,
                                    NULL);
        timer_mod(r, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
                  + atoi(l16rep));
    }
}

/* L16 forward: the tick chain below services one pending event-wake
 * per tick once MMCS_L16EV arms them (full block + decode below). */
#define MMCS_L16_MAX 8
struct mmcs_l16_ent {
    uint32_t evt_va;
    uint32_t stub_va;
    uint32_t evt_code;
    uint32_t slot_pa;
    int pending;
    /* L19: daemon-mode entries (MMCS_L19EV) — the wake-cadence engine
     * re-arms per pump iteration instead of a one-shot chain. */
    int daemon;
    int strikes;
    uint32_t ndeliv;
};
static struct mmcs_l16_ent mmcs_l16_ents[MMCS_L16_MAX];

/* L19: the wake-cadence daemon (full block + decode below) */
static void mmcs_l19_scan(void);
static int mmcs_l19_armed;
static uint32_t mmcs_l19_cadence_ms = 1000;
/* L26: the DoWait-orphan wake daemon (full block + decode below) */
static void mmcs_l26_scan(void);
static int mmcs_l26_armed;
static uint32_t mmcs_l26_cadence_ms = 2000;
static uint32_t mmcs_l26_max_deliv = 64;

static void mmcs_tick_deliver(void *opaque)
{
    static uint64_t ntick;
    static uint64_t l19_ticks;
    static uint64_t l26_ticks;
    bool hdevt = mmcs_hdevt_pending > 0;
    bool l16 = false;
    if (hdevt) {
        mmcs_inject_evt(0x200);
        if (--mmcs_hdevt_pending == 0) {
            fprintf(stderr, "MMCS-HDEVT: stub-evt deliveries done\n");
        }
        /* L15 fix: do NOT return early — the tick timer must re-arm
         * itself or the delivery kills every future tick (the L14
         * early-return silently stopped the scheduler tick after the
         * first HDEVT chain: the woken thread re-blocked into a tick
         * void and could never be rescheduled; "deliveries done" never
         * printed). We still skip this slot's 0x440 inject (the stub
         * evt consumed it) but keep the 1ms cadence alive. */
    } else {
        /* L19: the daemon scan runs on the tick chain — one scan per
         * cadence period (default every 1000th tick), each delivery
         * replaces this tick's 0x440 exactly like the L16/L18 chains */
        if (mmcs_l19_armed && ++l19_ticks >= mmcs_l19_cadence_ms) {
            l19_ticks = 0;
            mmcs_l19_scan();
        }
        /* L26: the DoWait-orphan wake daemon (same cadence class) */
        if (mmcs_l26_armed && ++l26_ticks >= mmcs_l26_cadence_ms) {
            l26_ticks = 0;
            mmcs_l26_scan();
        }
        /* L16: service one pending event-wake per tick (after the
         * HDEVT chain; same slot-consuming semantics, same guard).
         * L18: entries 4..7 (the v2 completion stubs) share the walk —
         * armed = pending>0, the parse no longer packs them. */
        for (int i = 0; i < MMCS_L16_MAX; i++) {
            struct mmcs_l16_ent *e = &mmcs_l16_ents[i];
            if (e->pending > 0) {
                mmcs_inject_evt(e->evt_code);
                if (--e->pending == 0 && !e->daemon) {
                    fprintf(stderr, "MMCS-L16: evt %03x deliveries done\n",
                            e->evt_code);
                }
                l16 = true;
                break;
            }
        }
        if (!l16) {
            mmcs_inject_evt(0x440);
        }
    }
    if (!hdevt && !l16 && getenv("MMCS_TMUDEBUG")
        && (ntick++ % 500) == 0) {
        uint32_t tcnt = 0;
        cpu_physical_memory_read(0xFFD8000C, &tcnt, 4);
        fprintf(stderr, "MMCS-TMU: tick#%" PRIu64 " vclk=%" PRId64
                " TCNT0=%08x\n", ntick,
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), tcnt);
    }
    QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_tick_deliver, NULL);
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1);
}

/* MMCS fork (L15 diagnostics): MMCS_HDEVT_TRACE=1 — sample the vendor
 * scheduler cells around the parked waiter every 10ms of virtual time
 * and print a line on ANY change (bounded: stops after 64 lines). Catches
 * the wake/schedule/resume sequence ground-truth without gdb (whose
 * stop sequencing proved unreliable for hot breakpoints). */
static void mmcs_hdevt_trace(void *opaque)
{
    struct { uint32_t phys; const char *name; } cells[] = {
        { 0x106FF030, "state16" },   /* waiter 0x906ff024 +0xc */
        { 0x106FF0D4, "ctx.pc" },    /* waiter +0xb4 */
        { 0x106FF0D0, "ctx.sp" },    /* waiter +0xb0 */
        { 0x0867EFA0, "pRunnable" },
        { 0x0867EFA4, "pth" },
        { 0x08679884, "flagpair16" },
        { 0x08679888, "drainB" },
        { 0x08679810, "pCur" },
    };
    static uint32_t prev[8];
    static int lines;
    uint32_t cur[8];
    bool changed = false;
    for (unsigned i = 0; i < 8; i++) {
        cur[i] = 0;
        cpu_physical_memory_read(cells[i].phys, &cur[i], 4);
        if (i == 5) {
            cur[i] &= 0xffff;   /* the word84 pair only: mask the noisy
                                 * per-tick byte at +2 (idle heartbeat) */
        }
        if (cur[i] != prev[i]) {
            changed = true;
        }
    }
    if (changed && lines < 256) {
        fprintf(stderr, "MMCS-TRACE t=%" PRId64 "ms", qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL));
        for (unsigned i = 0; i < 8; i++) {
            if (cur[i] != prev[i]) {
                fprintf(stderr, " %s=%08x->%08x", cells[i].name, prev[i], cur[i]);
            }
        }
        fprintf(stderr, "\n");
        lines++;
    }
    memcpy(prev, cur, sizeof prev);
    QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_hdevt_trace, NULL);
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
              + atoi(getenv("MMCS_HDEVT_TRACE_MS") ? : "10"));
}

/* MMCS fork (L18): MMCS_SCHEDTRACE=1 — sample the vendor scheduler cells
 * every 10ms of virtual time and print a line on ANY change (bounded:
 * 512 lines). DECODE MOTIVATION: the L17 state parks with the kernel
 * MAIN thread (0x906ff024 — the stock schedule.c alarm-loop lane,
 * SetThreadBasePrio(self, dwNKAlarmThrdPrio) + WaitForSingleObject
 * (hAlarmThreadWakeup, ONE_DAY=0x5265C00)) stuck INSIDE the
 * SetThreadBasePrio KCall (resume pc 0x908382ca), while the switcher's
 * pick cell *(0x8867efa4) and pCurTh *(0x88679894) still name the kill-
 * era CORPSE thread 0x9068f0c0 (state16=8=dead, ctx sp=0xbeffff5c
 * unmapped). The L15/L16 stub chain resumes waiters from tick context
 * without a switcher pass, so the current-thread bookkeeping never
 * advanced — this tracer catches the wake->MakeRun->pick->switch
 * dynamics ground-truth. */
static void mmcs_sched_trace(void *opaque)
{
    struct { uint32_t phys; const char *name; } cells[] = {
        { 0x0867EFA0, "q0" },       /* run-queue band0 head / pick input */
        { 0x0867EFA4, "pick" },     /* switcher's next-thread cell */
        { 0x08679894, "pCurTh" },   /* KData+0x94 (current thread) */
        { 0x08679884, "kcallflags" },
        { 0x08679888, "kcalldrain" },
        { 0x08679810, "pCurPrc" },
        { 0x106FF030, "boot.state16" },   /* 0x906ff024 +0xc */
        { 0x106FF0D4, "boot.ctxpc" },     /* +0xb4 */
        { 0x086CA24C, "q0th.state16" },   /* 0x906ca240 +0xc */
        { 0x086CA2F4, "q0th.ctxpc" },     /* +0xb4 */
        { 0x1068F0CC, "corpse.state16" }, /* 0x9068f0c0 +0xc */
        { 0x1068F0D4, "corpse.ctxpc" },   /* +0xb4 */
    };
    static uint32_t prev[12];
    static int lines;
    uint32_t cur[12];
    bool changed = false;
    for (unsigned i = 0; i < 12; i++) {
        cur[i] = 0;
        cpu_physical_memory_read(cells[i].phys, &cur[i], 4);
        if (cur[i] != prev[i]) {
            changed = true;
        }
    }
    if (changed && lines < 512) {
        fprintf(stderr, "MMCS-SCHED t=%" PRId64 "ms",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL));
        for (unsigned i = 0; i < 12; i++) {
            if (cur[i] != prev[i]) {
                fprintf(stderr, " %s=%08x->%08x", cells[i].name,
                        prev[i], cur[i]);
            }
        }
        fprintf(stderr, "\n");
        lines++;
    }
    memcpy(prev, cur, sizeof prev);
    QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_sched_trace, NULL);
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
              + atoi(getenv("MMCS_SCHEDTRACE_MS") ? : "10"));
}

/* MMCS fork (L16): MMCS_L16EV=<eventVA>@<delay_ms>[,...] — wake the
 * servant-side waiters of the L15 frontier. DECODE (L16, park walks +
 * full-RAM content scans + the stock CE5 mirror, all mirrored against
 * PRIVATE/WINCEOS/COREOS/STORAGE/STOREMGR/storemain.cpp and the fsdmgr
 * ghidra decode): the five parked events belong to THREE servant
 * threads of the filesys process (thread list {0x906ff024 the hd.dll
 * pump, 0x906a36f4, 0x906dc7a4, 0x906dcacc, ...}):
 *  - WAITER A 0x906a36f4 = the fsdmgr STOREMGR PNPThread (thread start
 *    0xc02c5da0 = FUN_c02c6048's CreateThread target, the stock
 *    PNPThread mirror) waiting WaitForMultiple(3) with a PROXY ARRAY on
 *    its kstack (0xd01cfad4/af8/b1c, stride 0x24 = sizeof(PROXY)) on
 *    {0x9069c6ac g_hAutoLoadEvent "SYSTEM\AutoLoadFileSystems"
 *    (manual-reset, NAMED — bType 0xff HT_MANUALEVENT in its proxy),
 *    0x906a3598 g_hPNPUpdateEvent (auto-reset), 0x906a3634 = the PNP
 *    msgqueue's read event (event+0x9c -> queue 0x8867ab14, whose
 *    message list holds TWO real pending notifications, data at
 *    0x906fedb0/0x906fef1c)}.
 *  - WAITER B 0x906dc7a4 = a second kernel service pump (start
 *    0x9083816c, the same pump class as the hd.dll thread's
 *    0x908382be loop; service cells at 0x8867eb34) waiting on
 *    0x906dc6e4 — no pending request (unset).
 *  - WAITER C 0x906dcacc = a filesys.dll-tail thread (start
 *    0xc00d0d40) that walked the Notify-class kernel methods
 *    (0x90842fcc/0x90843032 frames) waiting on 0x906dc9fc — unset.
 * THE SMOKING GUN (event +0x8c byte pair {+0x8d state, +0x8e flags}):
 * 0x9069c6ac AND 0x906a3634 sit SIGNALED (fb010000: state=1) with
 * their waiter proxies STILL LINKED — the vendor set paths ran (the
 * phase-2 sync autoload DID complete, the queue DID receive device
 * notifications) but the wakes were lost (the stock kernel prevents
 * this via the BlockWithHelper wCount re-check; the vendor
 * WaitForMultiple path does not) = the same missing-wake class L14
 * found on hd.dll, now with REAL state behind it. FIX: complete the
 * wake through 100% vendor code — per-event instances of the
 * L15-proven stub (guard -> EventModIntr walker 0x90827f68(pEvent,
 * EVENT_SET) -> MakeRunIfNeeded 0x908278e8) installed on the KILLSTK
 * page (blocks at 0xBF00E000+n*0x100, below the L14 stub at 0xF000,
 * clear of the kill-stack top 0xFF00 and the INTC reg window), wired
 * to EMPTY dispatch slots (evt 0x220/0x260/0x280/0x2A0/0x2C0 — the
 * fresh dispatch census shows only the default 0x90822e40 there),
 * delivered through the 1ms tick chain (the proven path; the stub's
 * event+0x8 guard makes the chained re-deliveries no-ops). One-shot
 * per list entry: NO permanent synthetic pumping (a second firing =
 * list the same VA again with a later delay). */
#define MMCS_L16_STUB_BASE 0xBF00E000
#define MMCS_L16_STUB_MARK 0xF0     /* marker cell at block+0xF0 */
static const uint32_t mmcs_l16_evts[MMCS_L16_MAX] = {
    0x220, 0x260, 0x280, 0x2A0, 0x2C0, 0x2E0, 0x300, 0x320
};
static const uint32_t mmcs_l16_slots[MMCS_L16_MAX] = {
    0x0867A044, 0x0867A04C, 0x0867A050, 0x0867A054,
    0x0867A058, 0x0867A05C, 0x0867A060, 0x0867A064
};

/* body = the L15 hdevt v2 stub verbatim (pool literals patched per
 * instance: .Le event VA + .Lm marker cell — located by VALUE search,
 * robust against layout drift) */
static uint8_t mmcs_l16_stub[] = {
    0x22, 0x4f,                /* sts.l pr,@-r15 */
    0xe6, 0x2f,                /* mov.l r14,@-r15 */
    0x0f, 0xd4,                /* mov.l .Le,r4 */
    0x42, 0x50,                /* mov.l @(8,r4),r0 (proxy head) */
    0x08, 0x20,                /* tst r0,r0 */
    0x13, 0x89,                /* bt Lret (already delivered: no-op) */
    0x0a, 0xe1,                /* mov #10,r1 (marker: delivery entered) */
    0x0c, 0xd2,                /* mov.l .Lm,r2 */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0x03, 0xe5,                /* mov #3,r5 (EVENT_SET) */
    0x0c, 0xd3,                /* mov.l .Lw,r3 */
    0x0b, 0x43,                /* jsr @r3 */
    0x09, 0x00,                /* nop */
    0x03, 0x6e,                /* mov r0,r14 (hWake = pTh) */
    0x0b, 0xe1,                /* mov #11,r1 (marker: walker returned) */
    0x08, 0xd2,                /* mov.l .Lm,r2 (reload: clobbered) */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0xe8, 0x2e,                /* tst r14,r14 */
    0x06, 0x89,                /* bt Lret */
    0xe3, 0x64,                /* mov r14,r4 */
    0x08, 0xd3,                /* mov.l .Lmri,r3 */
    0x0b, 0x43,                /* jsr @r3 */
    0x09, 0x00,                /* nop */
    0x0d, 0xe1,                /* mov #13,r1 (marker: MRI done) */
    0x03, 0xd2,                /* mov.l .Lm,r2 */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0xf6, 0x6e,                /* Lret: mov.l @r15+,r14 */
    0x26, 0x4f,                /* lds.l @r15+,pr */
    0x00, 0xe0,                /* mov #0,r0 (SYSINTR_NOP) */
    0x0b, 0x00,                /* rts */
    0x09, 0x00,                /* nop */
    0x09, 0x00,                /* nop (align pad) */
    0x00, 0xff, 0x00, 0xbf,    /* .Lm: marker cell */
    0x34, 0xc2, 0x6d, 0x90,    /* .Le: pEvent (patched) */
    0x68, 0x7f, 0x82, 0x90,    /* .Lw: 0x90827f68 walker */
    0xe8, 0x78, 0x82, 0x90,    /* .Lmri: 0x908278e8 MRI */
};

static void mmcs_l16_slot_restore(void *opaque)
{
    struct mmcs_l16_ent *e = opaque;
    static const uint32_t dflt = 0x90822e40;
    cpu_physical_memory_write(e->slot_pa, &dflt, 4);
    fprintf(stderr, "MMCS-L16: dispatch slot evt %03x restored\n",
            e->evt_code);
}

/* MMCS fork (L18): the v3 wake-completion stub (MMCS_L18EV). DECODE
 * (L18: SCHEDTRACE cell tracer + gdb bps at the switcher 0x90822b68 /
 * MRI 0x908278e8 / MakeRun 0x90825ee4 + Z2 pick-watchpoints): the
 * system has run WITHOUT its scheduler since t~3s — the servant death
 * while current froze pick (0x8867efa4) and pCurTh (KData+0x94) on the
 * corpse, and the CPU fell into the pc=0 kill-stack loop; every wake
 * since executes through the tick-interrupt context (the trampoline's
 * ctx load) WITHOUT the scheduler bookkeeping: the vendor walker
 * (0x90827f68) unlinks the waitblock and leaves the waiter
 * RUNNABLE(1)-not-queued, and the stub's MRI (0x908278e8) SKIPS it
 * (MRI MakeRuns only NEEDSRUN(3) — stock mirror schedule.c:967).
 * Z2 GROUND TRUTH on the pick cell 0x8867efa4: its writers = the
 * MakeRun-family enqueue (0x9082601c-class) and 0x90827452 — the
 * next-thread RECOMPUTE, called from drain2 (0x90827148), called from
 * the switcher entry (0x90822ba0) ONLY when word 0x88679888 == 1; the
 * switcher itself is only entered from a KCall-exit when BYTE
 * 0x88679884 == 1 (the KCall-thunk tail check: mov.b @r1; cmp/eq #1 ->
 * save-ctx -> bra 0x90822b68). The recompute walks the run-queue bands
 * from band 0, so it naturally replaces the stale corpse pick with the
 * highest live queued thread. v3 = v1 (walker + MRI) + MakeRun(hWake)
 * (the enqueue half MRI would have done for a NEEDSRUN waiter) + the
 * vendor's paired resched protocol: BYTE 0x88679884=1 (switcher entry)
 * and WORD 0x88679888=1 (drain2 pick recompute). Markers: 10 delivery,
 * 11 walker returned, 13 MRI done, 14 MakeRun done, 15 flag byte set,
 * 16 drain word set (cell at block+0xF0, same as v1/v2). */
static uint8_t mmcs_l18_stub[] = {
    0x22, 0x4f,                /* sts.l pr,@-r15 */
    0xe6, 0x2f,                /* mov.l r14,@-r15 */
    0x21, 0xd4,                /* mov.l .Le,r4        (@+140) */
    0x42, 0x50,                /* mov.l @(8,r4),r0 (proxy head) */
    0x08, 0x20,                /* tst r0,r0 */
    0x37, 0x89,                /* bt Lret124 (already delivered) */
    0x0a, 0xe1,                /* mov #10,r1 */
    0x1e, 0xd2,                /* mov.l .Lm,r2        (@+136) */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0x03, 0xe5,                /* mov #3,r5 (EVENT_SET) */
    0x1e, 0xd3,                /* mov.l .Lw,r3        (@+144) */
    0x0b, 0x43,                /* jsr @r3 */
    0x09, 0x00,                /* nop */
    0x03, 0x6e,                /* mov r0,r14 (hWake = pTh) */
    0x0b, 0xe1,                /* mov #11,r1 */
    0x1a, 0xd2,                /* mov.l .Lm,r2        (@+136) */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0xe8, 0x2e,                /* tst r14,r14 */
    0x2a, 0x89,                /* bt Lret124 */
    0xe3, 0x64,                /* mov r14,r4 */
    0x1a, 0xd3,                /* mov.l .Lmri,r3      (@+148) */
    0x0b, 0x43,                /* jsr @r3 */
    0x09, 0x00,                /* nop */
    0x0d, 0xe1,                /* mov #13,r1 (MRI done) */
    0x15, 0xd2,                /* mov.l .Lm,r2        (@+136) */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0xe3, 0x64,                /* mov r14,r4 */
    0x18, 0xd3,                /* mov.l .Lmk,r3       (@+152) */
    0x0b, 0x43,                /* jsr @r3 (MakeRun) */
    0x09, 0x00,                /* nop */
    0x0e, 0xe1,                /* mov #14,r1 (MakeRun done) */
    0x12, 0xd2,                /* mov.l .Lm,r2        (@+136) */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0x01, 0xe1,                /* mov #1,r1 */
    0x15, 0xd2,                /* mov.l .Lf,r2        (@+156) */
    0x10, 0x22,                /* mov.b r1,@r2 (switcher-entry flag) */
    0x0f, 0xe1,                /* mov #15,r1 (flag byte set) */
    0x0f, 0xd2,                /* mov.l .Lm,r2        (@+136) */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0x01, 0xe1,                /* mov #1,r1 */
    0x13, 0xd2,                /* mov.l .Lf2,r2       (@+160) */
    0x12, 0x22,                /* mov.l r1,@r2 (drain2 pick-recompute) */
    0x10, 0xe1,                /* mov #16,r1 (drain word set) */
    0x0c, 0xd2,                /* mov.l .Lm,r2        (@+136) */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0xe3, 0x64,                /* mov r14,r4 (hWake) */
    0x11, 0xd2,                /* mov.l .Lpick,r2     (@+164) */
    0x42, 0x22,                /* mov.l r4,@r2 (pick = hWake — the
                                 * vendor pick-set write class; the
                                 * switcher's drain2 recompute may
                                 * override it with the band walk) */
    0x11, 0xe1,                /* mov #17,r1 (pick set) */
    0x09, 0xd2,                /* mov.l .Lm,r2        (@+136) */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0x10, 0xd2,                /* mov.l .Lpcur,r2     (@+168) */
    0x20, 0x5e,                /* mov.l @r2,r14 (r14 = pCurTh — the
                                 * switcher's "current" it saves) */
    0x12, 0xe1,                /* mov #18,r1 (r14 set) */
    0x06, 0xd2,                /* mov.l .Lm,r2        (@+136) */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0x0e, 0xd3,                /* mov.l .Lsw,r3       (@+172) */
    0x0b, 0x43,                /* jsr @r3 (the vendor switcher
                                 * 0x90822b68: saves r14's ctx, drains
                                 * (drain2 = the pick recompute), loads
                                 * the pick's ctx — execution continues
                                 * THERE; the marker 19 below only runs
                                 * if no switch happened) */
    0x09, 0x00,                /* nop */
    0x13, 0xe1,                /* mov #19,r1 (switcher returned = no
                                 * switch — the pick equaled current) */
    0x03, 0xd2,                /* mov.l .Lm,r2        (@+136) */
    0x12, 0x22,                /* mov.l r1,@r2 */
    0xf6, 0x6f,                /* Lret124: mov.l @r15+,r14 */
    0x26, 0x4f,                /* lds.l @r15+,pr */
    0x00, 0xe0,                /* mov #0,r0 (SYSINTR_NOP) */
    0x0b, 0x00,                /* rts */
    0x09, 0x00,                /* nop */
    0x09, 0x00,                /* nop (pad) */
    0x00, 0xff, 0x00, 0xbf,    /* +136 .Lm: marker cell */
    0x34, 0xc2, 0x6d, 0x90,    /* +140 .Le: pEvent (patched) */
    0x68, 0x7f, 0x82, 0x90,    /* +144 .Lw: 0x90827f68 walker */
    0xe8, 0x78, 0x82, 0x90,    /* +148 .Lmri: 0x908278e8 MRI */
    0xe4, 0x5e, 0x82, 0x90,    /* +152 .Lmk: 0x90825ee4 MakeRun */
    0x84, 0x98, 0x67, 0x88,    /* +156 .Lf: 0x88679884 resched BYTE */
    0x88, 0x98, 0x67, 0x88,    /* +160 .Lf2: 0x88679888 drain2 WORD */
    0xa4, 0xef, 0x67, 0x88,    /* +164 .Lpick: 0x8867efa4 pick cell */
    0x94, 0x98, 0x67, 0x88,    /* +168 .Lpcur: 0x88679894 pCurTh */
    0x68, 0x2b, 0x82, 0x90,    /* +172 .Lsw: 0x90822b68 switcher */
};

static void mmcs_l18ev_fire(void *opaque)
{
    struct mmcs_l16_ent *e = opaque;
    uint32_t slot_cur = 0;
    cpu_physical_memory_read(e->slot_pa, &slot_cur, 4);
    if (slot_cur != 0x90822e40) {
        fprintf(stderr, "MMCS-L18: evt %03x slot busy (%08x) - SKIPPED\n",
                e->evt_code, slot_cur);
        return;
    }
    uint8_t stub[sizeof mmcs_l18_stub];
    memcpy(stub, mmcs_l18_stub, sizeof stub);
    uint8_t *le = (uint8_t *)memmem(stub, sizeof stub, "\x34\xc2\x6d\x90", 4);
    uint8_t *lm = (uint8_t *)memmem(stub, sizeof stub, "\x00\xff\x00\xbf", 4);
    if (!le || !lm) {
        fprintf(stderr, "MMCS-L18: stub literal locate FAILED\n");
        return;
    }
    stl_le_p(le, e->evt_va);
    stl_le_p(lm, e->stub_va + MMCS_L16_STUB_MARK);
    cpu_physical_memory_write(e->stub_va - 0xA0000000, stub,
                              sizeof stub);
    cpu_physical_memory_write(e->slot_pa, &e->stub_va, 4);
    e->pending = 8;    /* chain the next ticks (guard = no-op re-fires) */
    fprintf(stderr, "MMCS-L18: v2 stub @%08x for event %08x, slot evt %03x "
            "wired (walker+MRI+MakeRun+resched), chained to next ticks\n",
            e->stub_va, e->evt_va, e->evt_code);
    QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_l16_slot_restore,
                                e);
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 100);
}

/* MMCS fork (L19): MMCS_L19EV=va@ms[,va@ms..] — the wake-CADENCE engine
 * (the L18 one-shot leaves the pump starved after its first consumed
 * auto-reset wake). DECODE (L19, re_tools on the vendor fsdmgr + the
 * stock CE5 mirror PRIVATE/WINCEOS/COREOS/STORAGE/STOREMGR/storemain.cpp
 * + schedule.c:7151): the pump = the fsdmgr STOREMGR PNPThread
 * 0x906a36f4 (start 0xc02c5da0, ROM 0x90a86da0), and the vendor loop is
 * the stock PNPThread VERBATIM: WaitForMultipleObjects(3, {g_hPNPQueue,
 * g_hPNPUpdateEvent, g_hAutoLoadEvent}) then switch — case 0 = ONE
 * ReadMsgQueue(INFINITE) per wake (vendor 0x90a86f30 block: r4=@g_hPNPQ
 * cell 0xc02db380, INFINITE at sp+16 — one message per iteration), case
 * 1 = the g_dwUpdateState refresh walk, case 2 = ResetEvent(g_hAutoLoad
 * Event)+AutoLoadFileSystems(2,ASYNC) (0x90a86ef0-0x90a86f04). THE
 * LEGITIMATE PER-ITERATION WAKE SOURCE on real HW = the msgqueue
 * ARRIVAL event (WriteMsgQueue sets the queue's auto-reset data event
 * per notification — the waitable-handle "signaled iff non-empty"
 * invariant), plus SetEvent(g_hPNPUpdateEvent) from the
 * RefreshStore/UnmountStore paths (auto-reset) and the one-shot phase-2
 * SetEvent(g_hAutoLoadEvent) (manual, reset by the pump's own case 2).
 * The MAIN thread's alarm loop (0x908381b8, hAlarmThreadWakeup,
 * ONE_DAY) is the RTC-ALARM lane (IntrEvents[SYSINTR_RTC_ALARM]) — not
 * the device.exe pump; its 1s-class cadence justifies the DELIVERY
 * phase, not the wake source. In emulation the two device-interface
 * notifications were POSTED while the scheduler was dead — their
 * arrival sets are the pending wakes the vendor kernel never delivered
 * (the walker runs but MRI leaves waiters RUNNABLE-not-queued = the L18
 * lost-enqueue). FIX: a daemon on the 1ms tick chain (MMCS_L19EV_MS
 * cadence, default 1000ms = every 1000th tick, deliveries tied to the
 * tick phase exactly like the L16/L18 chains) scans the armed events
 * host-side and delivers the v4 completion stub (walker+MRI+MakeRun+
 * resched+switcher = 100% vendor code) when an event still has a LINKED
 * WAITER (proxy head @event+0x8 != 0 — the vendor walker itself owns
 * the auto-reset semantics: one wake per pump cycle). NOT permanent
 * spam: (a) at most one delivery per cadence period across ALL armed
 * events, (b) a movement signature over the scheduler/queue/event cells
 * — 3 consecutive no-movement deliveries park the daemon (the pump
 * idled through its pending set), (c) a hard cap MMCS_L19EV_MAX
 * (default 600). */
static uint32_t mmcs_l19_max_deliv = 600;
static uint32_t mmcs_l19_total;

/* the movement signature cells (phys): the three pump events'
 * waitblock/state pairs, the PNP queue struct, the runqueue pick/pth,
 * pCurTh, and the four frontier threads' state16/ctx pc cells. */
static const struct { uint32_t pa; } mmcs_l19_sig_cells[] = {
    { 0x1069C6B4 }, { 0x1069C738 },   /* 9069c6ac +0x8/+0x8c */
    { 0x106A35A0 }, { 0x106A3624 },   /* 906a3598 +0x8/+0x8c */
    { 0x106A363C }, { 0x106A36C0 },   /* 906a3634 +0x8/+0x8c */
    { 0x0867AB14 }, { 0x0867AB34 },   /* the PNP queue struct (0x20) */
    { 0x0867EFA4 }, { 0x0867EFA0 },   /* pick / pRunnable */
    { 0x08679894 },                   /* pCurTh */
    { 0x106A3700 }, { 0x106A37A8 },   /* PNPThread state16/ctx pc */
    { 0x106DCAD8 },                   /* waiter C state16 */
    { 0x106FF030 },                   /* MAIN thread state16 */
    { 0x106CA24C },                   /* LaunchXX walker state16 */
};
#define MMCS_L19_NSIG (ARRAY_SIZE(mmcs_l19_sig_cells) * 4)

static void mmcs_l19_signature(uint8_t *out)
{
    unsigned o = 0;
    for (unsigned i = 0; i < ARRAY_SIZE(mmcs_l19_sig_cells); i++) {
        cpu_physical_memory_read(mmcs_l19_sig_cells[i].pa, out + o, 4);
        o += 4;
    }
}

/* MMCS fork (L26): MMCS_L26EV — the DoWait-orphan wake daemon (the
 * v6 thread-completion stub).
 *
 * Decoded 2026-11-17 (L26 park census, l26_probe10): with the L25
 * loader lane clean + the L26 P1-alias dispatch fix, the boot parks
 * with the ENTIRE system = five threads ALL blocked at the vendor
 * DoWait loop 0x90837cf6 (ctx pc), state16 runstate BLOCKED(2):
 * MAIN 0x906ff024 (wait-obj 0 — the stock RunApps FSReady wait, the
 * LEGIT gate: filesys must earn it) plus FOUR orphaned servant
 * waiters (0x906feb58/0x906dd000/0x906dd7a4/0x906ddacc, kstacks
 * d006/d007/d009/d00a) whose wait objects live ON THEIR OWN STACKS
 * (thread+0x14c in [0xD0000000,0xDC000000)) and whose waitblocks were
 * NEVER LINKED (thread+0x1f8 == 0 — the BlockWithHelper half
 * completed the dequeue but the wake side was lost): NO stock
 * mechanism holds them, the run queue is empty, the L19 event daemon
 * finds nothing (they are not signaled+linked EVNTs) and the L19TH
 * v5 guard rejects BLOCKED targets. The class is address-independent
 * (each relaunch re-creates its stack events), so the daemon SCANS:
 * every cadence, bulk-read the object arena (P1 0x90680000-0x90700000,
 * phys 0x10680000) for a THREAD struct with the probe10 signature
 * (+0x20 kstack base in the D0 window, +0x24 == 0x10000, +0x2c kstack
 * low, ctx pc (+0xb4) == 0x90837cf6, state16 runstate == 2, wait-obj
 * (+0x14c) in the D0 stack window, waitblk (+0x1f8) == 0) and deliver
 * the v6 completion for the first: MakeRun(thread) + the resched
 * protocol stores + pick=thread + r14=pCurTh + the vendor switcher.
 * NO event-set: the stack wait structs are not EVNT-class (layout
 * unknown — the walker would corrupt fields); the woken thread re-
 * checks its own wait condition (the DoWait loop reads state16, finds
 * 0x4000 clear, exits the loop into its post-wait path). In-stub
 * guard: only MakeRun when the target is STILL BLOCKED(2) — chained
 * re-deliveries no-op; a thread that re-enters the wait is re-served
 * next cadence. MAIN's wait (wait-obj 0) is EXCLUDED (the FSReady
 * gate must be earned). Bounds: one delivery per cadence, 60 quiet
 * scans park, movement re-arms (the L19 discipline), hard cap
 * MMCS_L26EV_MAX (default 64). Stub at KILLSTK 0xBF00E200 (idx 2,
 * evt 0x280 — free when MMCS_L16EV is not armed), slot stays wired
 * (daemon mode). Needs MMCS_KILLSTK + MMCS_TICK (the delivery rides
 * the tick chain). */
static uint8_t mmcs_l26_stub[] = {
    0x22, 0x4f, 0xe6, 0x2f, 0x0f, 0xd4, 0x43, 0x50,
    0x03, 0xc9, 0x02, 0x88, 0x01, 0x8b, 0x14, 0xa0,
    0x09, 0x00, 0x09, 0x00, 0x0c, 0xd3, 0x0b, 0x43,
    0x09, 0x00, 0x01, 0xe1, 0x0b, 0xd2, 0x12, 0x22,
    0x01, 0xe1, 0x09, 0x00, 0x0a, 0xd2, 0x12, 0x22,
    0x06, 0xd4, 0x09, 0x00, 0x09, 0xd2, 0x42, 0x22,
    0x09, 0xd2, 0x20, 0x5e, 0x09, 0xd3, 0x0b, 0x43,
    0x09, 0x00, 0xf6, 0x6e, 0x26, 0x4f, 0x00, 0xe0,
    0x0b, 0x00, 0x09, 0x00, 0x00, 0xd0, 0x6d, 0x90,
    0xe4, 0x5e, 0x82, 0x90, 0x84, 0x98, 0x67, 0x88,
    0x88, 0x98, 0x67, 0x88, 0xa4, 0xef, 0x67, 0x88,
    0x94, 0x98, 0x67, 0x88, 0x68, 0x2b, 0x82, 0x90,
};
#define MMCS_L26_STUB_VA   0xBF00E200
#define MMCS_L26_SLOT_PA   0x0867A050   /* evt 0x280, idx 2 */
#define MMCS_L26_QUIET_PARK 60
static uint32_t mmcs_l26_total;

static void mmcs_l26_scan(void)
{
    static uint8_t prev_sig[MMCS_L19_NSIG];
    static int have_prev;
    static uint32_t quiet_scans;
    uint8_t sig[MMCS_L19_NSIG];

    if (mmcs_l26_total >= mmcs_l26_max_deliv) {
        if (mmcs_l26_armed) {
            fprintf(stderr, "MMCS-L26: hard cap %u deliveries reached - "
                    "daemon parked\n", mmcs_l26_total);
            mmcs_l26_armed = 0;
        }
        return;
    }
    mmcs_l19_signature(sig);
    bool moved = have_prev && memcmp(sig, prev_sig, MMCS_L19_NSIG) != 0;
    memcpy(prev_sig, sig, MMCS_L19_NSIG);
    have_prev = 1;
    if (moved) {
        quiet_scans = 0;
        if (!mmcs_l26_armed) {
            mmcs_l26_armed = 1;
            fprintf(stderr, "MMCS-L26: t=%" PRId64 "ms movement while "
                    "parked - re-armed (%u deliveries used)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l26_total);
        }
    } else if (mmcs_l26_armed && ++quiet_scans >= MMCS_L26_QUIET_PARK) {
        fprintf(stderr, "MMCS-L26: t=%" PRId64 "ms %u quiet scans - "
                "daemon parked at %u deliveries\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), quiet_scans,
                mmcs_l26_total);
        mmcs_l26_armed = 0;
        quiet_scans = 0;
    }
    if (!mmcs_l26_armed) {
        return;
    }
    /* the arena scan: find the first orphaned DoWait waiter */
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    for (uint32_t o = 0; o + 0x200 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, ctxpc, wobj, wblk;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&wobj, arena + o + 0x14c, 4);
        memcpy(&wblk, arena + o + 0x1f8, 4);
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000
            || (st16 & 3) != 2
            || ctxpc != 0x90837cf6
            || wobj < 0xD0000000 || wobj >= 0xDC000000
            || wblk != 0
            || tva == pcur) {
            continue;
        }
        /* deliver: patch .Lt (+0x44) with the thread VA, install the
         * stub, wire the slot once, arm one delivery */
        cpu_physical_memory_write(0x1F00E200 + 0x44, &tva, 4);
        cpu_physical_memory_write(0x1F00E200, mmcs_l26_stub,
                                  sizeof mmcs_l26_stub);
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L26_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L26_STUB_VA) {
            if (slot_cur != 0x90822e40) {
                fprintf(stderr, "MMCS-L26: slot evt 0x280 busy (%08x) - "
                        "scan skipped\n", slot_cur);
                return;
            }
            cpu_physical_memory_write(MMCS_L26_SLOT_PA,
                                      &(uint32_t){ MMCS_L26_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[2];
        e->evt_va = tva;
        e->stub_va = MMCS_L26_STUB_VA;
        e->evt_code = 0x280;
        e->slot_pa = MMCS_L26_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l26_total++;
        fprintf(stderr, "MMCS-L26: t=%" PRId64 "ms DoWait-orphan wake "
                "thread %08x (wait-obj %08x, kstk %08x, delivery "
                "%u/%u)\n", qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL),
                tva, wobj, kbase, mmcs_l26_total, mmcs_l26_max_deliv);
        return;                     /* one per cadence */
    }
}


/* MMCS fork (L19): MMCS_L19TH=threadVA@ms[,threadVA@ms] — the THREAD-
 * level enqueue completion (v5 stub). L19 r3 finding: with the L18-era
 * scheduler resurrection but no wake deliveries at all, the system
 * self-drives ONE context (the filesys phase-1 AutoLoadFileSystems
 * retry loop — bp-proven 5723 calls (1,SYNC), pr=c02c3de2) while the
 * PUMP 0x906a36f4 froze mid-init at t~3s as ANOTHER RUNNABLE(1)-not-
 * queued zombie (ctx pc c003c9e0 = mid k.coredll API, state16 0x41,
 * never linked on its wait events again) and the MAIN thread
 * 0x906ff024 equally zombie in the SetThreadBasePrio KCall (resume
 * 0x908382ca). The event-wake daemon cannot repair these (no linked
 * waitblock); the repair = the L18 v4 machinery applied to the THREAD:
 * MakeRun(pThread) (the enqueue half the vendor walker+MRI omit) +
 * the paired resched protocol stores + pick=pThread + r14=pCurTh +
 * jsr the vendor switcher. GUARD (in-stub): MakeRun only when the
 * thread's state16 runstate (+0xc) is RUNNABLE(1) or NEEDSRUN(3) —
 * chained tick re-deliveries no-op on running/blocked/dead targets.
 * Layout capstone-verified (builder: corpus scripts/emul/l19_stub_
 * build.py; pools @+0x48: .Lt(patched at fire) .Lmk=MakeRun 0x90825ee4
 * .Lf 0x88679884 .Lf2 0x88679888 .Lpick 0x8867efa4 .Lpcur 0x88679894
 * .Lsw = the switcher 0x90822b68). Stubs at KILLSTK 0xBF00EC00+n*0x100
 * (n <= 1 — 0xEF00 would collide with the L14 hdevt stub at 0xF000),
 * dispatched on the L16-era free slots evt 0x220/0x260 (indices 0-1;
 * skip when MMCS_L16EV owns them). */
static uint8_t mmcs_l19th_stub[] = {
    0x22, 0x4f, 0xe6, 0x2f,        /* sts.l pr,@-r15; mov.l r14,@-r15 */
    0x10, 0xd4, 0x43, 0x50,        /* mov.l .Lt,r4; mov.l @(12,r4),r0 */
    0x03, 0xc9, 0x01, 0x88,        /* and #3,r0; cmp/eq #1,r0 */
    0x03, 0x89, 0x03, 0x88,        /* bt mk; cmp/eq #3,r0 */
    0x01, 0x89, 0x14, 0xa0,        /* bt mk; bra Lret */
    0x09, 0x00, 0x09, 0x00,        /* nop; nop (mk: + align pad) */
    0x0c, 0xd3, 0x0b, 0x43,        /* mk: mov.l .Lmk,r3; jsr @r3 */
    0x09, 0x00, 0x01, 0xe1,        /* nop; mov #1,r1 */
    0x0b, 0xd2, 0x12, 0x22,        /* mov.l .Lf,r2; mov.l r1,@r2 */
    0x01, 0xe1, 0x09, 0x00,        /* mov #1,r1; nop (align) */
    0x0a, 0xd2, 0x12, 0x22,        /* mov.l .Lf2,r2; mov.l r1,@r2 */
    0x06, 0xd4, 0x09, 0x00,        /* mov.l .Lt,r4; nop (align) */
    0x09, 0xd2, 0x42, 0x22,        /* mov.l .Lpick,r2; mov.l r4,@r2 */
    0x09, 0xd2, 0x20, 0x5e,        /* mov.l .Lpcur,r2; mov.l @r2,r14 */
    0x09, 0xd3, 0x0b, 0x43,        /* mov.l .Lsw,r3; jsr @r3 */
    0x09, 0x00, 0xf6, 0x6e,        /* nop; Lret: mov.l @r15+,r14 */
    0x26, 0x4f, 0x00, 0xe0,        /* lds.l @r15+,pr; mov #0,r0 */
    0x0b, 0x00, 0x09, 0x00,        /* rts; nop */
    0x34, 0xc2, 0x6d, 0x90,        /* +0x48 .Lt: thread VA (patched) */
    0xe4, 0x5e, 0x82, 0x90,        /* .Lmk: 0x90825ee4 MakeRun */
    0x84, 0x98, 0x67, 0x88,        /* .Lf: 0x88679884 resched byte */
    0x88, 0x98, 0x67, 0x88,        /* .Lf2: 0x88679888 drain2 word */
    0xa4, 0xef, 0x67, 0x88,        /* .Lpick: 0x8867efa4 */
    0x94, 0x98, 0x67, 0x88,        /* .Lpcur: 0x88679894 */
    0x68, 0x2b, 0x82, 0x90,        /* .Lsw: 0x90822b68 switcher */
};

static void mmcs_l19th_fire(void *opaque)
{
    struct mmcs_l16_ent *e = opaque;
    uint32_t slot_cur = 0;
    cpu_physical_memory_read(e->slot_pa, &slot_cur, 4);
    if (slot_cur != 0x90822e40) {
        fprintf(stderr, "MMCS-L19TH: evt %03x slot busy (%08x) - SKIPPED\n",
                e->evt_code, slot_cur);
        return;
    }
    uint8_t stub[sizeof mmcs_l19th_stub];
    memcpy(stub, mmcs_l19th_stub, sizeof stub);
    uint8_t *lt = (uint8_t *)memmem(stub, sizeof stub, "\x34\xc2\x6d\x90", 4);
    if (!lt) {
        fprintf(stderr, "MMCS-L19TH: stub literal locate FAILED\n");
        return;
    }
    stl_le_p(lt, e->evt_va);
    cpu_physical_memory_write(e->stub_va - 0xA0000000, stub,
                              sizeof stub);
    cpu_physical_memory_write(e->slot_pa, &e->stub_va, 4);
    e->pending = 8;    /* chain the next ticks (guard = no-op re-fires) */
    fprintf(stderr, "MMCS-L19TH: thread-completion stub @%08x for thread "
            "%08x, slot evt %03x wired (MakeRun+resched+switcher), "
            "chained\n", e->stub_va, e->evt_va, e->evt_code);
    QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_l16_slot_restore,
                                e);
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 100);
}

static void mmcs_l19ev_fire(void *opaque)
{
    struct mmcs_l16_ent *e = opaque;
    uint32_t slot_cur = 0;
    cpu_physical_memory_read(e->slot_pa, &slot_cur, 4);
    if (slot_cur != 0x90822e40) {
        fprintf(stderr, "MMCS-L19: evt %03x slot busy (%08x) - SKIPPED\n",
                e->evt_code, slot_cur);
        return;
    }
    uint8_t stub[sizeof mmcs_l18_stub];
    memcpy(stub, mmcs_l18_stub, sizeof stub);
    uint8_t *le = (uint8_t *)memmem(stub, sizeof stub, "\x34\xc2\x6d\x90", 4);
    uint8_t *lm = (uint8_t *)memmem(stub, sizeof stub, "\x00\xff\x00\xbf", 4);
    if (!le || !lm) {
        fprintf(stderr, "MMCS-L19: stub literal locate FAILED\n");
        return;
    }
    stl_le_p(le, e->evt_va);
    stl_le_p(lm, e->stub_va + MMCS_L16_STUB_MARK);
    cpu_physical_memory_write(e->stub_va - 0xA0000000, stub,
                              sizeof stub);
    cpu_physical_memory_write(e->slot_pa, &e->stub_va, 4);
    /* no 100ms slot restore: the daemon keeps its slot wired for the
     * session — the in-stub guard (event+0x8 proxy head) makes idle
     * dispatches no-ops, and a vendor ISR claiming the slot simply
     * takes the evt over (the L18 self-registered ISR took 0x300,
     * which is why L19 skips that index) */
    e->daemon = 1;
    e->pending = 0;
    mmcs_l19_armed = 1;
    fprintf(stderr, "MMCS-L19: daemon stub @%08x for event %08x, slot evt "
            "%03x wired (walker+MRI+MakeRun+resched), cadence %ums\n",
            e->stub_va, e->evt_va, e->evt_code, mmcs_l19_cadence_ms);
}

/* one scan per cadence period, from the tick chain. r1/r2 lessons:
 * BOTH list cells matter — the +0x8 cell (the stub's guard list)
 * produced r1's real queue-event wake (marker 0x12, full switch) while
 * the +0x88 cell tracks the waitblock the walker unlinks; r2's
 * +0x88-only gate starved those lanes. Gate = EITHER cell non-zero;
 * the in-stub guard + the walker's own list check no-op a stale fire
 * (r1 marker 0x0b = harmless). Bound: the movement signature is
 * sampled EVERY scan (armed or parked) — 60 consecutive quiet scans
 * park the daemon, ANY movement re-arms it (r1 showed 176s dead zones
 * followed by late scheduler blips; the pump's own dry-well case-1
 * iterations reset nothing). */
#define MMCS_L19_QUIET_PARK 60
static void mmcs_l19_scan(void)
{
    static uint8_t prev_sig[MMCS_L19_NSIG];
    static int have_prev;
    static uint32_t quiet_scans, no_pick_scans;
    uint8_t sig[MMCS_L19_NSIG];
    if (mmcs_l19_total >= mmcs_l19_max_deliv) {
        if (mmcs_l19_armed) {
            fprintf(stderr, "MMCS-L19: hard cap %u deliveries reached - "
                    "daemon parked\n", mmcs_l19_total);
            mmcs_l19_armed = 0;
        }
        return;
    }
    mmcs_l19_signature(sig);
    bool moved = have_prev && memcmp(sig, prev_sig, MMCS_L19_NSIG) != 0;
    memcpy(prev_sig, sig, MMCS_L19_NSIG);
    have_prev = 1;
    if (moved) {
        quiet_scans = 0;
        if (!mmcs_l19_armed) {
            mmcs_l19_armed = 1;
            fprintf(stderr, "MMCS-L19: t=%" PRId64 "ms movement while "
                    "parked - re-armed (%u deliveries used)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l19_total);
        }
    } else if (mmcs_l19_armed && ++quiet_scans >= MMCS_L19_QUIET_PARK) {
        fprintf(stderr, "MMCS-L19: t=%" PRId64 "ms %u quiet scans - "
                "daemon parked at %u deliveries\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), quiet_scans,
                mmcs_l19_total);
        mmcs_l19_armed = 0;
        quiet_scans = 0;
    }
    if (!mmcs_l19_armed) {
        return;
    }
    /* the arena scan: the static L16-era event addresses go STALE the
     * moment the pump resumes (r4: its init re-created the msgqueue/
     * events, freeing the old slots — the daemon then fired 60x on
     * recycled junk). The faithful generalization: scan the kernel
     * object arena (P1 0x90680000-0x90700000, bulk-read) for ANY
     * EVNT-class object (event+0x94 -> HDATA, HDATA+0xc == the EVNT
     * CINFO 0x90822040) that sits SIGNALED (+0x8d == 1) with a linked
     * kstack waitblock (+0x8 / +0x88 in 0xd0000000-0xd1000000) = a
     * pending lost wake, wherever the arena put it. The delivery stub
     * (entry 0, evt 0x2C0) gets its .Le pool patched to the found
     * object per delivery. */
    static uint8_t arena[0x80000];
    static uint32_t pick_obj, pick_w8, pick_w88;
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    pick_obj = 0;
    for (uint32_t o = 0; o + 0x98 <= sizeof arena; o += 4) {
        uint32_t w8, w88, w8c, hdata;
        memcpy(&w8, arena + o + 0x8, 4);
        memcpy(&w88, arena + o + 0x88, 4);
        if (((w8 | w88) & 0xff000000) != 0xd0000000) {
            continue;
        }
        memcpy(&w8c, arena + o + 0x8c, 4);
        if (((w8c >> 8) & 0xff) != 1) {
            continue;                   /* not signaled */
        }
        memcpy(&hdata, arena + o + 0x94, 4);
        if (hdata < 0x90680000 || hdata >= 0x90700000) {
            continue;
        }
        uint32_t pci;
        uint32_t po = hdata - 0x90680000;
        if (po + 0x10 > sizeof arena) {
            continue;
        }
        memcpy(&pci, arena + po + 0xc, 4);
        if (pci != 0x90822040) {
            continue;                   /* not EVNT */
        }
        pick_obj = 0x90680000 + o;
        pick_w8 = w8;
        pick_w88 = w88;
        break;                          /* first hit: one per cycle */
    }
    if (!pick_obj) {
        /* census: bounded no-pick sample so a silent pump lane is
         * diagnosable from the log alone */
        if (++no_pick_scans % 60 == 1) {
            fprintf(stderr, "MMCS-L19: t=%" PRId64 "ms no lost wake in "
                    "the arena (scan %u)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), no_pick_scans);
        }
        return;               /* nothing wake-pending: stay silent */
    }
    no_pick_scans = 0;
    /* patch the generic delivery stub's event literal (.Le at +140)
     * and arm the delivery */
    for (int i = 0; i < MMCS_L16_MAX; i++) {
        struct mmcs_l16_ent *e = &mmcs_l16_ents[i];
        if (!e->daemon || e->pending) {
            continue;
        }
        uint32_t le = e->stub_va - 0xA0000000 + 140;
        cpu_physical_memory_write(le, &pick_obj, 4);
        e->pending = 1;
        e->ndeliv++;
        mmcs_l19_total++;
        fprintf(stderr, "MMCS-L19: t=%" PRId64 "ms deliver evt %03x "
                "ARENA event %08x (+0x8=%08x +0x88=%08x, delivery "
                "%u/%u)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), e->evt_code,
                pick_obj, pick_w8, pick_w88, mmcs_l19_total,
                mmcs_l19_max_deliv);
        break;
    }
}

static void mmcs_l16ev_fire(void *opaque)
{
    struct mmcs_l16_ent *e = opaque;
    uint32_t slot_cur = 0;
    cpu_physical_memory_read(e->slot_pa, &slot_cur, 4);
    if (slot_cur != 0x90822e40) {
        fprintf(stderr, "MMCS-L16: evt %03x slot busy (%08x) - SKIPPED\n",
                e->evt_code, slot_cur);
        return;
    }
    /* patch the two pool literals into a scratch copy (the pristine
     * template must never be mutated — later fires search it again) */
    uint8_t stub[sizeof mmcs_l16_stub];
    memcpy(stub, mmcs_l16_stub, sizeof stub);
    uint8_t *le = (uint8_t *)memmem(stub, sizeof stub, "\x34\xc2\x6d\x90", 4);
    uint8_t *lm = (uint8_t *)memmem(stub, sizeof stub, "\x00\xff\x00\xbf", 4);
    if (!le || !lm) {
        fprintf(stderr, "MMCS-L16: stub literal locate FAILED\n");
        return;
    }
    stl_le_p(le, e->evt_va);
    stl_le_p(lm, e->stub_va + MMCS_L16_STUB_MARK);
    /* P2 alias -> phys: subtract the P2 base 0xA0000000 (0xBF00Exxx ->
     * 0x1F00Exxx; the L15 hdevt stub at 0xBF00F000 uses the same
     * arithmetic — a -0x8000000/P1-style subtraction writes nowhere) */
    cpu_physical_memory_write(e->stub_va - 0xA0000000, stub,
                              sizeof stub);
    cpu_physical_memory_write(e->slot_pa, &e->stub_va, 4);
    e->pending = 8;    /* chain the next ticks (guard = no-op re-fires) */
    fprintf(stderr, "MMCS-L16: stub @%08x for event %08x, slot evt %03x "
            "wired, chained to next ticks\n",
            e->stub_va, e->evt_va, e->evt_code);
    QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_l16_slot_restore,
                                e);
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 100);
}

static void mmcs_l16_boot_parse(void)
{
    /* L18: MMCS_L18EV parses identically but arms the v2 completion
     * stubs on the FREE dispatch slots (indices 4..7: evt
     * 0x2C0/0x2E0/0x300/0x320 — the L16 census verified only the
     * default handler there) at 0xBF00E800+n*0x100 (clear of the L16
     * stubs below and the L14 hdevt stub at 0xF000).
     * L19: MMCS_L19EV shares the L18 slots/stubs but arms the
     * wake-cadence daemon (mmcs_l19ev_fire + the tick-chain scan);
     * indices {4,5,7} — index 6 (evt 0x300) stays FREE because the
     * real vendor ISR 0x9080cf0c self-registers there by t=210s.
     * L19TH: the thread-level enqueue completion (mmcs_l19th_fire)
     * on the L16-era slots 0-1 (evt 0x220/0x260), stubs at
     * 0xBF00EC00+n*0x100 (max 2 — 0xEF00 collides with hdevt). */
    const struct { const char *env; int first, base; int v2; } lists[] = {
        { "MMCS_L16EV", 0, MMCS_L16_STUB_BASE, 0 },
        { "MMCS_L18EV", 4, 0xBF00E800, 1 },
        { "MMCS_L19EV", 4, 0xBF00E800, 2 },
        { "MMCS_L19TH", 0, 0xBF00EC00, 3 },
    };
    if (getenv("MMCS_L18EV") && getenv("MMCS_L19EV")) {
        fprintf(stderr, "MMCS-L19: supersedes MMCS_L18EV — drop L18EV "
                "from the combo; not arming L19\n");
        return;
    }
    if (getenv("MMCS_L16EV") && getenv("MMCS_L19TH")) {
        fprintf(stderr, "MMCS-L19TH: shares slots 0-1 with MMCS_L16EV — "
                "drop L16EV; not arming L19TH\n");
        return;
    }
    /* L26: the DoWait-orphan wake daemon — slot idx 2 (evt 0x280)
     * would collide with MMCS_L16EV list entries >= 2 */
    if (getenv("MMCS_L26EV")) {
        if (getenv("MMCS_L16EV")) {
            fprintf(stderr, "MMCS-L26: shares slot idx 2 (evt 0x280) "
                    "with MMCS_L16EV — drop L16EV; not arming L26\n");
        } else {
            mmcs_l26_cadence_ms =
                atoi(getenv("MMCS_L26EV_MS") ? : "2000");
            if (!mmcs_l26_cadence_ms) {
                mmcs_l26_cadence_ms = 2000;
            }
            mmcs_l26_max_deliv = atoi(getenv("MMCS_L26EV_MAX") ? : "64");
            if (!mmcs_l26_max_deliv) {
                mmcs_l26_max_deliv = 64;
            }
            mmcs_l26_armed = 1;
            fprintf(stderr, "MMCS-L26: DoWait-orphan wake daemon armed "
                    "(cadence %ums, cap %u; stub %08x slot evt 0x280 "
                    "wired on first delivery)\n",
                    mmcs_l26_cadence_ms, mmcs_l26_max_deliv,
                    MMCS_L26_STUB_VA);
        }
    }
    mmcs_l19_cadence_ms = atoi(getenv("MMCS_L19EV_MS") ? : "1000");
    if (!mmcs_l19_cadence_ms) {
        mmcs_l19_cadence_ms = 1000;
    }
    mmcs_l19_max_deliv = atoi(getenv("MMCS_L19EV_MAX") ? : "600");
    if (!mmcs_l19_max_deliv) {
        mmcs_l19_max_deliv = 600;
    }
    for (unsigned li = 0; li < ARRAY_SIZE(lists); li++) {
        const char *spec = getenv(lists[li].env);
        if (!spec) {
            continue;
        }
        char buf[256];
        snprintf(buf, sizeof buf, "%s", spec);
        int n_list = 0;
        for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
            unsigned long va = 0, ms = 0;
            int maxn = lists[li].v2 == 2 ? 3
                     : lists[li].v2 == 3 ? 2 : MMCS_L16_MAX;
            if (sscanf(tok, "%lx@%lu", &va, &ms) != 2 || !va
                || n_list >= maxn) {
                fprintf(stderr, "MMCS-L16: bad spec '%s'\n", tok);
                continue;
            }
            /* L19 skips index 6 (evt 0x300 — reserved for the real
             * self-registered vendor ISR) */
            int idx = lists[li].first + n_list;
            if (lists[li].v2 == 2 && n_list >= 2) {
                idx = 7;
            }
            struct mmcs_l16_ent *e = &mmcs_l16_ents[idx];
            e->evt_va = va;
            e->stub_va = lists[li].base + (idx - lists[li].first) * 0x100;
            e->evt_code = mmcs_l16_evts[idx];
            e->slot_pa = mmcs_l16_slots[idx];
            e->pending = 0;
            e->daemon = lists[li].v2 == 2;
            e->strikes = 0;
            e->ndeliv = 0;
            fprintf(stderr, "MMCS-%s: event %08lx scheduled @%lums "
                    "(stub %08x slot evt %03x v%s)\n",
                    lists[li].v2 == 2 ? "L19" : (lists[li].v2 == 3
                                                     ? "L19TH"
                                                     : (lists[li].v2
                                                            ? "L18"
                                                            : "L16")),
                    va, ms, e->stub_va, e->evt_code,
                    lists[li].v2 == 2 ? "daemon"
                    : (lists[li].v2 == 3 ? "thread" : (lists[li].v2
                                                       ? "2" : "1")));
            QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                        lists[li].v2 == 2
                                            ? mmcs_l19ev_fire
                                            : (lists[li].v2 == 3
                                                   ? mmcs_l19th_fire
                                                   : (lists[li].v2
                                                          ? mmcs_l18ev_fire
                                                          : mmcs_l16ev_fire)),
                                        e);
            timer_mod(t, ms);
            n_list++;
        }
    }
}

static void mmcs_vintc_evt_deliver(void *opaque)
{
    mmcs_inject_evt(mmcs_vintc_evt_code);
    QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_vintc_evt_deliver, NULL);
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
              + atoi(getenv("MMCS_VINTC_EVT_MS") ? : "20"));
}

static void mmcs_vintc_pulse(void *opaque)
{
    static int level;
    level = !level;
    qemu_set_irq(mmcs_vintc_irl, level & 15);
    QEMUTimer *t __attribute__((unused)) = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_vintc_pulse, NULL);
    /* first pulse waits for the polled boot to settle (early IRQ derails
     * kernel init before filesys launches; verified 10ms+1000ms both die) */
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
              + atoi(getenv("MMCS_VINTC_DELAY") ? : "15000"));
}
static uint64_t mmcs_vintc_read(void *opaque, hwaddr off, unsigned size)
{
    uint64_t v = 0;
    if (off / 4 < 64) memcpy(&v, (uint8_t *)mmcs_vintc_regs + off, size);
    if (getenv("MMCS_TRACE")) {
        fprintf(stderr, "MMCS-VINTC R off=%05llx -> %08llx\n",
                (unsigned long long)off, (unsigned long long)v);
    }
    mmcs_vi_note(0, off, (uint32_t)v);
    return v;
}
static void mmcs_vintc_write(void *opaque, hwaddr off, uint64_t val, unsigned size)
{
    if (getenv("MMCS_TRACE")) {
        fprintf(stderr, "MMCS-VINTC W off=%05llx <- %08llx\n",
                (unsigned long long)off, (unsigned long long)val);
    }
    mmcs_vi_note(1, off, (uint32_t)val);
    if (off / 4 < 64) memcpy((uint8_t *)mmcs_vintc_regs + off, &val, size);
}
static const MemoryRegionOps mmcs_vintc_ops = {
    .read = mmcs_vintc_read, .write = mmcs_vintc_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
};

/* MMCS fork (L18): vendor-INTC access census (env MMCS_VINTC_CENSUS=1).
 * DECODE MOTIVATION (S134/L17): the NULL-call caller at 0x908381b8
 * computes r1 = *0x8867ed64 + 0xB8 and the parked dump showed
 * r1 = 0xf4008000 — the vendor global-struct base is 0xF4007F48-class
 * and the register block at +0xB8 = 0xF4008000 is the LIVE interrupt
 * controller (distinct from the loader's 0xF4000000 zero-sweep page and
 * the 0xF4001000/3000 kernel data refs). MMCS_TRACE per-access logging
 * is useless there (the S73 sweeps were 4.3M zero-writes), so this is a
 * bounded per-register histogram: read/write counts, first distinct
 * written values, and a ring of the most recent events — dumped every
 * 60s of virtual time and at MMCS_DUMP time. Ground truth for the
 * status/ack/mask decode without the flood. */
#define MMCS_VI_NT (0x10000u / 4)
static uint32_t mmcs_vi_nr[MMCS_VI_NT], mmcs_vi_nw[MMCS_VI_NT];
static uint32_t mmcs_vi_fv[MMCS_VI_NT][3];   /* first 3 distinct writes */
static uint8_t mmcs_vi_nv[MMCS_VI_NT];
static struct { uint32_t off, val; uint8_t is_w; } mmcs_vi_ring[256];
static int mmcs_vi_ring_i;
static int mmcs_vi_census;

static void mmcs_vi_note(int is_w, hwaddr off, uint32_t val)
{
    if (!mmcs_vi_census) {
        return;
    }
    unsigned i = off >> 2;
    if (i < MMCS_VI_NT) {
        if (is_w) {
            mmcs_vi_nw[i]++;
            if (mmcs_vi_nv[i] < 3) {
                for (int k = 0; k < mmcs_vi_nv[i]; k++) {
                    if (mmcs_vi_fv[i][k] == val) {
                        goto ring;
                    }
                }
                mmcs_vi_fv[i][mmcs_vi_nv[i]++] = val;
            }
        } else {
            mmcs_vi_nr[i]++;
        }
    }
ring:
    mmcs_vi_ring[mmcs_vi_ring_i].off = (uint32_t)off;
    mmcs_vi_ring[mmcs_vi_ring_i].val = val;
    mmcs_vi_ring[mmcs_vi_ring_i].is_w = (uint8_t)is_w;
    mmcs_vi_ring_i = (mmcs_vi_ring_i + 1) % ARRAY_SIZE(mmcs_vi_ring);
}

static void mmcs_vi_census_dump(void)
{
    if (!mmcs_vi_census) {
        return;
    }
    fprintf(stderr, "MMCS-VI-CENSUS t=%" PRId64 "ms\n",
            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL));
    /* per-4K-block summary */
    for (unsigned b = 0; b < 0x10000u / 0x1000u; b++) {
        uint64_t r = 0, w = 0;
        for (unsigned k = 0; k < 0x1000 / 4; k++) {
            r += mmcs_vi_nr[b * 0x400 + k];
            w += mmcs_vi_nw[b * 0x400 + k];
        }
        if (r || w) {
            fprintf(stderr, "  block +%04x: R=%llu W=%llu\n", b * 0x1000,
                    (unsigned long long)r, (unsigned long long)w);
        }
    }
    /* per-register detail, capped */
    int shown = 0, more = 0;
    for (unsigned i = 0; i < MMCS_VI_NT; i++) {
        if (!mmcs_vi_nr[i] && !mmcs_vi_nw[i]) {
            continue;
        }
        if (shown++ < 48) {
            fprintf(stderr, "  reg +%04x: R=%u W=%u vals {", i * 4,
                    mmcs_vi_nr[i], mmcs_vi_nw[i]);
            for (int k = 0; k < mmcs_vi_nv[i]; k++) {
                fprintf(stderr, "%s%08x", k ? "," : "", mmcs_vi_fv[i][k]);
            }
            fprintf(stderr, "}\n");
        } else {
            more++;
        }
    }
    if (more) {
        fprintf(stderr, "  (%d more registers with traffic)\n", more);
    }
    /* ring tail: the most recent 24 events, oldest first */
    fprintf(stderr, "  ring:");
    for (int k = ARRAY_SIZE(mmcs_vi_ring) - 24;
         k < ARRAY_SIZE(mmcs_vi_ring); k++) {
        if (k < 0) {
            continue;
        }
        int idx = (mmcs_vi_ring_i + k) % ARRAY_SIZE(mmcs_vi_ring);
        fprintf(stderr, " %c%04x=%08x", mmcs_vi_ring[idx].is_w ? 'W' : 'R',
                mmcs_vi_ring[idx].off, mmcs_vi_ring[idx].val);
    }
    fprintf(stderr, "\n");
}

static void mmcs_vi_census_tick(void *opaque)
{
    mmcs_vi_census_dump();
    QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_vi_census_tick, NULL);
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 60000);
}




/* USB OHCI at the SH7777's on-chip base (S70 register map, env-gated
 * via MMCS_USB for A/B testing). qemu's stock sysbus-ohci model provides
 * real OHCI register semantics for MLSIDK USB driver development. Called
 * from BOTH boot paths (full OS boot and MMCS_MLD payload mode). */
static void mmcs_usb_setup(void)
{
    if (!getenv("MMCS_USB")) {
        return;
    }
    DeviceState *ohci = qdev_new("sysbus-ohci");
    qdev_prop_set_uint32(ohci, "num-ports", 2);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(ohci), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(ohci), 0, 0xFFE70400);
    /* IRQ: the SH7777 OHCI sysintr 53-class mapping is Unknown; route to a
     * sink IRQ for now (polling driver, no guest IRQ needed yet). */
    qemu_irq ohci_irq = qemu_allocate_irq(
        (void (*)(void *, int, int))qemu_set_irq, NULL, 0);
    sysbus_connect_irq(SYS_BUS_DEVICE(ohci), 0, ohci_irq);
    fprintf(stderr, "MMCS: USB OHCI at 0xFFE70400 (env-gated)\n");

    /* Optional attached device for enumeration testing: the OHCI's USB bus
     * is created here (machine init), too late for -device CLI resolution,
     * so attach programmatically. MMCS_USB_DEV names the guest-visible USB
     * device (default: usb-storage). */
    const char *usb_dev = getenv("MMCS_USB_DEV");
    if (!usb_dev) {
        usb_dev = "usb-kbd";   /* self-contained HID: no drive/net backend */
    }
    /* the OHCI's USB bus is a child bus of the controller device (the
     * controller itself is NOT a USBDevice — do not USB_DEVICE() cast it) */
    BusState *usb_bus = qdev_get_child_bus(ohci, "usb-bus");
    if (!usb_bus) {
        /* fall back to the first child bus if unnamed */
        usb_bus = QLIST_FIRST(&ohci->child_bus);
    }
    assert(usb_bus);
    /* usb-cdc-acm takes a "chardev" property; the backend is created via
     * CLI: -chardev socket,id=mlsdkusb,path=...,server=on,wait=off and
     * looked up by that fixed id. */
    DeviceState *udev = qdev_new(usb_dev);
    if (strcmp(usb_dev, "usb-cdc-acm") == 0 || strcmp(usb_dev, "usb-serial") == 0) {
        Chardev *chr = qemu_chr_find("mlsdkusb");
        if (chr) {
            qdev_prop_set_chr(udev, "chardev", chr);
        } else {
            fprintf(stderr, "MMCS: usb-cdc-acm: no chardev id 'mlsdkusb' "
                    "(-chardev socket,id=mlsdkusb,...)\n");
        }
    }
    qdev_realize_and_unref(udev, usb_bus, &error_fatal);
    fprintf(stderr, "MMCS: USB device '%s' attached to port 1\n", usb_dev);
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
    if (getenv("MMCS_FBCON")) {
        mmcs_fbcon_init(sdram);
    }

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

    /* MMCS_FILEVIEW: scratch RAM (64 MB) at phys 0x20000000 backing the
     * launched servers' user heap-arena write misses below 0x40000000
     * (the 0x18NN0036-class per-launch coredll heap-grow faults — see
     * the do_interrupt hook in target/sh4/helper.c). Outside every unit
     * window, inside the SH4 PPN range; demand-zero per 4K page,
     * VA-deduped. */
    if (getenv("MMCS_FILEVIEW")) {
        MemoryRegion *fv = g_new(MemoryRegion, 1);
        memory_region_init_ram(fv, NULL, "mmcs.fileview", 64 * MiB,
                               &error_fatal);
        memory_region_add_subregion(get_system_memory(), 0x20000000, fv);
        fprintf(stderr, "MMCS: FILEVIEW scratch RAM at phys 0x20000000 "
                "(64 MB)\n");
    }

    /* MMCS_KILLSTK: 64KB RAM at phys 0x1F00000 backing the KillThread
     * dispatch stack (P2 0xBF00FF00-class; see the KILLSTK hook in
     * target/sh4/helper.c do_interrupt — the L11 kill-loop fix). Must
     * stay below phys 0x20000000: the SH4 P1/P2 windows only translate
     * the low 29 bits (P1/P2 0xA5000000-class aliases phys 0x05000000,
     * NOT 0x25000000 — first cut wrote to an unmapped hole and the
     * push-pop cycle read zeros back into pr).
     * L17: registered at priority 1 — the sh7750 model P1-aliases its
     * INTC register window at 0x1F000000..+0x1000, overlapping the
     * kill-stack's bottom page; a deep exception march on the kill
     * stack (the L17 A/B: the woken PNPThread's 0xC00000FD march,
     * ~0x450/level, reached 0xBF000E30) wrote into the INTC model and
     * cpu_abort'ed the emulator. No guest code uses the P1 INTC alias
     * in this boot (census: zero 0x1F00xxxx guest accesses; the kernel
     * addresses on-chip regs P4-style) — the kill stack wins. */
    if (getenv("MMCS_KILLSTK")) {
        MemoryRegion *ks = g_new(MemoryRegion, 1);
        memory_region_init_ram(ks, NULL, "mmcs.killstk", 64 * KiB,
                               &error_fatal);
        memory_region_add_subregion_overlap(get_system_memory(), 0x1F000000,
                                            ks, 1);
        cpu->env.mmcs_killstk_active = 1;
        fprintf(stderr, "MMCS: KILLSTK kill-stack RAM at phys 0x1F000000 "
                "(P2 0xBF00FF00)\n");
    }

    /* MMCS_SRVPG / MMCS_KSLOT (L12 relaunch-cycle fixes; hooks live in
     * target/sh4/helper.c — tlb_fill servant page-in synthesis and the
     * do_interrupt kernel-mode slot-call re-tag). SRVPG also needs its
     * scratch RAM for the seeded servant .data pages (phys 0x26000000,
     * 4 MB, outside every unit window, inside the SH4 PPN range).
     * MMCS_SRVPGTAB (L17): sidecar with the servant's TRUE decompressed
     * non-XIP section init content (see the mmcs_srvt block above) —
     * without it the compressed .data/.pdata sections seed from RAW
     * flash bytes (the L17 import-garbage root cause). */
    if (getenv("MMCS_SRVPG")) {
        cpu->env.mmcs_srvpg_active = 1;
        MemoryRegion *sp = g_new(MemoryRegion, 1);
        memory_region_init_ram(sp, NULL, "mmcs.srvpg", 4 * MiB,
                               &error_fatal);
        memory_region_add_subregion(get_system_memory(), 0x26000000, sp);
        fprintf(stderr, "MMCS: SRVPG servant scratch RAM at phys 0x26000000 "
                "(4 MB)\n");
        const char *stab = getenv("MMCS_SRVPGTAB");
        if (stab && *stab) {
            gsize tlen = 0;
            uint8_t *tbuf = NULL;
            if (g_file_get_contents(stab, (gchar **)&tbuf, &tlen, NULL)
                && tbuf && tlen > 8) {
                uint32_t magic = ldl_le_p(tbuf);
                uint32_t n = ldl_le_p(tbuf + 4);
                bool ok = false;
                if (magic == 0x31505253 && n > 0 && n <= MMCS_SRVT_MAX
                    && 8 + 16u * n <= tlen) {
                    /* v1 'SRP1': {va,size,off,flags} — non-XIP only */
                    for (unsigned i = 0; i < n; i++) {
                        mmcs_srvt[i].va = ldl_le_p(tbuf + 8 + 16 * i);
                        mmcs_srvt[i].size = ldl_le_p(tbuf + 8 + 16 * i + 4);
                        mmcs_srvt[i].rom = 0;
                        mmcs_srvt[i].off = ldl_le_p(tbuf + 8 + 16 * i + 8);
                        mmcs_srvt[i].flags = ldl_le_p(tbuf + 8 + 16 * i + 12);
                    }
                    ok = true;
                } else if (magic == 0x32505253 && n > 0 && n <= MMCS_SRVT_MAX
                           && 8 + 24u * n <= tlen) {
                    /* v2 'SRP2': {va,size,rom,flags,off,pad} — the full
                     * C0-window module manifest (XIP text: off==~0u) */
                    for (unsigned i = 0; i < n; i++) {
                        mmcs_srvt[i].va = ldl_le_p(tbuf + 8 + 24 * i);
                        mmcs_srvt[i].size = ldl_le_p(tbuf + 8 + 24 * i + 4);
                        mmcs_srvt[i].rom = ldl_le_p(tbuf + 8 + 24 * i + 8);
                        mmcs_srvt[i].flags = ldl_le_p(tbuf + 8 + 24 * i + 12);
                        mmcs_srvt[i].off = ldl_le_p(tbuf + 8 + 24 * i + 16);
                    }
                    ok = true;
                }
                if (ok) {
                    mmcs_srvt_blob = tbuf;
                    mmcs_srvt_blob_len = tlen;
                    mmcs_nsrvt = n;
                    fprintf(stderr, "MMCS: SRVPGTAB %s: %u sections",
                            stab, n);
                    for (int i = 0; i < n && i < 8; i++) {
                        fprintf(stderr, " %08x+%x", mmcs_srvt[i].va,
                                mmcs_srvt[i].size);
                    }
                    if (n > 8) {
                        fprintf(stderr, " ...");
                    }
                    fprintf(stderr, "\n");
                    if (mmcs_env_on("MMCS_IATFIX")) {
                        mmcs_iatfix_on = 1;
                        fprintf(stderr, "MMCS: IATFIX generalized C0-window "
                                "module service armed (manifest %u secs)\n",
                                n);
                        if (mmcs_env_on("MMCS_C0ARM")) {
                            mmcs_c0arm = 1;
                            fprintf(stderr, "MMCS: C0ARM kernel-side-servant "
                                    "lane (L22) — the SRVPG/IATFIX window "
                                    "service ignores the user-mode launch "
                                    "latch\n");
                        }
                        if (mmcs_env_on("MMCS_UWARM")) {
                            mmcs_uwarm = 1;
                            fprintf(stderr, "MMCS: UWARM current-process "
                                    "user-window service armed (L23, "
                                    "kernel-mode manifest rows)\n");
                        }
                    }
                } else {
                    fprintf(stderr, "MMCS: SRVPGTAB %s: bad magic/count - "
                            "IGNORED\n", stab);
                    g_free(tbuf);
                }
            } else {
                fprintf(stderr, "MMCS: SRVPGTAB %s: cannot read - IGNORED\n",
                        stab);
            }
        } else if (mmcs_env_on("MMCS_IATFIX")) {
            fprintf(stderr, "MMCS: IATFIX needs MMCS_SRVPGTAB; not arming\n");
        }
    }

    /* MMCS_FSVT (L28): the api-set cell binds (see the mmcs_fsvt block
     * above) + a small fallback table carve (all-stub; the real binds
     * use the vendor tables directly). 4KB at phys 0x1F020000 — inside
     * the P1/P2 29-bit window, clear of the KILLSTK carve
     * (0x1F000000+64K) and its L14-L26 stubs. Placed after the
     * SRVPGTAB load. */
    if (getenv("MMCS_FSVT") && mmcs_srvt_blob_len) {
        MemoryRegion *ft = g_new(MemoryRegion, 1);
        memory_region_init_ram(ft, NULL, "mmcs.fsvt", 4 * KiB,
                               &error_fatal);
        memory_region_add_subregion(get_system_memory(), MMCS_FSVT_PAGE, ft);
        static const uint32_t stubfill[0xE0 / 4] = { 0 };
        for (unsigned i = 0; i < ARRAY_SIZE(stubfill); i++) {
            uint32_t v = MMCS_FSVT_STUB;
            /* all-stub fallback fill */
            cpu_physical_memory_write(MMCS_FSVT_PAGE + 4 * i, &v, 4);
        }
        (void)stubfill;
        static const uint8_t stub[8] = {
            0xff, 0xe0,       /* mov #-1,r0 */
            0x0b, 0x00,       /* rts */
            0x09, 0x00, 0x09, 0x00,   /* nop; nop */
        };
        cpu_physical_memory_write(MMCS_FSVT_PAGE + 0xF00, stub, sizeof stub);
        mmcs_fsvt_armed = 1;
        fprintf(stderr, "MMCS: FSVT api-set cell rescue armed "
                "(FSINT direct + Wn32 ROM table; stub table @P1 %08x)\n",
                MMCS_FSVT_P1);
    }
    if (getenv("MMCS_KSLOT")) {
        cpu->env.mmcs_kslot_active = 1;
    }

    /* MMCS fork (L21): MMCS_PGOWN=1 — arm the write-sticky page-ownership
     * table (see the pgown block above; hooks at the tlb_set_page sites in
     * target/sh4/helper.c::superh_cpu_tlb_fill). */
    if (mmcs_env_on("MMCS_PGOWN")) {
        mmcs_pgown_armed = 1;
        fprintf(stderr, "MMCS: PGOWN write-sticky page ownership armed "
                "(user windows per-ASID, C0/stack/KData shared)\n");
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
        mmcs_usb_setup();
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
        if (getenv("MMCS_BOOTFS")) {
            /* MMCS fork (L20/S140): AutoLoad phase-0 boot-FS semantics.
             * DECODE: the filesys init sequence loops StartBootPhase(0)
             * at ~7 Hz because AutoLoadFileSystems(0) never mounts: the
             * live registry's AutoLoad subkeys enumerate the compiled-in
             * 'Relfs' entry only (BootPhase-less), and the vendor
             * per-entry processor (fsdmgr c02c390c, stock
             * storemain.cpp AutoLoadFileSystems body) defaults a MISSING
             * BootPhase to 1 (ROM 0x90a8497e `mov #1,r3`) -> 1 != 0 ->
             * skip -> no boot FS -> the init caller never accepts the
             * completion. GROUND TRUTH: the real default.fdf hive
             * (tree/Registry/default.reg) carries
             * [HKLM\System\StorageManager\AutoLoad\ObjectStore]
             * BootPhase=0 (Dll=filesys.dll, MountAsBootable=1,
             * MountAsRoot=1) — the object store IS the phase-0 boot
             * filesystem per the documented CE boot order (object store
             * -> ROM files -> registry -> phase-1 FSDs (Relfsd) ->
             * LaunchXX/device.dll at phase 2). The fdf apply is not
             * visible to the AutoLoad enumeration in emulation, so we
             * apply the ObjectStore semantics to the phase-0
             * enumeration instead: patch the sticky default 1 -> 0
             * (mov #1,r3 -> mov #0,r3 at the flash image of fsdmgr
             * .text). Env-gated, default off. */
            uint16_t mov0 = 0xE003;    /* mov #0,r3 */
            /* L27 fix: the old cpu_physical_memory_write here was a
             * silent no-op — the flash MR is added to the address space
             * only later (after set_readonly), so the write hit nothing
             * and every BOOTFS A/B since L20 ran unpatched. Write
             * through the RAM pointer instead (the L14 pool-patch
             * pattern). */
            uint8_t *fb0 = memory_region_get_ram_ptr(flash);
            *(uint16_t *)(fb0 + (0x90a8497e - 0x90800000)) = mov0;
            fprintf(stderr, "MMCS: BOOTFS AutoLoad BootPhase default "
                    "1->0 patched @ROM 0x90a8497e\n");
        }
        if (getenv("MMCS_BOOTLD")) {
            /* MMCS fork (L27/S147): loader-completion patches.
             * DECODE: the launch handshake (the boot-continuation's
             * launcher thread, kitl-region 0x9083e1ec = the stock
             * RunApps/SystemStartupFunc mirror: LoadOneLibraryW
             * "filesys.dll" flags 0x18000 -> CreateEvent(manual
             * "SYSTEM/FSReady") -> CreateKernelThread(pMod,hFSReady) ->
             * WaitForSingleObject(hFSReady,INFINITE)) never crosses its
             * first step: the by-name load (0x908367a4 -> wrapper
             * 0x908365fc -> InitModule 0x908360e8 OK -> Part2 hook
             * [[0x8867ebec]] = k.coredll c003c690) spins at 5-10 Hz
             * forever because Part2's completion semantics reject these
             * modules: DoImports returning 0 (pre-bound/empty import
             * descriptors — the FS_* dispatch ships literal targets)
             * never sets the 0x200 flag, the 0x300 DllMain gate never
             * passes, the LOADING bit 0x100 stays set and the free-gate
             * (ROM 0x908e771a `bt 0x908e7738`) falls through to the
             * FREE + NULL path — the pMod is freed, the load returns
             * NULL, the state machine retries, and the launcher
             * eventually parks waiting FSReady with the servant thread
             * never created (FileSysMain zero TBs, chain[23]/[24] NULL).
             * On HW the ROM-TOC boot walk pre-registers these modules
             * so the by-name find matches and the fresh-load path never
             * runs; in emulation the find misses (the list walk's name
             * chase) so every load is a fresh load. PATCHES (2 bytes
             * each, XIP flash, the MMCS_BOOTFS class):
             *  1. ROM 0x908e771a: bt->bra over the Part2 free path —
             *     Part2 always returns the pMod (never frees), so the
             *     by-name caller's hook result is non-NULL and the
             *     launcher receives its module.
             *  2. ROM 0x90836818: cmp/eq r2,r3 -> cmp/eq r3,r3 — the
             *     by-name postcheck ([pMod+14]&0x600)==0x200 accepts
             *     the module, which links it into the global module
             *     list so subsequent by-name finds MATCH and the 5-10
             *     Hz re-load state machines converge.
             * Env-gated, default off. */
            uint16_t bra = 0xA00D;      /* bra #13 -> 0x908e7738 */
            uint16_t cmpeqr3r3 = 0x3332;/* cmp/eq r3,r3 (always T) */
            /* direct RAM-pointer writes: the flash MR is not yet in the
             * address space here (see the BOOTFS note) */
            uint8_t *fb1 = memory_region_get_ram_ptr(flash);
            *(uint16_t *)(fb1 + (0x908e771a - 0x90800000)) = bra;
            *(uint16_t *)(fb1 + (0x90836818 - 0x90800000)) = cmpeqr3r3;
            fprintf(stderr, "MMCS: BOOTLD loader-completion patched "
                    "@ROM 0x908e771a (Part2 free-gate bra) + 0x90836818 "
                    "(byname 0x200 postcheck pass)\n");
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
        if (getenv("MMCS_ILKFIX")) {
            /* Arm the ILKFIX interlocked-op emulation (see helper.c
             * do_interrupt + tlb_fill hooks): KData page seeding/map +
             * exception-boundary emulation for slots holding live vendor
             * data. */
            cpu->env.mmcs_ilkfix_active = 1;
        }
        if (getenv("MMCS_RINGFIX")) {
            /* Arm the RINGFIX uHAL-ring write-drop synthesis (helper.c:
             * fault at 0x908075a2 returns r0=1, kernel exception
             * handler completes instead of fault-logging storms). */
            cpu->env.mmcs_ringfix_active = 1;
        }
        if (getenv("MMCS_KAPIFIX")) {
            /* Arm the KAPIFIX kernel-API-thunk late-bind / fail-return
             * (helper.c: fault at 0x908083fc). */
            cpu->env.mmcs_kapifix_active = 1;
        }
        if (getenv("MMCS_APIRET")) {
            /* Arm the APIRET user-mode direct-return recovery (helper.c:
             * user-mode fetch fault at the PSL trampoline window
             * 0x908236a8 -> set SR.MD, let the trampoline epilogue
             * unwind the call properly; see the L10 decode there).
             * Needs the launch lane (KILK-class combo) to matter. */
            cpu->env.mmcs_apiret_active = 1;
        }
        if (getenv("MMCS_COWFIX")) {
            /* Arm the COWFIX fork-side COW for user .data write
             * violations (helper.c: excp 0x060 -> private scratch page,
             * UTLB rewire, re-execute). */
            cpu->env.mmcs_cowfix_active = 1;
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
                /* first delivery must wait for the polled boot to settle
                 * (early injection derails kernel init; MMCS_VINTC_EVT_DELAY) */
                timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
                          + atoi(getenv("MMCS_VINTC_EVT_DELAY") ? : "12000"));
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
            /* MMCS fork (L13): the scheduler-tick delivery (see
             * mmcs_tick_deliver for the full decode) */
            if (mmcs_env_on("MMCS_TICK")) {
                QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                            mmcs_tick_deliver, NULL);
                timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
                          + atoi(getenv("MMCS_TICK_DELAY") ? : "12000"));
                fprintf(stderr, "MMCS: TICK evt 0x440 every 1ms "
                        "(delay %sms)\n",
                        getenv("MMCS_TICK_DELAY") ? : "12000");
                /* MMCS fork (L14): the parked boot-thread event-set
                 * delivery (see mmcs_hdevt_fire; needs KILLSTK + TICK) */
                /* MMCS fork (L15): MMCS_RINGNOP — unblock the uHAL
                 * ring producer (see mmcs_ringnop_arm above) */
                if (mmcs_env_on("MMCS_RINGNOP")) {
                    QEMUTimer *r = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                                mmcs_ringnop_arm, NULL);
                    timer_mod(r, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
                              + atoi(getenv("MMCS_RINGNOP_DELAY")
                                     ? : "140000"));
                    fprintf(stderr, "MMCS: RINGNOP ring unblock "
                            "(delay %sms)\n",
                            getenv("MMCS_RINGNOP_DELAY") ? : "140000");
                }
                if (mmcs_env_on("MMCS_HDEVT")) {
                    if (!mmcs_env_on("MMCS_KILLSTK")) {
                        fprintf(stderr, "MMCS-HDEVT: needs MMCS_KILLSTK "
                                "for the stub page; not arming\n");
                    } else {
                        QEMUTimer *h = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                                    mmcs_hdevt_fire, NULL);
                        timer_mod(h, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
                                  + atoi(getenv("MMCS_HDEVT_DELAY")
                                         ? : "140000"));
                        fprintf(stderr, "MMCS: HDEVT event-set delivery "
                                "(delay %sms)\n",
                                getenv("MMCS_HDEVT_DELAY") ? : "140000");
                    }
                }
                /* L16: servant-side waiter wakes (MMCS_L16EV list;
                  * needs the KILLSTK stub page + the TICK delivery
                  * chain, exactly like HDEVT). L18/L19/L19TH share
                  * the parse (the v2 completion stub / the wake-cadence
                  * daemon / the thread enqueue completion) with the
                  * same requirements. */
                if (getenv("MMCS_L16EV") || getenv("MMCS_L18EV")
                    || getenv("MMCS_L19EV") || getenv("MMCS_L19TH")) {
                    if (!mmcs_env_on("MMCS_KILLSTK")
                        || !mmcs_env_on("MMCS_TICK")) {
                        fprintf(stderr, "MMCS-L16: needs MMCS_KILLSTK"
                                "+MMCS_TICK; not arming\n");
                    } else {
                        mmcs_l16_boot_parse();
                    }
                }
                /* L18: scheduler-cell change tracer (see above) */
                if (mmcs_env_on("MMCS_SCHEDTRACE")) {
                    QEMUTimer *st = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                                 mmcs_sched_trace, NULL);
                    timer_mod(st, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
                              + 1000);
                    fprintf(stderr, "MMCS: SCHEDTRACE scheduler-cell "
                            "tracer armed\n");
                }
            }
        }
        MemoryRegion *mr = g_new(MemoryRegion, 1);
        memory_region_init_io(mr, NULL, &mmcs_vintc_ops, NULL,
                              "mmcs.vintc", 0x10000);
        memory_region_add_subregion(get_system_memory(), 0xF4000000, mr);
        /* L18: the vendor-INTC census (see the block above) */
        if (mmcs_env_on("MMCS_VINTC_CENSUS")) {
            mmcs_vi_census = 1;
            QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                        mmcs_vi_census_tick, NULL);
            timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 60000);
            fprintf(stderr, "MMCS: vendor-INTC census armed (60s cadence)\n");
        }
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

    /* census regions as logged stubs (skip the 0xFFE70000 cpg stub when
     * MMCS_USB is active so it cannot shadow the OHCI at 0xFFE70400) */
    for (unsigned i = 0; i < ARRAY_SIZE(mmcs_unimpl); i++) {
        if (getenv("MMCS_USB") && mmcs_unimpl[i].base == 0xFFE70000) {
            continue;
        }
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
    /* L26: the [UsbCommonInit] PFC handshake block (see ops above) —
     * a 16-byte carve at 0xFFE70800 over the census stub, priority 1 */
    if (getenv("MMCS_USBST")) {
        MemoryRegion *mr = g_new(MemoryRegion, 1);
        memory_region_init_io(mr, NULL, &mmcs_pfc_usb_ops, NULL,
                              "mmcs.pfc-usb", 0x10);
        memory_region_add_subregion_overlap(get_system_memory(),
                                            0xFFE70800, mr, 1);
        fprintf(stderr, "MMCS: USBST PFC handshake block at 0xFFE70800 "
                "(env MMCS_USBST)\n");
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

    mmcs_usb_setup();

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

    /* MMCS_JITFIX=1: periodic JIT-debugger-name breaker (see above) */
    if (getenv("MMCS_JITFIX")) {
        QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_jitfix_sweep,
                                    NULL);
        timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1000);
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
