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
#include "hw/sh4/mmcs-2dg.h"
#include "hw/sh4/mmcs-regvt.h"
#include "hw/sh4/mmcs-vintc.h"
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
#include "migration/vmstate.h"
#include "migration/register.h"

#define MMCS_FLASH_BASE 0x10800000
#define MMCS_FLASH_SIZE (128 * MiB)
#define MMCS_ENTRY      0x908066b0   /* kernel entry from image first record */

/* L18 vendor-INTC access census (defined near the vintc ops below) */

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
uint8_t *mmcs_srvt_blob;
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
hwaddr mmcs_rom_pa(uint32_t rom)
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
const void *mmcs_srvt_find(uint32_t va)
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
            if (s->off + o + n <= mmcs_srvt_blob_len) {
                memset(out, 0, 0x1000);
                /* L31: the page offset o must reach the copy source —
                 * the L17 code copied from s->off alone, so EVERY page
                 * past a section's first served the first page's bytes
                 * (filesys .data page c00d1000 served the pre-bound
                 * desc0-IAT head: the launch walker's count cell at
                 * c00d1020 read IAT slot 8 = StringCchCopyW
                 * 0x4003ed18, the insert-search walked 0x4003ed18
                 * entries off the table end and the kill walk retired
                 * the servant before the first CreateProcessW). */
                memcpy(out, mmcs_srvt_blob + s->off + o, n);
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
static uint32_t mmcs_pgown_nretire;

/* L34: is this phys page a GUEST-authored page (the vendor pager's own
 * RAM, [0x08600000,0x10700000) = ulRAMStart..ulRAMEnd)? The host-side
 * seed pools live elsewhere: COWFIX [0x10710000,0x10800000) (past
 * ulRAMEnd, under the flash window), FILEVIEW [0x20000000,0x24000000),
 * SRVPG [0x26000000,0x26400000). */
static bool mmcs_pgown_guest_page(uint32_t pa)
{
    return pa >= 0x08600000u && pa < 0x10700000u;
}

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
            if (cls == 1 && mmcs_pgown_guest_page(*pa)) {
                /* L34: PER-PROCESS RETIREMENT. The per-process user
                 * windows got a GUEST-authored remap to a fresh
                 * guest-RAM page — the vendor pager's fresh per-process
                 * copy (process death + relaunch: the pager decompresses
                 * the section into a new physical page; ROMHDR
                 * ulRAMStart..ulRAMEnd bounds the guest pool). The
                 * pinned copy belongs to the DEAD process — its critsec
                 * {OwnerThread=dead hTh, hCrit=old handle} and its
                 * CRT-init cells (g_hProcessHeap) must NOT leak into
                 * the newcomer: on HW the new process reads a fresh
                 * image-init copy. Retire the pin and adopt the guest's
                 * page as the new clean base (the first store re-pins).
                 * Host-seed re-serves (COWFIX/FILEVIEW/SRVPG pools,
                 * outside the guest range) keep the L21 flip-flop
                 * override — one shared backing for the same live
                 * mapping. */
                uint32_t old_pa = e->pa;
                e->pinned = 0;
                e->pa = *pa;
                e->nremap = 0;
                mmcs_pgown_nretire++;
                if (haslog && mmcs_pgown_nretire <= 32) {
                    fprintf(stderr, "MMCS-PGOWN: RETIRE va=%08x asid=%02x "
                            "pinned pa=%08x -> fresh guest pa=%08x "
                            "(per-process relaunch)\n",
                            page, key, old_pa, *pa);
                }
                return prot & ~PAGE_WRITE;
            }
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
            "retirements=%u launch-latch=%d\n",
            mmcs_pgown_nins, mmcs_pgown_npin, mmcs_pgown_novr,
            mmcs_pgown_nretire, (int)mmcs_ilkfix_user_seen);
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
QemuConsole *mmcs_con;

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
            /* MMCS_2DG capture retarget: the latched 2DG+0x50 plane
             * surface A is the DU scanout source; when the plane
             * descriptor shipped 0 (single-surface design — the
             * splash's live case), the DL walk's Poly4AA texture IS
             * the presented image. P1/P2 alias -> phys. Fallback: the
             * fixed 0x08B00000 assumption. */
            hwaddr fbp = 0x08B00000;
            if (mmcs_2dg.armed) {
                if (mmcs_2dg.surf_a) {
                    fbp = mmcs_2dg.surf_a & 0x1FFFFFFF;
                } else if (mmcs_2dg.tex) {
                    fbp = mmcs_2dg.tex & 0x1FFFFFFF;
                }
                fprintf(stderr, "MMCS: FB capture from 2DG presented "
                        "surface: phys %08x\n", (unsigned)fbp);
            }
            cpu_physical_memory_read(fbp, rgb565, sizeof rgb565);
            int n = snprintf((char *)ppm, sizeof ppm,
                             "P6\n%d %d\n255\n", FW, FH);
            for (int i = 0; i < FW * FH; i++) {
                uint16_t p = rgb565[2 * i] | rgb565[2 * i + 1] << 8;
                /* 565->888 with proper low-bit replication (the old
                 * (p>>9)/(p>>2) terms were unmasked and leaked the
                 * neighboring channels' bits into every captured
                 * frame's colors — e.g. the splash's exact 0xf804 red
                 * captured as orange (255,124,33)) */
                ppm[n + 3 * i + 0] = (p >> 8 & 0xf8) | (p >> 13 & 7);
                ppm[n + 3 * i + 1] = (p >> 3 & 0xfc) | (p >> 9 & 3);
                ppm[n + 3 * i + 2] = (p << 3 & 0xf8) | (p >> 2 & 7);
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
static void mmcs_nop_marker_jsrs(uint8_t *img, size_t len, hwaddr img_va,
                                 bool nop_user_coredll)
{
    /* L35: the user coredll fixed-slot .text XIP window (ROM 0x90853000,
     * size 0x625ba — the SRP2 manifest row 0) carries LIVE direct
     * `jsr @slot` syscall sites; exempt it unless MMCS_NOPALL. */
    const hwaddr user_text_lo = 0x90853000;
    const hwaddr user_text_hi = 0x90853000 + 0x625ba;
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
        if (hit && !nop_user_coredll
            && (hwaddr)(img_va + pc + 2) >= user_text_lo
            && (hwaddr)(img_va + pc + 2) < user_text_hi) {
            continue;      /* L35: leave the live user syscall jsrs alone */
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

/* MMCS_VINTC_IRQ=<ms>: pulse the SH4 IRL line every <ms> virtual ms.
 * Ground truth (S73): the stalled kernel WRITES-ONLY to the vendor INTC
 * (36.8M zero-mask sweeps, zero reads) = waiting for an interrupt we
 * never injected. This experiment asserts the line; the handler at
 * VBR+0x600 should take it. Level: IRL is active-low encoded priority. */
static SuperHCPU *mmcs_cpu;

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
        /* MMCS fork (L56d): the tick yields to an unconsumed wake-class
         * injection. The unconditional intevt overwrite raced the L56
         * wake out of existence in the live spinner world (EVTDBG
         * census: 23,392 takes all vec=400, ZERO vec=320) — the next
         * 1ms tick's 0x400 replaced the unconsumed 0x320 before the
         * KCall masked windows let the CPU accept it. Dead-idle worlds
         * took the wake within µs, so L54/L55 never met the race.
         * Wake-class = intevt < 0x400 (0x200 HDEVT, 0x280 L26, 0x2c0
         * L37, 0x2e0 L52, 0x320 L54/55/56, 0x3E0 VINTC); tick-over-
         * tick overwrite is unchanged — the default world stays
         * byte-identical. */
        if (env->mmcs_evt_inject && env->intevt < 0x400 && evt >= 0x400) {
            return;                 /* keep the wake armed; drop this tick */
        }
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
static int mmcs_l26m_armed;
static uint32_t mmcs_l26_cadence_ms = 2000;
/* L68/S219: the live KData user page (MMCS_L68KD; full block below) */
int mmcs_l68_kd_on(void);
uint32_t mmcs_l68_kdata_page_pa(void);
void mmcs_l68_repin_kdata_page(void);
/* L69/S220: the appverifier registry short-circuit (block below) */
int mmcs_l69ap_on(void);
int mmcs_l70ks_on(void);
static uint32_t mmcs_l32_stack_pa(uint32_t va);  /* L40: the L26M guard */
static uint32_t mmcs_l26_max_deliv = 64;
/* L36: the post-exit requeue daemon (full block + decode below) */
static void mmcs_l36_scan(void);
static int mmcs_l36_armed;
static uint32_t mmcs_l36_cadence_ms = 2000;
static uint32_t mmcs_l36_max_deliv = 16;
/* L52: the post-completion resched hand-off daemon (the S200
 * frontier — the pCurTh-frozen-at-epilogue class L36/L37 exclude;
 * full block + decode below) */
static void mmcs_l52_scan(void);
static int mmcs_l52_armed;
static uint32_t mmcs_l52_cadence_ms = 2000;
static uint32_t mmcs_l52_max_deliv = 4;
static uint32_t mmcs_l52_total;
static uint32_t mmcs_l52_key;        /* stability key {thread,pc} */
static uint32_t mmcs_l52_stable;     /* consecutive matching scans */
/* L53 (S201): the completion-helper spin — the cleanup-chain
 * self-loop restore (see mmcs_l53_scan) */
static void mmcs_l53_scan(void);
static int mmcs_l53_armed;
static uint32_t mmcs_l53_cadence_ms = 2000;
static uint32_t mmcs_l53_max_deliv = 4;
static uint32_t mmcs_l53_total;
static uint32_t mmcs_l53_key;        /* stability key {thread,entry} */
static uint32_t mmcs_l53_stable;     /* consecutive matching scans */
/* L54: the stale-pCurTh re-park wake — the S202 class (the L47
 * satisfy re-targeted at tva==pcur, gated on the dead-idle world;
 * see mmcs_l54_scan) */
static void mmcs_l54_scan(void);
static int mmcs_l54_armed;
static uint32_t mmcs_l54_cadence_ms = 2000;
static uint32_t mmcs_l54_max_deliv = 4;
static uint32_t mmcs_l54_total;
static uint32_t mmcs_l54_key;        /* stability key {thread,obj} */
static uint32_t mmcs_l54_stable;     /* consecutive matching scans */
/* L37: the KCall-exit lost-preempt CLASS daemon (full block + decode
 * below) — the generic superset of the per-site requeue daemons */
static void mmcs_l37_scan(void);
static int mmcs_l37_armed;
static uint32_t mmcs_l37_cadence_ms = 2000;
static uint32_t mmcs_l37_max_deliv = 16;
/* L32: the create-completion event daemon (full block + decode below) */
static void mmcs_l32_scan(void);
static int mmcs_l32_armed;
static uint32_t mmcs_l32_cadence_ms = 2000;
static uint32_t mmcs_l32_max_deliv = 64;
/* L46: the create-interlock SPLIT repair (one-shot; full block below) */
static void mmcs_l46_scan(void);
static uint32_t mmcs_l46_armed;
static uint32_t mmcs_l46_cadence_ms = 2000;
/* L47: the true-base wake-eval ctx repair (repeating; see
 * mmcs_l47_scan) */
static void mmcs_l47_scan(void);
static uint32_t mmcs_l47_armed;
static uint32_t mmcs_l47_cadence_ms = 2000;
static uint32_t mmcs_l47_max_deliv = 8;
static uint32_t mmcs_l47_total;
/* L50: the create-retry exit tape (READ-ONLY diagnostic; see
 * mmcs_l50_dbg) */
static void mmcs_l50_dbg(void);
static uint32_t mmcs_l50_armed;
static uint32_t mmcs_l50_cadence_ms = 250;
static uint32_t mmcs_l50_max_lines = 600;
static uint32_t mmcs_l50_lines;
/* L55: the S203 psi-array resolve diagnostic (READ-ONLY; rides the
 * L50 tape lines — see the dump block in mmcs_l50_dbg) */
static uint32_t mmcs_l55dbg_armed;

/* savestate lane: the tick-chain cadence counters were function-local
 * statics — hoisted so the snapshot can stream them (losing them
 * shifts every daemon scan phase by up to one cadence period after a
 * restore, which breaks identical-continuation verify). */
static uint64_t mmcs_tick_l19, mmcs_tick_l26, mmcs_tick_l32, mmcs_tick_l36;
static uint64_t mmcs_tick_l37, mmcs_tick_l46, mmcs_tick_l47, mmcs_tick_l50;
static uint64_t mmcs_tick_l52;
static uint64_t mmcs_tick_l53;
static uint64_t mmcs_tick_l72;
static uint64_t mmcs_tick_l73;
static uint64_t mmcs_tick_l74;
static uint64_t mmcs_tick_l74cr;
static uint64_t mmcs_tick_l74s4;
static uint64_t mmcs_tick_l75ho;
static uint64_t mmcs_tick_l76;
static uint64_t mmcs_tick_l77;
static uint64_t mmcs_tick_l78;
static uint64_t mmcs_tick_l79;
static uint64_t mmcs_tick_l54;
static uint64_t mmcs_tick_l55;
static uint64_t mmcs_tick_l58;
static uint64_t mmcs_tick_l59;
static uint64_t mmcs_tick_l56;
static uint64_t mmcs_tick_l62;
static uint64_t mmcs_tick_l64;
/* L55: the WAIT-ALL chained dual-entry multi-satisfy (S203; the scan
 * body + the delivery state live down at the L54 cluster — forward
 * declarations for the tick chain) */
static void mmcs_l55_scan(void);
static int mmcs_l55_armed;
static uint32_t mmcs_l55_cadence_ms;
static uint32_t mmcs_l55_max_deliv;
static uint32_t mmcs_l55_total;
static uint32_t mmcs_l55_key;
static uint32_t mmcs_l55_stable;
/* MMCS fork (L56): MMCS_L56EV — the post-return sticky-orphan
 * pulse (the S205 class — the sibling waiter's own completion).
 *
 * THE WORLD (the L55 landing): the wait machinery completes
 * end-to-end; the launcher thread (the spinner) runs the create-
 * wait's coredll completion loop (c00bb414: while (counter <
 * limit) WaitForMultipleObjects(1,&h,FALSE,INFINITE)) with the
 * L55 standing shape ([obj+0x8D]=1 AND [obj+0x8E]=1) making every
 * wait return INSTANT — 283K KCall cycles/s, counter FROZEN at
 * 1/limit 6, serial 0B. THE SIBLING-CLASS WAITERS stay BLOCKED at
 * the face: their events are THE STICKY CLASS ([+0x8D]==0 clear,
 * [+0x8E]==1 — EventModify's deferred-routing bit, the eval's
 * mark-arm trigger), waiters LINKED ([obj+8] != 0, the head
 * entry's [+0x1C] == the thread), [+0x90]==0.
 *
 * THE STOCK MACHINERY (this session's decode): the walker
 * fn_90827f68(obj,3) detaches the list ([obj+8]:=0), clears the
 * sig, bumps [th+0x42] (wCount), zeros [th+0x34]/[th+0x74], marks
 * the BLOCKED waiter RUNNABLE (st16|=3); MakeRunIfNeeded
 * fn_908278e8 then requeues via MakeRun. The broadcast caller
 * FUN_908433d4 pulses with type 3 ([obj+8D]:=(type==3)=1).
 *
 * THE DELIVERY (the composite the L40 seed experiments each
 * advanced ONE layer of, now atomic + in a LIVE world): (1) THE
 * UNMARK — the entry's type byte 0xff→4 (the wait-submit's own
 * arm value; the marked path never reads the sig — L40 seed 4);
 * (2) THE PULSE — the walker's object writes ([obj+8]:=0 detach,
 * [obj+0x8D]|=1) + the walker's thread writes (wCount++ halfword,
 * [th+0x34]:=0, [th+0x74]:=0, st16|=3); (3) THE RESULT PLANTS —
 * the L54 recipe on the entry ([th+0x1F8]:=entry, entry+0x20 :=
 * 0x1000, [th+0x1FC]:=0x1000, the verdict re-arm [sp+0x10]:=2);
 * (4) THE V9 WAKE — the shared stub (0xBF00E600, slot evt 0x320,
 * ents[7]; stands down while a pending L54/L55 delivery holds the
 * channel): MakeRun + the resched protocol stores + pick + the
 * vendor switcher — the preempt the standing-sig spin never
 * yields. NO feeder event, NO waiter-list manufacture: every
 * write is a vendor value the stock pulse/completion path itself
 * writes.
 *
 * Gates (all readback): arena thread + BLOCKED(2) at the generic
 * face 0x90837cf6 + bF==2 + susp [th+0xE]==0 + tmo [th+0x200]==-1
 * + tva != pCurTh + the wobj resolver (pTh-matched entry) + THE
 * STICKY CLASS on the object ({8D==0, 8E==1, +0x90==0, wlh!=0,
 * [wlh+0x1C]==tva}) + the user-continuation witness [th+0x150] in
 * the c00 window + NOT the kill grave (R14) + 2-cadence stability
 * keyed {thread,obj} + THE LIVE-WORLD GATE (pick==0 OR pick==pcur
 * — someone ELSE's pick = vendor mid-flight, SKIP) + cap (default
 * 2), self-terminating (the shape dies when the wait returns).
 * Env MMCS_L56EV (default OFF; MMCS_L56EV_MS cadence default
 * 2000; MMCS_L56EV_MAX cap default 2). Needs MMCS_KILLSTK +
 * MMCS_TICK. */
static void mmcs_l56_scan(void);
static int mmcs_l56_armed;
static int mmcs_l57_armed;    /* MMCS_L57EV: the v10 requeue stub */

/* MMCS fork (L58/S207): MMCS_L58EV — THE RESIDUAL-STICKY CLEANUP
 * (the falsifier write promoted to maintenance; the L53 one-word
 * class — no stub, no slot). THE S207 DECODE (live-proven): the
 * create event's [+0x8E]=1 marks the STICKY class (EventModify's
 * deferred-routing bit — every satisfy re-arms the sig from it);
 * [+0x8E]=0 is the NORMAL consumable class. The L55-era manual-reset
 * plant broke the wait's re-submit cycle so the walker could EXIT —
 * but the plant PERSISTS in the object long after the wait returned:
 * the residual that turned the completion loop into a spin and
 * starved every other thread (the falsifier: clear 8E -> the
 * launcher PARKS, bF 01->02 at the face, the sig consumed, the
 * satisfy stream stops). THE SCAN: pcur's wait-array-resolved object
 * with the standing shape {8D&1, 8E==1, +0x90==0} AND the
 * post-return witness [pTh+0x1F8]!=0 (the standing completed head —
 * the L55 plant is only retired AFTER the wait returned) -> clear
 * [+0x8E] := 0, ONE-SHOT per object (the done-set). INTERLOCK: the
 * L55 delivery skips retired objects (otherwise its cadence re-plants
 * the bit — the falsifier's first lesson: the standing combo's own
 * machinery was faithfully undoing the clears). Env MMCS_L58EV
 * (default OFF; MMCS_L58EV_MS cadence default 2000; cap 8 objects). */
static void mmcs_l58_scan(void);
static int mmcs_l58_armed;
static uint32_t mmcs_l58_cadence_ms;
static uint32_t mmcs_l58_total;
static uint32_t mmcs_l58_done[8];

/* MMCS fork (L62/S213): MMCS_L62EV — THE DEAD-OWNER CRIT RELEASE
 * (the stock m3-close shape: transfer the ownership to the waiting
 * heir + wake; the L62 recipe delivered).
 *
 * THE S213 DECODE (this session, Verified disasm + the live probes):
 * the loader crit 906fe3f0 = a kernel CRIT object (CINFO 0x908220a0
 * "CRIT", type 0x0c; the trailer {+0x94 state word, +0x98 lpcs ptr,
 * +0xa4 CINFO, +0xa8 self}). Its user-side CRITICAL_SECTION (lpcs)
 * sits at [crit+0x98] = d0040020 — ON THE DEAD OWNER'S KSTACK. The
 * enter path (fn_90840754): builds the proxy on the waiter's stack
 * (bType 12, tmo [th+0x200]:=-1), links it into the crit's priority
 * buckets, and BLOCKS at the park face 0x90840814; the retry tail
 * re-reads [lpcs+4] (the owner handle) vs [KData+8] (hCurThread) and
 * only exits the loop AS THE OWNER. The stock release = the CRIT
 * method[3] 0x908408bc: fn_90828a08 + the fn_90828a68 pop loop
 * (writes [lpcs+0]:=1, [lpcs+4]:=[heir th+0x3C], [lpcs+0xC]:=0,
 * byte[crit+0x94]:=0 free, the bucket/pProxList clears, wCount++,
 * [th+0x1F4]:=proxy) + MakeRunIfNeeded — the WAKE half. THE DISEASE
 * (live, t=110s stable): the owner (the RunApps thread 906dcacc,
 * handle 0x00570002 in [lpcs+4]) died into the kill grave holding
 * the crit (state 0x8000fb01, the launcher 906ca240's proxy linked
 * at bucket+0x08/pProxList+0x84) — the close NEVER ran: the waiter
 * sits BLOCKED at 0x90840814 forever, [lpcs+4] frozen at the dead
 * handle.
 *
 * THE FIX — the stock-shaped release, host-written exactly where the
 * vendor writes it, then the WAKE through the proven v9 channel
 * (MakeRun + the resched protocol + pick + the vendor switcher —
 * the L54 recipe): the resumed waiter's own retry tail reads
 * [lpcs+4] == its handle ([KData+8] as pcur) and exits the loop as
 * the owner through 100% vendor code.
 *
 * Filter (R23, the l48_fixtures l63 rows, CRIT-CENTRIC): an arena
 * object with the CRIT trailer {+0xa4 == 0x908220a0, +0xa8 == self},
 * the OWNED state ((state&0xffff0000)==0x80000000 && low16 != 0),
 * a queued proxy ([crit+0x84] != 0, P3-resolved, pTh [proxy+0x1C]
 * == the waiter tva), the waiter BLOCKED (st16&3)==2 at the enter
 * face 0x90840814 with susp 0 and tmo -1, and THE DEAD-OWNER PROOF:
 * the owner handle [lpcs+4] resolves an arena thread carrying a
 * GRAVE state16 ({0x58,0x18} or the DEAD bit 8 or the kill-grave ctx
 * 0x9083c102). Dead-idle world gate (L52b), 2-cadence stability
 * keyed {thread,crit}, hard cap (default 2), slot-guarded evt 0x320
 * (ents[7]). Env MMCS_L62EV (default OFF; MMCS_L62EV_MS cadence
 * default 2000; MMCS_L62EV_MAX cap default 2; MMCS_L62EV_DIAG=1
 * diagnose-only). Needs MMCS_TICK. */
static void mmcs_l62_scan(void);
static int mmcs_l62_armed;
static int mmcs_l62_diag;
static uint32_t mmcs_l62_cadence_ms;
static uint32_t mmcs_l62_max_deliv = 2;
static uint32_t mmcs_l62_total;
static uint32_t mmcs_l62_key;       /* stability key {thread,obj} */
static uint32_t mmcs_l62_stable;

static int mmcs_l58_retired(uint32_t obj)
{
    for (unsigned i = 0; i < 8; i++) {
        if (mmcs_l58_done[i] == obj) {
            return 1;
        }
    }
    return 0;
}

/* MMCS fork (L59/S210): MMCS_L59EV — THE COMPLETION-FORWARD PULSE
 * (the owner-directed forward move; the L40-seed pattern on the
 * proven machinery). THE S209 MEASUREMENT (the cascade watch): the
 * launcher live-cycles the kernel re-park loop on the RETIRED
 * (consumable) create event — 551,815 satisfy-copies, ZERO external
 * SETs: the completion producers are absent (the Jeep-lane
 * absent-counterparty class — parked as Open, not chased). THE MOVE:
 * a plain ONE-WORD SET ([obj+0x8D] := 1) per cadence — the cycling
 * eval consumes it within one pass (the satisfy [8D]:=[8E]=0), the
 * loop body runs, the counter +1; FIVE pulses walk the counter 1->6
 * and the launch loop EXITS into new territory. NO stub, no slot, no
 * wake (the thread is live in the kernel loop; the v9 guard would
 * reject low2!=2 anyway). GATES: the L58 resolver (pcur's
 * wait-array object) + the CONSUMABLE class {8D==0, 8E==0,
 * +0x90==0} + the standing completed head [pTh+0x1F8]!=0 (the
 * completion-loop waiter) + one pulse per cadence + CAP 6 (the
 * synthetic completions bounded; no exit by 6 = the decode is wrong,
 * not the pulse count). Env MMCS_L59EV (default OFF; MMCS_L59EV_MS
 * cadence default 2000 = one completion per 2s; cap 6). */
static void mmcs_l59_scan(void);
static int mmcs_l59_armed;
static int mmcs_l60_armed;    /* MMCS_L60EV: the SignalStarted synthesis */
/* MMCS fork (L64/S214): MMCS_L64EV — THE PACIFIC-EVENT AFTERMATH
 * WAKE-ONLY (the L63-named generalized aftermath lane; R24 rows in
 * the l48_fixtures). The WEDGED flavor's second park (live L63
 * PART 4, t=39204): after B1 cleared the crit park the launcher
 * parks BLOCKED at the GENERIC face 0x90837cf6 with the standing
 * vendor completion pair ([th+0x1F8]!=0, [th+0x1FC]==0x1000, tmo
 * -1) whose resolved object (the entry-layout law: obj =
 * [head+0x14]) is the "Pacific" EVENT 906ca6d8-class (CINFO
 * 90822040 @ obj+0xa4, self @+0xa8) — the death-close's completion
 * half stands, the wake half died with the owner. THE FIX = the v9
 * WAKE-ONLY, NO plants (the resumed eval consumes the head and the
 * wait returns 0x1000 through 100% vendor code). GATES (the L63
 * contract): 8E==0 (the L56 sticky class excluded — the double-wake
 * hazard), the arena+cinfo+self witness (the R13-ghost family never
 * resolves), the dead-idle world (L52b), the 2-cadence stability
 * keyed {waiter,obj}, the shared evt-0x320 channel guards, hard cap
 * (default 2), the tick-order contract (runs AFTER L56 and L62 in
 * the chain). Env MMCS_L64EV (default OFF; MMCS_L64EV_MS cadence
 * default 2000; MMCS_L64EV_MAX cap default 2; MMCS_L64EV_DIAG=1
 * diagnose-only). Needs MMCS_TICK. */
static void mmcs_l64_scan(void);
static int mmcs_l64_armed;
static int mmcs_l64_diag;
static uint32_t mmcs_l64_cadence_ms;
static uint32_t mmcs_l64_max_deliv = 2;
static uint32_t mmcs_l64_total;
static uint32_t mmcs_l64_key;
static uint32_t mmcs_l64_stable;
/* L72 (S223): the post-park completion hand-off — the consumed-
 * completion stale-pCurTh wake (see mmcs_l72_scan) */
static void mmcs_l72_scan(void);
static int mmcs_l72_armed;
static uint32_t mmcs_l72_cadence_ms = 2000;
static uint32_t mmcs_l72_max_deliv = 2;
static uint32_t mmcs_l72_total;
static uint32_t mmcs_l72_key;        /* stability key {thread,ctxpc} */
static uint32_t mmcs_l72_stable;     /* consecutive matching scans */
/* L75: the post-kill orphan hand-off (the MMCS_L75TX daemon half; full
 * block + decode below) — needs the L72 hand-off daemon (same stub, same
 * slot) to deliver once pCurTh names the orphan */
static void mmcs_l75ho_scan(void);
static int mmcs_l75ho_armed;
static uint32_t mmcs_l75ho_cadence_ms = 500;
static uint32_t mmcs_l75ho_max_deliv = 4;
static uint32_t mmcs_l75ho_total;
static uint32_t mmcs_l75ho_key;      /* stability key {thread,ctxpc} */
static uint32_t mmcs_l75ho_stable;   /* consecutive matching scans */
/* L76 (S227): THE EQUAL-PRIORITY STARVATION RE-ARM — the cNest delivery
 * (see mmcs_l76_scan): a RUNNABLE thread stands at the run-band head
 * while the monopolist's KCall'd walk-spin keeps cNest [0x88679885]==0,
 * so the outer KCall return's resched gate 0x9082304c never routes to
 * the switcher; nothing else (MakeRun's outrank tail, the tick's
 * rte-dropped resched-consider, the never-expiring quantum) ever sets
 * it in this world */
static void mmcs_l76_scan(void);
static int mmcs_l76_armed;
static uint32_t mmcs_l76_cadence_ms = 500;
static uint32_t mmcs_l76_max_deliv = 4;
static uint32_t mmcs_l76_total;
static uint32_t mmcs_l76_key;        /* stability key {pCurTh,band-head} */
static uint32_t mmcs_l76_stable;     /* consecutive matching scans */
/* L77 (S228): THE KILL-PATH API-LOCK CLEANUP RELEASE — the dying
 * thread's [th+0x164] lock-ownership clear (see mmcs_l77_scan): the
 * launcher's unhandled second-chance exception parks its own death in
 * the kill continuation's API-lock cleanup loop (fn_9083adfc), whose
 * transfer condition (owner cell == hCurTh|1) no future acquirer can
 * ever satisfy in the post-server-death world */
static void mmcs_l77_scan(void);
static void mmcs_l78_scan(void);
static void mmcs_l79_scan(void);
static int mmcs_l77_armed;
static uint32_t mmcs_l77_cadence_ms = 500;
static uint32_t mmcs_l77_max_deliv = 4;
static uint32_t mmcs_l77_total;
static uint32_t mmcs_l77_key;        /* stability key {pCurTh,crit} */
static uint32_t mmcs_l77_stable;     /* consecutive matching scans */
static int mmcs_l78_armed;
static uint32_t mmcs_l78_cadence_ms = 500;
static uint32_t mmcs_l78_max_deliv = 4;
static uint32_t mmcs_l78_total;
static uint32_t mmcs_l78_key;        /* stability key {candidate} */
static uint32_t mmcs_l78_stable;     /* consecutive matching scans */
static int mmcs_l79_armed;
static uint32_t mmcs_l79_cadence_ms = 500;
static uint32_t mmcs_l79_max_deliv = 4;
static uint32_t mmcs_l79_total;
static uint32_t mmcs_l79_key;        /* stability key {runner} */
static uint32_t mmcs_l79_stable;     /* consecutive matching scans */
/* L73 (S224): the churn livelock release — the stale sleep-node
 * self-link unlink (see mmcs_l73_scan) */
static void mmcs_l73_scan(void);
static void mmcs_l74_scan(void);
static void mmcs_l74cr_scan(void);
static int mmcs_l73_armed;
static uint32_t mmcs_l73_cadence_ms = 1000;
static uint32_t mmcs_l73_max_deliv = 12;
static uint32_t mmcs_l73_total;
static uint32_t mmcs_l73_key;        /* stability key {thread,head,nxt} */
static uint32_t mmcs_l73_stable;     /* consecutive matching scans */

/* MMCS fork (L74/S225): MMCS_L74EV — THE STANDING EXPIRY REAP (the
 * S225 recipe item (i), the OR branch; decoded 2026-11-24). The L73
 * honest limit closed statically + live: the vendor's sleep-list
 * expiry walk (drain1 0x90826f4c) has exactly ONE caller — the
 * switcher 0x90822b68 (jsr @r8 at 0x90822b92) — so no ISR/fn2 lane
 * can reach it; the monopoly (a KCall'd walk that never terminates)
 * starves the switcher, which starves the reap, which perpetuates
 * the stale node the walk spins against. The fn2/TUNI2 lane is
 * statically refuted (the evt-0x440 walker 0x90809d78 feeds only the
 * [0x8860200c] change-detect whose firing = the fn1b 0x908419f0
 * trapa#1 debug FATAL; the LIVE evt-0400 handler 0x90808980 drops
 * the resched-consider return at rte — S181/S224's live binds both
 * reaped nothing). THE PROMOTION: the L73EV unlink as the STANDING
 * uncapped daemon at a fast cadence, with the gate widened to the
 * one signature the L73 v4 samples missed: a RUNNING thread whose
 * OWN node sits at the sleep-list head SELF-LINKED, at ANY tick
 * flavor — the fresh submit's insert-before-stale-cursor re-links
 * [th+0x144] := th with a FUTURE [th+0x1E8], so the whole ~2s walk
 * spin holds the v4-skip shape (running + future tick). A running
 * thread is never a stock sleep-list member (the park sets state16
 * low2 := 2 before yielding); the 2-cadence stability (100ms apart)
 * excludes the sub-millisecond mid-park insert transient. The
 * expired-own-node flavor (nxt != th, wtick < now) rides along at
 * the same stability; a non-self next is SPLICED (head := nxt) so a
 * stale head never orphans a legit tail. Delivery = the L73 v2
 * unlink verbatim: sleeper cursor/flag clear at [th+0xB0]+0x10
 * (gated cursor == th) + the list surgery. Env MMCS_L74EV (default
 * OFF; MMCS_L74EV_MS cadence default 100; MMCS_L74EV_MAX cap default
 * 0 = STANDING/uncapped). Needs MMCS_TICK. */
static int mmcs_l74_armed;
static uint32_t mmcs_l74_cadence_ms = 100;
static uint32_t mmcs_l74_max_deliv;  /* 0 = standing/uncapped */
static uint32_t mmcs_l74_total;
static uint32_t mmcs_l74_key;        /* stability key {thread,head,nxt} */
static uint32_t mmcs_l74_stable;     /* consecutive matching scans */
static int mmcs_l74cr_armed;
static int mmcs_l74cr_diag;
static uint32_t mmcs_l74cr_cadence_ms = 2000;
static uint32_t mmcs_l74cr_max_deliv = 2;
static uint32_t mmcs_l74cr_total;
static uint32_t mmcs_l74cr_key;
static uint32_t mmcs_l74cr_stable;
static int mmcs_l74s4_armed;
static uint32_t mmcs_l74s4_done;     /* one-shot: the slot stock-clear */

/* MMCS fork (L74/S225): MMCS_L74S4 — THE SET-84 SLOT STOCK-CLEAR (the
 * S225 recipe item (iii), the "PerformCallBack proper" caught-fault
 * stock outcome). THE DECODE (Verified: ROM disasm of the dispatch
 * FUN_90843214 = the kernel-side API-set call shim): r0 =
 * fn_908291ec(84) (registered?); r12 = fn_9082bc84(proc) (the
 * ACTIVATEPROC switch, tail call 0x90837244 — BOTH the launcher and
 * the servant park inside it, pr 0x90843240); r2 = [0x8867eed0] THE
 * SLOT CELL; tst r2,r2 -> r2==0 RETURNS 0 CLEANLY (*** the stock
 * dead-server path — a server that died deregistered leaves the slot
 * NULL and every call returns 0, NO FAULT ***); else jsr
 * @[[[slot]+0xC]+0x234] — with the slot = 0xd0050260 (the byte-
 * reversal of the original registration 0x600205d0, a ZEROED D0-window
 * block) the [NULL+0x234] load faults c0000005 at 0x90843258 (18
 * live-observed in the post-L74CR cascade). THE REPAIR: the stock
 * semantics, one write — [0x8867eed0] := 0 when the slot points at
 * the zeroed-block artifact (the exact byte-reversed value OR the
 * self-witnessing shape: a kernel-window block whose first 0x20
 * bytes read zero and [+0xC] == NULL). ONE-SHOT (the cell re-stocks
 * only through RegisterAPISet). Env MMCS_L74S4 (default OFF). Needs
 * MMCS_TICK (rides the L74CR cadence). */
static void mmcs_l74s4_clear(void)
{
    if (mmcs_l74s4_done) {
        return;
    }
    uint32_t slot = 0;
    cpu_physical_memory_read(0x0867EED0, &slot, 4);
    if (!slot) {
        mmcs_l74s4_done = 1;         /* already stock-cleared */
        return;
    }
    if (slot == 0xd0050260) {
        /* the lineage-confirmed byte-reversal artifact */
    } else if (slot >= 0xD0000000 && slot < 0xDC000000) {
        /* the self-witnessing shape: a zeroed kernel-window block */
        uint32_t pa = slot - 0xC0000000;
        uint32_t w[8] = { 1, 1, 1, 1, 1, 1, 1, 1 };
        cpu_physical_memory_read(pa, w, sizeof w);
        for (int i = 0; i < 8; i++) {
            if (w[i]) {
                return;              /* not the zeroed artifact */
            }
        }
    } else {
        return;                      /* a live registration — hands off */
    }
    cpu_physical_memory_write(0x0867EED0, &(uint32_t){ 0 }, 4);
    mmcs_l74s4_done = 1;
    fprintf(stderr, "MMCS-L74S4: t=%" PRId64 "ms set-84 slot stock-cleared "
            "([0x8867eed0] := 0, was %08x the zeroed byte-reversed block; "
            "the dispatch's own null path returns 0 — the stock dead-server "
            "outcome, no more 0x234 faults)\n",
            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), slot);
}
static uint32_t mmcs_l59_cadence_ms;
static uint32_t mmcs_l59_pulses;
static uint32_t mmcs_l56_cadence_ms;
static uint32_t mmcs_l56_max_deliv;
static uint32_t mmcs_l56_total;
static uint32_t mmcs_l56_key;
static uint32_t mmcs_l56_stable;
static int mmcs_tick_live;    /* first mmcs_tick_deliver ran (post_load
                                * re-arms the chain only when set) */
static int mmcs_snap_restored; /* post_load marker: the stock tmu012 device
                                * carries no vmstate (S163), so TSTR reads
                                * 0 after a restore even when the fresh
                                * boot programmed it — the L43 TSTR
                                * sub-gate skips on restores (logged) */

/* MMCS fork (L38): MMCS_L38TIMER — the OAL timer-chain fn1 seed (the
 * S179 mechanism-(b) lane, decoded 2026-11-21).
 *
 * DECODE (this lane, live + static, with the extu.b correction): the
 * OAL dispatch thunks (0x908084b4 etc.) compute their slot as
 * `mov #-72/-76/-68,r3; extu.b r3,r3` — extu.b ZERO-extends, so the
 * slots are at [table+0xB8]/[+0xB4]/[+0xBC] (NOT the -0x48/-0x4c/
 * -0x44 the L37-era negative reading assumed; those cells are the
 * ROM template's 0x1010101 filler and the thunk never reads them).
 * The vtable RAM ([0x88602bec] -> 0x8867aa08) is the copy of the ROM
 * template at 0x90da9d0c, which SHIPS: fn1 [0x8867aac0] = fn2a
 * [0x8867aab4-slot table+0xB4] = 0x9082e598 (a default NOT-IMPLEMENTED
 * stub that returns benignly), fn1b [table+0xBC] = 0x908419f0 (a real
 * shipped fn), the tick core's time cells [table+0xC8] (CurMSec-class)
 * and [table+0xC4] (resched-time) = 0. On HW the OAL init rebinds fn1/
 * fn2a to the real timer handlers; under emulation the rebinding never
 * runs, so the timer-ISR entry 0x90809d78 calls the NO-OP stub every
 * tick (exec-window proven: the full ISR path runs — entry -> fn1
 * thunk -> 0x9082e598 -> timer-fn2 0x90808478 -> fn2-tail 0x90807e54
 * -> rts — but no time cell ever moves; the L37 "erased slots" premise
 * re-read: the slots are BOUND to the shipped default stub).
 *
 * The SEED: the vendor tick core 0x90808980 is the in-image function
 * matching the fn1 protocol exactly (no args; clears the TCR UNIE-class
 * bit at 0xffd80010; [table+0xC8] += [0x88602c60+0x14]; the 64-bit
 * counter at [0x88602c60+0x20/0x24] += [0x88602c60+0x18]; returns
 * [table+0xC8] >= [table+0xC4] — the resched-consider boolean). MMCS_
 * L38TIMER=1 binds it into the fn1 slot (once, idempotent; only when
 * the slot still holds the shipped default). fn2a stays the default
 * stub (absorbed) and fn1b keeps its shipped value. Default OFF. */
static void mmcs_l38timer_seed(void)
{
    static int done;
    if (done || !getenv("MMCS_L38TIMER")) {
        return;
    }
    uint32_t tab = 0;
    cpu_physical_memory_read(0x08602BEC, &tab, 4);
    if (tab != 0x8867AA08) {
        return;                       /* table not bound yet */
    }
    uint32_t fn1 = 0;
    cpu_physical_memory_read(0x0867AAC0, &fn1, 4);
    if (fn1 != 0x9082E598 && fn1 != 0x1010101 && fn1 != 0) {
        done = 1;                     /* someone bound it for real */
        return;
    }
    cpu_physical_memory_write(0x0867AAC0,
                              &(uint32_t){ 0x90808980 }, 4);
    done = 1;
    fprintf(stderr, "MMCS-L38TIMER: t=%" PRId64 "ms OAL fn1 slot bound "
            "(0x%08x -> 90808980 the vendor tick core)\n",
            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), fn1);
}

/* MMCS fork (L39/S181): MMCS_L39TBIND — the fn2a/fn1b timer-slot
 * binding EXPERIMENT (mechanism-(b) lane). The decode this lane: the
 * two remaining OAL dispatch slots are fn2a [table+0xB4] (called by
 * timer-fn2 0x90808478 with r4 = &{fn1's resched-consider return, 0,
 * old [0x8860200c]} — the counter-delta feed; expected to update the
 * change-detect cells [0x8860200c]/[0x88602010]) and fn1b [table+0xBC]
 * (fired by the fn2-tail 0x90807e54's change-detect via the thunk
 * 0x908084c8). The SHIPPED table holds the no-op default 0x9082e598
 * (fn2a) and 0x908419f0 (fn1b); the L37-dead-lane candidates
 * 0x90841fd0/0x90842038 (the table+0xA8/+0xAC neighbors) are x10000
 * 64-bit time converters whose (r4=in, r5=out64) protocol does NOT
 * match fn2a's 3-dword-ctx shape — the live A/B here records the
 * verdict either way. The resched-consider itself ([table+0xC8] >=
 * [table+0xC4], fn1's return) is fed by the SCHEDULER's quantum arming
 * site 0x9082760a ([table+0xC4] = r9 + a notify method through the
 * [0x8867f03c] scheduler vtable), NOT by these slots.
 * Env: MMCS_L39TBIND="b4=HEX,bc=HEX" (either optional), default off;
 * binds once at the L38TIMER cadence, only while a slot still holds
 * its shipped default. */
static void mmcs_l39tbind_seed(void)
{
    static int done;
    const char *spec = getenv("MMCS_L39TBIND");
    if (done || !spec || !*spec) {
        return;
    }
    uint32_t tab = 0;
    cpu_physical_memory_read(0x08602BEC, &tab, 4);
    if (tab != 0x8867AA08) {
        return;
    }
    char want[16] = { 0 };
    for (unsigned slot = 0; slot < 2; slot++) {
        const char *key = slot ? "bc=" : "b4=";
        const char *p = strstr(spec, key);
        if (!p) {
            continue;
        }
        p += 3;
        unsigned n = 0;
        while (n < 15 && p[n] && p[n] != ',' && p[n] != ' ') {
            want[n] = p[n];
            n++;
        }
        want[n] = 0;
        uint32_t val = strtoul(want, NULL, 16);
        uint32_t pa = slot ? 0x0867AAC4 : 0x0867AABC;
        uint32_t cur = 0;
        cpu_physical_memory_read(pa, &cur, 4);
        uint32_t dflt = slot ? 0x908419F0 : 0x9082E598;
        if (cur != dflt && cur != 0x1010101 && cur != 0) {
            continue;                 /* someone bound it for real */
        }
        cpu_physical_memory_write(pa, &val, 4);
        fprintf(stderr, "MMCS-L39TBIND: t=%" PRId64 "ms OAL %s slot "
                "bound (0x%08x -> 0x%08x)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), slot ? "fn1b" : "fn2a",
                cur, val);
    }
    done = 1;
}

/* MMCS fork (L42): MMCS_L42KILL — the impossible-user-forward spin
 * kill continuation (S187). DECODE (live, exec+int windows + park
 * walks, this lane): after the L41 told-waiter wait-return rewrite
 * completes the kernel launcher's stock continuation (close(FSReady
 * hEvent) -> 0x9083dff8 -> pSignalStarted(0) via [0x8867ed24]=
 * c00309a0 -> filesys SignalStarted c00badf0 -> the signaler chain
 * -> the handle-close walk -> close([0x8867aa00]) -> 0x9084887c ->
 * the reschedule park at the OAL idle), the LATE death-tell (the
 * S131 marshal 0x90825694, pending on the kstack since the t~14s
 * death cascade — the same never-consumed block the L41 decode
 * found clobbering the wait frame) fires and REWRITES the
 * launcher's saved ctx to a USER-mode forward: ctx+0xb0 :=
 * 0x400080f0 (the marshalled user exception record pointer in slot
 * 0; a stock user-thread SP cell reads the 0x2xxxx low identity
 * window, never 0x4xxxxxxx), ctx+0xb4 := 0. The switcher then tries
 * to return this KERNEL thread to user mode: the PSL-return
 * trampoline 0x90822d80 walks the current (kernel-space) page
 * tables for the user VA (level loads at 0x90822dbe / the walker
 * helper 0x9082ee98 at 0x9082eed0 / the pager's PTE write at
 * 0x90823cbc); the resolution can never succeed under the kernel
 * address space, and the retry loop spins at 0x90822dbe with
 * SR.BL set (0x70008001) — the load never retires (QEMU's
 * BL early-return in do_interrupt re-requests the reset and leaves
 * pc unchanged: "Stopped execution of TB chain before [90822dbe]"
 * x515K in -d exec), ticks stop being serviced, the daemon
 * movement signatures freeze (the L26/L37 daemons park on false
 * quiet), and the machine burns on the spin. An exception-boundary
 * hook CANNOT see this class (the deep-spin faults never deliver;
 * the pre-rewrite formation faults don't yet carry the planted
 * ctx) — the intercept must be the host-side pc sample. On HW a
 * kernel thread NEVER carries a user-mode forward — unreachable
 * vendor state — and the vendor's own semantics for this thread at
 * this point are its own function tail: the launcher fn 0x9083e1ec
 * ends `jsr 0x9083be50; mov #0,r4` (KillThread(0), the temp
 * supervisor's stock self-kill — the same tail the L41 tape
 * watched the thread executing toward when the tell hijacked it).
 * FIX (the L39KILL dispatch shape, driven from the host tick
 * daemon via run_on_cpu — the S161 handoff pattern): sample the
 * live pc every cadence; 3 consecutive samples inside the
 * trampoline/walker windows WHILE pCurTh carries the impossible
 * user-forward shape (alive RUNNING state16, ctx+0xb0 in the user
 * window) = the spin class -> rewrite the live cpu: SR.BL/RB
 * cleared (the kill continuation runs at the normal kernel level,
 * bank 0), r15 := P2 0xBF00FF00 (the kill-stack RAM page at phys
 * 0x1F000000, mapped every boot), r4 := 0, pc := 0x9083be50 —
 * the vendor's own KillThread, so the launcher's death completes
 * natively (the death is COMPLETED, not suppressed). Hard cap 4
 * dispatches. The sustain counter is ephemeral (no savestate row:
 * a restore re-detects the spin within 3 cadences; the default
 * boot never arms this knob). Env MMCS_L42KILL, default off;
 * MMCS_L42KILL_MS cadence (default 500). */
static int mmcs_l42_armed;
static uint32_t mmcs_l42_cadence_ms = 500;
static int mmcs_l42_sustain;
static int mmcs_l42_dispatched;
static uint64_t mmcs_tick_l42;

static void mmcs_l42kill_work(CPUState *cs, run_on_cpu_data data)
{
    SuperHCPU *cpu = SUPERH_CPU(cs);
    CPUSH4State *env = &cpu->env;
    uint32_t pc = env->pc;

    if (!((pc >= 0x90822d80u && pc < 0x90822e00u)
          || (pc >= 0x9082ee98u && pc < 0x9082ef10u)
          || (pc >= 0x90823cb0u && pc < 0x90823d30u))) {
        mmcs_l42_sustain = 0;           /* not the spin windows */
        return;
    }
    uint32_t pcur = 0, st = 0, ctxa = 0, ctxb = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    if (pcur < 0x90680000u || pcur >= 0x90700000u) {
        return;
    }
    cpu_physical_memory_read((pcur & 0x1fffffffu) + 0xc, &st, 4);
    /* BOTH ctx save points: the tell plants its user forward at the
     * +0x90/+0x94 slot (live-proven: 0x400080f0/0 while the +0xb0/
     * +0xb4 slot holds the real kernel ctx); the +0xb0 read stays as
     * the secondary class witness */
    cpu_physical_memory_read((pcur & 0x1fffffffu) + 0x90, &ctxa, 4);
    cpu_physical_memory_read((pcur & 0x1fffffffu) + 0xb0, &ctxb, 4);
    bool user_fwd = (ctxa >= 0x40000000u && ctxa < 0x48000000u)
                    || (ctxb >= 0x40000000u && ctxb < 0x48000000u);
    if ((st & 3) != 0 || (st & 8) != 0 || !user_fwd) {
        return;                         /* in-window but not the shape
                                         * yet — neither resets nor
                                         * advances the sustain */
    }
    if (++mmcs_l42_sustain < 3 || mmcs_l42_dispatched >= 4) {
        return;
    }
    mmcs_l42_dispatched++;
    fprintf(stderr, "MMCS-L42KILL: t=%" PRId64 "ms impossible-user-forward "
            "spin (pc=%08x pCurTh=%08x st16=%08x ctx +0x90/+0xb0=%08x/%08x) -> vendor "
            "kill continuation 9083be50 (%d)\n",
            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), pc, pcur, st, ctxa, ctxb,
            mmcs_l42_dispatched);
    env->sr &= ~((1u << SR_BL) | (1u << SR_RB));
    env->gregs[15] = 0xBF00FF00u;
    env->gregs[4] = 0;
    env->pc = 0x9083BE50u;
}

static void mmcs_l42_scan(void)
{
    run_on_cpu(first_cpu, mmcs_l42kill_work, RUN_ON_CPU_NULL);
}

/* MMCS fork (L43): MMCS_TICK_EVT — select the host tick's event code
 * (the timer-chain repair spec 2026-11-21, Option (a) RANK 1). The
 * stock MMCS_TICK delivery emits EVT 0x440 (TUNI2), whose dispatch
 * slot [0x8867a088] -> ISR 0x90809d78 walks fn slots that ship bound
 * to the rts-stub 0x9082e598 — a dormant path on real HW too (TMU2
 * never started, TSTR=0x03). The vendor 1ms system tick is TMU0
 * underflow (EVT 0x400 = TUNI0), dispatched at [0x8867a080] ->
 * 0x90808980, the ONLY in-image writer of CurMSec [P+0xC8] (P =
 * [0x8867aa04] = 0x8867aa08). MMCS_TICK_EVT=400 selects that
 * delivery: 100% vendor code thereafter (CurMSec advance, the
 * expiry-return resched-consider -> bResched, drain1, sleeper wakes,
 * the quantum re-arm). Default/unset = 0x440 = byte-identical to the
 * pre-L43 delivery.
 * Arm-time sanity gates (READ-ONLY guest checks, run ONCE at the
 * first delivery after the tick delay — the boot must have settled;
 * on any failure REFUSE-TO-ARM + warn and fall back to the stock
 * 0x440 delivery; NEVER write guest state):
 *   [0x8867aa04] == 0x8867aa08 && [0x88602bec] == 0x8867aa08 (P bound)
 *   [0x8867a080] == 0x90808980  (the TUNI0 ISR installed)
 *   [0x88602c74] == 1           (msPerTick; 0 => the ISR silently
 *                                no-ops — logged loudly per the spec)
 *   TSTR[0xFFD80004] bit0       (TMU0 started; S133 observed 0x03)
 * HARD HAZARD (spec §5 #6): nothing may ever feed [0x8860200c] (the
 * fn2-counter) — that fires fn1b 0x908419f0 = trapa#1 + debug-print
 * + self-spin FATAL. This knob writes NO guest state at all. */
static uint32_t mmcs_tick_evt(void)
{
    static uint32_t code;
    static int init;

    if (!init) {
        const char *v = getenv("MMCS_TICK_EVT");

        init = 1;
        code = 0x440;
        if (v && *v && strcmp(v, "0")) {
            uint32_t sel = strtoul(v, NULL, 16);
            uint32_t pk = 0, po = 0, slot = 0, mspertick = 0, tstr = 0;
            int tstr_ok, tstr_skip = mmcs_snap_restored;

            cpu_physical_memory_read(0x0867AA04, &pk, 4);
            cpu_physical_memory_read(0x08602BEC, &po, 4);
            cpu_physical_memory_read(0x0867A080, &slot, 4);
            cpu_physical_memory_read(0x08602C74, &mspertick, 4);
            cpu_physical_memory_read(0xFFD80004, &tstr, 4);
            tstr_ok = (tstr & 1) || tstr_skip;
            if (sel == 0x440) {
                /* explicit stock selection — no gates, no change */
            } else if (pk == 0x8867AA08 && po == 0x8867AA08
                       && slot == 0x90808980 && mspertick == 1
                       && tstr_ok) {
                code = sel;
                fprintf(stderr, "MMCS-TICK_EVT: t=%" PRId64 "ms gates PASS "
                        "(P=%08x/%08x slot[8867a080]=%08x msPerTick=%u "
                        "TSTR=%02x%s) — delivering evt %03x (the vendor "
                        "TUNI0 tick path)\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL),
                        pk, po, slot, mspertick, tstr & 0xff,
                        tstr_skip ? " (gate skipped: restore — tmu012 has "
                        "no vmstate, S163)" : "", code);
            } else {
                fprintf(stderr, "MMCS-TICK_EVT: t=%" PRId64 "ms REFUSED to "
                        "arm evt %03x (P=%08x/%08x slot[8867a080]=%08x "
                        "msPerTick=%u%s TSTR=%02x%s) — falling back to the "
                        "stock 0x440 delivery (read-only gates, no guest "
                        "writes)\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), sel,
                        pk, po, slot, mspertick,
                        mspertick == 0 ? " (SILENT NO-OP RISK)" : "",
                        tstr & 0xff, tstr_ok ? "" : " (TMU0 not started)");
            }
        }
    }
    return code;
}

static void mmcs_tick_deliver(void *opaque)
{
    static uint64_t ntick;
    bool hdevt = mmcs_hdevt_pending > 0;
    bool l16 = false;
    mmcs_tick_live = 1;
    mmcs_l38timer_seed();
    mmcs_l39tbind_seed();
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
        if (mmcs_l19_armed && ++mmcs_tick_l19 >= mmcs_l19_cadence_ms) {
            mmcs_tick_l19 = 0;
            mmcs_l19_scan();
        }
        /* L26: the DoWait-orphan wake daemon (same cadence class) */
        if (mmcs_l26_armed && ++mmcs_tick_l26 >= mmcs_l26_cadence_ms) {
            mmcs_tick_l26 = 0;
            mmcs_l26_scan();
        }
        /* L32: the create-completion event daemon (same class) */
        if (mmcs_l32_armed && ++mmcs_tick_l32 >= mmcs_l32_cadence_ms) {
            mmcs_tick_l32 = 0;
            mmcs_l32_scan();
        }
        /* L46: the create-interlock SPLIT repair daemon (same class;
         * one-shot — see mmcs_l46_scan) */
        if (mmcs_l46_armed && ++mmcs_tick_l46 >= mmcs_l46_cadence_ms) {
            mmcs_tick_l46 = 0;
            mmcs_l46_scan();
        }
        /* L47: the true-base wake-eval ctx repair (same class;
         * repeating, delivery-capped — see mmcs_l47_scan) */
        if (mmcs_l47_armed && ++mmcs_tick_l47 >= mmcs_l47_cadence_ms) {
            mmcs_tick_l47 = 0;
            mmcs_l47_scan();
        }
        /* L50: the create-retry exit tape (READ-ONLY; rides the tick
         * chain like the scans but never writes guest memory) */
        if (mmcs_l50_armed && ++mmcs_tick_l50 >= mmcs_l50_cadence_ms) {
            mmcs_tick_l50 = 0;
            mmcs_l50_dbg();
        }
        /* L36: the post-exit requeue daemon (same class) */
        if (mmcs_l36_armed && ++mmcs_tick_l36 >= mmcs_l36_cadence_ms) {
            mmcs_tick_l36 = 0;
            mmcs_l36_scan();
        }
        /* L37: the KCall-exit lost-preempt class daemon (same class) */
        if (mmcs_l37_armed && ++mmcs_tick_l37 >= mmcs_l37_cadence_ms) {
            mmcs_tick_l37 = 0;
            mmcs_l37_scan();
        }
        /* L52: the post-completion resched hand-off (same class) */
        if (mmcs_l52_armed && ++mmcs_tick_l52 >= mmcs_l52_cadence_ms) {
            mmcs_tick_l52 = 0;
            mmcs_l52_scan();
        }
        /* L53: the completion-helper spin chain-end restore (same
         * class; a pure one-word bookkeeping write — no stub, no
         * slot) */
        if (mmcs_l53_armed && ++mmcs_tick_l53 >= mmcs_l53_cadence_ms) {
            mmcs_tick_l53 = 0;
            mmcs_l53_scan();
        }
        /* L54: the stale-pCurTh re-park wake (the S202 class — the
         * L47 satisfy for tva==pcur through the v9 wake stub) */
        if (mmcs_l54_armed && ++mmcs_tick_l54 >= mmcs_l54_cadence_ms) {
            mmcs_tick_l54 = 0;
            mmcs_l54_scan();
        }
        /* L55: the WAIT-ALL chained dual-entry multi-satisfy (the
         * S203 class — the internal satisfaction check's honest
         * exit through the stock multi-completion shape) */
        if (mmcs_l55_armed && ++mmcs_tick_l55 >= mmcs_l55_cadence_ms) {
            mmcs_tick_l55 = 0;
            mmcs_l55_scan();
        }
        /* L56: the post-return sticky-orphan pulse (the S205 class
         * — the sibling waiter's own completion) */
        if (mmcs_l56_armed && ++mmcs_tick_l56 >= mmcs_l56_cadence_ms) {
            mmcs_tick_l56 = 0;
            mmcs_l56_scan();
        }
        /* L58: the residual-sticky cleanup (the S207 fix — the
         * falsifier write promoted to maintenance; one word, no
         * stub, no slot) */
        if (mmcs_l58_armed && ++mmcs_tick_l58 >= mmcs_l58_cadence_ms) {
            mmcs_tick_l58 = 0;
            mmcs_l58_scan();
        }
        /* L59: the completion-forward pulse (S210 — going forwards) */
        if (mmcs_l59_armed && ++mmcs_tick_l59 >= mmcs_l59_cadence_ms) {
            mmcs_tick_l59 = 0;
            mmcs_l59_scan();
        }
        /* L62: the dead-owner crit release (S213 — wake-only the
         * standing-completed BLOCKED crit waiter) */
        if (mmcs_l62_armed && ++mmcs_tick_l62 >= mmcs_l62_cadence_ms) {
            mmcs_tick_l62 = 0;
            mmcs_l62_scan();
        }
        /* L64: the Pacific-event aftermath wake (S214 — the
         * generalized standing-completed lane, EVNT objects; runs
         * AFTER L56/L62 per the tick-order contract) */
        if (mmcs_l64_armed && ++mmcs_tick_l64 >= mmcs_l64_cadence_ms) {
            mmcs_tick_l64 = 0;
            mmcs_l64_scan();
        }
        /* L72: the post-park completion hand-off (S223 — the
         * consumed-completion stale-pCurTh wake; runs after the
         * L64 family per the tick-order contract) */
        if (mmcs_l72_armed && ++mmcs_tick_l72 >= mmcs_l72_cadence_ms) {
            mmcs_tick_l72 = 0;
            mmcs_l72_scan();
        }
        /* L75: the post-kill orphan hand-off (S226 — restores the L72
         * gate (pCurTh == the orphan) behind a killed zombie; runs right
         * AFTER the L72 scan so the next L72 cadence delivers) */
        if (mmcs_l75ho_armed && ++mmcs_tick_l75ho >= mmcs_l75ho_cadence_ms) {
            mmcs_tick_l75ho = 0;
            mmcs_l75ho_scan();
        }
        /* L73: the churn livelock release (S224 — the stale sleep-node
         * self-link unlink; runs after the L72 hand-off per the
         * tick-order contract: the artifact survives the resume) */
        if (mmcs_l73_armed && ++mmcs_tick_l73 >= mmcs_l73_cadence_ms) {
            mmcs_tick_l73 = 0;
            mmcs_l73_scan();
        }
        /* L74: the standing expiry reap (S225 — the promoted L73EV
         * unlink, uncapped; runs after the L73 family per the
         * tick-order contract) */
        if (mmcs_l74_armed && ++mmcs_tick_l74 >= mmcs_l74_cadence_ms) {
            mmcs_tick_l74 = 0;
            mmcs_l74_scan();
        }
        /* L74CR: the reentrant API-lock deadlock break (S225 item
         * (ii); after the reap + the L62/L64 channel users per the
         * tick-order contract) */
        if (mmcs_l74cr_armed && ++mmcs_tick_l74cr >= mmcs_l74cr_cadence_ms) {
            mmcs_tick_l74cr = 0;
            mmcs_l74cr_scan();
        }
        /* L74S4: the set-84 slot stock-clear (S225 item (iii), the
         * one-shot dead-server repair; rides the L74CR cadence when
         * both are armed) */
        if (mmcs_l74s4_armed && ++mmcs_tick_l74s4 >= 1000) {
            mmcs_tick_l74s4 = 0;
            mmcs_l74s4_clear();
        }
        /* L76: the equal-priority starvation re-arm (S227 — the cNest
         * one-byte delivery; after the L74 reap family so the walk's
         * self-link is already unlinked when the gate is checked) */
        if (mmcs_l76_armed && ++mmcs_tick_l76 >= mmcs_l76_cadence_ms) {
            mmcs_tick_l76 = 0;
            mmcs_l76_scan();
        }
        /* L77: the kill-path API-lock cleanup release (S228 — the
         * dying thread's [th+0x164] ownership clear; after L76 so the
         * world settles its re-arm before the death completes) */
        if (mmcs_l77_armed && ++mmcs_tick_l77 >= mmcs_l77_cadence_ms) {
            mmcs_tick_l77 = 0;
            mmcs_l77_scan();
        }
        /* L78: the lost-MakeRun requeue (S229 — the stock empty-queue
         * head-path words for a RUNNABLE-marked off-queue thread; after
         * the L77 death so the post-death world is the one it serves) */
        if (mmcs_l78_armed && ++mmcs_tick_l78 >= mmcs_l78_cadence_ms) {
            mmcs_tick_l78 = 0;
            mmcs_l78_scan();
        }
        /* L79: the termination walker's dead-owner loop-exit (S230 —
         * the KData wait-node owner word + the requeue; after the L78
         * family so the parked-pair world is the one it serves) */
        if (mmcs_l79_armed && ++mmcs_tick_l79 >= mmcs_l79_cadence_ms) {
            mmcs_tick_l79 = 0;
            mmcs_l79_scan();
        }
        /* L42: the impossible-user-forward spin kill (host pc sample;
         * the deep-spin faults never reach the exception boundary) */
        if (mmcs_l42_armed && ++mmcs_tick_l42 >= mmcs_l42_cadence_ms) {
            mmcs_tick_l42 = 0;
            mmcs_l42_scan();
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
            /* L43: MMCS_TICK_EVT selects the delivered event code
             * (0x440 stock / 0x400 = the vendor TUNI0 tick ISR path;
             * arm-time gated read-only, see mmcs_tick_evt) */
            mmcs_inject_evt(mmcs_tick_evt());
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

/* savestate lane: per-daemon movement-signature state, hoisted from
 * the scan functions' function-local statics so the snapshot can
 * stream them (a restored daemon that re-arms from have_prev=0 can
 * deliver a wake the no-snapshot run would not — the quiet-park
 * discipline must survive the snapshot). */
static uint8_t mmcs_l19_sig[MMCS_L19_NSIG];
static int mmcs_l19_sig_have;
static uint32_t mmcs_l19_quiet, mmcs_l19_nopick;
static uint8_t mmcs_l26_sig[MMCS_L19_NSIG];
static int mmcs_l26_sig_have;
static uint32_t mmcs_l26_quiet;
static uint8_t mmcs_l32_sig[MMCS_L19_NSIG];
static int mmcs_l32_sig_have;
static uint32_t mmcs_l32_quiet;

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
 * the v7 completion for the first: MakeRun(thread) + the resched
 * protocol stores + pick=thread + r14=pCurTh + the vendor switcher.
 * NO event-set: the stack wait structs are not EVNT-class (layout
 * unknown — the walker would corrupt fields); the woken thread re-
 * checks its own wait condition (the DoWait loop reads state16, finds
 * 0x4000 clear, exits the loop into its post-wait path: the satisfied
 * re-evaluation at 0x90837d22 re-issues BlockWithHelper unless the
 * wait structs now satisfy — MakeRun itself is vendor-faithful for a
 * BLOCKED target: 0x90825ee4 guards only the [th+0xE] suspend byte,
 * then state16 = (state16 & ~3) | 1 and the pRunnable-band enqueue).
 * In-stub guard: only MakeRun when the target is STILL BLOCKED(2) —
 * chained re-deliveries no-op; a thread that re-enters the wait is
 * re-served next cadence. MAIN's wait (wait-obj 0) is EXCLUDED (the
 * FSReady gate must be earned). Bounds: one delivery per cadence, 60
 * quiet scans park, movement re-arms (the L19 discipline), hard cap
 * MMCS_L26EV_MAX (default 64). Stub at KILLSTK 0xBF00E200 (idx 2,
 * evt 0x280 — free when MMCS_L16EV is not armed), slot stays wired
 * (daemon mode). Needs MMCS_KILLSTK + MMCS_TICK (the delivery rides
 * the tick chain).
 *
 * L38 (S179): the delivery path is FIXED — two live-caught bugs (the
 * L36 session's marker readback + this lane's disasm). (1) The .Lt
 * PATCH-ORDER bug: the daemon patched .Lt BEFORE installing the stub
 * array, so the install silently restored the default .Lt
 * (0x906dd000) and every delivery acted on the WRONG thread. Now
 * install first, then patch the pool (.Lt +0x6c thread VA, .Lm +0x68
 * marker-cell VA) — the L36/L37 discipline. (2) The GUARD INVERSION:
 * the v6 stub's byte decode is `and #3; cmp/eq #2; BF mk; BRA Lret`
 * — it skipped MakeRun exactly when the target was STILL BLOCKED(2)
 * (the documented intent inverted in the builder's BF/BRA pair; the
 * stale comment said the opposite). The v7 stub guard is
 * `cmp/eq #2; BT mk` — accept BLOCKED(2), skip everything else. The
 * v7 stub also carries the L16/L36/L37 stage markers (1-5 at
 * [.Lm]=stub+0xF0) for the marker-readback delivery proof. */
static uint8_t mmcs_l26_stub[] = {
    0x22, 0x4f, 0xe6, 0x2f, 0x19, 0xd4, 0x43, 0x50,  /* +00 */
    0x03, 0xc9, 0x02, 0x88, 0x02, 0x89, 0x25, 0xa0,  /* +08 accept BLOCKED(2) */
    0x09, 0x00, 0x01, 0xe2, 0x14, 0xd2, 0x12, 0x22,  /* +10 marker 1 */
    0x15, 0xd3, 0x0b, 0x43, 0x09, 0x00, 0x02, 0xe2,  /* +18 MakeRun */
    0x11, 0xd2, 0x12, 0x22, 0x01, 0xe1, 0x09, 0x00,  /* +20 marker 2, resched byte */
    0x12, 0xd2, 0x12, 0x22, 0x01, 0xe1, 0x09, 0x00,  /* +28 drain2 word */
    0x11, 0xd2, 0x12, 0x22, 0x03, 0xe2, 0x09, 0x00,  /* +30 marker 3 */
    0x0b, 0xd2, 0x12, 0x22, 0x0b, 0xd4, 0x09, 0x00,  /* +38 .Lt reload */
    0x0e, 0xd2, 0x42, 0x22, 0x0e, 0xd2, 0x20, 0x5e,  /* +40 pick, r14=pCurTh */
    0x04, 0xe2, 0x09, 0x00, 0x06, 0xd2, 0x12, 0x22,  /* +48 marker 4 */
    0x0c, 0xd3, 0x0b, 0x43, 0x09, 0x00, 0x05, 0xe2,  /* +50 switcher */
    0x03, 0xd2, 0x12, 0x22, 0xf6, 0x6e, 0x26, 0x4f,  /* +58 marker 5, epilogue */
    0x00, 0xe0, 0x0b, 0x00, 0x09, 0x00, 0x09, 0x00,  /* +60 */
    /* pool */
    0x00, 0x00, 0x00, 0x00,   /* +0x68 .Lm: marker cell VA (patched) */
    0x00, 0xd0, 0x6d, 0x90,   /* +0x6c .Lt: thread VA (patched) */
    0xe4, 0x5e, 0x82, 0x90,   /* .Lmk: 0x90825ee4 MakeRun */
    0x84, 0x98, 0x67, 0x88,   /* .Lf: 0x88679884 resched byte */
    0x88, 0x98, 0x67, 0x88,   /* .Lf2: 0x88679888 drain2 word */
    0xa4, 0xef, 0x67, 0x88,   /* .Lpick: 0x8867efa4 */
    0x94, 0x98, 0x67, 0x88,   /* .Lpcur: 0x88679894 */
    0x68, 0x2b, 0x82, 0x90,   /* .Lsw: 0x90822b68 switcher */
};
#define MMCS_L26_STUB_VA   0xBF00E200
#define MMCS_L26_SLOT_PA   0x0867A050   /* evt 0x280, idx 2 */
#define MMCS_L26_QUIET_PARK 60
static uint32_t mmcs_l26_total;

static void mmcs_l26_scan(void)
{
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
    bool moved = mmcs_l26_sig_have
                 && memcmp(sig, mmcs_l26_sig, MMCS_L19_NSIG) != 0;
    memcpy(mmcs_l26_sig, sig, MMCS_L19_NSIG);
    mmcs_l26_sig_have = 1;
    if (moved) {
        mmcs_l26_quiet = 0;
        if (!mmcs_l26_armed) {
            mmcs_l26_armed = 1;
            fprintf(stderr, "MMCS-L26: t=%" PRId64 "ms movement while "
                    "parked - re-armed (%u deliveries used)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l26_total);
        }
    } else if (mmcs_l26_armed && ++mmcs_l26_quiet >= MMCS_L26_QUIET_PARK) {
        fprintf(stderr, "MMCS-L26: t=%" PRId64 "ms %u quiet scans - "
                "daemon parked at %u deliveries\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l26_quiet,
                mmcs_l26_total);
        mmcs_l26_armed = 0;
        mmcs_l26_quiet = 0;
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
        /* MMCS fork (L40): MMCS_L26M — the marked-entry guard (the
         * WEDGE decode, 2026-11-21). The DoWait waiter's wait entry
         * sits at wait-obj+0x10 (live: 906feb58's d006fd6c wobj ->
         * the d006fd7c entry {.., event@+0x14, type@+0x18, pTh@+0x1c});
         * the kernel's wait dispatcher (0x90837ab0) keys its per-type
         * path on the entry's type BYTE at +0x18: type 4/13 = the real
         * EVNT evaluation, type 1/0xff = the marked/teardown class ->
         * the unlink-and-retry path. Waking a thread whose entry is
         * MARKED (0xff) starts the kernel evaluation spin (the L40
         * WEDGE: the woken thread loops forever between the outer wait
         * face (0x908378ce..da, `bf` on the submit's nonzero return),
         * the KCall trampoline's defer check (0x90823112: cNest!=1 &&
         * dwKCRes!=1 -> set bResched, return, retry) and the unlink
         * helper 0x90827930 / the walk helper 0x90827964 — live
         * pc-census 15/24 samples at 0x90827930, cells frozen, the
         * daemons' movement signature FALSE-QUIET). Live-tested: the
         * cNest seed, the dwKCRes seed and the type-repair each
         * advance the spin exactly ONE layer then it re-forms — the
         * completion half needs the live scheduler. The guard skips
         * the marked class (let it stay blocked) so the park stays
         * clean instead of burning. Env MMCS_L26M, default off. */
        if (mmcs_l26m_armed) {
            uint32_t pa_t = mmcs_l32_stack_pa(wobj + 0x28);
            uint8_t tb = 0xff;
            if (pa_t) {
                cpu_physical_memory_read(pa_t, &tb, 1);
            }
            if (tb == 0xff) {
                fprintf(stderr, "MMCS-L26M: t=%" PRId64 "ms skip thread "
                        "%08x (wait-obj %08x) - MARKED entry (the wedge "
                        "class)\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, wobj);
                continue;
            }
        }
        /* MMCS fork (L49/S197): the create-walker class exclusion —
         * the co-delivery kill guard. DECODE (live, the -d int register
         * tape at the park-loop poll 0x90837cfa `mov.w @(12,r8),r0` +
         * the L44DBG kslot-raise record dumps + the L26EV-off A/B,
         * 2026-11-22): the L48 "walker dies on dead-process memory"
         * reading is REFUTED — the walker's death (exp=180, spc in
         * c00361xx) is OUR OWN co-timed L26 stub delivery poisoning
         * the resumed register file: both daemons fire at the same
         * 2000ms cadence boundary; the L47 evt-0x220 wake lands first
         * (the resumed r8 = the parked TCB cell 906cb240 -> the poll
         * reads the state word -> benign, the cycle completes), then
         * the L26 evt-0x280 stub hits the re-parked walker and its
         * delivery-context registers pass through the switcher into
         * the resumed frame (int tape: r17=bf00e200 the L26 stub
         * page, r22=0x280, r8=0x289d a daemon-internal value) — the
         * poll [r8+12] = [0x28a9] on NO page -> unresolvable 0x040 ->
         * the c0000005 raise -> the vendor kill grave. A/B: with the
         * L26 delivery removed the walker SURVIVES every completion
         * cycle (deliveries 1-3, parked-cycling alive at 40s, no
         * raise, serial 720). Post-L48 the walker's wake is owned by
         * the native evt-0x220 channel (the L32 slot fix made the
         * L47FIX's stub the true carrier); the L26's delivery to the
         * same thread is the pre-L48 carrier leftover — redundant and
         * lethal. GUARD (the L46 LINKED discriminator): when the L47
         * daemon is armed, resolve the candidate's waited object
         * through its own wait-array entry (pTh match) and SKIP when
         * it is the LINKED create-interlock shape (an arena object
         * with a non-zero waiter-list head) — the R1-vs-R3 class
         * disjointness the delivery-decision table already asserts.
         * Default world untouched (the guard is read-only and gated on
         * MMCS_L47FIX arming). */
        if (mmcs_l47_armed) {
            uint32_t obj49 = 0;
            for (uint32_t wi = 0; wi <= 0x80; wi += 4) {
                uint32_t pa1 = mmcs_l32_stack_pa(wobj + wi + 0x14);
                uint32_t w1 = 0;
                if (!pa1) {
                    continue;
                }
                cpu_physical_memory_read(pa1, &w1, 4);
                if (w1 != tva) {
                    continue;
                }
                uint32_t pa2 = mmcs_l32_stack_pa(wobj + wi + 0xC);
                if (pa2) {
                    cpu_physical_memory_read(pa2, &obj49, 4);
                }
                break;
            }
            if (obj49 >= 0x90680000 && obj49 < 0x90780000) {
                uint32_t wlh49 = 0;
                cpu_physical_memory_read(obj49 - 0x80000000 + 8, &wlh49, 4);
                if (wlh49 != 0) {
                    fprintf(stderr, "MMCS-L49: t=%" PRId64 "ms skip thread "
                            "%08x (wait-obj %08x, obj %08x LINKED) - the "
                            "create-interlock class is the L47 channel's "
                            "domain (the co-delivery register poison, "
                            "S197)\n",
                            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva,
                            wobj, obj49);
                    continue;
                }
            }
        }
        /* deliver: install, THEN patch the pool (.Lt +0x6c thread VA,
         * .Lm +0x68 marker-cell VA) and init the marker cell to a
         * known sentinel — the L38 fix (the old patch-then-install
         * order silently restored the default .Lt=0x906dd000 and the
         * v6 guard's inversion then no-op'ed every delivery on the
         * BLOCKED wrong target; live-caught by the L36 marker
         * readback) — the L36/L37 discipline */
        cpu_physical_memory_write(0x1F00E200, mmcs_l26_stub,
                                  sizeof mmcs_l26_stub);
        cpu_physical_memory_write(0x1F00E200 + 0x6c, &tva, 4);
        cpu_physical_memory_write(0x1F00E200 + 0x68,
                                  &(uint32_t){ MMCS_L26_STUB_VA + 0xf0 }, 4);
        cpu_physical_memory_write(0x1F00E2F0,
                                  &(uint32_t){ MMCS_L26_STUB_VA + 0xf0 }, 4);
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
        /* MMCS fork (L45): MMCS_L45DBG — the create-interlock split
         * tape (S191, diagnostic-only, default OFF). At each walker
         * delivery, print the S191 gate cells: (1) the waited event's
         * sig byte (+0x8d) — the walker's object never signals; (2)
         * the state of the two 0x90835f14-class shim threads (the
         * create-interlock signalers; both end in the kill grave
         * st16=0x18, ctx 0x9083c102); (3) the sig byte of the
         * observed psi.he target (the 8Hz create-retry storm's SET
         * landing object, arena-census-stable 0x90690898 in the
         * L45 boots — the SPLIT half the walker never waits on).
         * Pure readback; no guest writes; caps at the L26 delivery
         * cadence (it only fires inside this daemon's delivery). */
        if (getenv("MMCS_L45DBG")) {
            uint32_t evobj = 0, ent2 = 0;
            for (uint32_t wi = 0; wi <= 0x80; wi += 4) {
                uint32_t pa1 = mmcs_l32_stack_pa(wobj + wi + 0x14);
                uint32_t w1 = 0;
                if (!pa1) {
                    continue;
                }
                cpu_physical_memory_read(pa1, &w1, 4);
                if (w1 != tva) {
                    continue;
                }
                uint32_t pa2 = mmcs_l32_stack_pa(wobj + wi + 0xC);
                if (pa2) {
                    cpu_physical_memory_read(pa2, &evobj, 4);
                }
                ent2 = wobj + wi;
                break;
            }
            uint8_t sig45 = 0, sig45b = 0;
            if (evobj >= 0x90680000 && evobj < 0x90780000) {
                cpu_physical_memory_read(evobj - 0x80000000 + 0x8d,
                                         &sig45, 1);
            }
            cpu_physical_memory_read(0x90690898 - 0x80000000 + 0x8d,
                                     &sig45b, 1);
            fprintf(stderr, "MMCS-L45DBG: entry %08x waited-obj %08x "
                    "sig %02x; psi.he-target 90690898 sig %02x; "
                    "shims:", ent2, evobj, sig45, sig45b);
            for (uint32_t stva = 0x906900c0; ; stva = 0x90690c7c) {
                uint32_t s16 = 0, pcw = 0;
                cpu_physical_memory_read(stva - 0x80000000 + 0xc,
                                         &s16, 4);
                cpu_physical_memory_read(stva - 0x80000000 + 0xb4,
                                         &pcw, 4);
                fprintf(stderr, " %08x st16=%08x ctx=%08x",
                        stva, s16, pcw);
                if (stva == 0x90690c7c) {
                    break;
                }
            }
            fprintf(stderr, "\n");
        }
        return;                     /* one per cadence */
    }
}


/* MMCS fork (L32): MMCS_L32EV — the create-completion event daemon.
 *
 * Decoded 2026-11-18 (L32, the S152 frontier): the launch loop is
 * live and CreateProcessW('\shell.exe') runs: the kernel m3
 * (0x9082cbf4) creates the proc + the 64K kstack + the first thread
 * (entry 0x90835f14 = ThreadStart: load via 0x90835540, setup via
 * 0x90835bb0 — the USER startup runs INSIDE this call — then
 * EventModify([pTh+8] handle, SET) at 0x90835fd8 = THE
 * create-completion interlock, then KillThread-class exit), MakeRun
 * (0x9083b1e8, suspend-count path -> the 90825ee4 enqueue) kicks it,
 * and the walker waits INFINITE on the proc+8 manual event
 * (0x90837bcc = WaitForObjects(1, &proc->hEvent, INFINITE), park pc
 * 0x90837cf6, the wait-struct array on the walker's own stack).
 * The child's first thread RUNS (9 user syscalls through the USER
 * coredll) but dies inside the 0x90835bb0 user phase at the startup
 * QPC return: the WIN32 m129 nested slot call (pr=0x908236a8, the
 * PSL trampoline) returns with the USER-mode SSR (the L10 class),
 * the MD-only APIRET recovery runs the trampoline with the USER
 * gregs, it reads its frame off the USER stack, garbage-jumps, and
 * the vendor kill machinery reaps the child (the KILLSTK rescue at
 * pc=0x9083be50 sp=0x10) — BEFORE EventModify ever runs: the
 * create-complete event stays unsignaled and the walker parks
 * forever (the S152 all-blocked park, pick=0).
 *
 * The L32 delivery = the stock guarantee the wait always terminates:
 * scan for a DoWait-parked thread whose kstack return chain carries a
 * kernel CreateProcessW-region pc (the create-walker discriminator —
 * the L26 orphan stack-waiters never carry one; MAIN's wait-obj-0 is
 * excluded by the D0 filter), resolve its waited event from the
 * wait-array entry on its stack ({.., obj @+0xC, prio(w) @+0x10,
 * pTh @+0x14} — the entry whose pTh matches the thread; the event =
 * a small {next, prev, waiter-list@+8} arena header with the waiter
 * entry linked), and when the event sits UNSIGNALED set it
 * ([event+0x8d] |= 1, the EventModify SET state byte) + repair the
 * wait-context linkage ([pTh+0x1F8] = the wait entry, the entry type
 * byte +0x18 = 4 the EVNT class) + wake the waiter with the proven
 * v7 completion stub (the L26 machinery: MakeRun + the resched
 * protocol + pick + the vendor switcher). The D0-stack reads go
 * through the PGOWN/FILEVIEW va->pa tables (P3 stacks, no P1
 * identity). KNOWN GATE (the S153 frontier): the woken walker
 * re-evaluates the wait via the KCall dispatch keyed on the
 * [pTh+0x1F8] wait-context type — the re-block observed with the
 * +0x18=4/entry-link repair means the satisfied-evaluation reads
 * more state (the 0x90828244 dispatch walk) — the delivery
 * machinery itself lands cleanly (bp-proven wake).
 * Bounds: one delivery per cadence, 60 quiet scans park, movement
 * re-arms, hard cap MMCS_L32EV_MAX (default 64). Stub at KILLSTK
 * 0xBF00EC00 (the L19TH idx-0 slot, evt 0x220 — skip when L19TH is
 * armed). Needs MMCS_KILLSTK + MMCS_TICK. */
#define MMCS_L32_STUB_VA   0xBF00EC00
/* MMCS fork (L48): the slot PA repair — the dispatch table read is
 * handler = *(u32*)(0x8867a000 + (evt>>3)) (the L13 decode, proven
 * live: evt 0xAE0 -> 0x8867a15c; the L16EV table below agrees), so evt
 * 0x220's slot is 0x8867a044, NOT 0x8867a030 — the L32-era 0x30 was a
 * transcription slip 0x14 bytes low (the evt-0x180 slot, never
 * dispatched). LIVE-CAUGHT (the L48 session, marker readback): the
 * L26 stub (evt 0x280 -> 0x50, CORRECT) executed (marker 1) while the
 * L32/L46/L47 stub at the wrong slot NEVER did (marker = the planted
 * sentinel) — every apparent L32/L46 "v7 wake" was actually carried
 * by the co-armed L26 daemon's MakeRun, and the L47's f1f8 plant
 * (which makes the walker FAIL the L26 wblk==0 filter) actively
 * blocked the only working wake channel. The wrong-slot guard also
 * explains the L46-era mysteries (deliveries that "fired" only at
 * L26 cadences). */
#define MMCS_L32_SLOT_PA   0x0867A044   /* evt 0x220 (evt>>3 = 0x44) */
#define MMCS_L32_QUIET_PARK 60
static uint32_t mmcs_l32_total;

/* MMCS fork (L33): exported for the CBRET callback-return completion
 * (target/sh4/helper.c) — the D0 kstacks are P3/UTLB (no P1 identity),
 * so kernel-stack frame writes must resolve through the PGOWN
 * write-sticky table first, the FILEVIEW dedup table second (the L32
 * daemon discipline). Returns 0 when unknown. */
uint32_t mmcs_stack_va2pa(uint32_t va)
{
    struct mmcs_pgown_ent *e = mmcs_pgown_find(va & ~0xFFFu,
                                               MMCS_PGOWN_ASID_SHARED);
    if (e) {
        return e->pa + (va & 0xFFF);
    }
    uint32_t pa = mmcs_fv_va2pa(va);
    return pa;
}

static uint32_t mmcs_l32_stack_pa(uint32_t va)
{
    return mmcs_stack_va2pa(va);
}

static void mmcs_l32_scan(void)
{
    uint8_t sig[MMCS_L19_NSIG];

    if (mmcs_l32_total >= mmcs_l32_max_deliv) {
        if (mmcs_l32_armed) {
            fprintf(stderr, "MMCS-L32: hard cap %u deliveries reached - "
                    "daemon parked\n", mmcs_l32_total);
            mmcs_l32_armed = 0;
        }
        return;
    }
    mmcs_l19_signature(sig);
    bool moved = mmcs_l32_sig_have
                 && memcmp(sig, mmcs_l32_sig, MMCS_L19_NSIG) != 0;
    memcpy(mmcs_l32_sig, sig, MMCS_L19_NSIG);
    mmcs_l32_sig_have = 1;
    if (moved) {
        mmcs_l32_quiet = 0;
        if (!mmcs_l32_armed) {
            mmcs_l32_armed = 1;
            fprintf(stderr, "MMCS-L32: t=%" PRId64 "ms movement while "
                    "parked - re-armed (%u deliveries used)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l32_total);
        }
    } else if (mmcs_l32_armed && ++mmcs_l32_quiet >= MMCS_L32_QUIET_PARK) {
        fprintf(stderr, "MMCS-L32: t=%" PRId64 "ms %u quiet scans - "
                "daemon parked at %u deliveries\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l32_quiet,
                mmcs_l32_total);
        mmcs_l32_armed = 0;
        mmcs_l32_quiet = 0;
    }
    if (!mmcs_l32_armed) {
        return;
    }
    /* the arena scan: a DoWait waiter whose waited object is a REAL
     * unsignaled EVNT = the walker inside CreateProcessW's
     * create-completion wait */
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
        /* resolve the waited object: the wait-array entry has
         * {.., obj @+0xC, prio(w) @+0x10, pTh @+0x14} — find the
         * entry whose pTh matches this thread (live-decoded: the
         * walker's entry lands at wobj+0x60 with obj=the create
         * event, a small {next, prev, waiter-list@+8} header in the
         * arena, the waiter entry linked via [event+8]) */
        uint32_t obj = 0;
        for (uint32_t wi = 0; wi <= 0x80; wi += 4) {
            uint32_t pa1 = mmcs_l32_stack_pa(wobj + wi + 0x14);
            uint32_t w1 = 0;
            if (!pa1) {
                continue;
            }
            cpu_physical_memory_read(pa1, &w1, 4);
            if (w1 != tva) {
                continue;
            }
            uint32_t pa2 = mmcs_l32_stack_pa(wobj + wi + 0xC);
            if (pa2) {
                cpu_physical_memory_read(pa2, &obj, 4);
            }
            break;
        }
        if (obj < 0x90680000 || obj >= 0x90780000) {
            continue;               /* not an arena kernel object */
        }
        /* the create-walker discriminator: the saved kstack return
         * chain must contain a pc inside kernel CreateProcessW's
         * post-wait region [0x9082ceac, 0x9082cf00) — the L26-class
         * orphan stack-waiters never carry it */
        uint32_t ssp = 0, is_cpw = 0;
        cpu_physical_memory_read(tva - 0x80000000 + 0xb0, &ssp, 4);
        if (ssp >= 0xD0000000 && ssp < 0xDC000000) {
            for (uint32_t sa = ssp; sa < ssp + 0x60; sa += 4) {
                uint32_t pa3 = mmcs_l32_stack_pa(sa);
                uint32_t w3 = 0;
                if (!pa3) {
                    continue;
                }
                cpu_physical_memory_read(pa3, &w3, 4);
                if (w3 >= 0x9082c000 && w3 < 0x90838000) {
                    is_cpw = 1;
                    break;
                }
            }
        }
        if (!is_cpw) {
            continue;
        }
        /* SET the event (the EventModify SET state byte) + repair the
         * wait context linkage (the vendor wait machinery keys the
         * re-evaluation on [pTh+0x1F8] -> the wait entry, whose +0x18
         * type byte selects the object dispatch — both zero in the
         * unlinked-launch class; the EVENT type = 4 per the CINFO
         * numbering) + deliver the wake (the L26 v7 stub) */
        uint32_t sigbyte = 0;
        cpu_physical_memory_read(obj - 0x80000000 + 0x8d, &sigbyte, 1);
        if (sigbyte & 1) {
            continue;               /* already signaled — not ours */
        }
        sigbyte |= 1;
        cpu_physical_memory_write(obj - 0x80000000 + 0x8d, &sigbyte, 1);
        /* the wait-context repair: [pTh+0x1F8] = the wait entry (the
         * pTh-matched slot), the entry's type byte (+0x18) = 4 (EVNT)
         */
        for (uint32_t wi = 0; wi <= 0x80; wi += 4) {
            uint32_t pa1 = mmcs_l32_stack_pa(wobj + wi + 0x14);
            uint32_t w1 = 0;
            if (!pa1) {
                continue;
            }
            cpu_physical_memory_read(pa1, &w1, 4);
            if (w1 == tva) {
                uint32_t entry = wobj + wi;
                cpu_physical_memory_write(tva - 0x80000000 + 0x1f8,
                                          &entry, 4);
                uint32_t t4 = 4;
                uint32_t pa2 = mmcs_l32_stack_pa(entry + 0x18);
                if (pa2) {
                    uint32_t curb = 0;
                    cpu_physical_memory_read(pa2, &curb, 4);
                    if (curb == 0) {
                        cpu_physical_memory_write(pa2, &t4, 4);
                    }
                }
                break;
            }
        }
        /* deliver: install, THEN patch the pool (.Lt +0x6c thread VA,
         * .Lm +0x68 marker-cell VA) + init the marker cell — the L38
         * .Lt patch-order fix (same class as L26; the old order
         * restored the default .Lt and the v6 guard inversion then
         * rejected the BLOCKED wrong target) */
        cpu_physical_memory_write(0x1F00EC00, mmcs_l26_stub,
                                  sizeof mmcs_l26_stub);
        cpu_physical_memory_write(0x1F00EC00 + 0x6c, &tva, 4);
        cpu_physical_memory_write(0x1F00EC00 + 0x68,
                                  &(uint32_t){ MMCS_L32_STUB_VA + 0xf0 }, 4);
        cpu_physical_memory_write(0x1F00ECF0,
                                  &(uint32_t){ MMCS_L32_STUB_VA + 0xf0 }, 4);
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L32_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L32_STUB_VA) {
            if (slot_cur != 0x90822e40) {
                fprintf(stderr, "MMCS-L32: slot evt 0x220 busy (%08x) - "
                        "scan skipped\n", slot_cur);
                return;
            }
            cpu_physical_memory_write(MMCS_L32_SLOT_PA,
                                      &(uint32_t){ MMCS_L32_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[0];
        e->evt_va = tva;
        e->stub_va = MMCS_L32_STUB_VA;
        e->evt_code = 0x220;
        e->slot_pa = MMCS_L32_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l32_total++;
        fprintf(stderr, "MMCS-L32: t=%" PRId64 "ms create-completion "
                "event %08x SET + wake thread %08x (wait-obj %08x, "
                "delivery %u/%u)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), obj, tva, wobj,
                mmcs_l32_total, mmcs_l32_max_deliv);
        return;                     /* one per cadence */
    }
}

/* MMCS fork (L46): MMCS_L46FIX — the create-interlock SPLIT repair
 * (S193, decoded 2026-11-21; the L45 S191 decode's named next rung).
 *
 * THE SPLIT (L45, live): the create-walker's interlock has TWO
 * objects. The walker (ctx pc 0x90837cf6 = the SC_CreateProc
 * WaitForObjects face, schedule.c:6901) binds the event resolved
 * through its OWN wait-array entry — sig byte 0x00 forever, the
 * walker's wait entry linked on that object's waiter list — while
 * the loader-side shims' SETs (the 8Hz create-retry storm,
 * t=3.3-9.5s, SET jsr 0x90835fda) land on the psi-side event; both
 * 0x90835f14-class shims die into the kill grave by ~9.5s, so
 * nothing will ever signal the walker's object: CreateProcessW
 * never returns, the filesys launch loop cannot iterate past its
 * FIRST create, Depend20/SignalStarted(10) never entered.
 *
 * THE FIX — the stock completion re-delivered through the proven
 * L32EV family (same recipe verbatim): the EventModify-SET state
 * byte on the walker's OWN waited object (the vendor SET semantics
 * L45 taped landing on the wrong half), the wait-context linkage
 * repair ([pTh+0x1F8] wait entry + type byte 4 EVNT, both
 * repair-if-zero only), and the L26 v7 stub wake (MakeRun + resched
 * + pick + switcher) — the SAME wake delivery the L26EV daemon
 * already runs on this exact thread every cadence (L45: "walker
 * re-evaluates, re-blocks"); with the sig byte SET, the same vendor
 * re-evaluation completes the wait natively and CreateProcessW
 * returns through 100% vendor code.
 *
 * Discriminators (all readback; run-variance safe):
 *  - the create-walker face: ctx pc 0x90837cf6, (st16&3)==2 BLOCKED,
 *    D0 64K kstack, waited object resolved through the walker's OWN
 *    wait-array entry (pTh-matched, the L32EV resolver loop) = an
 *    arena object with sig byte 0x00 whose waiter-list head [obj+8]
 *    is NON-zero — the LINKED shape, the complement of L32EV's
 *    unlinked launch class (wblk==0);
 *  - the kstack return chain carries a 0x9082c000-0x90838000 kernel
 *    create-window address (is_cpw — same as L32EV);
 *  - STABILITY: the same {thread, sp, waited obj, sig 0} shape on
 *    >= 2 consecutive cadences (the storm long dead, the interlock
 *    provably abandoned — the delivery is one-shot total).
 * Env MMCS_L46FIX (default OFF; cadence MMCS_L46FIX_MS default
 * 2000). Shares the L32 slot (evt 0x220 / ents[0] / stub
 * 0xBF00EC00) with L32EV — disjoint classes, pending/slot-guarded.
 * Needs MMCS_KILLSTK + MMCS_TICK. */
static uint32_t mmcs_l46_done, mmcs_l46_stable;
static uint32_t mmcs_l46_key;

static void mmcs_l46_scan(void)
{
    if (!mmcs_l46_armed || mmcs_l46_done) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    for (uint32_t o = 0; o + 0x200 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, ctxpc, wobj;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&wobj, arena + o + 0x14c, 4);
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000
            || (st16 & 3) != 2
            || ctxpc != 0x90837cf6
            || wobj < 0xD0000000 || wobj >= 0xDC000000
            || tva == pcur) {
            continue;
        }
        /* resolve the waited object through the walker's own
         * wait-array entry (the L32EV resolver) */
        uint32_t obj = 0;
        for (uint32_t wi = 0; wi <= 0x80; wi += 4) {
            uint32_t pa1 = mmcs_l32_stack_pa(wobj + wi + 0x14);
            uint32_t w1 = 0;
            if (!pa1) {
                continue;
            }
            cpu_physical_memory_read(pa1, &w1, 4);
            if (w1 != tva) {
                continue;
            }
            uint32_t pa2 = mmcs_l32_stack_pa(wobj + wi + 0xC);
            if (pa2) {
                cpu_physical_memory_read(pa2, &obj, 4);
            }
            break;
        }
        if (obj < 0x90680000 || obj >= 0x90780000) {
            continue;               /* not an arena kernel object */
        }
        uint8_t sig46 = 0;
        cpu_physical_memory_read(obj - 0x80000000 + 0x8d, &sig46, 1);
        if (sig46 & 1) {
            continue;               /* signaled — not the dead half */
        }
        uint32_t wlh = 0;
        cpu_physical_memory_read(obj - 0x80000000 + 8, &wlh, 4);
        if (wlh == 0) {
            continue;               /* unlinked = L32EV's class */
        }
        /* the create-body kstack witness (is_cpw — same as L32EV but
         * a wider window: the walker's sp wobbles between the L26EV
         * re-wake frames and the postwait return cell can sit past
         * +0x60 in the re-entered frame — live-caught) */
        uint32_t ssp = 0, is_cpw = 0;
        cpu_physical_memory_read(tva - 0x80000000 + 0xb0, &ssp, 4);
        if (ssp >= 0xD0000000 && ssp < 0xDC000000) {
            for (uint32_t sa = ssp; sa < ssp + 0x80; sa += 4) {
                uint32_t pa3 = mmcs_l32_stack_pa(sa);
                uint32_t w3 = 0;
                if (!pa3) {
                    continue;
                }
                cpu_physical_memory_read(pa3, &w3, 4);
                /* the CREATE BODY proper [0x9082ce00,0x9082ed00):
                 * the postwait 9082ceb6 + the wait-return 9082ec86
                 * cells — NOT the wide wait-wrapper window (the face
                 * 0x90837cf6 is the GENERIC WaitForObjects face;
                 * live-caught: the wide window matched a MARKED DoWait
                 * orphan (906dd000) and the one-shot fired on the
                 * wrong thread) */
                if (w3 >= 0x9082ce00 && w3 < 0x9082ed00) {
                    is_cpw = 1;
                    break;
                }
            }
        }
        if (!is_cpw) {
            continue;
        }
        /* the filesys post-create witness: [th+0x150] reads the
         * filesys continuation (the walker's live value c00bb4e0 —
         * the TRUE post-CreateProcessW site, the L36-era c00bb3ba
         * label corrected); a generic kernel-side waiter carries a
         * kernel-window return there */
        uint32_t wret = 0;
        cpu_physical_memory_read(tva - 0x80000000 + 0x150, &wret, 4);
        if (wret < 0xC0000000 || wret >= 0xC1000000) {
            continue;
        }
        /* stability: the same dead interlock across >= 2 cadences.
         * The key is {thread, waited obj} ONLY — the walker's sp
         * wobbles between the L26EV re-wake frames (live-caught: the
         * sp-keyed counter never accumulated although every filter
         * passed; the interlock identity is thread+object). */
        uint32_t key = tva ^ obj;
        {   /* one-shot diagnostic: the first full-shape candidate's
             * cells + the delivery-gate state */
            static int once;
            if (!once) {
                once = 1;
                fprintf(stderr, "MMCS-L46: diag t=%" PRId64 "ms cand "
                        "%08x st16=%08x wobj=%08x obj=%08x sig=%02x "
                        "wlh=%08x ssp=%08x is_cpw=%u ents0pend=%u "
                        "key=%08x\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, st16,
                        wobj, obj, sig46, wlh, ssp, is_cpw,
                        mmcs_l16_ents[0].pending, key);
            }
        }
        if (key != mmcs_l46_key) {
            mmcs_l46_key = key;
            mmcs_l46_stable = 1;
            break;                  /* candidate seen — keep the count */
        }
        if (++mmcs_l46_stable < 2) {
            break;                  /* candidate seen — keep the count */
        }
        /* DELIVER — the L32EV recipe verbatim: SET state byte, ctx
         * repair (if-zero), v7 stub wake on the walker */
        if (mmcs_l16_ents[0].pending) {
            return;                 /* L32EV mid-delivery — retry */
        }
        sig46 |= 1;
        cpu_physical_memory_write(obj - 0x80000000 + 0x8d, &sig46, 1);
        for (uint32_t wi = 0; wi <= 0x80; wi += 4) {
            uint32_t pa1 = mmcs_l32_stack_pa(wobj + wi + 0x14);
            uint32_t w1 = 0;
            if (!pa1) {
                continue;
            }
            cpu_physical_memory_read(pa1, &w1, 4);
            if (w1 == tva) {
                uint32_t entry = wobj + wi;
                uint32_t f8 = 0;
                cpu_physical_memory_read(tva - 0x80000000 + 0x1f8,
                                          &f8, 4);
                if (f8 == 0) {
                    cpu_physical_memory_write(tva - 0x80000000 + 0x1f8,
                                              &entry, 4);
                }
                uint32_t t4 = 4;
                uint32_t pa2 = mmcs_l32_stack_pa(entry + 0x18);
                if (pa2) {
                    uint32_t curb = 0;
                    cpu_physical_memory_read(pa2, &curb, 4);
                    if (curb == 0) {
                        cpu_physical_memory_write(pa2, &t4, 4);
                    }
                }
                break;
            }
        }
        cpu_physical_memory_write(0x1F00EC00, mmcs_l26_stub,
                                  sizeof mmcs_l26_stub);
        cpu_physical_memory_write(0x1F00EC00 + 0x6c, &tva, 4);
        cpu_physical_memory_write(0x1F00EC00 + 0x68,
                                  &(uint32_t){ MMCS_L32_STUB_VA + 0xf0 }, 4);
        cpu_physical_memory_write(0x1F00ECF0,
                                  &(uint32_t){ MMCS_L32_STUB_VA + 0xf0 }, 4);
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L32_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L32_STUB_VA) {
            if (slot_cur != 0x90822e40) {
                fprintf(stderr, "MMCS-L46: slot evt 0x220 busy (%08x) - "
                        "retry next cadence\n", slot_cur);
                return;
            }
            cpu_physical_memory_write(MMCS_L32_SLOT_PA,
                                      &(uint32_t){ MMCS_L32_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[0];
        e->evt_va = tva;
        e->stub_va = MMCS_L32_STUB_VA;
        e->evt_code = 0x220;
        e->slot_pa = MMCS_L32_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l46_done = 1;
        fprintf(stderr, "MMCS-L46: t=%" PRId64 "ms create-interlock SPLIT "
                "repair: obj %08x sig 00->01 (linked waiter-list %08x), "
                "ctx repair + v7 stub wake walker %08x (sp %08x, wait-obj "
                "%08x)\n", qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), obj, wlh,
                tva, ssp, wobj);
        /* no post-loop reset: the counter is monotonic per-key (a
         * mid-wake scan that misses the shape is noise, not
         * evidence of interlock life — the key-change path alone
         * resets; live-caught: the every-other-scan reset starved
         * the delivery forever while every sampled cell matched) */
        return;                     /* one-shot total */
    }
}

/* MMCS fork (L47): MMCS_L47FIX — the TRUE-BASE wake-eval ctx repair
 * (S195/S196, decoded 2026-11-21; the S195 datum's named last layer).
 *
 * THE DECODE (the wake evaluation fn 0x90828200, KCall'd from the park
 * face 0x90837cf6 via pool 0x90837dac): the eval reads its wait ENTRY
 * pointer from [pTh+0x1F8], the waited OBJECT at entry+0x14, the TYPE
 * BYTE at entry+0x18 (dispatch: 4/13 = the real EVNT path; 1/0xff =
 * the marked class; else = default), the SIG BYTE at obj+0x8D, and on
 * a signaled EVNT consumes it (sig := byte[obj+0x8E]) then runs the
 * satisfy bookkeeping ([pTh+0x1F8] := [entry+0x10], [wobj+4]/[wobj+8]
 * rotation, byte[pTh+0xF] := 0) returning [entry+0x20] as the wait
 * result. THE TRUE ENTRY BASE on the walker's live stack = wobj+0x08
 * (there entry+0x14 = the event, entry+0x18's byte = the flags word's
 * low byte = 04 EVNT, entry+0x20 = wobj+0x28 = the WAIT_OBJECT_0
 * result cell).
 *
 * WHY THE L46 REPAIR NEVER COMPLETED THE WAIT (live-caught, P6-P8
 * boots): the L46 planted [pTh+0x1F8] = wobj+0x10 — 8 HIGH — so the
 * eval dereferenced the THREAD TCB as the object (its +0x8d byte is
 * not the event's sig) and its type-4 repair write landed on wobj+0x28
 * (the result cell, making a satisfied return read 4). And the failed
 * eval's re-block path ZEROES [pTh+0x1F8] again, while the L26 scan
 * filter itself requires [th+0x1F8]==0 (the wblk cell) — so a standing
 * one-shot ctx plant either never survives to the next eval or blocks
 * the very wake that would run it. The type byte (the flags word at
 * wobj+0x20) is ALSO boot-unstable (0003fb04 vs 00000000 across
 * boots).
 *
 * THE FIX — a REPEATING repair that re-plants every cadence AND
 * delivers its own v7 wake (the L46 stub recipe verbatim): [pTh+0x1F8]
 * = wobj+0x08 (the true base), the type byte (wobj+0x20 low byte) |=
 * 0x04, the result cell [wobj+0x28] := 0, the sig byte |= 1 (the stock
 * SET). With the true base the vendor eval completes the wait natively
 * (consume + satisfy + WAIT_OBJECT_0) and the create body's stock
 * postwait predicate ([lppi+0] != 0 — already passing on the non-zero
 * teardown sentinel) lets CreateProcessW return through 100% vendor
 * code. Self-healing: if a cycle still fails, the next cadence
 * re-plants (the shape guard = the walker still parked at the dead
 * interlock; natural stop when the wait completes).
 *
 * Discriminators: the L46 shape verbatim (the create-body window
 * [0x9082ce00,0x9082ed00), the filesys post-create witness [th+0x150],
 * the linked waiter-list, sig 0x00 = still dead, is_cpw).
 * Env MMCS_L47FIX (default OFF; MMCS_L47FIX_MS cadence default 2000;
 * MMCS_L47FIX_MAX delivery cap default 8). Shares the L32 slot (evt
 * 0x220 / ents[0] / stub 0xBF00EC00) — pending/slot-guarded, disjoint
 * from the one-shot L46 by the cap counter. Needs MMCS_KILLSTK +
 * MMCS_TICK. */
static void mmcs_l47_scan(void)
{
    if (!mmcs_l47_armed || mmcs_l47_total >= mmcs_l47_max_deliv) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    for (uint32_t o = 0; o + 0x200 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, ctxpc, wobj, wret;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&wobj, arena + o + 0x14c, 4);
        memcpy(&wret, arena + o + 0x150, 4);
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000
            || (st16 & 3) != 2
            || ctxpc != 0x90837cf6
            || wobj < 0xD0000000 || wobj >= 0xDC000000
            || wret < 0xC0000000 || wret >= 0xC1000000
            || tva == pcur) {
            continue;
        }
        /* resolve the waited object through the walker's own
         * wait-array entry (the L32EV resolver; keeps the matched
         * wi for the entry-base derivation below) */
        uint32_t obj = 0, wi_found = 0;
        for (uint32_t wi = 0; wi <= 0x80; wi += 4) {
            uint32_t pa1 = mmcs_l32_stack_pa(wobj + wi + 0x14);
            uint32_t w1 = 0;
            if (!pa1) {
                continue;
            }
            cpu_physical_memory_read(pa1, &w1, 4);
            if (w1 != tva) {
                continue;
            }
            uint32_t pa2 = mmcs_l32_stack_pa(wobj + wi + 0xC);
            if (pa2) {
                cpu_physical_memory_read(pa2, &obj, 4);
            }
            wi_found = wi;
            break;
        }
        if (obj < 0x90680000 || obj >= 0x90780000) {
            continue;               /* not an arena kernel object */
        }
        uint8_t sig47 = 0;
        cpu_physical_memory_read(obj - 0x80000000 + 0x8d, &sig47, 1);
        if (sig47 & 1) {
            continue;               /* signaled — vendor world moving */
        }
        uint32_t wlh = 0;
        cpu_physical_memory_read(obj - 0x80000000 + 8, &wlh, 4);
        if (wlh == 0) {
            continue;               /* unlinked = L32EV's class */
        }
        /* the create-body kstack witness (is_cpw — the L46 window) */
        uint32_t ssp = 0, is_cpw = 0;
        cpu_physical_memory_read(tva - 0x80000000 + 0xb0, &ssp, 4);
        if (ssp >= 0xD0000000 && ssp < 0xDC000000) {
            for (uint32_t sa = ssp; sa < ssp + 0x80; sa += 4) {
                uint32_t pa3 = mmcs_l32_stack_pa(sa);
                uint32_t w3 = 0;
                if (!pa3) {
                    continue;
                }
                cpu_physical_memory_read(pa3, &w3, 4);
                if (w3 >= 0x9082ce00 && w3 < 0x9082ed00) {
                    is_cpw = 1;
                    break;
                }
            }
        }
        if (!is_cpw) {
            continue;
        }
        /* DELIVER — the true-base plants + the L46 stub recipe */
        if (mmcs_l16_ents[0].pending) {
            return;                 /* L32/L46 mid-delivery — retry */
        }
        /* The eval's entry base is FRAME-WOBBLE-DEPENDENT (live-caught:
         * the waiter-entry fields sit at wobj+0x10 in one boot and
         * wobj+0x18 in another — the L46-commit's sp-wobble class).
         * The invariant: the eval wants the entry whose +0x14 cell
         * holds THE EVENT = the resolver's wi MINUS 8. Derive it
         * dynamically and VERIFY against the resolved object. */
        if (!wi_found || wi_found < 8) {
            continue;               /* resolver lost the entry — skip */
        }
        uint32_t entry47 = wobj + wi_found - 8;
        uint32_t pa_e = mmcs_l32_stack_pa(entry47 + 0x14);
        uint32_t objchk = 0;
        if (pa_e) {
            cpu_physical_memory_read(pa_e, &objchk, 4);
        }
        if (!pa_e || objchk != obj) {
            fprintf(stderr, "MMCS-L47: entry verify FAILED (entry %08x "
                    "objchk %08x vs obj %08x) - skip\n",
                    entry47, objchk, obj);
            continue;
        }
        /* (1) the ctx cell: the true entry base */
        cpu_physical_memory_write(tva - 0x80000000 + 0x1f8,
                                  &entry47, 4);
        /* (2) the type byte: entry+0x18's low byte must carry EVNT(4)
         * — naturally 04 in every observed layout; force idempotently */
        uint32_t pa_t = mmcs_l32_stack_pa(entry47 + 0x18);
        if (pa_t) {
            uint32_t fw = 0;
            cpu_physical_memory_read(pa_t, &fw, 4);
            if ((fw & 0xff) != 0x04) {
                fw = (fw & 0xffffff00) | 0x04;
                cpu_physical_memory_write(pa_t, &fw, 4);
            }
        }
        /* (3) the result cells := 0x1000 — WAIT_OBJECT_0 in the
         * kernel's packed result form (bit 12 = the completion
         * weight, bits 10-11 = the index; the 0x9082eca4 leaf adds
         * the same 0x1000 per satisfied entry). TWO cells carry it:
         * [entry+0x20] (the satisfy tail's return — eval#1) AND
         * [pTh+0x1FC] (the wait-result CACHE — the bF==0 early-out's
         * return, eval#2 — the park-loop fn returns the LAST eval's
         * r10, and the loop re-arms once after a satisfy, so the
         * cache is the value that actually flows up the tower). The
         * stock wake chain writes the cache; the dead-loader world
         * never does — the zero result keeps the entry word pending
         * and the postwait gate re-waits forever (the S198 decode). */
        uint32_t res47 = 0x1000;
        uint32_t pa_r = mmcs_l32_stack_pa(entry47 + 0x20);
        if (pa_r) {
            uint32_t cur = 0;
            cpu_physical_memory_read(pa_r, &cur, 4);
            if (cur != 0x1000) {
                cpu_physical_memory_write(pa_r, &res47, 4);
            }
        }
        cpu_physical_memory_write(tva - 0x80000000 + 0x1fc,
                                  &res47, 4);
        /* (3b) THE S199 VERDICT RE-ARM — the extractor/fold decode
         * (L51): the walker parks at the face INSIDE the postwait
         * helper's extractor call (the fold's own jsr return
         * 0x9082ec86 sits at [sp+4]); the re-submitted wait's
         * no-entry eval re-block ZEROED the park loop's verdict cell
         * [sp+0x10], so at wake the loop exits without any eval and
         * returns the stub-forged r0=0 — the 0x1000 dies between the
         * fn's return and the fold. The stock submit ARMS the verdict
         * (=2); the stock wake keeps it armed until an eval runs.
         * Restore the stock word: at wake the vendor loop re-KCalls
         * its own eval inline (with the plants above: the type-4
         * satisfy — sig consumed, bF:=0, *verdict:=0 — returning
         * [entry+0x20]=0x1000 as a REAL r0). Idempotent: only when
         * the cell reads 0 (no stacking, no mid-cycle overwrite). */
        {
            uint32_t vsp = 0;
            cpu_physical_memory_read(tva - 0x80000000 + 0xb0, &vsp, 4);
            if (vsp >= 0xD0000000 && vsp < 0xDC000000) {
                uint32_t pa_v = mmcs_l32_stack_pa(vsp + 0x10);
                if (pa_v) {
                    uint32_t verdict = 0;
                    cpu_physical_memory_read(pa_v, &verdict, 4);
                    if (verdict == 0) {
                        cpu_physical_memory_write(
                            pa_v, &(uint32_t){ 2 }, 4);
                    }
                }
            }
        }
        /* (4) the stock SET: sig byte |= 1 */
        sig47 |= 1;
        cpu_physical_memory_write(obj - 0x80000000 + 0x8d, &sig47, 1);
        /* (5) the v7 stub wake (the L46 recipe verbatim) */
        cpu_physical_memory_write(0x1F00EC00, mmcs_l26_stub,
                                  sizeof mmcs_l26_stub);
        cpu_physical_memory_write(0x1F00EC00 + 0x6c, &tva, 4);
        cpu_physical_memory_write(0x1F00EC00 + 0x68,
                                  &(uint32_t){ MMCS_L32_STUB_VA + 0xf0 }, 4);
        cpu_physical_memory_write(0x1F00ECF0,
                                  &(uint32_t){ MMCS_L32_STUB_VA + 0xf0 }, 4);
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L32_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L32_STUB_VA) {
            if (slot_cur != 0x90822e40) {
                fprintf(stderr, "MMCS-L47: slot evt 0x220 busy (%08x) - "
                        "retry next cadence\n", slot_cur);
                return;
            }
            cpu_physical_memory_write(MMCS_L32_SLOT_PA,
                                      &(uint32_t){ MMCS_L32_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[0];
        e->evt_va = tva;
        e->stub_va = MMCS_L32_STUB_VA;
        e->evt_code = 0x220;
        e->slot_pa = MMCS_L32_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l47_total++;
        fprintf(stderr, "MMCS-L47: t=%" PRId64 "ms true-base ctx repair "
                "%u/%u: walker %08x wobj %08x entry %08x obj %08x sig "
                "00->01 (type 4, result cells 1000: entry+0x20 + "
                "th+0x1FC cache)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l47_total,
                mmcs_l47_max_deliv, tva, wobj, entry47, obj);
        return;                     /* one delivery per cadence */
    }
}

/* MMCS fork (L50): MMCS_L50DBG — the create-retry exit tape.
 *
 * S198: after the L47 delivery completes the interlock state (sig
 * consumed, bF cleared, the park loop exits), the create body
 * RE-PARKS instead of returning. The completion chain (this
 * session's decode): park loop 0x90837ce2 (verdict cell [sp+0x10],
 * re-arm back-edge 0x90837d22 bf while NON-zero) -> eval 0x90828244
 * (the satisfy never writes *result; only the bF==0 EARLY-OUT does,
 * returning the [pTh+0x1FC] wait-result cache) -> 0x90848330 ->
 * postwait helper 0x9082ec44 (0x1000 gate at 0x9082ec5e; the fold
 * *state = [ws+0]|waitret at 0x9082ec88) -> walk 0x9082e7a0 ->
 * submit 0x90830444 -> the outer face loop. This knob DUMPS the
 * walker's cells every cadence (READ-ONLY — no writes, no wakes):
 * the ctx cells, the wait chain (wobj/sig/flags), the [pTh+0x1FC]
 * cache and the kstack witness words — the frames tell which layer
 * holds the re-park. Default OFF; the default-off world is
 * byte-identical (no guest writes at all). */
static void mmcs_l50_dbg(void)
{
    if (!mmcs_l50_armed || mmcs_l50_lines >= mmcs_l50_max_lines) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    for (uint32_t o = 0; o + 0x210 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, ctxpc, ctxsp, wobj;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&ctxsp, arena + o + 0xb0, 4);
        memcpy(&wobj, arena + o + 0x14c, 4);
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000) {
            continue;
        }
        /* the create-body kstack witness (the L46 window) — the tape's
         * target discriminator, ANY state (parked or mid-cycle) */
        uint32_t ssp = ctxsp;
        int is_cpw = 0;
        if (ssp >= 0xD0000000 && ssp < 0xDC000000) {
            for (uint32_t sa = ssp; sa < ssp + 0x80; sa += 4) {
                uint32_t pa3 = mmcs_l32_stack_pa(sa);
                uint32_t w3 = 0;
                if (!pa3) {
                    continue;
                }
                cpu_physical_memory_read(pa3, &w3, 4);
                if (w3 >= 0x9082ce00 && w3 < 0x9082ed00) {
                    is_cpw = 1;
                    break;
                }
            }
        }
        if (!is_cpw) {
            continue;
        }
        uint8_t bF = (st16 >> 24) & 0xff;   /* +0xF waiting flag */
        uint32_t f1f8 = 0, t1fc = 0, t200 = 0, t34 = 0;
        memcpy(&f1f8, arena + o + 0x1f8, 4);
        memcpy(&t1fc, arena + o + 0x1fc, 4);
        memcpy(&t200, arena + o + 0x200, 4);
        memcpy(&t34, arena + o + 0x34, 4);
        fprintf(stderr,
                "MMCS-L50: t=%" PRId64 "ms th %08x%s st16=%08x bF=%02x "
                "pc=%08x sp=%08x wobj=%08x f1f8=%08x t1fc=%08x t200=%08x "
                "t34=%08x",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva,
                tva == pcur ? " *CUR*" : "", st16, bF, ctxpc, ctxsp, wobj,
                f1f8, t1fc, t200, t34);
        /* the waited object chain (sig / flags word / waiter-list) */
        if (wobj >= 0xD0000000 && wobj < 0xDC000000) {
            uint32_t obj = 0, wi_found = 0;
            for (uint32_t wi = 0; wi <= 0x80; wi += 4) {
                uint32_t pa1 = mmcs_l32_stack_pa(wobj + wi + 0x14);
                uint32_t w1 = 0;
                if (!pa1) {
                    continue;
                }
                cpu_physical_memory_read(pa1, &w1, 4);
                if (w1 != tva) {
                    continue;
                }
                uint32_t pa2 = mmcs_l32_stack_pa(wobj + wi + 0xC);
                if (pa2) {
                    cpu_physical_memory_read(pa2, &obj, 4);
                }
                wi_found = wi;
                break;
            }
            if (wi_found && obj >= 0x90680000 && obj < 0x90780000) {
                uint8_t sig = 0, mark = 0;
                uint32_t wlh = 0, flags = 0;
                cpu_physical_memory_read(obj - 0x80000000 + 0x8d,
                                         &sig, 1);
                cpu_physical_memory_read(obj - 0x80000000 + 0x8f,
                                         &mark, 1);
                cpu_physical_memory_read(obj - 0x80000000 + 8, &wlh, 4);
                uint32_t pa_f = mmcs_l32_stack_pa(wobj + wi_found + 0x10);
                if (pa_f) {
                    cpu_physical_memory_read(pa_f, &flags, 4);
                }
                fprintf(stderr, " obj=%08x sig=%02x mark=%02x wlh=%08x "
                        "flags(+w%x)=%08x", obj, sig, mark, wlh,
                        wi_found + 8, flags);
            }
        }
        /* the kstack witness words — WIDENED (S199): [sp-0x40,
         * sp+0x180) — the S198 window [sp,sp+0x100) cut off the
         * outermost frames (the launch-loop TBs c00ce888/c00be89a
         * sit at sp+0xe0) and the deeper KCall residue; the
         * extractor/fold frames (the fold's jsr return 0x9082ec86
         * at [sp+4], the verdict [sp+0x10]) stay in-frame */
        if (ssp >= 0xD0000000 && ssp < 0xDC000000) {
            fprintf(stderr, " kstack:");
            for (uint32_t sa = ssp - 0x40; sa < ssp + 0x180; sa += 4) {
                uint32_t pa3 = mmcs_l32_stack_pa(sa);
                uint32_t w3 = 0;
                if (!pa3) {
                    w3 = 0xdeadbeef;
                } else {
                    cpu_physical_memory_read(pa3, &w3, 4);
                }
                fprintf(stderr, " %08x", w3);
            }
            /* the extractor's global waiter lists (the S199 decode:
             * the KCall'd reaper 0x90848214 unlinks the head of
             * 0x8867e740 (arg!=0) / 0x8867e748 (arg==0)) + the
             * record-decoder table base cell [KData+0x8C] —
             * read-only, one line each. S200: + the resched hand-off
             * cells (pick/pRunnable/flag/drain2/pCurTh — the idle
             * world's evidence) */
            {
                static const struct { uint32_t va; const char *tag; }
                exreg[] = {
                    { 0x8867e740, "wl1" },
                    { 0x8867e748, "wl2" },
                    { 0x8867988c, "t8c" },
                    { 0x8867efa0, "rq" },
                    { 0x88679884, "rs" },
                    { 0x88679894, "pc2" },
                };
                for (unsigned k = 0; k < 6; k++) {
                    uint32_t buf[2];
                    cpu_physical_memory_read(
                        exreg[k].va - 0x80000000, buf, sizeof buf);
                    fprintf(stderr, " %s: %08x %08x", exreg[k].tag,
                            buf[0], buf[1]);
                }
            }
        }
        /* the psi-side wait-array cells (the create body's r8+8 array:
         * the packed {handle<<16 | status} entry words — S198's gate
         * target; diagnostic dump of the two known psi neighborhoods) */
        {
            static const struct { uint32_t va; const char *tag; }
            psireg[] = {
                { 0x9069ad80, "psi-walker" },
                { 0x90690950, "psi-storm" },
            };
            for (unsigned k = 0; k < 2; k++) {
                uint32_t buf[8];
                cpu_physical_memory_read(psireg[k].va - 0x80000000,
                                         buf, sizeof buf);
                fprintf(stderr, " %s:", psireg[k].tag);
                for (unsigned j = 0; j < 8; j++) {
                    fprintf(stderr, " %08x", buf[j]);
                }
            }
        }
        /* MMCS fork (L55): MMCS_L55DBG — the S203 psi-array resolve
         * (READ-ONLY). The kstack witness cell [sp+0x20]-class holds
         * the create body's psi-array pointer (d0043124-class — the
         * user handle-table pages, unreachable by the monitor's flat
         * PA map). Resolve through the L32 page-table resolver, dump
         * the array + one level of its D0-pointers (the group hunt).
         * PLUS the group-shape scan: the runner's subarray = a run of
         * element words; the pending gate (word & 0xFFFFFF3F) <=
         * 0x1000; hunt {satisfied, pending} adjacent pairs + the
         * back-pointers to them (the group entries). Default OFF; no
         * guest writes. */
        if (mmcs_l55dbg_armed) {
            static uint32_t l55_pairs_seen;
            for (int cw = 20; cw <= 28; cw += 4) {
                uint32_t cpa = mmcs_l32_stack_pa(ssp + cw);
                uint32_t cand = 0;
                if (cpa) {
                    cpu_physical_memory_read(cpa, &cand, 4);
                }
                if (cpa && cand >= 0xD0000000 && cand < 0xDC000000) {
                    fprintf(stderr, " L55[sp+%x]->%08x:", cw, cand);
                    for (uint32_t wi = 0; wi < 12; wi++) {
                        uint32_t wpa = mmcs_l32_stack_pa(cand + wi * 4);
                        uint32_t w = 0;
                        if (wpa) {
                            cpu_physical_memory_read(wpa, &w, 4);
                        } else {
                            w = 0xdeadbee0 + wi;
                        }
                        fprintf(stderr, " %08x", w);
                    }
                    /* one level: the first two in-range pointers */
                    for (uint32_t wi = 0; wi < 12; wi++) {
                        uint32_t wpa = mmcs_l32_stack_pa(cand + wi * 4);
                        uint32_t w = 0;
                        if (!wpa) {
                            continue;
                        }
                        cpu_physical_memory_read(wpa, &w, 4);
                        if (w >= 0xD0000000 && w < 0xDC000000
                            && w != cand) {
                            fprintf(stderr, " |d[%x]->%08x:", wi * 4, w);
                            for (uint32_t wj = 0; wj < 8; wj++) {
                                uint32_t p2 = mmcs_l32_stack_pa(w + wj * 4);
                                uint32_t v2 = 0;
                                if (p2) {
                                    cpu_physical_memory_read(p2, &v2, 4);
                                } else {
                                    v2 = 0xdeadbee0 + wj;
                                }
                                fprintf(stderr, " %08x", v2);
                            }
                        }
                    }
                }
            }
            /* THE GROUP-SHAPE SCAN (bounded: the first 6 prints, once
             * each — the arena copy is already in hand) */
            if (l55_pairs_seen < 6) {
                for (uint32_t o2 = 0; o2 + 8 <= sizeof arena; o2 += 4) {
                    uint32_t w0, w1;
                    memcpy(&w0, arena + o2, 4);
                    memcpy(&w1, arena + o2 + 4, 4);
                    if ((w0 & 0xFFFFFF3F) > 0x1000 && w1 != 0
                        && (w1 & 0xFFFFFF3F) <= 0x1000
                        && w1 >= 0x400) {
                        /* back-pointer hunt: a word == 0x90680000+o2 */
                        uint32_t bp = 0;
                        for (uint32_t o3 = 0; o3 + 4 <= sizeof arena;
                             o3 += 4) {
                            uint32_t w3;
                            memcpy(&w3, arena + o3, 4);
                            if (w3 == 0x90680000 + o2) {
                                bp = 0x90680000 + o3;
                                break;
                            }
                        }
                        fprintf(stderr, "\nMMCS-L55: PAIR @%08x: %08x "
                                "%08x (bp %08x)", 0x90680000 + o2,
                                w0, w1, bp);
                        if (++l55_pairs_seen >= 6) {
                            break;
                        }
                    }
                }
            }
        }
        fprintf(stderr, "\n");
        mmcs_l50_lines++;
        return;                     /* one walker per cadence */
    }
}

/* MMCS fork (L36): MMCS_L36EV — the post-exit requeue daemon (the
 * S173 frontier, decoded 2026-11-20).
 *
 * DECODE (the exec-TB trace of the death window + the park census +
 * probeF's walker/proc/event walk, successor-combo plain runs): after
 * MMCS_USERJSR both shell.exe threads die for real and the kernel
 * kill path (FUN_9083be50) COMPLETES — the proc is torn down
 * (piVar5[0xc]=2, threads unlinked, the hProc handle entry flagged
 * signaled [entry+0x8e]|=8) and the wake core 0x9083fe94(entry,3)
 * runs ONCE and completes. Two waiters resume at the wait-return face
 * 0x90837fa8; ONE of them (the WIN32 servant executing the
 * CreateProcessW wait for the launcher, hProc 0x00400002 in hand) is
 * left RUNNING(0)-but-NEVER-RE-ENQUEUED mid-handle-lookup at
 * 0x9083b682 (inside FUN_9083b668, right after its table-lookup jsr):
 * a KCall-level switch preempted it mid-execution (the second death's
 * final reschedule 0x908230e6 from the KillThread tail) and the
 * vendor requeue never ran — pick/pRunnable/chain[23]/[24] all stay 0
 * while the OEMIdle loop spins forever. THE SAME CLASS the L18EV
 * decode named for the fsdmgr world: "the vendor walker unlinks the
 * waitblock and leaves the waiter RUNNABLE-not-queued, and MRI
 * MakeRuns only NEEDSRUN(3)" — here the whole preempt-requeue is
 * lost, not just the MRI half.
 *
 * FIX = the stock guarantee a preempted runnable thread re-enters the
 * runnable set, delivered through 100% vendor code (the L19TH v5
 * stub shape): MakeRun(0x90825ee4) — whose own internal guard is the
 * [th+0xE] suspend byte (MakeRun proceeds for our state-0 class and
 * sets state16|1 + enqueues into the pRunnable bands) — then the
 * resched protocol stores (BYTE 0x88679884=1 the switcher-entry flag,
 * WORD 0x88679888=1 the drain2 pick-recompute), pick(0x8867efa4)=pTh,
 * r14=pCurTh and jsr the vendor switcher 0x90822b68 (saves current,
 * drains, loads the pick — execution continues at the thread's saved
 * ctx = the mid-lookup tst, and the satisfied-handle evaluation
 * unwinds the wait through the vendor's own code). The stub guard is
 * `state16&3 == 0` (the L36 target class ONLY — states 1/3 stay the
 * L19TH domain, and the guard makes the chained re-fires no-ops once
 * MakeRun has flipped the state to 1).
 *
 * The daemon scan (host-side, on the 1ms tick chain, the L26/L32
 * discipline): when the movement signature says the system parked
 * AND pick==0 AND pRunnable==0 AND at least one kill-epilogue grave
 * exists (a thread whose ctx cells carry 0x9083c102 — the deaths
 * happened), find the first arena thread with a D0 kstack whose
 * state16 low bits say RUNNING(0), that is NOT a grave, whose ctx
 * cells sit outside the OAL idle window [0x90808000,0x9080a000), and
 * that is not pCurTh — then deliver. Bounds: one delivery per
 * cadence (MMCS_L36EV_MS, default 2000), 60 quiet scans park the
 * daemon, movement re-arms, hard cap MMCS_L36EV_MAX (default 16).
 * Stub at KILLSTK 0xBF00ED00, dispatch slot evt 0x2A0 (PA
 * 0x0867A054, the evt>>3 formula — the L16 table entry 3; skip when
 * MMCS_L16EV is armed). Needs MMCS_KILLSTK + MMCS_TICK. */
static uint8_t mmcs_l36_stub[] = {
    0x22, 0x4f, 0xe6, 0x2f, 0x19, 0xd4, 0x43, 0x50,  /* +00 */
    0x03, 0xc9, 0x00, 0x88, 0x02, 0x89, 0x25, 0xa0,  /* +08 */
    0x09, 0x00, 0x01, 0xe2, 0x14, 0xd2, 0x12, 0x22,  /* +10 */
    0x15, 0xd3, 0x0b, 0x43, 0x09, 0x00, 0x02, 0xe2,  /* +18 */
    0x11, 0xd2, 0x12, 0x22, 0x01, 0xe1, 0x09, 0x00,  /* +20 */
    0x12, 0xd2, 0x12, 0x22, 0x01, 0xe1, 0x09, 0x00,  /* +28 */
    0x11, 0xd2, 0x12, 0x22, 0x03, 0xe2, 0x09, 0x00,  /* +30 */
    0x0b, 0xd2, 0x12, 0x22, 0x0b, 0xd4, 0x09, 0x00,  /* +38 */
    0x0e, 0xd2, 0x42, 0x22, 0x0e, 0xd2, 0x20, 0x5e,  /* +40 */
    0x04, 0xe2, 0x09, 0x00, 0x06, 0xd2, 0x12, 0x22,  /* +48 */
    0x0c, 0xd3, 0x0b, 0x43, 0x09, 0x00, 0x05, 0xe2,  /* +50 */
    0x03, 0xd2, 0x12, 0x22, 0xf6, 0x6e, 0x26, 0x4f,  /* +58 */
    0x00, 0xe0, 0x0b, 0x00, 0x09, 0x00, 0x09, 0x00,  /* +60 */
    /* pool */
    0x00, 0x00, 0x00, 0x00,   /* +0x68 .Lm: marker cell VA (patched) */
    0x00, 0xd0, 0x6d, 0x90,   /* +0x6c .Lt: thread VA (patched) */
    0xe4, 0x5e, 0x82, 0x90,   /* .Lmk: 0x90825ee4 MakeRun */
    0x84, 0x98, 0x67, 0x88,   /* .Lf: 0x88679884 resched byte */
    0x88, 0x98, 0x67, 0x88,   /* .Lf2: 0x88679888 drain2 word */
    0xa4, 0xef, 0x67, 0x88,   /* .Lpick: 0x8867efa4 */
    0x94, 0x98, 0x67, 0x88,   /* .Lpcur: 0x88679894 */
    0x68, 0x2b, 0x82, 0x90,   /* .Lsw: 0x90822b68 switcher */
};
#define MMCS_L36_STUB_VA   0xBF00ED00
#define MMCS_L36_SLOT_PA   0x0867A054   /* evt 0x2A0, idx 3 */
#define MMCS_L36_QUIET_PARK 60
static uint32_t mmcs_l36_total;
static uint32_t mmcs_l36_quiet;
static uint8_t mmcs_l36_sig[MMCS_L19_NSIG];
static int mmcs_l36_sig_have;

static void mmcs_l36_scan(void)
{
    uint8_t sig[MMCS_L19_NSIG];

    if (mmcs_l36_total >= mmcs_l36_max_deliv) {
        if (mmcs_l36_armed) {
            fprintf(stderr, "MMCS-L36: hard cap %u deliveries reached - "
                    "daemon parked\n", mmcs_l36_total);
            mmcs_l36_armed = 0;
        }
        return;
    }
    mmcs_l19_signature(sig);
    bool moved = mmcs_l36_sig_have
                 && memcmp(sig, mmcs_l36_sig, MMCS_L19_NSIG) != 0;
    memcpy(mmcs_l36_sig, sig, MMCS_L19_NSIG);
    mmcs_l36_sig_have = 1;
    if (moved) {
        mmcs_l36_quiet = 0;
        if (!mmcs_l36_armed) {
            mmcs_l36_armed = 1;
            fprintf(stderr, "MMCS-L36: t=%" PRId64 "ms movement while "
                    "parked - re-armed (%u deliveries used)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l36_total);
        }
    } else if (mmcs_l36_armed && ++mmcs_l36_quiet >= MMCS_L36_QUIET_PARK) {
        fprintf(stderr, "MMCS-L36: t=%" PRId64 "ms %u quiet scans - "
                "daemon parked at %u deliveries\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l36_quiet,
                mmcs_l36_total);
        mmcs_l36_armed = 0;
        mmcs_l36_quiet = 0;
    }
    if (!mmcs_l36_armed) {
        return;
    }
    /* the whole-system-blocked gate: nothing queued at all */
    uint32_t pick = 0, prun = 0;
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    if (pick != 0 || prun != 0) {
        return;
    }
    /* the arena scan: the post-exit lost-preempt thread */
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    int graves = 0;
    uint32_t cand = 0, cand_pc = 0, cand_sp = 0, cand_st = 0;
    for (uint32_t o = 0; o + 0x200 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, pc0, pc1;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&pc0, arena + o + 0xb0, 4);
        memcpy(&pc1, arena + o + 0xb4, 4);
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000) {
            continue;
        }
        uint32_t tva = 0x90680000 + o;
        /* the kill-epilogue graves (both ctx save points) */
        if (pc0 == 0x9083c102 || pc1 == 0x9083c102) {
            graves++;
            continue;
        }
        if (cand || tva == pcur || (st16 & 3) != 0) {
            continue;
        }
        /* outside the OAL idle/timer window, inside the kernel image */
        uint32_t pc = (pc0 >= 0x90820000 && pc0 < 0x90840000) ? pc0 : pc1;
        if (pc < 0x90820000 || pc >= 0x90840000) {
            continue;
        }
        if (pc >= 0x90808000 && pc < 0x9080a000) {
            continue;
        }
        cand = tva;
        cand_pc = pc;
        cand_sp = (pc == pc0) ? pc1 : pc0;
        cand_st = st16;
    }
    if (!cand || !graves) {
        return;                     /* not the post-exit park shape */
    }
    /* deliver: install, THEN patch the pool (.Lt +0x6c thread VA, .Lm
     * +0x68 marker-cell VA) — the L26/L32 order (patch-then-install)
     * silently restores the default .Lt and the delivery no-ops on the
     * wrong thread (live-caught: .Lt readback 0x906dd000 after 10+
     * deliveries) */
    cpu_physical_memory_write(0x1F00ED00, mmcs_l36_stub,
                              sizeof mmcs_l36_stub);
    cpu_physical_memory_write(0x1F00ED00 + 0x6c, &cand, 4);
    cpu_physical_memory_write(0x1F00ED00 + 0x68,
                              &(uint32_t){ MMCS_L36_STUB_VA + 0xf0 }, 4);
    cpu_physical_memory_write(0x1F00EDF0,
                              &(uint32_t){ MMCS_L36_STUB_VA + 0xf0 }, 4);
    uint32_t slot_cur = 0;
    cpu_physical_memory_read(MMCS_L36_SLOT_PA, &slot_cur, 4);
    if (slot_cur != MMCS_L36_STUB_VA) {
        if (slot_cur != 0x90822e40) {
            fprintf(stderr, "MMCS-L36: slot evt 0x2a0 busy (%08x) - "
                    "scan skipped\n", slot_cur);
            return;
        }
        cpu_physical_memory_write(MMCS_L36_SLOT_PA,
                                  &(uint32_t){ MMCS_L36_STUB_VA }, 4);
    }
    struct mmcs_l16_ent *e = &mmcs_l16_ents[3];
    e->evt_va = cand;
    e->stub_va = MMCS_L36_STUB_VA;
    e->evt_code = 0x2A0;
    e->slot_pa = MMCS_L36_SLOT_PA;
    e->daemon = 1;
    e->pending = 1;
    mmcs_l36_total++;
    fprintf(stderr, "MMCS-L36: t=%" PRId64 "ms post-exit requeue thread "
            "%08x (state16 %08x, ctx pc %08x sp %08x, %d graves, "
            "delivery %u/%u)\n",
            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), cand, cand_st,
            cand_pc, cand_sp, graves, mmcs_l36_total, mmcs_l36_max_deliv);
}

/* MMCS fork (L52): MMCS_L52EV — the POST-COMPLETION RESCHED HAND-OFF
 * (the S200 frontier, decoded 2026-11-22; the L51 verdict re-arm made
 * the create-interlock COMPLETE through 100% vendor code and moved
 * the stall one tower-level up).
 *
 * THE STALL (Observed, the L51 tape): the walker 906cb240 frozen
 * RUNNABLE-at-return at pc=0x90837ae8 — the EPILOGUE of the
 * wait-completion dispatcher 0x90837ab0 (the entry TYPE byte's
 * dispatch to the KCall'd helpers 0x90827930/0x90827964 through the
 * KCall dispatcher 0x908230e6) — st16=00001040 (low2=0 RUNNING,
 * bF=00), wobj=0, *CUR*, pc constant t=18259..76852. The launch-loop
 * TBs c00ce888/c00be89a already on the walker's outer frames.
 *
 * THE MECHANISM (Verified disasm): the KCall dispatcher's SR-masked
 * return tail checks BYTE [0x88679884]==1 then WORD [0x88679888]==1 —
 * either set → the resched path 0x9082312c saves the walker's resume
 * point ([th+0xB4]:=pr=0x90837ae8, [th+0xB8]:=SSR, [th+0xB0]:=sp)
 * and bra's the vendor switcher 0x90822b68 with r14=pCurTh. The
 * switcher saved the live r8-r13 into [th+0x94..0xA8], drained, and
 * took the pick==0 IDLE path (0x90822c3c) — the walker was never
 * re-queued (the dead-loader world's lost preempt: state16 low2 stays
 * 0, the pRunnable bands empty), so no drain ever recomputes pick to
 * it; the CPU spins in the OAL idle loop with pCurTh STALE == walker.
 * The L36EV/L37EV daemons EXCLUDE pCurTh; L26EV/L47 target BLOCKED
 * shapes — nothing matches.
 *
 * THE FIX — the L18EV-v4/v5 resched hand-off recipe (the decision
 * table action A), re-targeted at the pCurTh-frozen shape, delivered
 * through 100% vendor code:
 *   MakeRun(0x90825ee4)(walker) — PURE requeue (this session's full
 *     decode: susp-byte guard [th+0xE], state16:=(state16&~3)|1, the
 *     pRunnable-bands insert at 0x8867efa0, saves/restores r8/r9,
 *     PLAIN rts — no internal resched tail)
 *   [0x88679884]:=1 (the switcher-entry flag word)
 *   [0x88679888]:=1 (the drain2 pick recompute)
 *   pick [0x8867efa4]:=walker; r14:=[0x88679894] (== walker here)
 *   jsr the vendor switcher 0x90822b68 — drains, pick==r14 → the
 *   0x90822bcc resume path: spc=[th+0xB4], sp=[th+0xB0],
 *   ssr=[th+0xB8] → rte → the walker executes the epilogue (add #16,
 *   lds pr=[sp+0x10]=0x90837d40, rts, r8 from [sp+0x14]) → the
 *   park-loop fn → CreateProcessW RETURNS to c00ce888 → the launch
 *   loop iterates.
 *
 * THE S200-SPECIFIC HAZARD — THE POISON-NEUTRALIZER (the L49 §8.2
 * register-poison family, now landing on the PRIZE thread): the
 * switcher entry saves the DELIVERY context's live r8-r13 into
 * [r14+0x94..0xA8] — and r14 == pCurTh == the WALKER (stale). In the
 * L36/L37 world that save lands on the interrupted thread's own ctx;
 * here it would OVERWRITE the walker's real saved r8-r13. r9-r13 are
 * callee-saved and flow through 0x90837ab0 (its prologue saves only
 * r8) — poisoning them corrupts the park-loop fn's live values. THE
 * FIX: the v8 stub PRE-LOADS r8-r13 from the walker's own ctx block
 * BEFORE the hand-off chain — the switcher's save then writes back
 * the SAME values (identity). The tick int entry pushes its frame on
 * the STACK, not into the TCB ctx (tape-proven: the walker ctx cells
 * stay constant across 1ms ticks for 58 s), so the block holds the
 * walker's real r8-r13 at delivery time.
 *
 * The v8 guard (in-stub): state16&3 == 0 AND the bF byte [th+0xF]
 * == 0. Markers 1..4 at stub+0xF0 (1 guard passed, 2 MakeRun done,
 * 3 protocol stores done, 4 pre-switcher); marker 5 only if the
 * switcher RETURNS (= no switch — the no-progress tell).
 *
 * The daemon scan (host-side, the L47 discipline): arena thread +
 * tva == pCurTh (THE discriminator — the inverse of L36/L37) +
 * (st16&3)==0 + bF==0 + ctx pc == 0x90837ae8 (the frozen epilogue)
 * + the is_cpw create-body witness + 2-cadence stability keyed
 * {thread,pc} + the world gate pick==0 && pRunnable==0. Repeating,
 * delivery-capped, SELF-TERMINATING (once the walker leaves the
 * epilogue the discriminator stops matching).
 *
 * Stub at KILLSTK 0xBF00E400 (the L16 stub-base block idx 4 — free
 * while MMCS_L16EV is off), dispatch slot evt 0x2E0 (PA 0x0867A05C,
 * ents[5]). Env MMCS_L52EV (default OFF; MMCS_L52EV_MS cadence
 * default 2000; MMCS_L52EV_MAX cap default 4). Needs MMCS_KILLSTK +
 * MMCS_TICK. */
static uint8_t mmcs_l52_stub[] = {
    /* prologue + the state guard (state16&3 == 0, the RUNNING family) */
    0x22, 0x4f, 0xe6, 0x2f, 0x20, 0xd4, 0x43, 0x50,  /* +0x00 */
    0x03, 0xc9, 0x00, 0x88, 0x01, 0x89, 0x34, 0xa0,
    0x09, 0x00,
    /* the bF byte guard ([th+0xF] == 0 — the wait is done) */
    0x4f, 0x84, 0x0c, 0x60, 0x00, 0x88, 0x2f, 0x8b,  /* +0x10 */
    /* the poison-neutralizer preload: r8-r13 := [th+0x94..0xA8] */
    0x43, 0x62, 0x64, 0x72, 0x30, 0x72,
    0x26, 0x68, 0x26, 0x69, 0x26, 0x6a, 0x26, 0x6b,  /* +0x20 */
    0x26, 0x6c, 0x26, 0x6d,
    /* marker 1; MakeRun(walker) */
    0x15, 0xd2, 0x01, 0xe1, 0x12, 0x22, 0x09, 0x00,
    0x15, 0xd3, 0x0b, 0x43, 0x09, 0x00, 0x09, 0x00,  /* +0x30 */
    /* marker 2; the resched protocol stores */
    0x11, 0xd2, 0x02, 0xe1, 0x12, 0x22, 0x09, 0x00,
    0x12, 0xd2, 0x01, 0xe1, 0x12, 0x22, 0x09, 0x00,  /* +0x40 */
    0x11, 0xd2, 0x01, 0xe1, 0x12, 0x22, 0x09, 0x00,
    /* marker 3; pick := walker; r14 := pCurTh; marker 4 */
    0x0b, 0xd2, 0x03, 0xe1, 0x12, 0x22, 0x09, 0x00,  /* +0x50 */
    0x0e, 0xd2, 0x42, 0x22, 0x0e, 0xd2, 0x20, 0x5e,
    0x07, 0xd2, 0x04, 0xe1, 0x12, 0x22, 0x09, 0x00,  /* +0x60 */
    /* the vendor switcher jsr; marker 5 (no-switch tell); epilogue */
    0x0c, 0xd3, 0x0b, 0x43, 0x09, 0x00, 0x09, 0x00,
    0x03, 0xd2, 0x05, 0xe1, 0x12, 0x22, 0xf6, 0x6e,  /* +0x70 */
    0x26, 0x4f, 0x00, 0xe0, 0x0b, 0x00, 0x09, 0x00,
    /* pool (patched at delivery: .Lm +0x84, .Lcand +0x88) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* +0x80 */
    0xe4, 0x5e, 0x82, 0x90,   /* +0x8c .Lmk: 0x90825ee4 MakeRun */
    0x84, 0x98, 0x67, 0x88,   /* +0x90 .Lf: 0x88679884 resched flag */
    0x88, 0x98, 0x67, 0x88,   /* +0x94 .Lf2: 0x88679888 drain2 word */
    0xa4, 0xef, 0x67, 0x88,   /* +0x98 .Lpick: 0x8867efa4 */
    0x94, 0x98, 0x67, 0x88,   /* +0x9c .Lpcur: 0x88679894 */
    0x68, 0x2b, 0x82, 0x90,   /* +0xa0 .Lsw: 0x90822b68 the switcher */
};
#define MMCS_L52_STUB_VA   0xBF00E400
#define MMCS_L52_SLOT_PA   0x0867A05C   /* evt 0x2E0, idx 5 */
#define MMCS_L52_EPILOGUE_PC 0x90837AE8 /* the frozen dispatcher epilogue */

static void mmcs_l52_scan(void)
{
    if (!mmcs_l52_armed || mmcs_l52_total >= mmcs_l52_max_deliv) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0, pick = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    for (uint32_t o = 0; o + 0x210 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, ctxpc, ctxsp;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&ctxsp, arena + o + 0xb0, 4);
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000
            || tva != pcur                     /* THE discriminator */
            || (st16 & 3) != 0                 /* RUNNING/lost-preempt */
            || (st16 >> 24) != 0               /* bF cleared */
            || ctxpc != MMCS_L52_EPILOGUE_PC   /* frozen at the epilogue */
            /* the dead-idle world gate: pick==0 (nothing queued) OR
             * pick==tva (the drain2 keep-current bookkeeping — the
             * LIVE S200 shape: the tape reads pick == walker while
             * the CPU idles; someone ELSE's pick = vendor world
             * mid-flight, skip) */
            || (pick != 0 && pick != tva)
            || prun != 0) {
            continue;
        }
        /* the create-body kstack witness (is_cpw — the L46 window) */
        uint32_t ssp = ctxsp;
        int is_cpw = 0;
        if (ssp >= 0xD0000000 && ssp < 0xDC000000) {
            for (uint32_t sa = ssp; sa < ssp + 0x80; sa += 4) {
                uint32_t pa3 = mmcs_l32_stack_pa(sa);
                uint32_t w3 = 0;
                if (!pa3) {
                    continue;
                }
                cpu_physical_memory_read(pa3, &w3, 4);
                if (w3 >= 0x9082ce00 && w3 < 0x9082ed00) {
                    is_cpw = 1;
                    break;
                }
            }
        }
        if (!is_cpw) {
            continue;
        }
        /* 2-cadence stability keyed {thread,pc} (the L46 discipline) */
        uint32_t key = tva ^ ctxpc;
        if (mmcs_l52_key != key) {
            mmcs_l52_key = key;
            mmcs_l52_stable = 1;
            fprintf(stderr, "MMCS-L52: t=%" PRId64 "ms frozen shape "
                    "seen: th %08x *CUR* st16=%08x pc=%08x sp=%08x "
                    "(stability %u/2)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, st16,
                    ctxpc, ctxsp, mmcs_l52_stable);
            return;
        }
        if (++mmcs_l52_stable < 2) {
            return;
        }
        /* DELIVER — install, THEN patch the pool (the L36 order) */
        cpu_physical_memory_write(0x1F00E400, mmcs_l52_stub,
                                  sizeof mmcs_l52_stub);
        cpu_physical_memory_write(0x1F00E400 + 0x88, &tva, 4);
        cpu_physical_memory_write(0x1F00E400 + 0x84,
                                  &(uint32_t){ MMCS_L52_STUB_VA + 0xf0 },
                                  4);
        cpu_physical_memory_write(0x1F00E4F0,
                                  &(uint32_t){ MMCS_L52_STUB_VA + 0xf0 },
                                  4);
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L52_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L52_STUB_VA) {
            if (slot_cur != 0x90822e40) {
                fprintf(stderr, "MMCS-L52: slot evt 0x2e0 busy (%08x) - "
                        "scan skipped\n", slot_cur);
                return;
            }
            cpu_physical_memory_write(MMCS_L52_SLOT_PA,
                                      &(uint32_t){ MMCS_L52_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[5];
        e->evt_va = tva;
        e->stub_va = MMCS_L52_STUB_VA;
        e->evt_code = 0x2E0;
        e->slot_pa = MMCS_L52_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l52_total++;
        fprintf(stderr, "MMCS-L52: t=%" PRId64 "ms resched hand-off "
                "%u/%u: walker %08x *CUR* st16=%08x (MakeRun + stores + "
                "pick + the vendor switcher; markers at %08x)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l52_total,
                mmcs_l52_max_deliv, tva, st16,
                MMCS_L52_STUB_VA + 0xf0);
        return;                     /* one delivery per cadence */
    }
    /* no frozen shape this scan — reset the stability tracker */
    mmcs_l52_key = 0;
    mmcs_l52_stable = 0;
}

/* MMCS fork (L53): MMCS_L53EV — THE COMPLETION-HELPER SPIN (S201,
 * decoded 2026-11-22; the L52 hand-off made the walker LIVE but it
 * spins in the park fn's exit cleanup — the spin is print-silent,
 * serial 720, era park).
 *
 * THE SPIN (Verified disasm + Observed tape): the park fn 0x90837bd0's
 * exit runs the CLEANUP-DISPATCH LOOP 0x90837d3a-44 — `jsr the
 * wait-completion dispatcher 0x90837ab0(entry)` then `r8 := [r8+16]`,
 * repeating while the link != 0 — terminating ONLY on a zero chain
 * link. The +16 field is DUAL-USE: the block-chain during the wait
 * (the init fn 0x90837b30: [b+16] = b+36, last = 0) and the FREE-LIST
 * link after the eval 0x90828244's common tail 0x9082846e-88 pops the
 * completed head [pTh+0x1F8] and pushes the entry onto the free list
 * ([entry+16] := [pTh+52]; [pTh+52] := entry). The L47-era repair
 * cycles re-completed the SAME entry (the L50b counter walk 2->5) —
 * each re-completion re-pushed block0, and the push found the free
 * head ALREADY == block0: [block0+16] == block0 (Observed:
 * [d00bf660] == d00bf650, constant across the whole live tape) — THE
 * SELF-LOOP. The cleanup loop then dispatches block0 forever: the
 * dispatcher's TYPE-4 path KCalls helper B 0x90827964, which reads
 * [entry+12] == 0 (already unlinked) and early-returns without a
 * write — 100% live, never terminating. THE WALKER'S REGISTER
 * SNAPSHOTS (the L52b probe): pc 0x908230e6/0x908230f6 at the KCall
 * wrapper, pr = 0x90837ae8 (the dispatcher epilogue), r4 = d00bf650,
 * r3 = 0x90827964 — and the anchor pair on the walker's kstack:
 * [d00bf620] = 0x90837d40 (the dispatcher's pushed pr = the cleanup
 * jsr's return) with [d00bf624] = d00bf650 (the pushed r8 = the
 * entry).
 *
 * THE FIX — THE CHAIN-END RESTORE: write [entry+16] := 0 — the exact
 * value the stock single-completion world leaves (the free-push onto
 * a list not already holding the entry; the stock wake chain's own
 * bookkeeping — the dead-loader world's double-push is OUR repair-era
 * artifact). The same repair family as the L50b wait-result-cache
 * write: ONE WORD, guest-side bookkeeping restored, no stub, no slot,
 * no manufactured feeder. After the write the loop's next
 * `mov.l @(16,r8),r8` reads 0 -> the walk ends -> 0x90837d46 (r9 ==
 * sp+40, the <=4-handles init identity) -> the plain exit 0x90837d72
 * -> THE PARK FN RETURNS r0 = r10 (the eval's last result — the
 * cached [pTh+0x1FC] = 0x1000) -> the fold/postwait chain ->
 * CreateProcessW RETURNS to c00ce888 -> the launch loop iterates.
 *
 * RACE SAFETY (Verified): with [entry+12] == 0 helper B only reads
 * +12 and returns (no writes); the dispatcher writes only its own
 * pushed frame; the loop re-reads +16 every iteration; the tick int
 * entry pushes below sp (the entry lives above it). The free list
 * [pTh+52] stays = block0, now a VALID 1-deep list (block0 -> 0).
 *
 * The daemon scan (host-side, the L52 discipline): arena thread +
 * tva == pCurTh (the live-spin shape) + (st16&3)==0 + bF==0 + ctxpc
 * in the spin cycle set {0x908230e6, 0x908230f6, 0x90837ae8} (the
 * KCall-wrapper/epilogue resched saves) + the is_cpw create-body
 * witness + THE SPIN SIGNATURE: the anchor pair {0x90837d40, E} in
 * the kstack window [ctxsp-0x40, ctxsp+0x180) with E a stack address
 * on this frame and [E+16] == E (the self-loop) and [E+12] == 0
 * (drained — helper B already no-ops) + 2-cadence stability keyed
 * {thread,entry}. Repeating, delivery-capped (default 4),
 * SELF-TERMINATING (the signature needs the self-loop; after the
 * write it reads 0). Env MMCS_L53EV (default OFF; MMCS_L53EV_MS
 * cadence default 2000; MMCS_L53EV_MAX cap default 4). Needs
 * MMCS_TICK. */
static void mmcs_l53_scan(void)
{
    if (!mmcs_l53_armed || mmcs_l53_total >= mmcs_l53_max_deliv) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    for (uint32_t o = 0; o + 0x210 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, ctxpc, ctxsp;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&ctxsp, arena + o + 0xb0, 4);
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000
            || tva != pcur                     /* the live-spin shape */
            || (st16 & 3) != 0                 /* RUNNING bookkeeping */
            || (st16 >> 24) != 0               /* bF cleared */
            || (ctxpc != 0x908230e6 && ctxpc != 0x908230f6
                && ctxpc != 0x90837ae8)) {     /* the spin cycle set */
            continue;
        }
        /* the create-body kstack witness (is_cpw — the L46 window) */
        uint32_t ssp = ctxsp;
        int is_cpw = 0;
        if (ssp >= 0xD0000000 && ssp < 0xDC000000) {
            for (uint32_t sa = ssp; sa < ssp + 0x80; sa += 4) {
                uint32_t pa3 = mmcs_l32_stack_pa(sa);
                uint32_t w3 = 0;
                if (!pa3) {
                    continue;
                }
                cpu_physical_memory_read(pa3, &w3, 4);
                if (w3 >= 0x9082ce00 && w3 < 0x9082ed00) {
                    is_cpw = 1;
                    break;
                }
            }
        }
        if (!is_cpw) {
            continue;
        }
        /* THE SPIN SIGNATURE: the cleanup-loop anchor pair
         * {0x90837d40, E} in the kstack window with [E+16] == E
         * (the self-loop) and [E+12] == 0 (drained) */
        uint32_t entry = 0;
        if (ssp >= 0xD0000000 && ssp < 0xDC000000) {
            for (uint32_t sa = ssp - 0x40; sa + 4 < ssp + 0x180;
                 sa += 4) {
                uint32_t pa3 = mmcs_l32_stack_pa(sa);
                uint32_t w3 = 0;
                if (!pa3) {
                    continue;
                }
                cpu_physical_memory_read(pa3, &w3, 4);
                if (w3 != 0x90837d40) {
                    continue;           /* not the cleanup-jsr anchor */
                }
                uint32_t pa4 = mmcs_l32_stack_pa(sa + 4);
                uint32_t cand = 0;
                if (!pa4) {
                    continue;
                }
                cpu_physical_memory_read(pa4, &cand, 4);
                if (cand < 0xD0000000 || cand >= 0xDC000000
                    || cand < ssp - 0x40 || cand >= ssp + 0x400) {
                    continue;           /* not a block on this frame */
                }
                uint32_t pa16 = mmcs_l32_stack_pa(cand + 0x10);
                uint32_t w16 = 0;
                if (!pa16) {
                    continue;
                }
                cpu_physical_memory_read(pa16, &w16, 4);
                if (w16 != cand) {
                    continue;           /* link not the self-loop */
                }
                uint32_t pa12 = mmcs_l32_stack_pa(cand + 0xc);
                uint32_t w12 = 0;
                if (pa12) {
                    cpu_physical_memory_read(pa12, &w12, 4);
                }
                if (w12 != 0) {
                    continue;           /* still linked — not drained */
                }
                entry = cand;
                break;
            }
        }
        if (!entry) {
            continue;
        }
        /* 2-cadence stability keyed {thread,entry} (the L46/L52
         * discipline — the signature must persist across scans) */
        uint32_t key = tva ^ entry;
        if (mmcs_l53_key != key) {
            mmcs_l53_key = key;
            mmcs_l53_stable = 1;
            fprintf(stderr, "MMCS-L53: t=%" PRId64 "ms spin shape seen: "
                    "th %08x *CUR* pc=%08x entry %08x [E+16]=%08x "
                    "(stability %u/2)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, ctxpc,
                    entry, entry, mmcs_l53_stable);
            return;
        }
        if (++mmcs_l53_stable < 2) {
            return;
        }
        /* DELIVER — the chain-end restore: [entry+16] := 0 */
        uint32_t pa_w = mmcs_l32_stack_pa(entry + 0x10);
        if (!pa_w) {
            fprintf(stderr, "MMCS-L53: entry %08x +0x10 unmapped - "
                    "skip\n", entry);
            return;
        }
        cpu_physical_memory_write(pa_w, &(uint32_t){ 0 }, 4);
        mmcs_l53_total++;
        fprintf(stderr, "MMCS-L53: t=%" PRId64 "ms chain-end restore "
                "%u/%u: walker %08x entry %08x [E+16] := 0 (the cleanup "
                "walk ends -> the park fn returns r10=0x1000)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l53_total,
                mmcs_l53_max_deliv, tva, entry);
        return;                     /* one delivery per cadence */
    }
    /* no spin shape this scan — reset the stability tracker */
    mmcs_l53_key = 0;
    mmcs_l53_stable = 0;
}

/* MMCS fork (L54): MMCS_L54EV — THE STALE-pCurTh RE-PARK WAKE (S202,
 * decoded 2026-11-22; the S201 rung made the park fn RETURN r0=r10
 * through 100% vendor code — then the fold pass completed and the
 * wait fn's tail 0x9083d41c re-parked the walker at the face with
 * pCurTh STALE == the walker: the S181 dead-idle world).
 *
 * THE STALL (Observed, the L53 verify tape): the walker 906cb240
 * re-parked BLOCKED at pc=0x90837cf6 (st16=02001042, bF=02, sp=
 * d00bf628, wobj=d00bf640, tmo=ffffffff INFINITE), f1f8=0 (drained),
 * t1fc=00001000 (the L50b cache intact), the live kstack return at
 * [sp+0x58]=0x908305a8 = fn_90830444's TAIL jsr 0x9083d41c (the
 * block-until-signaled submit — the fold-pass frames already
 * returned; the [sp+4]=0x9082ec86 residue is the earlier cycle's),
 * pick=0/pRunnable=0, pCurTh STALE == the walker. The L47 daemon's
 * tva != pcur exclusion can never fire; the L52 daemon wants
 * bF==0 + the epilogue pc; the L53 signature is gone — the wake
 * channel is starved BY the stale-pCurTh shape.
 *
 * THE MECHANISM (Verified disasm, the L54 Part 1 decode): the
 * create body's wait is a WAIT-ALL (fn_90830444 flags bit 12 → the
 * fold pass 0x90830518-0x90830546); post-S201 the fold completed
 * and the tail's submit parked the walker — a STOCK park waiting
 * for the interlock event the dead loader will never set. The
 * stock wake (the event SET chain) died with the loader world.
 *
 * THE FIX — the L47-class satisfy RE-TARGETED at tva==pcur, gated
 * on the dead-idle world (the L52b refinement: pick==0 OR
 * pick==cand — someone ELSE's pick = vendor mid-flight, SKIP),
 * delivered through THE V9 STUB = the L52 v8 recipe with the L26
 * v7 guard class for the BLOCKED shape:
 *   in-stub guard: (state16 & 3) == 2 (BLOCKED — MakeRun's class)
 *   THE POISON-NEUTRALIZER PRELOAD: r8-r13 := [th+0x94..0xA8] —
 *     the switcher's entry save lands on the walker's OWN ctx
 *     (r14 == pCurTh == walker, stale) AND the resume-at-the-face
 *     needs the walker's true r8 (the entry pointer) for the
 *     [r8+12] state poll — the ctx-block preload IS the
 *     stock-faithful frame restore for this shape (the L49 §8.2
 *     family neutralized)
 *   MakeRun 0x90825ee4 (the requeue) + the resched protocol
 *   stores ([0x88679884]:=1, [0x88679888]:=1) + pick:=walker +
 *   r14:=[0x88679894] + jsr the vendor switcher 0x90822b68 →
 *   drains recompute pick==r14 → the 0x90822bcc resume path →
 *   spc=[th+0xB4]=0x90837cf6 → rte → the poll → the eval (with
 *   the plants: the REAL type-4 satisfy) → the park fn returns
 *   0x1000 → the 0x9083d41c tail RETURNS → fn_90830444 returns →
 *   the servant marshal → the create body proceeds →
 *   CreateProcessW RETURNS to c00ce888.
 * The plants are the L47 chain verbatim (the true base, the type
 * byte, the dual 0x1000 result cells, the verdict re-arm, the sig
 * SET). The co-delivery hazard stays covered by the L49 guard
 * (the L26 scan skips the LINKED create-interlock class whenever
 * MMCS_L47FIX is armed — the standing combo always co-arms).
 *
 * Host filter: the L47 discriminators (arena, BLOCKED(2), the face
 * pc, the wobj resolution through the walker's OWN pTh-matched
 * wait-array entry, sig==0 consumed, wlh!=0 LINKED, the is_cpw
 * witness, the [th+0x150] filesys witness) MINUS the tva!=pcur
 * exclusion PLUS tva == pCurTh (THE discriminator — the inverse of
 * L47) + the dead-idle world gate + 2-cadence stability keyed
 * {thread,obj} (the L46 discipline). Repeating, delivery-capped
 * (default 4), SELF-TERMINATING (the shape dies when the wait
 * completes or the world moves).
 *
 * Stub v9 at KILLSTK 0xBF00E600 (block idx 6 — free while
 * MMCS_L16EV is off), dispatch slot evt 0x320 (PA 0x0867A064,
 * ents[7] — evt 0x300 is reserved for the L18 self-registered
 * ISR). Env MMCS_L54EV (default OFF; MMCS_L54EV_MS cadence default
 * 2000; MMCS_L54EV_MAX cap default 4). Needs MMCS_TICK. */
static uint8_t mmcs_l54_stub[] = {
    /* prologue + the state guard (state16&3 == 2, the BLOCKED family) */
    0x22, 0x4f, 0xe6, 0x2f, 0x20, 0xd4, 0x43, 0x50,  /* +0x00 */
    0x03, 0xc9, 0x02, 0x88, 0x01, 0x89, 0x34, 0xa0,
    0x09, 0x00,
    /* (the v8's bF==0 guard dropped — the BLOCKED waiter's bF is
     * the waiting flag itself; nops keep the layout) */
    0x09, 0x00, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00,  /* +0x10 */
    /* the poison-neutralizer preload: r8-r13 := [th+0x94..0xA8] */
    0x43, 0x62, 0x64, 0x72, 0x30, 0x72,
    0x26, 0x68, 0x26, 0x69, 0x26, 0x6a, 0x26, 0x6b,  /* +0x20 */
    0x26, 0x6c, 0x26, 0x6d,
    /* marker 1; MakeRun(walker) */
    0x15, 0xd2, 0x01, 0xe1, 0x12, 0x22, 0x09, 0x00,
    0x15, 0xd3, 0x0b, 0x43, 0x09, 0x00, 0x09, 0x00,  /* +0x30 */
    /* marker 2; the resched protocol stores */
    0x11, 0xd2, 0x02, 0xe1, 0x12, 0x22, 0x09, 0x00,
    0x12, 0xd2, 0x01, 0xe1, 0x12, 0x22, 0x09, 0x00,  /* +0x40 */
    0x11, 0xd2, 0x01, 0xe1, 0x12, 0x22, 0x09, 0x00,
    /* marker 3; pick := walker; r14 := pCurTh; marker 4 */
    0x0b, 0xd2, 0x03, 0xe1, 0x12, 0x22, 0x09, 0x00,  /* +0x50 */
    0x0e, 0xd2, 0x42, 0x22, 0x0e, 0xd2, 0x20, 0x5e,
    0x07, 0xd2, 0x04, 0xe1, 0x12, 0x22, 0x09, 0x00,  /* +0x60 */
    /* the vendor switcher jsr; marker 5 (no-switch tell); epilogue */
    0x0c, 0xd3, 0x0b, 0x43, 0x09, 0x00, 0x09, 0x00,
    0x03, 0xd2, 0x05, 0xe1, 0x12, 0x22, 0xf6, 0x6e,  /* +0x70 */
    0x26, 0x4f, 0x00, 0xe0, 0x0b, 0x00, 0x09, 0x00,
    /* pool (patched at delivery: .Lm +0x84, .Lcand +0x88) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* +0x80 */
    0xe4, 0x5e, 0x82, 0x90,   /* +0x8c .Lmk: 0x90825ee4 MakeRun */
    0x84, 0x98, 0x67, 0x88,   /* +0x90 .Lf: 0x88679884 resched flag */
    0x88, 0x98, 0x67, 0x88,   /* +0x94 .Lf2: 0x88679888 drain2 word */
    0xa4, 0xef, 0x67, 0x88,   /* +0x98 .Lpick: 0x8867efa4 */
    0x94, 0x98, 0x67, 0x88,   /* +0x9c .Lpcur: 0x88679894 */
    0x68, 0x2b, 0x82, 0x90,   /* +0xa0 .Lsw: 0x90822b68 the switcher */
};
#define MMCS_L54_STUB_VA   0xBF00E600
#define MMCS_L54_SLOT_PA   0x0867A064   /* evt 0x320, idx 7 */

/* MMCS fork (L57/S206): the v10 wake stub — v9 + THE INTERRUPTED-
 * CURRENT REQUEUE. The S206 decode: the vendor switcher 0x90822b68
 * saves the outgoing thread ([old+0x94..0xA8] regs + SR at +0xA4 :=
 * 0x102, [old+0x60]:=0) and switches to pick, but NEVER requeues the
 * old current — in stock the scheduler's preempt path re-inserts the
 * current into the ready list BEFORE picking; the v9 stub bypassed
 * that (harmless in the L54/L55 dead-idle self-switch worlds; in the
 * L56 two-live-thread world it ORPHANED the launcher: switched out
 * mid-KCall-submit, st16 RUNNING-class, off the pick path forever).
 * THE FIX: after MakeRun(target), old := [0x88679894]; if old !=
 * target -> MakeRun(old) (the vendor's own 0x90825ee4: the +0xE
 * suspended guard, st16:=(s&~3)|1, the [th+0x41]-priority enqueue
 * into the DAT_90826048 buckets, the resched flag). The old==target
 * guard is the double-list-insert corruption protector (the L54/L55
 * worlds switch the walker to itself). LAYOUT: a 20-byte insertion at
 * +0x3c (instruction and pool shift equally — every v9 pc-relative
 * displacement stays valid; the pool stays 4-aligned); pool +20:
 * .Lm +0x98, .Lcand +0x9c, .Lmk +0xa0, .Lf +0xa4, .Lf2 +0xa8,
 * .Lpick +0xac, .Lpcur +0xb0, .Lsw +0xb4. 184 bytes, capstone-
 * verified against QEMU's own decode table (target/sh4/translate.c:
 * cmp/eq Rm,Rn = 0x3000 — the 0x3004 nibble is div1, the first
 * draft's trap). Env MMCS_L57EV (default OFF) — rides the L56
 * delivery (requires MMCS_L56EV). */
static uint8_t mmcs_l57_stub[] = {
    0x22, 0x4f, 0xe6, 0x2f, 0x25, 0xd4, 0x43, 0x50,
    0x03, 0xc9, 0x02, 0x88, 0x01, 0x89, 0x3e, 0xa0,
    0x09, 0x00, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00,
    0x09, 0x00, 0x43, 0x62, 0x64, 0x72, 0x30, 0x72,
    0x26, 0x68, 0x26, 0x69, 0x26, 0x6a, 0x26, 0x6b,
    0x26, 0x6c, 0x26, 0x6d, 0x1a, 0xd2, 0x01, 0xe1,
    0x12, 0x22, 0x09, 0x00, 0x1a, 0xd3, 0x0b, 0x43,
    0x09, 0x00, 0x09, 0x00, 0x1c, 0xd4, 0x42, 0x64,
    0x16, 0xd5, 0x50, 0x34, 0x04, 0x89, 0x09, 0x00,
    0x15, 0xd3, 0x0b, 0x43, 0x09, 0x00, 0x09, 0x00,
    0x11, 0xd2, 0x02, 0xe1, 0x12, 0x22, 0x09, 0x00,
    0x12, 0xd2, 0x01, 0xe1, 0x12, 0x22, 0x09, 0x00,
    0x11, 0xd2, 0x01, 0xe1, 0x12, 0x22, 0x09, 0x00,
    0x0b, 0xd2, 0x03, 0xe1, 0x12, 0x22, 0x09, 0x00,
    0x0e, 0xd2, 0x42, 0x22, 0x0e, 0xd2, 0x20, 0x5e,
    0x07, 0xd2, 0x04, 0xe1, 0x12, 0x22, 0x09, 0x00,
    0x0c, 0xd3, 0x0b, 0x43, 0x09, 0x00, 0x09, 0x00,
    0x03, 0xd2, 0x05, 0xe1, 0x12, 0x22, 0xf6, 0x6e,
    0x26, 0x4f, 0x00, 0xe0, 0x0b, 0x00, 0x09, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe4, 0x5e, 0x82, 0x90, 0x84, 0x98, 0x67, 0x88,
    0x88, 0x98, 0x67, 0x88, 0xa4, 0xef, 0x67, 0x88,
    0x94, 0x98, 0x67, 0x88, 0x68, 0x2b, 0x82, 0x90,
};

static void mmcs_l54_scan(void)
{
    if (!mmcs_l54_armed || mmcs_l54_total >= mmcs_l54_max_deliv) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0, pick = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    /* THE DEAD-IDLE WORLD GATE (the L52b refinement): pick==0 OR
     * pick==cand (the keep-current bookkeeping); someone ELSE's
     * pick = vendor mid-flight — SKIP */
    if (prun != 0 || (pick != 0 && pick != pcur)) {
        return;
    }
    for (uint32_t o = 0; o + 0x200 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, ctxpc, wobj, wret;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&wobj, arena + o + 0x14c, 4);
        memcpy(&wret, arena + o + 0x150, 4);
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000
            || (st16 & 3) != 2
            || ctxpc != 0x90837cf6
            || wobj < 0xD0000000 || wobj >= 0xDC000000
            || wret < 0xC0000000 || wret >= 0xC1000000
            || tva != pcur) {           /* THE discriminator — the
                                          * INVERSE of the L47 scan */
            continue;
        }
        /* resolve the waited object through the walker's own
         * wait-array entry (the L32EV/L47 resolver) */
        uint32_t obj = 0, wi_found = 0;
        for (uint32_t wi = 0; wi <= 0x80; wi += 4) {
            uint32_t pa1 = mmcs_l32_stack_pa(wobj + wi + 0x14);
            uint32_t w1 = 0;
            if (!pa1) {
                continue;
            }
            cpu_physical_memory_read(pa1, &w1, 4);
            if (w1 != tva) {
                continue;
            }
            uint32_t pa2 = mmcs_l32_stack_pa(wobj + wi + 0xC);
            if (pa2) {
                cpu_physical_memory_read(pa2, &obj, 4);
            }
            wi_found = wi;
            break;
        }
        if (obj < 0x90680000 || obj >= 0x90780000) {
            continue;               /* not an arena kernel object */
        }
        uint8_t sig54 = 0;
        cpu_physical_memory_read(obj - 0x80000000 + 0x8d, &sig54, 1);
        if (sig54 & 1) {
            continue;               /* signaled — vendor world moving */
        }
        uint32_t wlh = 0;
        cpu_physical_memory_read(obj - 0x80000000 + 8, &wlh, 4);
        if (wlh == 0) {
            continue;               /* unlinked = L32EV's class */
        }
        /* the create-body kstack witness (is_cpw — the L46 window) */
        uint32_t ssp = 0, is_cpw = 0;
        cpu_physical_memory_read(tva - 0x80000000 + 0xb0, &ssp, 4);
        if (ssp >= 0xD0000000 && ssp < 0xDC000000) {
            for (uint32_t sa = ssp; sa < ssp + 0x80; sa += 4) {
                uint32_t pa3 = mmcs_l32_stack_pa(sa);
                uint32_t w3 = 0;
                if (!pa3) {
                    continue;
                }
                cpu_physical_memory_read(pa3, &w3, 4);
                if (w3 >= 0x9082ce00 && w3 < 0x9082ed00) {
                    is_cpw = 1;
                    break;
                }
            }
        }
        if (!is_cpw) {
            continue;
        }
        /* the eval's entry base derived dynamically (the L47
         * frame-wobble discipline: entry = wobj + wi - 8, VERIFIED
         * against the resolved object before planting) */
        if (!wi_found || wi_found < 8) {
            continue;               /* resolver lost the entry — skip */
        }
        uint32_t entry54 = wobj + wi_found - 8;
        uint32_t pa_e = mmcs_l32_stack_pa(entry54 + 0x14);
        uint32_t objchk = 0;
        if (pa_e) {
            cpu_physical_memory_read(pa_e, &objchk, 4);
        }
        if (!pa_e || objchk != obj) {
            fprintf(stderr, "MMCS-L54: entry verify FAILED (entry %08x "
                    "objchk %08x vs obj %08x) - skip\n",
                    entry54, objchk, obj);
            continue;
        }
        /* 2-cadence stability keyed {thread,obj} (the L46/L52
         * discipline — the shape must persist across scans) */
        uint32_t key = tva ^ obj;
        if (mmcs_l54_key != key) {
            mmcs_l54_key = key;
            mmcs_l54_stable = 1;
            fprintf(stderr, "MMCS-L54: t=%" PRId64 "ms stale-pCurTh park "
                    "seen: th %08x *CUR* st16=%08x pc=%08x obj %08x "
                    "sig %02x wlh %08x (stability %u/2; pick %08x)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, st16,
                    ctxpc, obj, sig54, wlh, mmcs_l54_stable, pick);
            return;
        }
        if (++mmcs_l54_stable < 2) {
            return;
        }
        /* DELIVER — the L47 plants, then the v9 wake */
        /* (1) the ctx cell: the true entry base */
        cpu_physical_memory_write(tva - 0x80000000 + 0x1f8,
                                  &entry54, 4);
        /* (2) the type byte: entry+0x18's low byte carries EVNT(4) */
        uint32_t pa_t = mmcs_l32_stack_pa(entry54 + 0x18);
        if (pa_t) {
            uint32_t fw = 0;
            cpu_physical_memory_read(pa_t, &fw, 4);
            if ((fw & 0xff) != 0x04) {
                fw = (fw & 0xffffff00) | 0x04;
                cpu_physical_memory_write(pa_t, &fw, 4);
            }
        }
        /* (3) the result cells := 0x1000 (the satisfy tail + the
         * wait-result cache — the S198 dual-cell write) */
        uint32_t res54 = 0x1000;
        uint32_t pa_r = mmcs_l32_stack_pa(entry54 + 0x20);
        if (pa_r) {
            uint32_t cur = 0;
            cpu_physical_memory_read(pa_r, &cur, 4);
            if (cur != 0x1000) {
                cpu_physical_memory_write(pa_r, &res54, 4);
            }
        }
        cpu_physical_memory_write(tva - 0x80000000 + 0x1fc,
                                  &res54, 4);
        /* (3b) the S199 verdict re-arm — [sp+0x10] := 2 when 0 */
        {
            uint32_t vsp = 0;
            cpu_physical_memory_read(tva - 0x80000000 + 0xb0, &vsp, 4);
            if (vsp >= 0xD0000000 && vsp < 0xDC000000) {
                uint32_t pa_v = mmcs_l32_stack_pa(vsp + 0x10);
                if (pa_v) {
                    uint32_t verdict = 0;
                    cpu_physical_memory_read(pa_v, &verdict, 4);
                    if (verdict == 0) {
                        cpu_physical_memory_write(
                            pa_v, &(uint32_t){ 2 }, 4);
                    }
                }
            }
        }
        /* (4) the stock SET: sig byte |= 1 */
        sig54 |= 1;
        cpu_physical_memory_write(obj - 0x80000000 + 0x8d, &sig54, 1);
        /* (5) THE V9 WAKE — install, THEN patch the pool (the L36
         * order), then the slot */
        cpu_physical_memory_write(0x1F00E600, mmcs_l54_stub,
                                  sizeof mmcs_l54_stub);
        cpu_physical_memory_write(0x1F00E600 + 0x88, &tva, 4);
        cpu_physical_memory_write(0x1F00E600 + 0x84,
                                  &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 },
                                  4);
        cpu_physical_memory_write(0x1F00E6F0,
                                  &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 },
                                  4);
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L54_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L54_STUB_VA) {
            if (slot_cur != 0x90822e40) {
                fprintf(stderr, "MMCS-L54: slot evt 0x320 busy (%08x) - "
                        "retry next cadence\n", slot_cur);
                return;
            }
            cpu_physical_memory_write(MMCS_L54_SLOT_PA,
                                      &(uint32_t){ MMCS_L54_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[7];
        e->evt_va = tva;
        e->stub_va = MMCS_L54_STUB_VA;
        e->evt_code = 0x320;
        e->slot_pa = MMCS_L54_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l54_total++;
        fprintf(stderr, "MMCS-L54: t=%" PRId64 "ms stale-pCurTh wake "
                "%u/%u: walker %08x *CUR* obj %08x entry %08x sig "
                "00->01 (the L47 plants + the v9 wake: MakeRun + the "
                "resched hand-off; markers at %08x)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l54_total,
                mmcs_l54_max_deliv, tva, obj, entry54,
                MMCS_L54_STUB_VA + 0xf0);
        return;                     /* one delivery per cadence */
    }
    /* no stale-pCurTh park this scan — reset the stability tracker */
    mmcs_l54_key = 0;
    mmcs_l54_stable = 0;
}

/* MMCS fork (L55): MMCS_L55EV — THE WAIT'S INTERNAL SATISFACTION
 * CHECK: the chained DUAL-ENTRY delivery (S203, decoded 2026-11-22).
 *
 * THE DECODE (this session, Verified disasm + the live probes):
 * the wait fn 0x90830444's TAIL 0x9083d41c is zone-gated OFF in this
 * world ([base+0x368] reads 0 live) — the re-submit is NOT the tail;
 * the cycle runs in the park fn 0x90837bcc's FACE LOOP (the eval
 * KCall fn_90828244): each eval consumes ONE completed-list head
 * ([pTh+0x1F8]), and when the head is EMPTY + the tmo cell
 * [pTh+0x200] == -1 the re-block path fires (verdict := 0, bF := 2,
 * state := BLOCKED, [base+0x88] := 1 — the frozen KCall-return park
 * at the face pc 0x90837cf6). The L54 delivery plants ONE completed
 * entry per cycle: the satisfy consumes it (the count [pTh+0x66]
 * walks +1), the park fn returns 0x1000, but the WAIT-ALL driver
 * (0x90837e24 — the park fn's caller at 0x90837ed2, its per-element
 * validate loop 0x90837e78 resolving each psi word through
 * 0x9082d460 into the driver's results array) re-checks the OTHER
 * element, finds it still owed, and re-submits — the same frames
 * rebuild at the same sp. ONE delivery can never finish a
 * two-element WAIT-ALL: the stock world satisfies BOTH before the
 * re-check (the completed list carries both entries chained via
 * +0x10; the face's cleanup-dispatch loop 0x90837d3a walks the whole
 * chain).
 *
 * THE FIX — the stock manual-reset shape + the ghost's sig: the
 * eval's type-4 satisfy runs [obj+0x8D] := [obj+0x8E] (Verified
 * 0x908283ae-0x908283b8) — the L47/L54 world set 0x8D only (the
 * auto-reset shape: one satisfy consumes the bit and the driver-
 * level re-check reads it CLEAR — the re-submit forever). The
 * stock manual-reset event keeps BOTH cells set (0x8D for the
 * wake, 0x8E as the post-consume sig), and the ghost namespace
 * node (the psi element whose +0xC target IS the event — Observed
 * [wobj+0xDC] = 9069a7e8 with [9069a7e8+0xC] = 9069a588) carries
 * its own sig byte. The delivery: the L47 plants verbatim (the
 * type byte, the dual 0x1000 cells, the completed head, the
 * verdict re-arm) + the {0x8D, 0x8E} pair + the verified ghost's
 * sig (only when its +0xC == the event; never a feeder event,
 * never a waiter-list change — the R13 exclusion holds) + THE V9
 * WAKE (the L54 recipe verbatim).
 *
 * Filter: the L54 discriminators VERBATIM (arena, BLOCKED, the face
 * pc, tva == pCurTh, the dead-idle world gate, the wobj resolution,
 * the is_cpw witness, the 2-cadence stability) MINUS the
 * single-entry break, PLUS n >= 2 (the WAIT-ALL shape) and the
 * per-entry frame-wobble verify. Self-terminating; capped (default
 * 4). Default OFF; the default-off world is untouched. When L55EV
 * and L54EV are both set, L54 stands down (the L55 delivery is a
 * superset — the single-entry world stays the L54's). */
static void mmcs_l55_scan(void)
{
    if (!mmcs_l55_armed || mmcs_l55_total >= mmcs_l55_max_deliv) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0, pick = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    /* THE DEAD-IDLE WORLD GATE (the L52b refinement, verbatim) */
    if (prun != 0 || (pick != 0 && pick != pcur)) {
        return;
    }
    for (uint32_t o = 0; o + 0x200 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, ctxpc, wobj, wret;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&wobj, arena + o + 0x14c, 4);
        memcpy(&wret, arena + o + 0x150, 4);
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000
            || ctxpc != 0x90837cf6
            || tva != pcur) {
            continue;
        }
        /* THE S204 SHAPE (the S203 exit's successor): the walker
         * RUNNABLE-at-the-face ((st16&3)==0) with the STANDING
         * satisfied state (the non-empty completed head
         * [pTh+0x1F8]; bF may be 1 (the satisfy in flight) or 0
         * (the wait done, the return pending)) — the CPU never
         * switched back (the dead-idle world with pCurTh STALE ==
         * walker). Wake-only: no plants — the state is already the
         * stock satisfied shape. */
        if ((st16 & 3) == 0) {
            uint8_t bf = 0;
            cpu_physical_memory_read(tva - 0x80000000 + 0xF, &bf, 1);
            uint32_t f1f8 = 0;
            cpu_physical_memory_read(tva - 0x80000000 + 0x1F8,
                                     &f1f8, 4);
            if (f1f8 == 0) {
                continue;
            }
            /* the create-body kstack witness (is_cpw) */
            uint32_t ssp = 0, is_cpw = 0;
            cpu_physical_memory_read(tva - 0x80000000 + 0xb0,
                                     &ssp, 4);
            if (ssp >= 0xD0000000 && ssp < 0xDC000000) {
                for (uint32_t sa = ssp; sa < ssp + 0x80; sa += 4) {
                    uint32_t pa3 = mmcs_l32_stack_pa(sa);
                    uint32_t w3 = 0;
                    if (!pa3) {
                        continue;
                    }
                    cpu_physical_memory_read(pa3, &w3, 4);
                    if (w3 >= 0x9082ce00 && w3 < 0x9082ed00) {
                        is_cpw = 1;
                        break;
                    }
                }
            }
            if (!is_cpw) {
                continue;
            }
            uint32_t key = tva ^ f1f8;
            if (mmcs_l55_key != key) {
                mmcs_l55_key = key;
                mmcs_l55_stable = 1;
                fprintf(stderr, "MMCS-L55: t=%" PRId64 "ms S204 "
                        "runnable-at-face seen: th %08x *CUR* "
                        "st16=%08x bF=%02x f1f8=%08x (stability "
                        "%u/2; pick %08x)\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL),
                        tva, st16, bf, f1f8, mmcs_l55_stable, pick);
                return;
            }
            if (++mmcs_l55_stable < 2) {
                return;
            }
            /* WAKE-ONLY — the v9 stub + the slot (the L54 recipe
             * verbatim, no plants) */
            cpu_physical_memory_write(0x1F00E600, mmcs_l54_stub,
                                      sizeof mmcs_l54_stub);
            cpu_physical_memory_write(0x1F00E600 + 0x88, &tva, 4);
            cpu_physical_memory_write(
                0x1F00E600 + 0x84,
                &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 }, 4);
            cpu_physical_memory_write(
                0x1F00E6F0,
                &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 }, 4);
            uint32_t slot_cur = 0;
            cpu_physical_memory_read(MMCS_L54_SLOT_PA, &slot_cur, 4);
            if (slot_cur != MMCS_L54_STUB_VA) {
                if (slot_cur != 0x90822e40) {
                    fprintf(stderr, "MMCS-L55: slot evt 0x320 busy "
                            "(%08x) - retry next cadence\n", slot_cur);
                    return;
                }
                cpu_physical_memory_write(
                    MMCS_L54_SLOT_PA,
                    &(uint32_t){ MMCS_L54_STUB_VA }, 4);
            }
            struct mmcs_l16_ent *e = &mmcs_l16_ents[7];
            e->evt_va = tva;
            e->stub_va = MMCS_L54_STUB_VA;
            e->evt_code = 0x320;
            e->slot_pa = MMCS_L54_SLOT_PA;
            e->daemon = 1;
            e->pending = 1;
            mmcs_l55_total++;
            fprintf(stderr, "MMCS-L55: t=%" PRId64 "ms S204 wake-only "
                    "%u/%u: walker %08x *CUR* bF=%02x f1f8=%08x (the "
                    "standing satisfied state; the v9 wake; markers "
                    "at %08x)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL),
                    mmcs_l55_total, mmcs_l55_max_deliv, tva, bf, f1f8,
                    MMCS_L54_STUB_VA + 0xf0);
            return;
        }
        if ((st16 & 3) != 2
            || wobj < 0xD0000000 || wobj >= 0xDC000000
            || wret < 0xC0000000 || wret >= 0xC1000000) {
            continue;
        }
        /* collect ALL pTh-matched wait-array entries (the L54
         * resolver's walk without the first-match break) */
        uint32_t wis[4], objs[4];
        int n = 0;
        for (uint32_t wi = 0; wi <= 0xC0 && n < 4; wi += 4) {
            uint32_t pa1 = mmcs_l32_stack_pa(wobj + wi + 0x14);
            uint32_t w1 = 0;
            if (!pa1) {
                continue;
            }
            cpu_physical_memory_read(pa1, &w1, 4);
            if (w1 != tva) {
                continue;
            }
            uint32_t pa2 = mmcs_l32_stack_pa(wobj + wi + 0xC);
            uint32_t obj = 0;
            if (pa2) {
                cpu_physical_memory_read(pa2, &obj, 4);
            }
            if (obj < 0x90680000 || obj >= 0x90780000) {
                continue;           /* not an arena kernel object */
            }
            wis[n] = wi;
            objs[n] = obj;
            n++;
        }
        if (n < 1) {
            continue;               /* no resolved entry — not ours */
        }
        /* the per-entry sig gate: all consumed (the cycling world —
         * a signaled entry means the vendor world is moving) */
        int skip = 0;
        for (int i = 0; i < n; i++) {
            uint8_t sig = 0;
            cpu_physical_memory_read(objs[i] - 0x80000000 + 0x8d,
                                     &sig, 1);
            if (sig & 1) {
                skip = 1;
                break;
            }
            uint32_t wlh = 0;
            cpu_physical_memory_read(objs[i] - 0x80000000 + 8,
                                     &wlh, 4);
            if (wlh == 0) {
                skip = 1;           /* unlinked = L32EV's class */
                break;
            }
        }
        if (skip) {
            continue;
        }
        /* the create-body kstack witness (is_cpw — the L46 window) */
        uint32_t ssp = 0, is_cpw = 0;
        cpu_physical_memory_read(tva - 0x80000000 + 0xb0, &ssp, 4);
        if (ssp >= 0xD0000000 && ssp < 0xDC000000) {
            for (uint32_t sa = ssp; sa < ssp + 0x80; sa += 4) {
                uint32_t pa3 = mmcs_l32_stack_pa(sa);
                uint32_t w3 = 0;
                if (!pa3) {
                    continue;
                }
                cpu_physical_memory_read(pa3, &w3, 4);
                if (w3 >= 0x9082ce00 && w3 < 0x9082ed00) {
                    is_cpw = 1;
                    break;
                }
            }
        }
        if (!is_cpw) {
            continue;
        }
        /* the per-entry base + frame-wobble verify (the L47
         * discipline: entry = wobj + wi - 8, VERIFIED against the
         * resolved object before any plant) */
        uint32_t entries[4];
        for (int i = 0; i < n; i++) {
            if (wis[i] < 8) {
                skip = 1;
                break;
            }
            entries[i] = wobj + wis[i] - 8;
            uint32_t pa_e = mmcs_l32_stack_pa(entries[i] + 0x14);
            uint32_t objchk = 0;
            if (pa_e) {
                cpu_physical_memory_read(pa_e, &objchk, 4);
            }
            if (!pa_e || objchk != objs[i]) {
                fprintf(stderr, "MMCS-L55: entry verify FAILED (entry "
                        "%08x objchk %08x vs obj %08x) - skip\n",
                        entries[i], objchk, objs[i]);
                skip = 1;
                break;
            }
        }
        if (skip) {
            continue;
        }
        /* 2-cadence stability keyed {thread,objs} */
        uint32_t key = tva;
        for (int i = 0; i < n; i++) {
            key ^= objs[i] * (i + 1);
        }
        if (mmcs_l55_key != key) {
            mmcs_l55_key = key;
            mmcs_l55_stable = 1;
            fprintf(stderr, "MMCS-L55: t=%" PRId64 "ms WAIT-ALL park "
                    "seen: th %08x *CUR* n=%d objs", qemu_clock_get_ms(
                    QEMU_CLOCK_VIRTUAL), tva, n);
            for (int i = 0; i < n; i++) {
                fprintf(stderr, " %08x", objs[i]);
            }
            fprintf(stderr, " (stability %u/2; pick %08x)\n",
                    mmcs_l55_stable, pick);
            return;
        }
        if (++mmcs_l55_stable < 2) {
            return;
        }
        /* DELIVER — the per-entry L47 plants, the manual-reset stock
         * shape, the wake */
        for (int i = 0; i < n; i++) {
            /* the type byte: entry+0x18's low byte carries EVNT(4) */
            uint32_t pa_t = mmcs_l32_stack_pa(entries[i] + 0x18);
            if (pa_t) {
                uint32_t fw = 0;
                cpu_physical_memory_read(pa_t, &fw, 4);
                if ((fw & 0xff) != 0x04) {
                    fw = (fw & 0xffffff00) | 0x04;
                    cpu_physical_memory_write(pa_t, &fw, 4);
                }
            }
            /* the result cell := 0x1000 (guarded) */
            uint32_t pa_r = mmcs_l32_stack_pa(entries[i] + 0x20);
            if (pa_r) {
                uint32_t cur = 0;
                cpu_physical_memory_read(pa_r, &cur, 4);
                if (cur != 0x1000) {
                    cpu_physical_memory_write(pa_r,
                                              &(uint32_t){ 0x1000 }, 4);
                }
            }
            /* THE MANUAL-RESET STOCK SHAPE (the S203 decode): the
             * eval's type-4 satisfy runs [obj+0x8D] := [obj+0x8E]
             * (Verified 0x908283ae-0x908283b8) — the L47/L54 world
             * set 0x8D only (the auto-reset shape: one satisfy
             * consumes the bit, the driver-level re-check reads it
             * CLEAR, the wait re-submits forever). The stock
             * manual-reset event keeps BOTH set: 0x8D for the wake,
             * 0x8E as the post-consume sig the re-check reads.
             * MMCS fork (L58 interlock): a RETIRED object (the S207
             * residual-sticky cleanup's done-set) is never re-planted
             * — the falsifier's first lesson: this cadence otherwise
             * faithfully undoes the cleanup. */
            if (mmcs_l58_retired(objs[i])) {
                continue;
            }
            uint8_t sig = 0;
            cpu_physical_memory_read(objs[i] - 0x80000000 + 0x8d,
                                     &sig, 1);
            sig |= 1;
            cpu_physical_memory_write(objs[i] - 0x80000000 + 0x8d,
                                      &sig, 1);
            uint8_t mark8e = 0;
            cpu_physical_memory_read(objs[i] - 0x80000000 + 0x8e,
                                     &mark8e, 1);
            mark8e |= 1;
            cpu_physical_memory_write(objs[i] - 0x80000000 + 0x8e,
                                      &mark8e, 1);
            /* the ghost node's own sig: the driver-level re-check
             * may read the ELEMENT's object (the namespace node
             * whose +0xC target IS this event — Observed [wobj+0xDC]
             * = 9069a7e8, [9069a7e8+0xC] = 9069a588). Verified before
             * the plant: only when the node targets THIS event. */
            for (uint32_t goff = 0x80; goff <= 0x120; goff += 4) {
                uint32_t pa_g = mmcs_l32_stack_pa(wobj + goff);
                uint32_t ghost = 0;
                if (!pa_g) {
                    continue;
                }
                cpu_physical_memory_read(pa_g, &ghost, 4);
                if (ghost < 0x90680000 || ghost >= 0x90780000) {
                    continue;
                }
                uint32_t gtarget = 0;
                cpu_physical_memory_read(ghost - 0x80000000 + 0xC,
                                         &gtarget, 4);
                if (gtarget != objs[i]) {
                    continue;
                }
                uint8_t gsig = 0;
                cpu_physical_memory_read(ghost - 0x80000000 + 0x8d,
                                         &gsig, 1);
                if (!(gsig & 1)) {
                    gsig |= 1;
                    cpu_physical_memory_write(
                        ghost - 0x80000000 + 0x8d, &gsig, 1);
                    fprintf(stderr, "MMCS-L55: ghost node %08x sig "
                            "00->01 (targets the event %08x)\n",
                            ghost, objs[i]);
                }
            }
        }
        /* the completed head + the wait-result cache */
        cpu_physical_memory_write(tva - 0x80000000 + 0x1f8,
                                  &entries[n - 1], 4);
        cpu_physical_memory_write(tva - 0x80000000 + 0x1fc,
                                  &(uint32_t){ 0x1000 }, 4);
        /* the S199 verdict re-arm — [sp+0x10] := 2 when 0 */
        if (ssp >= 0xD0000000 && ssp < 0xDC000000) {
            uint32_t pa_v = mmcs_l32_stack_pa(ssp + 0x10);
            if (pa_v) {
                uint32_t verdict = 0;
                cpu_physical_memory_read(pa_v, &verdict, 4);
                if (verdict == 0) {
                    cpu_physical_memory_write(
                        pa_v, &(uint32_t){ 2 }, 4);
                }
            }
        }
        /* THE V9 WAKE — install, THEN patch the pool (the L36
         * order), then the slot (the L54 recipe verbatim) */
        cpu_physical_memory_write(0x1F00E600, mmcs_l54_stub,
                                  sizeof mmcs_l54_stub);
        cpu_physical_memory_write(0x1F00E600 + 0x88, &tva, 4);
        cpu_physical_memory_write(0x1F00E600 + 0x84,
                                  &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 },
                                  4);
        cpu_physical_memory_write(0x1F00E6F0,
                                  &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 },
                                  4);
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L54_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L54_STUB_VA) {
            if (slot_cur != 0x90822e40) {
                fprintf(stderr, "MMCS-L55: slot evt 0x320 busy (%08x) - "
                        "retry next cadence\n", slot_cur);
                return;
            }
            cpu_physical_memory_write(MMCS_L54_SLOT_PA,
                                      &(uint32_t){ MMCS_L54_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[7];
        e->evt_va = tva;
        e->stub_va = MMCS_L54_STUB_VA;
        e->evt_code = 0x320;
        e->slot_pa = MMCS_L54_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l55_total++;
        fprintf(stderr, "MMCS-L55: t=%" PRId64 "ms manual-reset "
                "delivery %u/%u: walker %08x *CUR* n=%d entries",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l55_total,
                mmcs_l55_max_deliv, tva, n);
        for (int i = 0; i < n; i++) {
            fprintf(stderr, " %08x->obj %08x", entries[i], objs[i]);
        }
        fprintf(stderr, " (the {8d,8e} stock shape + the ghost sig "
                "+ the v9 wake; markers at %08x)\n",
                MMCS_L54_STUB_VA + 0xf0);
        return;                     /* one delivery per cadence */
    }
    /* no WAIT-ALL park this scan — reset the stability tracker */
    mmcs_l55_key = 0;
    mmcs_l55_stable = 0;
}

static void mmcs_l56_scan(void)
{
    if (!mmcs_l56_armed || mmcs_l56_total >= mmcs_l56_max_deliv) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0, pick = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    /* THE LIVE-WORLD GATE (the dead-idle gate's post-return
     * replacement): pick==0 (idle) OR pick==pcur (the keep-current
     * bookkeeping — the spinner's steady state); someone ELSE's
     * pick = vendor mid-flight — SKIP */
    if (pick != 0 && pick != pcur) {
        return;
    }
    for (uint32_t o = 0; o + 0x210 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, ctxpc, wobj, wret, tmo;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&wobj, arena + o + 0x14c, 4);
        memcpy(&wret, arena + o + 0x150, 4);
        memcpy(&tmo, arena + o + 0x200, 4);
        uint32_t tva = 0x90680000 + o;
        uint8_t bf = arena[o + 0xf], susp = arena[o + 0xe];
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000
            || (st16 & 3) != 2                 /* BLOCKED */
            || ctxpc != 0x90837cf6              /* the generic face */
            || bf != 2                          /* mid-wait flag */
            || susp != 0                        /* not suspended */
            || tmo != 0xffffffff                /* INFINITE wait */
            || wobj < 0xD0000000 || wobj >= 0xDC000000
            /* the kernel-continuation witness: the sticky orphan's
             * [th+0x150] carries the KERNEL window (live: 90845b78
             * — the teardown-path continuation; NOT the create
             * walker's c00 filesys window) */
            || wret < 0x90800000 || wret >= 0x90A00000
            || tva == pcur) {                   /* never the current */
            continue;
        }
        /* resolve the waited object through the waiter's own
         * wait-array entry (the L32EV/L47 resolver) */
        uint32_t obj = 0, wi_found = 0;
        for (uint32_t wi = 0; wi <= 0x80; wi += 4) {
            uint32_t pa1 = mmcs_l32_stack_pa(wobj + wi + 0x14);
            uint32_t w1 = 0;
            if (!pa1) {
                continue;
            }
            cpu_physical_memory_read(pa1, &w1, 4);
            if (w1 != tva) {
                continue;
            }
            uint32_t pa2 = mmcs_l32_stack_pa(wobj + wi + 0xC);
            if (pa2) {
                cpu_physical_memory_read(pa2, &obj, 4);
            }
            wi_found = wi;
            break;
        }
        if (obj < 0x90680000 || obj >= 0x90780000) {
            continue;               /* not an arena kernel object */
        }
        /* THE STICKY CLASS: {8D==0 clear, 8E==1 sticky, +0x90==0,
         * LINKED waiters with the head entry owned by THIS thread} */
        uint8_t sig56 = 0, sticky = 0, z90 = 1;
        cpu_physical_memory_read(obj - 0x80000000 + 0x8d, &sig56, 1);
        cpu_physical_memory_read(obj - 0x80000000 + 0x8e, &sticky, 1);
        cpu_physical_memory_read(obj - 0x80000000 + 0x90, &z90, 1);
        if ((sig56 & 1) || sticky != 1 || z90 != 0) {
            continue;               /* not the sticky orphan shape */
        }
        uint32_t wlh = 0;
        cpu_physical_memory_read(obj - 0x80000000 + 8, &wlh, 4);
        if (wlh < 0xD0000000 || wlh >= 0xDC000000) {
            continue;               /* unlinked / bogus list head */
        }
        uint32_t pa_h = mmcs_l32_stack_pa(wlh + 0x1c);
        uint32_t headth = 0;
        if (pa_h) {
            cpu_physical_memory_read(pa_h, &headth, 4);
        }
        if (!pa_h || headth != tva) {
            continue;               /* the head entry is not ours */
        }
        /* the entry verify (the L54 discipline): the resolver's
         * entry base must round-trip to the same object */
        if (!wi_found || wi_found < 8) {
            continue;
        }
        uint32_t entry56 = wobj + wi_found - 8;
        uint32_t pa_e = mmcs_l32_stack_pa(entry56 + 0x14);
        uint32_t objchk = 0;
        if (pa_e) {
            cpu_physical_memory_read(pa_e, &objchk, 4);
        }
        if (!pa_e || objchk != obj) {
            fprintf(stderr, "MMCS-L56: entry verify FAILED (entry %08x "
                    "objchk %08x vs obj %08x) - skip\n",
                    entry56, objchk, obj);
            continue;
        }
        /* 2-cadence stability keyed {thread,obj} */
        uint32_t key = tva ^ obj;
        if (mmcs_l56_key != key) {
            mmcs_l56_key = key;
            mmcs_l56_stable = 1;
            fprintf(stderr, "MMCS-L56: t=%" PRId64 "ms sticky-orphan park "
                    "seen: th %08x st16=%08x pc=%08x obj %08x sig %02x "
                    "8e %02x wlh %08x wret %08x (stability %u/2; pick "
                    "%08x pcur %08x)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, st16,
                    ctxpc, obj, sig56, sticky, wlh, wret,
                    mmcs_l56_stable, pick, pcur);
            return;
        }
        if (++mmcs_l56_stable < 2) {
            return;
        }
        /* channel guard: the v9 stub/slot is shared with L54/L55 */
        if (mmcs_l16_ents[7].pending) {
            return;                 /* a wake mid-flight — retry */
        }
        /* DELIVER (1) THE UNMARK: the entry's type byte 0xff->4 */
        uint32_t pa_t = mmcs_l32_stack_pa(entry56 + 0x18);
        if (pa_t) {
            uint32_t fw = 0;
            cpu_physical_memory_read(pa_t, &fw, 4);
            if ((fw & 0xff) != 0x04) {
                fw = (fw & 0xffffff00) | 0x04;
                cpu_physical_memory_write(pa_t, &fw, 4);
            }
        }
        /* (2) THE PULSE — the walker's object writes */
        cpu_physical_memory_write(obj - 0x80000000 + 8,
                                  &(uint32_t){ 0 }, 4);
        sig56 |= 1;
        cpu_physical_memory_write(obj - 0x80000000 + 0x8d, &sig56, 1);
        /* the walker's thread writes (wCount halfword++; the t34/t74
         * clears). NOTE: the walker's st16|=3 write is DELIBERATELY
         * NOT done host-side — the v9 stub's own state guard requires
         * (st16&3)==2 (BLOCKED) at entry, and its MakeRun performs
         * the stock state change (state16:=(s&~3)|1) itself; the
         * walker's |3 intermediate only feeds MakeRunIfNeeded's
         * condition check, which the stub's direct MakeRun replaces
         * (live-caught: the premature |3 failed the stub guard and
         * the wake silently early-exited, marker cell unread) */
        uint32_t pa_w = tva - 0x80000000 + 0x42;
        uint16_t wc = 0;
        cpu_physical_memory_read(pa_w, &wc, 2);
        wc++;
        cpu_physical_memory_write(pa_w, &wc, 2);
        cpu_physical_memory_write(tva - 0x80000000 + 0x34,
                                  &(uint32_t){ 0 }, 4);
        cpu_physical_memory_write(tva - 0x80000000 + 0x74,
                                  &(uint32_t){ 0 }, 4);
        /* (3) THE RESULT PLANTS — the L54 recipe on the entry */
        cpu_physical_memory_write(tva - 0x80000000 + 0x1f8,
                                  &entry56, 4);
        uint32_t res56 = 0x1000;
        uint32_t pa_r = mmcs_l32_stack_pa(entry56 + 0x20);
        if (pa_r) {
            cpu_physical_memory_write(pa_r, &res56, 4);
        }
        cpu_physical_memory_write(tva - 0x80000000 + 0x1fc,
                                  &res56, 4);
        {
            uint32_t vsp = 0;
            cpu_physical_memory_read(tva - 0x80000000 + 0xb0, &vsp, 4);
            if (vsp >= 0xD0000000 && vsp < 0xDC000000) {
                uint32_t pa_v = mmcs_l32_stack_pa(vsp + 0x10);
                if (pa_v) {
                    uint32_t verdict = 0;
                    cpu_physical_memory_read(pa_v, &verdict, 4);
                    if (verdict == 0) {
                        cpu_physical_memory_write(
                            pa_v, &(uint32_t){ 2 }, 4);
                    }
                }
            }
        }
        /* (4) THE WAKE — the v10 requeue stub when MMCS_L57EV is set
         * (the S206 fix: MakeRun(old) when old != target), else the
         * shared v9. The v10 pool sits +20: .Lm +0x98, .Lcand +0x9c. */
        if (mmcs_l57_armed) {
            cpu_physical_memory_write(0x1F00E600, mmcs_l57_stub,
                                      sizeof mmcs_l57_stub);
            cpu_physical_memory_write(0x1F00E600 + 0x9c, &tva, 4);
            cpu_physical_memory_write(0x1F00E600 + 0x98,
                                      &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 },
                                      4);
        } else {
            cpu_physical_memory_write(0x1F00E600, mmcs_l54_stub,
                                      sizeof mmcs_l54_stub);
            cpu_physical_memory_write(0x1F00E600 + 0x88, &tva, 4);
            cpu_physical_memory_write(0x1F00E600 + 0x84,
                                      &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 },
                                      4);
        }
        cpu_physical_memory_write(0x1F00E6F0,
                                  &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 },
                                  4);
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L54_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L54_STUB_VA) {
            if (slot_cur != 0x90822e40) {
                fprintf(stderr, "MMCS-L56: slot evt 0x320 busy (%08x) - "
                        "retry next cadence\n", slot_cur);
                return;
            }
            cpu_physical_memory_write(MMCS_L54_SLOT_PA,
                                      &(uint32_t){ MMCS_L54_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[7];
        e->evt_va = tva;
        e->stub_va = MMCS_L54_STUB_VA;
        e->evt_code = 0x320;
        e->slot_pa = MMCS_L54_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l56_total++;
        fprintf(stderr, "MMCS-L56: t=%" PRId64 "ms sticky-orphan pulse "
                "%u/%u: th %08x obj %08x entry %08x 8e=1 (the unmark + "
                "the walker pulse {detach,8d|=1,wCount++,t34,t74,|3} + "
                "the L54 plants + the v9 wake; markers at %08x)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l56_total,
                mmcs_l56_max_deliv, tva, obj, entry56,
                MMCS_L54_STUB_VA + 0xf0);
        return;                     /* one delivery per cadence */
    }
    /* no sticky-orphan park this scan — reset the stability tracker */
    mmcs_l56_key = 0;
    mmcs_l56_stable = 0;
}

static void mmcs_l58_scan(void)
{
    if (!mmcs_l58_armed || mmcs_l58_total >= 8) {
        return;
    }
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    if (pcur < 0x90680000 || pcur >= 0x90780000) {
        return;                       /* not an arena thread */
    }
    uint32_t f1f8 = 0, wobj = 0;
    cpu_physical_memory_read(pcur - 0x80000000 + 0x1F8, &f1f8, 4);
    cpu_physical_memory_read(pcur - 0x80000000 + 0x14C, &wobj, 4);
    if (!f1f8 || wobj < 0xD0000000 || wobj >= 0xDC000000) {
        return;    /* no standing completed head / no wait array */
    }
    /* resolve the waited object through pcur's own wait-array entry
     * (the L32EV/L47 resolver, as in l56_scan) */
    uint32_t obj = 0;
    for (uint32_t wi = 0; wi <= 0x80; wi += 4) {
        uint32_t pa1 = mmcs_l32_stack_pa(wobj + wi + 0x14);
        uint32_t w1 = 0;
        if (!pa1) {
            continue;
        }
        cpu_physical_memory_read(pa1, &w1, 4);
        if (w1 != pcur) {
            continue;
        }
        uint32_t pa2 = mmcs_l32_stack_pa(wobj + wi + 0xC);
        if (pa2) {
            cpu_physical_memory_read(pa2, &obj, 4);
        }
        break;
    }
    if (obj < 0x90680000 || obj >= 0x90780000) {
        return;                       /* not an arena kernel object */
    }
    /* the sticky-standing residue: {8D&1, 8E==1, +0x90==0} */
    uint8_t sig58 = 0, sticky = 0, z90 = 1;
    cpu_physical_memory_read(obj - 0x80000000 + 0x8d, &sig58, 1);
    cpu_physical_memory_read(obj - 0x80000000 + 0x8e, &sticky, 1);
    cpu_physical_memory_read(obj - 0x80000000 + 0x90, &z90, 1);
    if (!(sig58 & 1) || sticky != 1 || z90 != 0) {
        return;
    }
    if (mmcs_l58_retired(obj)) {
        return;                       /* one-shot per object */
    }
    /* THE CLEAR (one word, the L53 class — no stub, no slot) */
    uint8_t zero = 0;
    cpu_physical_memory_write(obj - 0x80000000 + 0x8e, &zero, 1);
    mmcs_l58_done[mmcs_l58_total++] = obj;
    fprintf(stderr, "MMCS-L58: t=%" PRId64 "ms residual-sticky cleanup: "
            "obj %08x [8E]:=0 (th %08x f1f8 %08x — the post-return "
            "residue retired; the stock consumable class resumes; "
            "the launcher parks at its next wait)\n",
            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), obj, pcur, f1f8);
}

static void mmcs_l62_scan(void)
{
    if (!mmcs_l62_armed || mmcs_l62_total >= mmcs_l62_max_deliv) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0, pick = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    /* THE DEAD-IDLE WORLD GATE (the L52b refinement, verbatim) */
    if (prun != 0 || (pick != 0 && pick != pcur)) {
        if (mmcs_l62_diag) {
            fprintf(stderr, "MMCS-L62(diag): t=%" PRId64 "ms world "
                    "gate: prun %08x pick %08x pcur %08x\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), prun, pick,
                    pcur);
        }
        return;
    }
    /* THE CINFO-ANCHORED SCAN: the CRIT trailer wobbles across heap
     * generations (the proxy list head read +0x84 in the L62-walk
     * instance, +0x88 in the current one — live-caught), so anchor
     * on the CINFO cell itself: [cinfo+4] = pvObj = the crit base
     * (the self-witness), state = [cinfo-0x10], lpcs = [cinfo-0xc];
     * the queued proxy is found through the PRIORITY BUCKETS
     * (crit+0x00..+0x7F — the vendor fn_90828a68's own resolution
     * walk), never through a hardcoded list-head offset. */
    for (uint32_t o = 0x10; o + 8 <= sizeof arena; o += 4) {
        uint32_t cinfo;
        memcpy(&cinfo, arena + o, 4);
        if (cinfo != 0x908220a0) {
            continue;
        }
        uint32_t ova;
        memcpy(&ova, arena + o + 4, 4);
        if (ova < 0x90680000 || ova >= 0x90780000 || (ova & 3)) {
            continue;               /* pvObj self-witness failed */
        }
        uint32_t oo = ova - 0x90680000;
        if (oo + 0x90 > sizeof arena) {
            continue;
        }
        uint32_t ostate, lpcs;
        memcpy(&ostate, arena + o - 0x10, 4);
        memcpy(&lpcs, arena + o - 0xc, 4);
        /* the OWNED state: base 0x80000000 with the low bits set —
         * a FREE crit (low16==0) owes nobody anything */
        if ((ostate & 0xffff0000u) != 0x80000000u
            || (ostate & 0xffff) == 0
            || lpcs < 0xD0000000 || lpcs >= 0xDC000000) {
            if (mmcs_l62_diag) {
                fprintf(stderr, "MMCS-L62(diag): t=%" PRId64 "ms crit "
                        "%08x not-owned/free {state %08x lpcs %08x} "
                        "- skip\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), ova,
                        ostate, lpcs);
            }
            continue;
        }
        /* the queued proxy: the priority-bucket walk */
        uint32_t proxlist = 0, pa_px = 0, px_th = 0;
        for (uint32_t k = 0; k < 32; k++) {
            uint32_t bk;
            memcpy(&bk, arena + oo + 4 * k, 4);
            if (bk < 0xD0000000 || bk >= 0xDC000000) {
                continue;
            }
            uint32_t pa = mmcs_l32_stack_pa(bk);
            if (!pa) {
                if (mmcs_l62_diag) {
                    fprintf(stderr, "MMCS-L62(diag): t=%" PRId64 "ms "
                            "crit %08x bucket[%u] %08x PA-UNRESOLVED\n",
                            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), ova,
                            k, bk);
                }
                continue;
            }
            uint32_t th = 0;
            cpu_physical_memory_read(pa + 0x1c, &th, 4);
            if (th < 0x90680000 || th >= 0x90780000) {
                if (mmcs_l62_diag) {
                    fprintf(stderr, "MMCS-L62(diag): t=%" PRId64 "ms "
                            "crit %08x bucket[%u] %08x pTh %08x "
                            "NOT-TCB\n",
                            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), ova,
                            k, bk, th);
                }
                continue;
            }
            proxlist = bk;
            pa_px = pa;
            px_th = th;
            break;                  /* the first resolvable bucket */
        }
        if (!proxlist) {
            if (mmcs_l62_diag) {
                fprintf(stderr, "MMCS-L62(diag): t=%" PRId64 "ms crit "
                        "%08x owned but NO resolvable queued proxy "
                        "{state %08x lpcs %08x}\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), ova,
                        ostate, lpcs);
            }
            continue;               /* no resolvable queued proxy */
        }
        uint32_t to = px_th - 0x90680000;
        if (to + 0x220 > sizeof arena) {
            continue;
        }
        uint32_t st16, ctxpc, kbase, ksz, tmo, heir_h;
        memcpy(&st16, arena + to + 0xc, 4);
        memcpy(&ctxpc, arena + to + 0xb4, 4);
        memcpy(&kbase, arena + to + 0x20, 4);
        memcpy(&ksz, arena + to + 0x24, 4);
        memcpy(&tmo, arena + to + 0x200, 4);
        memcpy(&heir_h, arena + to + 0x3c, 4);
        uint8_t susp = arena[to + 0xe];
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || ctxpc != 0x90840814     /* the CRIT-enter park face */
            || (st16 & 3) != 2
            || susp != 0
            || tmo != 0xffffffff
            || (heir_h & 0xff000000) != 0) {   /* a 00xxxxxx handle */
            if (mmcs_l62_diag) {
                fprintf(stderr, "MMCS-L62(diag): t=%" PRId64 "ms crit "
                        "%08x waiter %08x SHAPE-MISS {st16 %08x ctx "
                        "%08x kbase %08x ksz %08x susp %u tmo %08x "
                        "heir %08x}\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), ova,
                        px_th, st16, ctxpc, kbase, ksz, susp, tmo,
                        heir_h);
            }
            continue;
        }
        /* THE DEAD-OWNER PROOF: the lpcs owner handle resolves an
         * arena thread in a GRAVE state */
        uint32_t pa_own = mmcs_l32_stack_pa(lpcs + 4);
        if (!pa_own) {
            fprintf(stderr, "MMCS-L62: t=%" PRId64 "ms crit %08x "
                    "waiter %08x at the enter face — lpcs %08x+4 "
                    "PA-UNRESOLVED\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), ova,
                    px_th, lpcs);
            continue;
        }
        uint32_t owner_h = 0;
        cpu_physical_memory_read(pa_own, &owner_h, 4);
        int owner_dead = 0;
        uint32_t owner_tcb = 0;
        if ((owner_h & 0xff000000) == 0 && owner_h != heir_h) {
            for (uint32_t oi = 0; oi + 0xb8 <= sizeof arena; oi += 4) {
                uint32_t h;
                memcpy(&h, arena + oi + 0x3c, 4);
                if (h != owner_h) {
                    continue;
                }
                uint32_t ost, opcc;
                memcpy(&ost, arena + oi + 0xc, 4);
                memcpy(&opcc, arena + oi + 0xb4, 4);
                if (ost == 0x58 || ost == 0x18 || (ost & 8)
                    || opcc == 0x9083c102) {
                    owner_dead = 1;
                    owner_tcb = 0x90680000 + oi;
                }
                break;
            }
        }
        if (mmcs_l62_diag) {
            fprintf(stderr, "MMCS-L62(diag): t=%" PRId64 "ms crit %08x "
                    "{state %08x lpcs %08x proxlist %08x} waiter %08x "
                    "st16=%08x heir_h %08x owner_h %08x (tcb %08x) "
                    "dead=%d\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), ova, ostate,
                    lpcs, proxlist, px_th, st16, heir_h, owner_h,
                    owner_tcb, owner_dead);
        }
        if (!owner_dead) {
            /* FLAVOR B1 — THE TRANSFER-LANDED PARK: the m3-close's
             * transfer half ALREADY ran ([lpcs+4] == the waiter's
             * own handle — the enter-loop decode 0x90840856: the
             * resumed waiter's own face tail compares [lpcs+4] vs
             * [KData+8] and EXITS AS THE OWNER when they match; the
             * owned-tail jsr fixes the recursion cells through
             * vendor code). Only the WAKE half is owed: WAKE-ONLY,
             * ZERO host writes. */
            if (owner_h != heir_h || (owner_h & 0xff000000) != 0) {
                continue;   /* a live owner: never manufacture */
            }
            /* 2-cadence stability keyed {waiter,crit} */
            uint32_t key = px_th ^ (ova * 5);
            if (mmcs_l62_key != key) {
                mmcs_l62_key = key;
                mmcs_l62_stable = 1;
                fprintf(stderr, "MMCS-L62: t=%" PRId64 "ms transfer-"
                        "landed crit waiter seen: crit %08x waiter "
                        "%08x heir_h %08x already at [lpcs+4] (the "
                        "m3 transfer landed; only the wake died) "
                        "(stability %u/2; pick %08x pcur %08x)\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), ova,
                        px_th, heir_h, mmcs_l62_stable, pick, pcur);
                return;
            }
            if (++mmcs_l62_stable < 2) {
                return;
            }
            if (mmcs_l16_ents[7].pending) {
                fprintf(stderr, "MMCS-L62: t=%" PRId64 "ms evt-0x320 "
                        "wake mid-flight - retry next cadence\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL));
                return;
            }
            uint32_t slot_cur = 0;
            cpu_physical_memory_read(MMCS_L54_SLOT_PA, &slot_cur, 4);
            if (slot_cur != MMCS_L54_STUB_VA
                && slot_cur != 0x90822e40) {
                fprintf(stderr, "MMCS-L62: slot evt 0x320 busy (%08x)"
                        " - retry next cadence\n", slot_cur);
                return;
            }
            if (mmcs_l62_diag) {
                fprintf(stderr, "MMCS-L62(diag): shape STABLE — would "
                        "WAKE-ONLY the transfer-landed waiter %08x "
                        "(zero writes; the face tail exits as the "
                        "owner); diag mode, no delivery\n", px_th);
                return;
            }
            uint32_t tva = px_th;
            cpu_physical_memory_write(0x1F00E600, mmcs_l54_stub,
                                      sizeof mmcs_l54_stub);
            cpu_physical_memory_write(0x1F00E600 + 0x88, &tva, 4);
            cpu_physical_memory_write(
                0x1F00E600 + 0x84,
                &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 }, 4);
            cpu_physical_memory_write(
                0x1F00E6F0,
                &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 }, 4);
            if (slot_cur != MMCS_L54_STUB_VA) {
                cpu_physical_memory_write(
                    MMCS_L54_SLOT_PA,
                    &(uint32_t){ MMCS_L54_STUB_VA }, 4);
            }
            struct mmcs_l16_ent *e = &mmcs_l16_ents[7];
            e->evt_va = tva;
            e->stub_va = MMCS_L54_STUB_VA;
            e->evt_code = 0x320;
            e->slot_pa = MMCS_L54_SLOT_PA;
            e->daemon = 1;
            e->pending = 1;
            mmcs_l62_total++;
            fprintf(stderr, "MMCS-L62: t=%" PRId64 "ms transfer-landed "
                    "crit wake-only %u/%u: crit %08x waiter %08x "
                    "heir_h %08x ([lpcs+4] already the heir — the m3 "
                    "transfer landed, the wake died with the owner; "
                    "ZERO writes: the resumed face tail reads "
                    "[lpcs+4]==[KData+8] and exits the enter loop as "
                    "the owner through vendor code; markers at "
                    "%08x)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL),
                    mmcs_l62_total, mmcs_l62_max_deliv, ova, tva,
                    heir_h, MMCS_L54_STUB_VA + 0xf0);
            return;                 /* one delivery per cadence */
        }
        /* 2-cadence stability keyed {waiter,crit} */
        uint32_t key = px_th ^ (ova * 3);
        if (mmcs_l62_key != key) {
            mmcs_l62_key = key;
            mmcs_l62_stable = 1;
            fprintf(stderr, "MMCS-L62: t=%" PRId64 "ms dead-owner crit "
                    "seen: crit %08x waiter %08x owner_h %08x (tcb "
                    "%08x) lpcs %08x state %08x (stability %u/2; pick "
                    "%08x pcur %08x)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), ova, px_th,
                    owner_h, owner_tcb, lpcs, ostate, mmcs_l62_stable,
                    pick, pcur);
            return;
        }
        if (++mmcs_l62_stable < 2) {
            return;
        }
        /* CHANNEL GUARDS FIRST (the R23 'channel busy -> WAIT'
         * ordering — the m3-close writes are NOT idempotent, they
         * must never be abandoned half-done: a wake mid-flight or a
         * foreign slot holder means retry NEXT cadence with the
         * world untouched) */
        if (mmcs_l16_ents[7].pending) {
            fprintf(stderr, "MMCS-L62: t=%" PRId64 "ms evt-0x320 wake "
                    "mid-flight - retry next cadence\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL));
            return;
        }
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L54_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L54_STUB_VA && slot_cur != 0x90822e40) {
            fprintf(stderr, "MMCS-L62: slot evt 0x320 busy (%08x) - "
                    "retry next cadence\n", slot_cur);
            return;
        }
        if (mmcs_l62_diag) {
            fprintf(stderr, "MMCS-L62(diag): shape STABLE — would "
                    "release crit %08x to heir %08x; diag mode, no "
                    "delivery\n", ova, px_th);
            return;
        }
        /* DELIVER — the stock m3-close writes, exactly where the
         * vendor writes them (fn_90828a68 + fn_90828a08), then the
         * v9 WAKE (the state flip via the stub's own MakeRun) */
        uint32_t pa_l0 = mmcs_l32_stack_pa(lpcs);
        uint32_t pa_lC = mmcs_l32_stack_pa(lpcs + 0xc);
        if (pa_l0) {
            cpu_physical_memory_write(pa_l0, &(uint32_t){ 1 }, 4);
        }
        cpu_physical_memory_write(pa_own, &heir_h, 4);
        if (pa_lC) {
            cpu_physical_memory_write(pa_lC, &(uint32_t){ 0 }, 4);
        }
        /* the state clear, CINFO-anchored (the wobble-proof cell):
         * the state cell's arena offset = (o - 0x10) */
        cpu_physical_memory_write(0x10680000 + (o - 0x10),
                                  &(uint32_t){ 0x80000000 }, 4);
        /* every queued-reference cell that carries the proxy
         * (buckets + the wobbly list head(s)) — surgical, only
         * cells that EQUAL the proxy */
        for (uint32_t k = 0; k < 0x24; k++) {
            uint32_t bk;
            memcpy(&bk, arena + oo + 4 * k, 4);
            if (bk == proxlist) {
                cpu_physical_memory_write(ova - 0x80000000 + 4 * k,
                                          &(uint32_t){ 0 }, 4);
            }
        }
        cpu_physical_memory_write(pa_px + 0xc, &(uint32_t){ 0 }, 4);
        uint16_t wc;
        memcpy(&wc, arena + to + 0x42, 2);
        wc++;
        cpu_physical_memory_write(px_th - 0x80000000 + 0x42, &wc, 2);
        cpu_physical_memory_write(px_th - 0x80000000 + 0x1f4,
                                  &proxlist, 4);
        /* THE V9 WAKE (the L54 recipe verbatim). NOTE: the v9 (not
         * the v10 requeue) is CORRECT here — the outgoing current
         * at the settled park is the devmgr's PARKED 500ms sleeper
         * (BLOCKED-class, stock-parked: its wake comes from the
         * SleepList timeout, never the run queue), not the S206
         * RUNNING-class interrupted submitter MakeRun(old) exists
         * for */
        uint32_t tva = px_th;
        cpu_physical_memory_write(0x1F00E600, mmcs_l54_stub,
                                  sizeof mmcs_l54_stub);
        cpu_physical_memory_write(0x1F00E600 + 0x88, &tva, 4);
        cpu_physical_memory_write(
            0x1F00E600 + 0x84,
            &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 }, 4);
        cpu_physical_memory_write(
            0x1F00E6F0,
            &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 }, 4);
        if (slot_cur != MMCS_L54_STUB_VA) {
            cpu_physical_memory_write(
                MMCS_L54_SLOT_PA,
                &(uint32_t){ MMCS_L54_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[7];
        e->evt_va = tva;
        e->stub_va = MMCS_L54_STUB_VA;
        e->evt_code = 0x320;
        e->slot_pa = MMCS_L54_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l62_total++;
        fprintf(stderr, "MMCS-L62: t=%" PRId64 "ms dead-owner crit "
                "release %u/%u: crit %08x waiter %08x heir_h %08x "
                "(owner_h %08x tcb %08x was the grave; the stock "
                "m3-close writes: lpcs{%08x:=1, +4:=%08x, +c:=0} + "
                "state 80000000 + buckets/proxlist cleared + wCount++ "
                "+ the v9 wake; the heir's own retry tail exits the "
                "loop as the owner; markers at %08x)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l62_total,
                mmcs_l62_max_deliv, ova, tva, heir_h, owner_h,
                owner_tcb, lpcs, heir_h, MMCS_L54_STUB_VA + 0xf0);
        return;                     /* one delivery per cadence */
    }
    /* FLAVOR A — THE STANDING-COMPLETED GENERIC PARK (the death-close
     * aftermath, the f3b6d51 decode): the waiter BLOCKED at the
     * generic face 0x90837cf6 whose completed-list head [th+0x1F8]
     * STANDS (the stock death-close wrote it + the result cache
     * [th+0x1FC]:=0x1000) but the WAKE half died with the owner —
     * nobody ever reschedules the thread to run its own eval. The
     * resolved object (the completed entry's +0xC) = a CRIT in the
     * FREE state (0x80000000) with the D0-grave owner ctx. THE FIX =
     * the v9 WAKE-ONLY, NO plants: the resumed thread's own eval
     * consumes the head and the wait returns 0x1000 through 100%
     * vendor code (the L54/L55 class discipline; the waiter then
     * walks to the crit-enter face where FLAVOR B takes over). */
    for (uint32_t o = 0; o + 0x220 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, st16, ctxpc, f1f8, t1fc, t200;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&f1f8, arena + o + 0x1f8, 4);
        memcpy(&t1fc, arena + o + 0x1fc, 4);
        memcpy(&t200, arena + o + 0x200, 4);
        uint8_t susp = arena[o + 0xe];
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || (st16 & 3) != 2
            || ctxpc != 0x90837cf6      /* the generic wait face */
            || susp != 0
            || t200 != 0xffffffff
            || tva == pcur              /* the L54 class owns tva==pcur */
            || f1f8 == 0                /* no standing head = not the aftermath */
            || t1fc != 0x1000) {        /* the pair must be vendor-shaped */
            continue;
        }
        /* resolve the completed entry's object — THE ENTRY LAYOUT
         * (the eval fn_90828244 decode, 0x908282b6/0x90828398):
         * r8 = [th+0x1F8] (the head), obj = [r8+0x14] (mov.l
         * @(20,r8),r4 on every type arm), type byte = [r8+0x18].
         * (The L26/L32 resolver's {obj@+0xC, pTh@+0x14} reads are
         * relative to head+8 — the first A-branch draft read +0xC
         * off the head and silently missed the crit.) */
        uint32_t pa_e = mmcs_l32_stack_pa(f1f8 + 0x14);
        if (!pa_e) {
            if (mmcs_l62_diag) {
                fprintf(stderr, "MMCS-L62(diag): t=%" PRId64 "ms "
                        "standing waiter %08x entry %08x+0xc "
                        "PA-UNRESOLVED\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva,
                        f1f8);
            }
            continue;
        }
        uint32_t obj = 0;
        cpu_physical_memory_read(pa_e, &obj, 4);
        if (obj < 0x90680000 || obj >= 0x90780000) {
            continue;               /* not an arena object */
        }
        uint32_t ob = obj - 0x90680000;
        if (ob + 0xac > sizeof arena) {
            continue;
        }
        uint32_t ocinfo, oself, ostate, octx;
        memcpy(&ocinfo, arena + ob + 0xa4, 4);
        memcpy(&oself, arena + ob + 0xa8, 4);
        memcpy(&ostate, arena + ob + 0x94, 4);
        memcpy(&octx, arena + ob + 0x98, 4);
        if (ocinfo != 0x908220a0 || oself != obj
            || ostate != 0x80000000
            || octx < 0xD0000000 || octx >= 0xDC000000) {
            /* the owned flavor = FLAVOR B's world; the healthy
             * gwes-code owner ctx = a live owner class; the non-CRIT
             * object = the L55/L59 event lanes */
            fprintf(stderr, "MMCS-L62: t=%" PRId64 "ms standing "
                    "waiter %08x entry %08x obj %08x {cinfo %08x "
                    "self %08x state %08x octx %08x} - not the free-"
                    "crit aftermath\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva,
                    f1f8, obj, ocinfo, oself, ostate, octx);
            continue;
        }
        /* 2-cadence stability keyed {waiter,obj} */
        uint32_t key = tva ^ (obj * 3);
        if (mmcs_l62_key != key) {
            mmcs_l62_key = key;
            mmcs_l62_stable = 1;
            fprintf(stderr, "MMCS-L62: t=%" PRId64 "ms standing-"
                    "completed crit waiter seen: th %08x entry %08x "
                    "obj %08x (free, octx %08x the grave; f1f8 %08x "
                    "t1fc %08x) (stability %u/2; pick %08x pcur "
                    "%08x)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, f1f8,
                    obj, octx, f1f8, t1fc, mmcs_l62_stable, pick,
                    pcur);
            return;
        }
        if (++mmcs_l62_stable < 2) {
            return;
        }
        /* channel guards (the shared evt-0x320 discipline) */
        if (mmcs_l16_ents[7].pending) {
            fprintf(stderr, "MMCS-L62: t=%" PRId64 "ms evt-0x320 wake "
                    "mid-flight - retry next cadence\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL));
            return;
        }
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L54_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L54_STUB_VA && slot_cur != 0x90822e40) {
            fprintf(stderr, "MMCS-L62: slot evt 0x320 busy (%08x) - "
                    "retry next cadence\n", slot_cur);
            return;
        }
        if (mmcs_l62_diag) {
            fprintf(stderr, "MMCS-L62(diag): shape STABLE — would "
                    "WAKE-ONLY the standing waiter %08x (no plants); "
                    "diag mode, no delivery\n", tva);
            return;
        }
        /* DELIVER — the v9 WAKE-ONLY (no plants: the vendor's own
         * completion stands; the resumed eval consumes it) */
        uint32_t tva2 = tva;
        cpu_physical_memory_write(0x1F00E600, mmcs_l54_stub,
                                  sizeof mmcs_l54_stub);
        cpu_physical_memory_write(0x1F00E600 + 0x88, &tva2, 4);
        cpu_physical_memory_write(
            0x1F00E600 + 0x84,
            &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 }, 4);
        cpu_physical_memory_write(
            0x1F00E6F0,
            &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 }, 4);
        if (slot_cur != MMCS_L54_STUB_VA) {
            cpu_physical_memory_write(
                MMCS_L54_SLOT_PA,
                &(uint32_t){ MMCS_L54_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[7];
        e->evt_va = tva2;
        e->stub_va = MMCS_L54_STUB_VA;
        e->evt_code = 0x320;
        e->slot_pa = MMCS_L54_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l62_total++;
        fprintf(stderr, "MMCS-L62: t=%" PRId64 "ms standing-completed "
                "crit wake-only %u/%u: th %08x entry %08x obj %08x "
                "(the vendor's completion pair stands {f1f8 %08x, "
                "t1fc %08x}; NO plants — the resumed eval consumes "
                "the head and the wait returns 0x1000 through vendor "
                "code; markers at %08x)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l62_total,
                mmcs_l62_max_deliv, tva2, f1f8, obj, f1f8, t1fc,
                MMCS_L54_STUB_VA + 0xf0);
        return;                     /* one delivery per cadence */
    }
    /* no dead-owner crit this scan — reset the stability tracker */
    mmcs_l62_key = 0;
    mmcs_l62_stable = 0;
}

/* L64/S214: the Pacific-event aftermath wake — the generalized
 * standing-completed lane (EVNT objects; R24). See the L64EV comment
 * block above for the decode + the gate contract. */
static void mmcs_l64_scan(void)
{
    if (!mmcs_l64_armed || mmcs_l64_total >= mmcs_l64_max_deliv) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0, pick = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    if (prun != 0 || (pick != 0 && pick != pcur)) {
        if (mmcs_l64_diag) {
            fprintf(stderr, "MMCS-L64(diag): t=%" PRId64 "ms world "
                    "gate: prun %08x pick %08x pcur %08x\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), prun, pick,
                    pcur);
        }
        return;
    }
    for (uint32_t o = 0; o + 0x220 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, st16, ctxpc, f1f8, t1fc, t200;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&f1f8, arena + o + 0x1f8, 4);
        memcpy(&t1fc, arena + o + 0x1fc, 4);
        memcpy(&t200, arena + o + 0x200, 4);
        uint8_t susp = arena[o + 0xe];
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || (st16 & 3) != 2
            || ctxpc != 0x90837cf6      /* the generic wait face */
            || susp != 0
            || t200 != 0xffffffff
            || tva == pcur              /* the L54 class owns tva==pcur */
            || f1f8 == 0
            || t1fc != 0x1000) {
            continue;
        }
        /* the entry-layout law (the eval fn_90828244 decode): obj =
         * [head+0x14] */
        uint32_t pa_e = mmcs_l32_stack_pa(f1f8 + 0x14);
        if (!pa_e) {
            if (mmcs_l64_diag) {
                fprintf(stderr, "MMCS-L64(diag): t=%" PRId64 "ms "
                        "standing waiter %08x entry %08x+0x14 "
                        "PA-UNRESOLVED\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva,
                        f1f8);
            }
            continue;
        }
        uint32_t obj = 0;
        cpu_physical_memory_read(pa_e, &obj, 4);
        if (obj < 0x90680000 || obj >= 0x90780000) {
            continue;               /* the R13-ghost family never
                                     * resolves into the arena */
        }
        uint32_t ob = obj - 0x90680000;
        if (ob + 0xac > sizeof arena) {
            continue;
        }
        uint32_t ocinfo, oself, sig8d, sig8e;
        memcpy(&ocinfo, arena + ob + 0xa4, 4);
        memcpy(&oself, arena + ob + 0xa8, 4);
        uint8_t s8d = arena[ob + 0x8d];
        uint8_t s8e = arena[ob + 0x8e];
        sig8d = s8d;
        sig8e = s8e;
        (void)sig8d;
        if (ocinfo == 0x908220a0) {
            continue;               /* the CRIT aftermath = R23a
                                     * flavor A's own lane */
        }
        if (ocinfo != 0x90822040 || oself != obj
            || (sig8d == 0 && sig8e == 1)) {
            /* near-miss lines are UN-GATED (the L63 lesson: armed
             * runs must show their skips). The excluded class =
             * the L56 residue {8D==0, 8E==1}: the live sig ABSENT,
             * only the sticky bit stands — L56EV's pulse lane owns
             * it. The LIVE-SIG shape {8D==1, 8E==1} (the manual-
             * reset SET state — the live Pacific cells, t=36200
             * of the armed run) PASSES: a waiter on a SET
             * manual-reset event returns immediately in stock. */
            fprintf(stderr, "MMCS-L64: t=%" PRId64 "ms standing "
                    "waiter %08x entry %08x obj %08x {cinfo %08x "
                    "self %08x 8D %02x 8E %02x} - not the clean "
                    "Pacific-EVNT aftermath (see the gate)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva,
                    f1f8, obj, ocinfo, oself, sig8d, sig8e);
            continue;
        }
        /* 2-cadence stability keyed {waiter,obj} */
        uint32_t key = tva ^ (obj * 7);
        if (mmcs_l64_key != key) {
            mmcs_l64_key = key;
            mmcs_l64_stable = 1;
            fprintf(stderr, "MMCS-L64: t=%" PRId64 "ms Pacific-event "
                    "aftermath waiter seen: th %08x entry %08x obj "
                    "%08x {cinfo %08x 8D %02x 8E %02x} f1f8 %08x t1fc "
                    "%08x (stability %u/2; pick %08x pcur %08x)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, f1f8,
                    obj, ocinfo, sig8d, sig8e, f1f8, t1fc,
                    mmcs_l64_stable, pick, pcur);
            return;
        }
        if (++mmcs_l64_stable < 2) {
            return;
        }
        /* channel guards (the shared evt-0x320 discipline) */
        if (mmcs_l16_ents[7].pending) {
            fprintf(stderr, "MMCS-L64: t=%" PRId64 "ms evt-0x320 wake "
                    "mid-flight - retry next cadence\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL));
            return;
        }
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L54_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L54_STUB_VA && slot_cur != 0x90822e40) {
            fprintf(stderr, "MMCS-L64: t=%" PRId64 "ms slot evt 0x320 "
                    "busy (%08x) - retry next cadence\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), slot_cur);
            return;
        }
        if (mmcs_l64_diag) {
            fprintf(stderr, "MMCS-L64(diag): shape STABLE — would "
                    "WAKE-ONLY the Pacific-event waiter %08x (obj "
                    "%08x; no plants); diag mode, no delivery\n",
                    tva, obj);
            return;
        }
        /* DELIVER — the v9 WAKE-ONLY (no plants: the vendor's own
         * completion stands; the resumed eval consumes it) */
        uint32_t tva2 = tva;
        cpu_physical_memory_write(0x1F00E600, mmcs_l54_stub,
                                  sizeof mmcs_l54_stub);
        cpu_physical_memory_write(0x1F00E600 + 0x88, &tva2, 4);
        cpu_physical_memory_write(
            0x1F00E600 + 0x84,
            &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 }, 4);
        cpu_physical_memory_write(
            0x1F00E6F0,
            &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 }, 4);
        if (slot_cur != MMCS_L54_STUB_VA) {
            cpu_physical_memory_write(
                MMCS_L54_SLOT_PA,
                &(uint32_t){ MMCS_L54_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[7];
        e->evt_va = tva2;
        e->stub_va = MMCS_L54_STUB_VA;
        e->evt_code = 0x320;
        e->slot_pa = MMCS_L54_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l64_total++;
        fprintf(stderr, "MMCS-L64: t=%" PRId64 "ms Pacific-event "
                "aftermath wake-only %u/%u: th %08x entry %08x obj "
                "%08x (the vendor completion pair stands {f1f8 %08x, "
                "t1fc %08x}; 8D=%02x 8E=%02x — the L56 residue class "
                "is {8D==0, 8E==1}; NO "
                "plants — the resumed eval consumes the head and the "
                "wait returns 0x1000 through vendor code; markers at "
                "%08x)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l64_total,
                mmcs_l64_max_deliv, tva2, f1f8, obj, f1f8, t1fc,
                arena[ob + 0x8d], arena[ob + 0x8e],
                MMCS_L54_STUB_VA + 0xf0);
        return;                     /* one delivery per cadence */
    }
    /* no Pacific park this scan — reset the stability tracker */
    mmcs_l64_key = 0;
    mmcs_l64_stable = 0;
}

/* MMCS fork (L72/S223): MMCS_L72EV — THE POST-PARK COMPLETION
 * HAND-OFF (the OEMIdle-park world, decoded 2026-11-24; the L71/S222
 * "the masked sleep never wakes" reading corrected live: the park IS
 * the vendor's OWN live tick-driven idle drain — pc oscillates
 * 0x90822b96 (the switcher drain) <-> 0x908089fe (OEMIdle's
 * post-sleep reload), the L13 tick + the in_sleep BL-bypass deliver
 * the wake every pass, the idle counter [0x8867aad8] advances 0x2b62
 * per pass, the KCall defer cells read CLEAN {cNest=0, dwKCRes=0}
 * (the switcher's drain consumes the L52 protocol stores as designed
 * — the leak question answered; cNest==1 is the vendor's own standing
 * idle-drain marker, re-armed at 0x90822c5c after every idle call).
 * THE STALL (Observed, the l72 census): pick [0x8867efa4] == 0 and
 * pRunnable [0x8867efa0] == 0 FOREVER — the empty-runnable-set idle:
 * the world's threads are BLOCKED and the launcher (pCurTh STALE ==
 * 906ca240) sits with the CONSUMED completion {f1f8==0, t1fc==
 * 0x1000} at the wait-eval tail ctxpc=0x908378d8 (the tst r0,r0;
 * bf re-wait / r0==0 -> the flag poll -> rts -> pr=90843240 the
 * set-84 dispatch family) — the completion's MakeRun was lost in the
 * kills' aftermath. The L64 lane covers the PENDING-entry shape
 * (f1f8!=0, tva!=pcur); the L54 lane the LINKED wait with plants;
 * NOTHING covers the CONSUMED stale-pCurTh shape — the wake channel
 * is starved by exactly this park.
 *
 * THE FIX — the MINIMAL hand-off (v2): the resume path needs only
 * pick == pCurTh (the switcher 0x90822bb2 `cmp/eq r0,r14 -> bt
 * 0x90822bcc`) — NO scheduling state is touched:
 *   in-stub guard: (st16&3)==2 BLOCKED && [th+0x1F8]==0 (consumed)
 *     && [th+0x1FC]==0x1000 (the cached completion)
 *   the poison-neutralizer preload r8-r13 := [th+0x94..0xA8]
 *     (the switcher's entry save lands on the walker's OWN ctx,
 *     r14 == pCurTh == walker, stale)
 *   pick [0x8867efa4] := th ; r14 := [0x88679894] (== th) ;
 *   r0 := 0 (the wait-satisfied eval-tail value at the tst r0,r0
 *   resume point) ; jsr the vendor switcher 0x90822b68 -> the drain
 *   finds the cells CLEAN (no 0x90826f4c completion-drain call, no
 *   drain2 recompute) -> pick == r14 -> the 0x90822bcc resume path:
 *   r8/r9 from [th+0x94/0x98], r11-r15 from [th+0xA0..0xB0],
 *   spc=[th+0xB4], sp=[th+0xB0], ssr=[th+0xB8] -> rte -> the
 *   launcher's continuation (the flag poll -> rts to the 90843240
 *   set-84 call chain -> the park fn -> CreateProcessW RETURNS to
 *   c00ce888 -> the launch loop iterates).
 *   (v1 lesson, live-caught: MakeRun + the [0x88679884]:=1 protocol
 *   store made the switcher's cNest==1 drain — 0x90826f4c, its own
 *   MakeRun on the pick — re-insert the already-banded thread; the
 *   sorted-insert walk at 0x90825f7e-92 never exits on an
 *   equal-priority self-link — the walk spin, 100s+ observed. v2
 *   resumes the thread AS the current thread, exactly the stock
 *   lost-preempt outcome.)
 * Markers at stub+0xF0 (1 guard passed, 4 pre-switcher, 5 the
 * no-switch tell).
 *
 * Host filter: the L52 discipline — arena TCB + tva == pCurTh (THE
 * discriminator) + (st16&3)==2 + the consumed-completion pair
 * {f1f8==0, t1fc==0x1000} + ctxpc in the wait-eval tail window
 * [0x90837800, 0x9083800) + the dead-idle world gate (pick==0 ||
 * pick==tva; pRunnable==0) + 2-cadence stability keyed
 * {thread,ctxpc}. Repeating, delivery-capped (default 2),
 * SELF-TERMINATING (the shape dies when the wait resumes).
 *
 * Stub at KILLSTK 0xBF00E400 (SHARED with L52 — the shapes are
 * exclusive: L52 wants the FROZEN epilogue (st16&3)==0 at
 * 0x90837ae8, L72 the BLOCKED consumed-completion eval tail; both
 * write their own copy at delivery), dispatch slot evt 0x2E0
 * (PA 0x0867A05C, ents[5]). Env MMCS_L72EV (default OFF;
 * MMCS_L72EV_MS cadence default 2000; MMCS_L72EV_MAX cap default 2).
 * Needs MMCS_KILLSTK + MMCS_TICK. */
static uint8_t mmcs_l72_stub[] = {
    0x86, 0x2f, 0x96, 0x2f, 0xa6, 0x2f, 0xb6, 0x2f,
    0xc6, 0x2f, 0xd6, 0x2f, 0x22, 0x4f, 0x10, 0xd4,
    0x43, 0x50, 0x02, 0xc8, 0x38, 0x89, 0x01, 0xc8,
    0x36, 0x8b, 0x7e, 0xe0, 0x08, 0x40, 0x4e, 0x02,
    0x28, 0x22, 0x31, 0x8b, 0x10, 0xe1, 0x18, 0x41,
    0x04, 0x70, 0x4e, 0x02, 0x10, 0x32, 0x2b, 0x8b,
    0x25, 0xe0, 0x08, 0x40, 0x4e, 0x08, 0x04, 0x70,
    0x4e, 0x09, 0x04, 0x70, 0x4e, 0x0a, 0x04, 0x70,
    0x4e, 0x0b, 0x04, 0x70, 0x4e, 0x0c, 0x04, 0x70,
    0x4e, 0x0d, 0x03, 0xa0, 0x09, 0x00, 0x09, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0xe2, 0x0d, 0xd1,
    0x22, 0x21, 0x0e, 0xd4, 0x0e, 0xd2, 0x42, 0x22,
    0x0e, 0xd2, 0x22, 0x6e, 0x00, 0xe0, 0x04, 0xe2,
    0x0d, 0xd1, 0x22, 0x21, 0x0d, 0xd2, 0x0b, 0x42,
    0x09, 0x00, 0x05, 0xe2, 0x0c, 0xd1, 0x22, 0x21,
    0x26, 0x4f, 0xf6, 0x6d, 0xf6, 0x6c, 0xf6, 0x6b,
    0xf6, 0x6a, 0xf6, 0x69, 0x0b, 0x00, 0xf6, 0x68,
    0xf6, 0xaf, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe4, 0x5e, 0x82, 0x90, 0x00, 0x00, 0x00, 0x00,
    0xa4, 0xef, 0x67, 0x88, 0x94, 0x98, 0x67, 0x88,
    0x00, 0x00, 0x00, 0x00, 0x68, 0x2b, 0x82, 0x90,
    0x00, 0x00, 0x00, 0x00,
};
#define MMCS_L72_STUB_VA   0xBF00E400
#define MMCS_L72_SLOT_PA   0x0867A05C   /* evt 0x2E0, idx 5 (L52-shared) */

static void mmcs_l72_scan(void)
{
    if (!mmcs_l72_armed || mmcs_l72_total >= mmcs_l72_max_deliv) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0, pick = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    for (uint32_t o = 0; o + 0x220 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, ctxpc, ctxsp, f1f8, t1fc;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&ctxsp, arena + o + 0xb0, 4);
        memcpy(&f1f8, arena + o + 0x1f8, 4);
        memcpy(&t1fc, arena + o + 0x1fc, 4);
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000
            || tva != pcur                     /* THE discriminator */
            || (st16 & 3) != 2                 /* BLOCKED */
            || f1f8 != 0                       /* entry consumed */
            || t1fc != 0x1000                  /* cached completion */
            || ctxpc < 0x90837800              /* the wait-eval tail */
            || ctxpc >= 0x90838000             /* window */
            /* the dead-idle world gate: pick==0 (nothing queued) OR
             * pick==tva (the drain2 keep-current bookkeeping) —
             * someone ELSE's pick = vendor world mid-flight, skip */
            || (pick != 0 && pick != tva)
            || prun != 0) {
            continue;
        }
        /* 2-cadence stability keyed {thread,ctxpc} (the L46/L52
         * discipline — the shape must persist across scans) */
        uint32_t key = tva ^ ctxpc;
        if (mmcs_l72_key != key) {
            mmcs_l72_key = key;
            mmcs_l72_stable = 1;
            fprintf(stderr, "MMCS-L72: t=%" PRId64 "ms post-park shape "
                    "seen: th %08x *CUR* BLOCKED st16=%08x ctxpc=%08x "
                    "sp=%08x f1f8=%08x t1fc=%08x (stability %u/2)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, st16,
                    ctxpc, ctxsp, f1f8, t1fc, mmcs_l72_stable);
            return;
        }
        if (++mmcs_l72_stable < 2) {
            return;
        }
        /* DELIVER — first THE LEAK REPAIR (the S223 recipe item (i),
         * live-caught: the L52 hand-off's protocol stores
         * {[0x88679884]:=1, [0x88679888]:=1} STAND LEAKED after the
         * walker's continuation re-parks — every later switcher
         * entry then calls the cNest==1 completion drain 0x90826f4c,
         * whose own MakeRun on the pick re-inserts the still-banded
         * thread; the sorted-insert walk at 0x90825f7e-92 never
         * exits on the equal-priority self-link (the walk spin,
         * 100s+ observed). The park-shape gates make a legit
         * in-flight KCall impossible here (pick==0 && pRunnable==0
         * && the pCurTh-consumed-completion shape) — clear both
         * cells to the stock idle state). Then install, THEN patch
         * the pools (the L36 order). */
        cpu_physical_memory_write(0x08679884, &(uint32_t){ 0 }, 4);
        cpu_physical_memory_write(0x08679888, &(uint32_t){ 0 }, 4);
        cpu_physical_memory_write(0x1F00E400, mmcs_l72_stub,
                                  sizeof mmcs_l72_stub);
        cpu_physical_memory_write(0x1F00E400 + 0x50, &tva, 4);
        cpu_physical_memory_write(0x1F00E400 + 0x94, &tva, 4);
        uint32_t maddr = MMCS_L72_STUB_VA + 0xf0;
        cpu_physical_memory_write(0x1F00E400 + 0x8c, &maddr, 4);
        cpu_physical_memory_write(0x1F00E400 + 0xa0, &maddr, 4);
        cpu_physical_memory_write(0x1F00E400 + 0xa8, &maddr, 4);
        cpu_physical_memory_write(0x1F00E4F0, &maddr, 4);
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L72_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L72_STUB_VA) {
            if (slot_cur != 0x90822e40) {
                fprintf(stderr, "MMCS-L72: slot evt 0x2e0 busy (%08x) - "
                        "scan skipped\n", slot_cur);
                return;
            }
            cpu_physical_memory_write(MMCS_L72_SLOT_PA,
                                      &(uint32_t){ MMCS_L72_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[5];
        e->evt_va = tva;
        e->stub_va = MMCS_L72_STUB_VA;
        e->evt_code = 0x2E0;
        e->slot_pa = MMCS_L72_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l72_total++;
        fprintf(stderr, "MMCS-L72: t=%" PRId64 "ms post-park completion "
                "hand-off %u/%u: th %08x *CUR* BLOCKED ctxpc=%08x "
                "(the leak repair cNest/dwKCRes := 0 + pick + r0:=0 + "
                "the switcher resume; markers at %08x)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l72_total,
                mmcs_l72_max_deliv, tva, ctxpc, MMCS_L72_STUB_VA + 0xf0);
        return;                     /* one delivery per cadence */
    }
    /* no post-park shape this scan — reset the stability tracker */
    mmcs_l72_key = 0;
    mmcs_l72_stable = 0;
}

/* MMCS fork (L75/S226): the POST-KILL ORPHAN HAND-OFF — the daemon half
 * of MMCS_L75TX (the exception-boundary half lives in target/sh4/helper.c:
 * the dying-thread forward's dead address-space exit). DECODE (live, the
 * l75_census2 + l75_ho tapes on the l74-chain restore + MMCS_L75TX): the
 * kill lands and the scheduler IDLES (pc 0x908089fe, CurMSec ~960/s) with
 * pick == 0, pRunnable == 0, sleepHead == 0 — an EMPTY world. pCurTh is
 * the killed ZOMBIE (st16 02000018, ctxpc 0x9083c102 = KillThread's tail,
 * ctxsp on the KILLSTK page: the stock switcher's idle path never touches
 * pCurTh) and the launcher 0x906ca240 is an ORPHANED BLOCKED thread — the
 * L52/L54/L72 class (st16 020000e2, ctxpc 0x908378d8 = the wait-eval
 * tail, the consumed completion {f1f8 0, f1fc 0x1000}, in NO list: slnk 0,
 * wobj 0), byte-identical to its l74-chain cells: the L74CR wake stub took
 * the CPU from the launcher mid sleep-insert (the evt-0x320 interrupt
 * hit it at spc 0x908263e6 inside the insert walk) and its node was never
 * linked. The standing MMCS_L72EV hand-off is gated on tva == pCurTh —
 * behind a zombie it can never fire. DELIVERED HERE: when the world is
 * the dead-idle zombie shape and exactly this orphan park shape stands
 * (2-cadence stability), pCurTh := the orphan (ONE host write to
 * [0x88679894]) and the standing L72 daemon delivers its own hand-off on
 * its next cadence (the L72 stub/recipe verbatim — nothing new runs).
 * Env MMCS_L75TX (default off; needs MMCS_L72EV with budget —
 * MMCS_L72EV_MAX); MMCS_L75HO_MS cadence default 500, MMCS_L75HO_MAX cap
 * default 4. */
static void mmcs_l75ho_scan(void)
{
    if (!mmcs_l75ho_armed || mmcs_l75ho_total >= mmcs_l75ho_max_deliv
        || !mmcs_l72_armed) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0, pick = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    /* the dead-idle world: nothing queued, nothing picked */
    if (prun != 0 || pick != 0
        || pcur < 0x90680000 || pcur >= 0x90680000 + sizeof arena - 0x220) {
        return;
    }
    /* pCurTh must be the killed zombie: DYING (0x18) with its context
     * parked on the KILLSTK page (the kill continuation's stack) */
    uint32_t po = pcur - 0x90680000;
    uint32_t zst = 0, zsp = 0;
    memcpy(&zst, arena + po + 0xc, 4);
    memcpy(&zsp, arena + po + 0xb0, 4);
    if ((zst & 0x18) != 0x18 || zsp < 0xBF000000 || zsp >= 0xBF010000) {
        return;
    }
    for (uint32_t o = 0; o + 0x220 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, ctxpc, f1f8, t1fc, slnk, wobj;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&f1f8, arena + o + 0x1f8, 4);
        memcpy(&t1fc, arena + o + 0x1fc, 4);
        memcpy(&slnk, arena + o + 0x144, 4);
        memcpy(&wobj, arena + o + 0x14c, 4);
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000
            || tva == pcur
            || (st16 & 3) != 2                 /* BLOCKED */
            || f1f8 != 0                       /* entry consumed */
            || t1fc != 0x1000                  /* cached completion */
            || ctxpc < 0x90837800              /* the wait-eval tail */
            || ctxpc >= 0x90838000             /* window (the L72 pair) */
            || slnk != 0                       /* in no sleep list */
            || wobj != 0) {                   /* no wait object */
            continue;
        }
        /* 2-cadence stability keyed {thread,ctxpc} */
        uint32_t key = tva ^ ctxpc;
        if (mmcs_l75ho_key != key) {
            mmcs_l75ho_key = key;
            mmcs_l75ho_stable = 1;
            fprintf(stderr, "MMCS-L75TX: post-kill orphan shape seen: th %08x "
                    "BLOCKED st16=%08x ctxpc=%08x behind zombie pCurTh %08x "
                    "(stability %u/2)\n", tva, st16, ctxpc, pcur,
                    mmcs_l75ho_stable);
            return;
        }
        if (++mmcs_l75ho_stable < 2) {
            return;
        }
        /* DELIVER — one write: pCurTh := the orphan; the standing L72
         * daemon (same tick chain, after this scan) does the rest */
        cpu_physical_memory_write(0x08679894, &tva, 4);
        mmcs_l75ho_total++;
        fprintf(stderr, "MMCS-L75TX: post-kill orphan hand-off %u/%u: pCurTh "
                "%08x (killed zombie) := %08x (the orphaned launcher park "
                "ctxpc=%08x); the MMCS_L72EV daemon delivers next cadence\n",
                mmcs_l75ho_total, mmcs_l75ho_max_deliv, pcur, tva, ctxpc);
        return;
    }
    mmcs_l75ho_key = 0;
    mmcs_l75ho_stable = 0;
}

/* MMCS fork (L76/S227): MMCS_L76EV — THE EQUAL-PRIORITY STARVATION
 * RE-ARM (the cNest one-byte delivery; decoded 2026-11-24, the
 * recycled-servant lane).
 *
 * THE DECODE (Observed: l76_census2 + probes 1-10 + the hotblocks
 * aggregate on the l75-postkill restore; Verified: ROM disasm + the
 * wince500 mirror): the post-kill world holds TWO threads — the
 * launcher 0x906ca240 (inside the JIT-launch waiter UserDbgTrap/
 * FUN_90839f90, polling SC_ProcGetCode(pi.hProcess) == STILL_ACTIVE
 * with Sleep(250)) and the RECYCLED TCB 0x906a3c38 = the JIT
 * DEBUGGER's primary thread (CreateProcess'd by the launcher's own
 * second-chance set-84 0x234 exception; process Q 0x9068f958, hProc
 * 0x00e70002, start [th+0x150] = ThreadStart 0x90835f14). The
 * debugger thread stands RUNNABLE at prio 0xfb (the launcher's own —
 * inherited, never boosted) at the band-31 head [0x8867F024] with
 * well-formed FIFO links — and NEVER gets the CPU (356/356 samples =
 * the launcher):
 *
 *  (α) the law: equal priority never preempts — MakeRun/CreateThread
 *      write pick only on STRICT outrank (semantics-map §3; the
 *      vendor's FUN_9082611c FIFO-tail insert for equals);
 *  (β) the monopoly: the launcher's KCall'd sleep-insert walk spins
 *      at ~1.6M it/s (the S224 signature; the L74EV reap unlinks the
 *      re-created self-link ~5x/s but the loop re-submits within one
 *      iteration);
 *  (γ) the gate: the OUTER KCall return's resched check at
 *      0x9082304c — cNest [0x88679885] == 1 -> [0x88679884] word :=
 *      1 -> bra 0x90822b0a (the pre-switcher save) -> THE SWITCHER.
 *      Live cNest == 0x00 always, so the bf is taken and the
 *      switcher/drain2/MakeRun/ThreadStart/OEMIdle each executed ZERO
 *      times in a 12 s hotblocks window. Nothing in this world sets
 *      cNest: the tick's resched-consider is dropped at rte, MakeRun
 *      never runs (no wakes), the quantum never expires, and a bare
 *      [0x88679888] := 1 is consumed without a switch (probe9).
 *
 * THE DELIVERY (probe10, live-proven): ONE byte, cNest := 1. The very
 * next outer KCall return takes the vendor's own gate -> the
 * pre-switcher save -> the switcher -> the idle path -> drain2 (floor
 * [0x8867a9fc] = 0xff >= band 0xfb -> pick := the queue head) -> THE
 * STARVED THREAD RUNS. On HW this is the quantum-expiry resched the
 * monopolist's never-completing KCall starves here.
 *
 * GATE (the starvation shape, 2-cadence stable): a RUNNABLE
 * (st16 low2 == 1) thread at the run-band head [0x8867efa0] that is
 * NOT pCurTh, does NOT outrank it (prio byte >= pCurTh's — if it
 * outranked, stock's own outrank tail would have fired), pick == 0
 * and cNest == 0. Both TCBs must live in the kernel-arena VA window
 * (0x88600000..0x90800000, VA-0x80000000 == PA).
 *
 * Env MMCS_L76EV (default off); MMCS_L76EV_MS cadence default 500,
 * MMCS_L76EV_MAX cap default 4. */
static void mmcs_l76_scan(void)
{
    if (!mmcs_l76_armed || mmcs_l76_total >= mmcs_l76_max_deliv) {
        return;
    }
    uint32_t pcur = 0, pick = 0, prun = 0, kd84 = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    cpu_physical_memory_read(0x08679884, &kd84, 4);
    /* the starvation shape: a queued non-current candidate, no pick,
     * and the KCall-return gate un-armed */
    if (prun == 0 || prun == pcur || pick != 0
        || ((kd84 >> 8) & 0xff) != 0
        || prun < 0x88600000 || prun >= 0x90800000
        || pcur < 0x88600000 || pcur >= 0x90800000) {
        mmcs_l76_key = 0;
        mmcs_l76_stable = 0;
        return;
    }
    uint32_t pst = 0, pw = 0, cst = 0, cw = 0;
    cpu_physical_memory_read(prun - 0x80000000 + 0x0C, &pst, 4);
    cpu_physical_memory_read(prun - 0x80000000 + 0x40, &pw, 4);
    cpu_physical_memory_read(pcur - 0x80000000 + 0x40, &cw, 4);
    cpu_physical_memory_read(pcur - 0x80000000 + 0x0C, &cst, 4);
    uint8_t cand_prio = (pw >> 8) & 0xff;    /* [th+0x41] */
    uint8_t cur_prio = (cw >> 8) & 0xff;
    /* RUNNABLE candidate that does NOT outrank the current (equal or
     * lower priority; stock handles outrank itself) and a current
     * thread still in the running/transition states (low2 != 2-only
     * parked-blocked is fine — the stale-mark class runs BLOCKED) */
    if ((pst & 3) != 1 || cand_prio < cur_prio || (cst & 3) == 3) {
        mmcs_l76_key = 0;
        mmcs_l76_stable = 0;
        return;
    }
    uint32_t key = pcur ^ prun;
    if (mmcs_l76_key != key) {
        mmcs_l76_key = key;
        mmcs_l76_stable = 1;
        fprintf(stderr, "MMCS-L76: starvation shape seen: pCurTh %08x "
                "(prio %02x, st16 %08x) monopolizes while band head %08x "
                "(prio %02x, st16 %08x) RUNNABLE, pick 0, cNest 0 "
                "(stability %u/2)\n",
                pcur, cur_prio, cst, prun, cand_prio, pst,
                mmcs_l76_stable);
        return;
    }
    if (++mmcs_l76_stable < 2) {
        return;
    }
    /* DELIVER — one byte: cNest := 1; the vendor's own KCall-return
     * gate (0x9082304c) then routes to the pre-switcher save, the
     * switcher, the idle-path drain and pick := the band head */
    uint8_t one = 1;
    cpu_physical_memory_write(0x08679885, &one, 1);
    mmcs_l76_total++;
    fprintf(stderr, "MMCS-L76: equal-priority starvation re-arm %u/%u: "
            "cNest [0x88679885] := 1 (pCurTh %08x prio %02x vs band head "
            "%08x prio %02x) — the vendor KCall-return gate reschedules\n",
            mmcs_l76_total, mmcs_l76_max_deliv, pcur, cur_prio,
            prun, cand_prio);
    mmcs_l76_key = 0;
    mmcs_l76_stable = 0;
}

/* MMCS fork (L77/S228): MMCS_L77EV — THE KILL-PATH API-LOCK CLEANUP
 * RELEASE (the dying thread's lock-ownership clear; decoded
 * 2026-11-24, the userdbgtrap-churn lane).
 *
 * THE DECODE (Observed: l77_census/probes 1-9 + the high-cadence RSP
 * sampling on the l76-rearm restore; Verified: ROM disasm + the
 * wince500 mirror): the L76 world's "UserDbgTrap churn" is NOT in
 * UserDbgTrap — the launcher 0x906ca240 is on ITS OWN DEATH PATH. Its
 * unhandled second-chance set-84 exception (code 0xC0000005 parked at
 * TCB+0x38) ran the vendor chain (exception dispatcher -> UserDbgTrap
 * FUN_90839f90 -> the JIT-debugger CreateProcess + poll), the poll is
 * PAST, and the kill continuation FUN_9083be50 called its API-LOCK
 * CLEANUP fn_9083adfc (xref: the ONLY caller), whose loop
 * KCall(fn_90826f20 = "[pCurTh+0x164] ? that-crit : mark+0") waits for
 * the ownership transfer that fn_90828a08 performs only when the
 * owner cell pair [crit+0x98]+{0,+4} (= 0x8867adf4/0x8867adf4+4, the
 * KData API-lock owner cells) names the CURRENT thread
 * ([KData+8]|1, stocked by the switcher at 0x90822bc4 on every real
 * switch). Live: the cells read {1, 1} (the loop's own mark) vs
 * hCurTh|1 = 0x5c0003 — the E-branch transfer can never fire because
 * NO thread will ever acquire the dead API set's lock again, and the
 * stale waiter mark halfword[crit+0x96] == 0x8000 (the L74-era
 * deadlock residue) keeps the loop on the E branch instead of the
 * no-waiter D branch. The loop spins at KCall rate forever: A PARK
 * INSIDE THE VENDOR'S OWN DEATH MACHINERY.
 *
 * THE DELIVERY (probe8, live-proven): ONE word, [pCurTh+0x164] := 0.
 * The very next poll takes fn_90826f20's own zero path (it sets the
 * released-mark halfword[pCurTh+12] |= 0x10 itself and returns 0), the
 * loop exits through the vendor tail (F = 0x9082bbb4, G = 0x9082bc84),
 * the kill continuation proceeds and the death LANDS (ctxpc reaches
 * the kill-epilogue grave 0x9083c102, st16 0x020000d8) — the world
 * settles into the healthy tick-driven dead-idle (OEMIdle drain
 * cycling, no cascade, no exception storm). On HW the transfer chain
 * completes because live threads re-acquire the API lock constantly;
 * the stock-shape clear is what the vendor machinery reaches through
 * that chain.
 *
 * GATE (2-cadence stable): pCurTh = a kernel-arena TCB carrying a
 * DEATH CODE ([th+0x38] & 0xF0000000 == 0xC0000000, the NTSTATUS
 * fatal class) + the DYING mark (st16 [th+0xC] bit 0x08 — the L75
 * DYING vocabulary) + a standing lock ownership [th+0x164] = an arena
 * crit whose halfword[+0x96] == 0x8000 (the E-branch mark) and whose
 * owner pair [+0x98] lands in KData with the transfer condition
 * standing FALSE ([owner+4] != [th+0x3C]|1 — if it named the current
 * thread, the vendor's own transfer branch would fire; never
 * compete with it).
 *
 * Env MMCS_L77EV (default off); MMCS_L77EV_MS cadence default 500,
 * MMCS_L77EV_MAX cap default 4. */
static void mmcs_l77_scan(void)
{
    if (!mmcs_l77_armed || mmcs_l77_total >= mmcs_l77_max_deliv) {
        return;
    }
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    if (pcur < 0x88600000 || pcur >= 0x90800000) {
        mmcs_l77_key = 0;
        mmcs_l77_stable = 0;
        return;
    }
    uint32_t pa = pcur - 0x80000000;
    uint32_t crit = 0, st16 = 0, code = 0, hth = 0;
    cpu_physical_memory_read(pa + 0x164, &crit, 4);
    cpu_physical_memory_read(pa + 0x0C, &st16, 4);
    cpu_physical_memory_read(pa + 0x38, &code, 4);
    cpu_physical_memory_read(pa + 0x3C, &hth, 4);
    /* the dying-with-an-exception witness: the death code + the
     * DYING bit (the L75 0x02000008 vocabulary; the cleanup-world
     * launcher reads 0x020000c8) */
    if (crit < 0x88600000 || crit >= 0x90800000
        || ((code & 0xF0000000) != 0xC0000000)
        || !(st16 & 0x08)) {
        mmcs_l77_key = 0;
        mmcs_l77_stable = 0;
        return;
    }
    uint16_t hw96 = 0;
    uint32_t pown = 0, own2 = 0;
    cpu_physical_memory_read(crit - 0x80000000 + 0x96, &hw96, 2);
    cpu_physical_memory_read(crit - 0x80000000 + 0x98, &pown, 4);
    if (hw96 != 0x8000 || pown < 0x88600000 || pown >= 0x90800000) {
        mmcs_l77_key = 0;
        mmcs_l77_stable = 0;
        return;
    }
    cpu_physical_memory_read(pown - 0x80000000 + 4, &own2, 4);
    /* the transfer condition standing false: if the owner cell already
     * named hCurTh|1 the vendor's own transfer branch (fn_90828a08
     * 0x90828a28) would fire — do not compete with the vendor path */
    if (own2 == ((hth | 1) & 0xFFFFFFFF)) {
        mmcs_l77_key = 0;
        mmcs_l77_stable = 0;
        return;
    }
    uint32_t key = pcur ^ crit;
    if (mmcs_l77_key != key) {
        mmcs_l77_key = key;
        mmcs_l77_stable = 1;
        fprintf(stderr, "MMCS-L77: kill-path cleanup shape seen: pCurTh "
                "%08x (st16 %08x, code %08x) holds crit %08x "
                "{hw96 %04x, owner %08x/%08x vs hTh %08x} "
                "(stability %u/2)\n",
                pcur, st16, code, crit, hw96, pown, own2, hth,
                mmcs_l77_stable);
        return;
    }
    if (++mmcs_l77_stable < 2) {
        return;
    }
    /* DELIVER — one word: [pCurTh+0x164] := 0; the vendor's own next
     * poll (KCall fn_90826f20) takes its zero path (the released-mark
     * halfword |= 0x10 is ITS write), the cleanup loop exits through
     * the vendor tail and the death completes */
    uint32_t zero = 0;
    cpu_physical_memory_write(pa + 0x164, &zero, 4);
    mmcs_l77_total++;
    fprintf(stderr, "MMCS-L77: kill-path cleanup release %u/%u: "
            "[pCurTh+0x164] := 0 (pCurTh %08x crit %08x code %08x; the "
            "vendor zero-path exit -> the death lands)\n",
            mmcs_l77_total, mmcs_l77_max_deliv, pcur, crit, code);
    mmcs_l77_key = 0;
    mmcs_l77_stable = 0;
}

/* MMCS fork (L78/S229): MMCS_L78EV — THE LOST-MAKERUN REQUEUE (the
 * stock empty-queue head-path delivery for a RUNNABLE-marked thread
 * off the run queue; decoded 2026-11-25, the post-dead-world lane).
 *
 * THE DECODE (Observed: l78_census/probe1..3 on the l77-postdeath
 * restore; Verified: ROM disasm of MakeRun 0x90825ee4 + the semantics
 * map §3): the post-death world parks in the healthy tick-driven
 * dead-idle with pCurTh = the zombie launcher, pick = 0 and pRunnable
 * [0x8867efa0] = 0 — while the sibling 0x906dc000 (the KITL worker,
 * start cell [th+0x150] = 0x90845b78 kitl.dll) sits RUNNABLE-marked
 * (st16 low2 == 1) at the multi-wait face 0x90837cf6 (FUN_90837bcc),
 * SELF-LINKED (+0x154/+0x158 == th — the insert's thread-side writes
 * survived) but with EVERY band head cell 0: the second half of its
 * MakeRun (the band-head + pRunnable writes) was lost in the kills'
 * aftermath. The L76EV gate reads prun == 0 so it can never fire.
 * THE STOCK SHAPE (MakeRun's empty-queue head fast path, disasm:
 * [th+0x148] := 0; band_head[prio>>3] := th at 0x8867efa8+4*band;
 * pRunnable := th; SetReschedule dwKCRes := 1 when pick == 0) —
 * delivered, the idle drain's pick scan (FUN_90827148, walks the
 * pRunnable +0x144 chain for the first RUNNABLE) computes pick := th
 * and the switcher 0x90822b68 resumes it through 100% vendor code.
 * LIVE-PROVEN (l78_probe2/3): the sibling runs its wait-return walk
 * and EXITS CLEANLY (the grave 0x9083c102, death code [th+0x38] = 0,
 * no fault, no serial, sp unwound past the kitl start frame, the
 * world stays in the healthy dead-idle).
 *
 * GATE (2-cadence stable): the dead-idle world (pRunnable == 0 and
 * pick in {0, pCurTh}) + an arena TCB, NOT pCurTh, RUNNABLE-marked
 * (st16 low2 == 1), self-linked +0x154/+0x158, its band head cell 0,
 * a sane prio byte — and (the absent-counterparty honesty) the wait
 * face ctxpc in FUN_90837bcc's window [0x90837c00, 0x9083800) with
 * the verdict cell [th+0x74] == 0 (a satisfied/cached wait verdict —
 * the resume is the vendor's own wait-return path). Arena scan
 * 0x90680000..0x90700000, first match.
 *
 * Env MMCS_L78EV (default off); MMCS_L78EV_MS cadence default 500,
 * MMCS_L78EV_MAX cap default 4. */
static void mmcs_l78_scan(void)
{
    if (!mmcs_l78_armed || mmcs_l78_total >= mmcs_l78_max_deliv) {
        return;
    }
    uint32_t pcur = 0, pick = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    /* the dead-idle world: nobody queued, nothing picked */
    if (prun != 0 || (pick != 0 && pick != pcur)) {
        mmcs_l78_key = 0;
        mmcs_l78_stable = 0;
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t cand = 0, cst16 = 0, cprio = 0;
    for (uint32_t o = 0; o + 0x220 <= sizeof arena; o += 4) {
        uint32_t st16, ctxpc, w74, l154, l158;
        memcpy(&st16, arena + o + 0x0c, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&w74, arena + o + 0x74, 4);
        memcpy(&l154, arena + o + 0x154, 4);
        memcpy(&l158, arena + o + 0x158, 4);
        uint32_t tva = 0x90680000 + o;
        uint8_t prio = arena[o + 0x41];
        if ((st16 & 3) != 1                       /* RUNNABLE-marked */
            || tva == pcur                        /* not the current */
            || l154 != tva || l158 != tva         /* self-linked */
            || prio == 0                          /* sane prio byte */
            || ctxpc < 0x90837C00                 /* the wait face */
            || ctxpc >= 0x90838000
            || w74 != 0) {                        /* satisfied verdict */
            continue;
        }
        uint32_t bh = 0;
        cpu_physical_memory_read(0x0867EFA8 + 4 * (prio >> 3), &bh, 4);
        if (bh != 0) {
            continue;                             /* band occupied */
        }
        cand = tva;
        cst16 = st16;
        cprio = prio;
        break;
    }
    if (!cand) {
        mmcs_l78_key = 0;
        mmcs_l78_stable = 0;
        return;
    }
    if (mmcs_l78_key != cand) {
        mmcs_l78_key = cand;
        mmcs_l78_stable = 1;
        fprintf(stderr, "MMCS-L78: lost-MakeRun shape seen: candidate "
                "%08x (st16 %08x, prio %02x, band %u head 0, pRunnable "
                "0, pick %08x) (stability %u/2)\n",
                cand, cst16, cprio, cprio >> 3, pick, mmcs_l78_stable);
        return;
    }
    if (++mmcs_l78_stable < 2) {
        return;
    }
    /* DELIVER — the stock MakeRun empty-queue head fast path: the
     * thread-side self-links and the RUNNABLE mark are already in
     * place; the missing words are the queue-side ones */
    uint32_t zero = 0, one = 1;
    cpu_physical_memory_write(cand - 0x80000000 + 0x148, &zero, 4);
    cpu_physical_memory_write(0x0867EFA8 + 4 * (cprio >> 3), &cand, 4);
    cpu_physical_memory_write(0x0867EFA0, &cand, 4);
    cpu_physical_memory_write(0x08679888, &one, 4);
    mmcs_l78_total++;
    fprintf(stderr, "MMCS-L78: lost-MakeRun requeue %u/%u: [band%u head] "
            ":= %08x, [pRunnable] := %08x, dwKCRes := 1 (st16 %08x prio "
            "%02x) — the vendor idle-drain pick scan + switcher resume\n",
            mmcs_l78_total, mmcs_l78_max_deliv, cprio >> 3, cand, cand,
            cst16, cprio);
    mmcs_l78_key = 0;
    mmcs_l78_stable = 0;
}

/* MMCS fork (L79/S230): MMCS_L79EV — THE TERMINATION WALKER'S
 * DEAD-OWNER LOOP-EXIT (the sibling's crit-face completion; decoded
 * 2026-11-25, the crit-face lane).
 *
 * THE DECODE (Observed: l79_probe1..6 on the l78-parkedpair restore;
 * Verified: ROM disasm of the walker FUN_90840754): the sibling
 * 0x906dc000 (BLOCKED + DYING, st16 0x0200004a) parks at the crit face
 * 0x90840814 INSIDE the PROCESS-TERMINATION WALKER FUN_90840754 (its
 * ONLY caller FUN_908383c8 = the kill-everything continuation; the
 * entry gate [param_1+0x98] == param_2). The walker walks the thread
 * list terminating threads and its loop tail (0x9084084a-62) compares
 * [param_2+4] (the wait-node's OWNER HANDLE) against [KData+8]
 * (hCurTh, the switcher-stocked current-thread handle) — the loop
 * exits only when the CURRENT thread's handle equals the node's
 * owner. THE REGISTER MAPPING (live-proven, probe5 — the rung-4 note
 * RETRACTED: its save-block words were the CALLEE's registers):
 * r8 = param_1 = 0x906ff75c (the arena thread-proxy object), r10 =
 * param_2 = 0x8867eaa0 = THE KDATA WAIT-NODE GLOBAL {+0 count,
 * +4 owner hTh, +8 obj, ...} — the same object the S127/L8 pool
 * decode found (0x90836014 -> 0x8867eaa0, the 0x908383c8
 * creation/kill family's param_2).
 *
 * THE STALL: the node's owner cell reads 0xe80002 = THE PARKED DBG
 * THREAD's hTh (the L78 parked pair's other half — BLOCKED at its own
 * wait-eval tail, never becoming current), while the walk runs ON THE
 * SIBLING: on every wake the sibling executes the tail with hCurTh =
 * 0x4e0002 != 0xe80002 = the compare NEVER matches and the loop
 * re-enters the blocking KCall — the walker churns at KCall rate
 * (probe5's pc/ctxpc census: the tail's queue-unlink 0x90827964, the
 * wait-submit 0x90828784, the case-1 calls 0x9083d358/0x90828924)
 * with ctxpc pinned at the face. In stock the OWNER thread runs its
 * own walk and the compare matches first-past; our post-kill world
 * shuffled the walk onto the sibling's context (the L75-class
 * ownership divergence).
 *
 * THE DELIVERY (live-proven, probe6): ONE WORD — [0x8867eaa0+4] :=
 * the runner's own hTh — plus the L78-style requeue (the st16
 * RUNNABLE re-mark + band head + pRunnable + dwKCRes). The vendor
 * machinery then does everything: the pick scan switches to the
 * runner (hCurTh := its hTh), the resumed walk executes the tail, the
 * compare MATCHES, the exit call (pool 0x908408b8 = 0x90827b94) runs,
 * the node's owner cell CLEARS ITSELF (the stock wait-node teardown
 * consuming the match — live-caught: 0x4e0002 -> 0), and the
 * termination completes: THE GRAVE 0x9083c102 (st16 0x02000058, sp
 * unwound, no fault, no serial) in ~2 s.
 *
 * GATE (2-cadence stable): the stale-pCurTh world (pCurTh an arena
 * TCB; pRunnable == 0 and pick in {0, pCurTh}) + the self-witnessed
 * node ([0x8867EAA0+8] = an arena object whose [+0x98] ==
 * 0x8867EAA0 — the entry-gate relation) + the owner [0x8867EAA0+4] =
 * the hTh of a PARKED arena thread (found by scan, (st16&3)==2, NOT
 * pCurTh — the owner cannot become current) + a RUNNER arena TCB
 * (scan, first match) with ctxpc in the walker window [0x90840754,
 * 0x90840880), (st16&3)==2 BLOCKED at the walker's blocking KCall,
 * the DYING mark (st16 bit 0x08), a sane prio byte, and its own band
 * head cell 0.
 *
 * Env MMCS_L79EV (default off); MMCS_L79EV_MS cadence default 500,
 * MMCS_L79EV_MAX cap default 4. */
static void mmcs_l79_scan(void)
{
    if (!mmcs_l79_armed || mmcs_l79_total >= mmcs_l79_max_deliv) {
        return;
    }
    uint32_t pcur = 0, pick = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    if (pcur < 0x90680000 || pcur >= 0x90780000
        || prun != 0 || (pick != 0 && pick != pcur)) {
        mmcs_l79_key = 0;
        mmcs_l79_stable = 0;
        return;
    }
    /* the self-witnessed KData wait-node */
    uint32_t node = 0x8867EAA0u;
    uint32_t obj = 0, gate = 0, owner = 0;
    cpu_physical_memory_read(node - 0x80000000 + 8, &obj, 4);
    if (obj < 0x90680000 || obj >= 0x90780000) {
        mmcs_l79_key = 0;
        mmcs_l79_stable = 0;
        return;
    }
    cpu_physical_memory_read(obj - 0x80000000 + 0x98, &gate, 4);
    cpu_physical_memory_read(node - 0x80000000 + 4, &owner, 4);
    if (gate != node || owner == 0) {
        mmcs_l79_key = 0;
        mmcs_l79_stable = 0;
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    /* the owner: a PARKED arena thread (BLOCKED — it cannot execute the
     * walk even when it is the STALE pCurTh, the parked-pair world's
     * exact shape: the DBG parked BLOCKED as the current thread) */
    int owner_parked = 0;
    for (uint32_t o = 0; o + 0x220 <= sizeof arena; o += 4) {
        uint32_t h, st;
        memcpy(&h, arena + o + 0x3c, 4);
        memcpy(&st, arena + o + 0x0c, 4);
        if (h == owner && (st & 3) == 2) {
            owner_parked = 1;
            break;
        }
    }
    if (!owner_parked) {
        mmcs_l79_key = 0;
        mmcs_l79_stable = 0;
        return;
    }
    /* the runner: BLOCKED + DYING at the walker face, off-queue */
    uint32_t runner = 0, rst16 = 0, rprio = 0, rhth = 0;
    for (uint32_t o = 0; o + 0x220 <= sizeof arena; o += 4) {
        uint32_t st16, ctxpc, hth, l154, l158;
        memcpy(&st16, arena + o + 0x0c, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&hth, arena + o + 0x3c, 4);
        memcpy(&l154, arena + o + 0x154, 4);
        memcpy(&l158, arena + o + 0x158, 4);
        uint32_t tva = 0x90680000 + o;
        uint8_t prio = arena[o + 0x41];
        if ((st16 & 3) != 2                       /* BLOCKED */
            || !(st16 & 0x08)                     /* DYING */
            || tva == pcur
            || hth == owner                       /* not the owner */
            || ctxpc < 0x90840754                 /* the walker window */
            || ctxpc >= 0x90840880
            || prio == 0
            || l154 != tva || l158 != tva) {      /* self-linked residue */
            continue;
        }
        uint32_t bh = 0;
        cpu_physical_memory_read(0x0867EFA8 + 4 * (prio >> 3), &bh, 4);
        if (bh != 0) {
            continue;
        }
        runner = tva;
        rst16 = st16;
        rprio = prio;
        rhth = hth;
        break;
    }
    if (!runner) {
        mmcs_l79_key = 0;
        mmcs_l79_stable = 0;
        return;
    }
    if (mmcs_l79_key != runner) {
        mmcs_l79_key = runner;
        mmcs_l79_stable = 1;
        fprintf(stderr, "MMCS-L79: walker dead-owner shape seen: runner "
                "%08x (st16 %08x, prio %02x, hTh %08x) at the face, node "
                "%08x owner %08x (a parked thread) (stability %u/2)\n",
                runner, rst16, rprio, rhth, node, owner, mmcs_l79_stable);
        return;
    }
    if (++mmcs_l79_stable < 2) {
        return;
    }
    /* DELIVER — the loop-exit word + the L78-style requeue */
    uint32_t zero = 0, one = 1;
    uint32_t runnable = (rst16 & 0xFFFF0000) | ((rst16 & 0xFFFC) | 1);
    cpu_physical_memory_write(node - 0x80000000 + 4, &rhth, 4);
    cpu_physical_memory_write(runner - 0x80000000 + 0x0C, &runnable, 4);
    cpu_physical_memory_write(runner - 0x80000000 + 0x148, &zero, 4);
    cpu_physical_memory_write(0x0867EFA8 + 4 * (rprio >> 3), &runner, 4);
    cpu_physical_memory_write(0x0867EFA0, &runner, 4);
    cpu_physical_memory_write(0x08679888, &one, 4);
    mmcs_l79_total++;
    fprintf(stderr, "MMCS-L79: walker dead-owner loop-exit %u/%u: "
            "[node %08x +4] := %08x (the runner's hTh) + the requeue "
            "(st16 %08x -> RUNNABLE, band %u head, pRunnable, dwKCRes) — "
            "the vendor tail compare matches, the exit call runs, the "
            "node owner self-clears, the death lands at the grave\n",
            mmcs_l79_total, mmcs_l79_max_deliv, node, rhth, rst16,
            rprio >> 3);
    mmcs_l79_key = 0;
    mmcs_l79_stable = 0;
}

/* MMCS fork (L73/S224): MMCS_L73EV — THE CHURN LIVELOCK RELEASE (the
 * stale sleep-node self-link unlink; decoded 2026-11-24, the S224
 * wait-retry-churn lane).
 *
 * THE DECODE (Observed: l73_census.py + the hotblocks aggregate on the
 * l73-churn snapshot; Verified: ROM disasm): the L72 hand-off resumes
 * the launcher as the CURRENT thread, but the L52-era stub insert left
 * its node on the SLEEP LIST forever — head [0x8867ef8c] == th AND
 * [th+0x144] == th (the self-link; wake tick [th+0x1E8] = 0x6ffc,
 * ancient) — the same insert artifact whose run-queue half was the
 * L72 walk-spin engine. Every subsequent timed-wait submit
 * (fn_90828164 -> fn_908263cc, the `while (KCall(PutThreadToSleep) ||
 * GET_NEEDSLEEP)` loop face 0x908378ce) walks the sleep list to find
 * the insert position; the walk's tick compare ([cand+0x1E8] <
 * deadline) always advances to the candidate, L6440 sets cursor :=
 * candidate and returns 1 (re-evaluate) — with the candidate's next
 * pointing AT ITSELF the walk NEVER terminates: the launcher spins
 * 1.65M walk iterations/s INSIDE a KCall that never completes, so the
 * KCall tail / resched-now path is never reached — A SCHEDULER
 * MONOPOLY (no other thread can run, interrupts tick CurMSec but
 * bResched is only consumed at the KCall exit). The wait's deadline
 * still expires (fn_90828164 returns 0 when now >= deadline — the
 * observed ~2s re-poll cadence), so the livelock does not stop the
 * poll loop itself; it burns the CPU and starves the world.
 *
 * THE FIX: unlink the impossible-stock state. A CURRENT thread cannot
 * be a member of the sleep list (a sleeping thread is BLOCKED and off
 * pCurTh). Gates: pCurTh == t (an arena TCB) && [0x8867ef8c] == t &&
 * [t+0x144] == t && 2-cadence stability keyed {t, head, nxt}.
 * Delivery: [t+0x144] := 0 and [0x8867ef8c] := 0 host-side. The next
 * wait submit's walk then completes through 100% vendor code: the
 * empty-list insert path (L6532/L6562) parks the thread properly
 * (state16 := BLOCKED|0x20, [t+0x1E8] := deadline, dwReschedTime
 * min-update), dwKCRes := 1 -> the KCall tail resched-now -> the
 * switcher -> the world gets the CPU back. Env MMCS_L73EV (default
 * OFF; MMCS_L73EV_MS cadence default 1000; MMCS_L73EV_MAX cap
 * default 4). Needs MMCS_TICK. */
static void mmcs_l73_scan(void)
{
    if (!mmcs_l73_armed || mmcs_l73_total >= mmcs_l73_max_deliv) {
        return;
    }
    uint32_t pcur = 0, pick = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    if (pcur < 0x90680000 || pcur >= 0x90780000) {
        return;                       /* not an arena thread */
    }
    uint32_t tpa = pcur - 0x80000000;
    uint32_t kbase = 0, ksz = 0, klow = 0;
    cpu_physical_memory_read(tpa + 0x20, &kbase, 4);
    cpu_physical_memory_read(tpa + 0x24, &ksz, 4);
    cpu_physical_memory_read(tpa + 0x2c, &klow, 4);
    if (kbase < 0xD0000000 || kbase >= 0xDC000000
        || ksz != 0x10000
        || klow < 0xD0000000 || klow >= 0xDC000000) {
        return;                       /* not a TCB shape */
    }
    uint32_t head = 0, nxt = 0;
    cpu_physical_memory_read(0x0867EF8C, &head, 4);
    cpu_physical_memory_read(tpa + 0x144, &nxt, 4);
    if (head != pcur) {
        mmcs_l73_key = 0;
        mmcs_l73_stable = 0;
        return;
    }
    /* THE UNIFIED STALE-NODE GATE (v4): the current thread is RUNNING
     * ((st16&3)!=2) while its own node sits at the sleep-list head
     * with an EXPIRED wake tick ([th+0x1E8] < CurMSec) — the node the
     * vendor's tick-bottom-half expiry (the fn1/L38TIMER lane) should
     * have reaped. Two live shapes: the L52-era SELF-LINK (nxt==th,
     * the walk-spin engine) and the RESURRECTED clean node (nxt==0,
     * re-created every poll cycle: the expired own node at the head
     * makes each fresh walk's tick-compare advance the cursor onto
     * it, and the r4!=0 insert path re-links th before itself).
     * A future-tick head==pcur belongs to a live park — skip (the
     * thread would be BLOCKED anyway). */
    uint32_t st16 = 0, wtick = 0, now = 0;
    cpu_physical_memory_read(tpa + 0xc, &st16, 4);
    cpu_physical_memory_read(tpa + 0x1E8, &wtick, 4);
    cpu_physical_memory_read(0x0867AAD0, &now, 4);
    int self_link = (nxt == pcur);
    if ((st16 & 3) == 2 || wtick >= now) {
        /* parked with a live node — stock; reset */
        mmcs_l73_key = 0;
        mmcs_l73_stable = 0;
        return;
    }
    uint32_t key = pcur ^ head ^ nxt;
    if (mmcs_l73_key != key) {
        mmcs_l73_key = key;
        mmcs_l73_stable = 1;
        fprintf(stderr, "MMCS-L73: t=%" PRId64 "ms stale sleep node seen: "
                "th %08x *CUR* head %08x nxt %08x%s tick %08x now %08x "
                "(stability %u/2)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), pcur, head, nxt,
                self_link ? " [self-link]" : " [expired-own-node]",
                wtick, now, mmcs_l73_stable);
        return;
    }
    if (++mmcs_l73_stable < 2) {
        return;
    }
    /* DELIVER v2: unlink the list cells AND the in-flight sleeper's
     * walk cursor. (v1 lesson, live-caught in the first A/B: the list
     * unlink alone is undone within ONE submit — the churn's last
     * L6440 left [sleeper+0] == th (the cursor == the thread itself);
     * the next submit's r4!=0 path (L651e -> L652e -> L6562) performs
     * "insert before the cursor": [th+0x144] := pCurTh == th — the
     * SELF-LINK RE-CREATED, then the walk spins against it again. The
     * sleeper is the wait-face frame at [th+0xB0]+0x10 (Verified: the
     * face 0x908378b0 prologue; live: sp 0xd00beaa4 -> sleeper
     * 0xd00beab4); its +0 must equal th for the clear to be safe
     * (self-evidencing gate — a cursor pointing anywhere else belongs
     * to a different, legitimate walk). */
    uint32_t ctxsp = 0, cursor = 0;
    cpu_physical_memory_read(tpa + 0xb0, &ctxsp, 4);
    int cursor_cleared = 0;
    if (ctxsp >= 0xD0000000 && ctxsp < 0xDC000000) {
        uint32_t spa = ctxsp - 0xC0000000 + 0x10;
        cpu_physical_memory_read(spa, &cursor, 4);
        if (cursor == pcur) {
            cpu_physical_memory_write(spa, &(uint32_t){ 0 }, 4);
            cpu_physical_memory_write(spa + 6, &(uint16_t){ 0 }, 2);
            cursor_cleared = 1;
        }
    }
    cpu_physical_memory_write(0x0867EF8C, &(uint32_t){ 0 }, 4);
    cpu_physical_memory_write(tpa + 0x144, &(uint32_t){ 0 }, 4);
    mmcs_l73_total++;
    fprintf(stderr, "MMCS-L73: t=%" PRId64 "ms stale sleep-node unlinked "
            "%u/%u: th %08x *CUR*%s ([0x8867ef8c] := 0, [th+0x144] := 0%s; "
            "the next wait submit parks through vendor code)\n",
            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l73_total,
            mmcs_l73_max_deliv, pcur, self_link ? " [self-link]"
            : " [expired-own-node reaped]",
            cursor_cleared ? ", sleeper cursor+flag := 0" :
            " (sleeper cursor not th — list-only)");
}

static void mmcs_l74_scan(void)
{
    if (!mmcs_l74_armed) {
        return;
    }
    if (mmcs_l74_max_deliv && mmcs_l74_total >= mmcs_l74_max_deliv) {
        return;
    }
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    if (pcur < 0x90680000 || pcur >= 0x90780000) {
        return;                       /* not an arena thread */
    }
    uint32_t tpa = pcur - 0x80000000;
    uint32_t kbase = 0, ksz = 0, klow = 0;
    cpu_physical_memory_read(tpa + 0x20, &kbase, 4);
    cpu_physical_memory_read(tpa + 0x24, &ksz, 4);
    cpu_physical_memory_read(tpa + 0x2c, &klow, 4);
    if (kbase < 0xD0000000 || kbase >= 0xDC000000
        || ksz != 0x10000
        || klow < 0xD0000000 || klow >= 0xDC000000) {
        return;                       /* not a TCB shape */
    }
    uint32_t head = 0, nxt = 0;
    cpu_physical_memory_read(0x0867EF8C, &head, 4);
    cpu_physical_memory_read(tpa + 0x144, &nxt, 4);
    if (head != pcur) {
        mmcs_l74_key = 0;
        mmcs_l74_stable = 0;
        return;
    }
    uint32_t st16 = 0;
    cpu_physical_memory_read(tpa + 0xc, &st16, 4);
    /* THE RUNNING+OWN-NODE SIGNATURE (the L74 widening): a current
     * thread at the sleep-list head is impossible-stock at ANY tick
     * flavor. Shape A = the self-link (nxt == th, the walk-spin
     * engine, recreated every submit with a FUTURE [th+0x1E8] — the
     * exact window the L73 v4 expired-tick guard skipped) — NOTE the
     * st16 gate does NOT apply: the L72-resumed launcher carries a
     * STALE BLOCKED mark (live-caught in the first A/B: st16
     * 020000e2 while pCurTh executes the walk spin; the resume never
     * re-marks the state) — pCurTh-at-the-head IS the running fact.
     * Shape B = the expired own node (wtick < now) — the st16 gate
     * HOLDS here: a properly parked BLOCKED thread with a passed
     * deadline is the stock expiry case, not ours to unlink (orphan
     * risk); only the RUNNING mark makes it impossible-stock. */
    int self_link = (nxt == pcur);
    if (!self_link) {
        uint32_t wtick = 0, now = 0;
        if ((st16 & 3) == 2) {
            /* BLOCKED with a live node — a stock park */
            mmcs_l74_key = 0;
            mmcs_l74_stable = 0;
            return;
        }
        cpu_physical_memory_read(tpa + 0x1E8, &wtick, 4);
        cpu_physical_memory_read(0x0867AAD0, &now, 4);
        if (wtick >= now) {
            mmcs_l74_key = 0;
            mmcs_l74_stable = 0;
            return;
        }
    }
    uint32_t key = pcur ^ head ^ nxt;
    if (mmcs_l74_key != key) {
        mmcs_l74_key = key;
        mmcs_l74_stable = 1;
        fprintf(stderr, "MMCS-L74: t=%" PRId64 "ms standing-reap shape "
                "seen: th %08x *CUR* RUNNING head %08x nxt %08x%s "
                "(stability %u/2)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), pcur, head, nxt,
                self_link ? " [self-link]" : " [expired-own-node]",
                mmcs_l74_stable);
        return;
    }
    if (++mmcs_l74_stable < 2) {
        return;
    }
    /* DELIVER — the L73 v2 unlink, with the head SPLICE: a non-self
     * next keeps the tail ([0x8867ef8c] := nxt); the self-link/clean
     * node clears the head outright. The in-flight sleeper's walk
     * cursor ([th+0xB0]+0x10, gated == th — the v2 lesson: the stale
     * cursor re-creates the self-link within ONE submit) is cleared
     * first. */
    uint32_t ctxsp = 0, cursor = 0;
    cpu_physical_memory_read(tpa + 0xb0, &ctxsp, 4);
    int cursor_cleared = 0;
    if (ctxsp >= 0xD0000000 && ctxsp < 0xDC000000) {
        uint32_t spa = ctxsp - 0xC0000000 + 0x10;
        cpu_physical_memory_read(spa, &cursor, 4);
        if (cursor == pcur) {
            cpu_physical_memory_write(spa, &(uint32_t){ 0 }, 4);
            cpu_physical_memory_write(spa + 6, &(uint16_t){ 0 }, 2);
            cursor_cleared = 1;
        }
    }
    uint32_t newhead = self_link ? 0 : nxt;
    cpu_physical_memory_write(0x0867EF8C, &newhead, 4);
    cpu_physical_memory_write(tpa + 0x144, &(uint32_t){ 0 }, 4);
    mmcs_l74_total++;
    fprintf(stderr, "MMCS-L74: t=%" PRId64 "ms standing reap %u%s: th %08x "
            "*CUR* RUNNING%s ([0x8867ef8c] := %08x, [th+0x144] := 0%s; the "
            "walk completes through vendor code)\n",
            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l74_total,
            mmcs_l74_max_deliv ? " (capped)" : " (standing)",
            pcur, self_link ? " [self-link]" : " [expired-own-node]",
            newhead,
            cursor_cleared ? ", sleeper cursor+flag := 0" :
            " (sleeper cursor not th — list-only)");
}

/* MMCS fork (L74/S225): MMCS_L74CR — THE REENTRANT API-SET-LOCK
 * DEADLOCK BREAK (the S225 recipe item (ii); decoded 2026-11-24 on
 * the l74-reap world). THE DECODE (Observed: the l74_svframe +
 * l74_owner probes; Verified: ROM disasm): the servant/devmgr thread
 * (the event 0x90699d68's owner = the SETTER the launcher's polled
 * wait needs) is BLOCKED at the crit-enter face ctxpc=0x90840814
 * after KCall(fn_90828924) — the block core (state16 low2 := 2,
 * dwKCRes := 1). THE LOCK: the crit record at 0x906ff598
 * {+0/+4: lpcs-self 906ff4ec, +8: 0x8000fb01 OWNED with the PI bytes
 * 0xfb, +0xC: 0x8867adf4 = &the KData owner-handle cell}; the owner
 * handle [0x8867adf8] = 0x005c0002 = THE LAUNCHER'S OWN HANDLE (the
 * ONLY arena TCB carrying it — alive, churning the poll). THE
 * REENTRANCY WITNESS: BOTH threads carry the set-84 dispatch arg
 * spill {[th+0x7C] = [slot84] = 0xd0050260, [th+0x80] = 0x234} and
 * the same saved pr 0x90843240 — the servant's enter sits inside
 * FUN_90843214's ACTIVATEPROC tail (fn_9082bc84 -> 0x90837244) just
 * like the launcher's wait: the caller HOLDS the API-set lock across
 * its PerformCallBack wait while the server-side handler needs the
 * SAME lock to service the call. Stock never holds this lock across
 * the PSL wait — the L63-era acquisition's release was destroyed by
 * the kills' aftermath. THE FIX (the L63 B1 composite, manufactured):
 * transfer the owner cell [waiter_r10 + 4] := the waiter's own
 * handle [th+0x3C] (the enter-tail's own compare: [r10+4] vs
 * [[0x8867ed64]+8] — the current-handle cell — EXITS AS THE OWNER
 * when equal; the woken waiter's own tail then clears [pcur+0x14C]
 * and walks the owned-tail through vendor code) + the v9 WAKE (the
 * L54 stub, evt 0x320, shared-channel guarded). Guards: the waiter
 * shape {arena TCB + ctxpc == 0x90840814 + (st16&3)==2 + the
 * dispatch spill pair} + THE DEADLOCK WITNESS (the owner handle ==
 * the pcur thread's OWN [pcur+0x3C] AND pcur carries the SAME
 * dispatch spill — a live owner that is itself mid-dispatch on the
 * same call: only this reentrant shape is ever released; a plain
 * live owner is NEVER manufactured) + 2-cadence stability. Env
 * MMCS_L74CR (default OFF; MMCS_L74CR_MS cadence default 2000;
 * MMCS_L74CR_MAX cap default 2; MMCS_L74CR_DIAG = the verbose
 * near-miss diag). Needs MMCS_TICK. */

static void mmcs_l74cr_scan(void)
{
    if (!mmcs_l74cr_armed || mmcs_l74cr_total >= mmcs_l74cr_max_deliv) {
        return;
    }
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    if (pcur < 0x90680000 || pcur >= 0x90780000) {
        return;
    }
    uint32_t po = pcur - 0x90680000;
    /* THE OWNER-SIDE WITNESS FIRST: pcur carries a dispatch spill (a
     * D0-window method-table pointer + the 0x234 offset). NOTE the
     * spill-vs-CELL comparison is deliberately avoided: the L74S4
     * stock-clear may legitimately have cleared the slot cell before
     * this scan's stability completes (the ab3 world-split lesson) —
     * the reentrancy witness is the TWO THREADS' spills matching,
     * whatever the cell reads. */
    uint32_t p_sp7c = 0, p_sp80 = 0, p_h3c = 0;
    cpu_physical_memory_read(0x10680000 + po + 0x7C, &p_sp7c, 4);
    cpu_physical_memory_read(0x10680000 + po + 0x80, &p_sp80, 4);
    cpu_physical_memory_read(0x10680000 + po + 0x3C, &p_h3c, 4);
    if (p_sp7c < 0xD0000000 || p_sp7c >= 0xDC000000 || p_sp80 != 0x234
        || (p_h3c & 0xff000000)) {
        if (mmcs_l74cr_diag) {
            fprintf(stderr, "MMCS-L74CR(diag): t=%" PRId64 "ms pcur %08x "
                    "not mid-dispatch {sp7c %08x sp80 %08x h3c %08x} - skip\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), pcur, p_sp7c,
                    p_sp80, p_h3c);
        }
        return;
    }
    /* scan for the waiter: the crit-enter park with the same spill */
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    for (uint32_t o = 0; o + 0x220 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, st16, ctxpc, sp7c, sp80, h3c, r10;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&sp7c, arena + o + 0x7c, 4);
        memcpy(&sp80, arena + o + 0x80, 4);
        memcpy(&h3c, arena + o + 0x3c, 4);
        memcpy(&r10, arena + o + 0x9c, 4);
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || ctxpc != 0x90840814     /* the crit-enter park face */
            || (st16 & 3) != 2
            || arena[o + 0xe] != 0     /* not suspended */
            || sp7c != p_sp7c || sp80 != 0x234
            || (h3c & 0xff000000) != 0
            || tva == pcur) {
            continue;
        }
        /* the owner cell = the waiter's own enter-tail compare cell */
        if (r10 < 0x88600000 || r10 >= 0x88700000) {
            if (mmcs_l74cr_diag) {
                fprintf(stderr, "MMCS-L74CR(diag): t=%" PRId64 "ms waiter "
                        "%08x r10 %08x not KData - skip\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, r10);
            }
            continue;
        }
        uint32_t owner_h = 0;
        cpu_physical_memory_read(r10 - 0x80000000 + 4, &owner_h, 4);
        if (owner_h != p_h3c) {
            /* not the reentrant pair — a foreign/live owner: NEVER
             * manufacture (the L62 law) */
            if (mmcs_l74cr_diag) {
                fprintf(stderr, "MMCS-L74CR(diag): t=%" PRId64 "ms waiter "
                        "%08x owner_h %08x != pcur handle %08x - not the "
                        "reentrant pair, skip\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, owner_h,
                        p_h3c);
            }
            continue;
        }
        /* 2-cadence stability keyed {waiter, owner} */
        uint32_t key = tva ^ (owner_h * 5);
        if (mmcs_l74cr_key != key) {
            mmcs_l74cr_key = key;
            mmcs_l74cr_stable = 1;
            fprintf(stderr, "MMCS-L74CR: t=%" PRId64 "ms reentrant API-lock "
                    "deadlock seen: waiter %08x (crit face, spill {slot84, "
                    "0x234}) vs owner pcur %08x h %08x - ALSO mid-dispatch "
                    "(stability %u/2)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, pcur, p_h3c,
                    mmcs_l74cr_stable);
            return;
        }
        if (++mmcs_l74cr_stable < 2) {
            return;
        }
        /* channel guards FIRST (the R23 ordering law) */
        if (mmcs_l16_ents[7].pending) {
            fprintf(stderr, "MMCS-L74CR: t=%" PRId64 "ms evt-0x320 wake "
                    "mid-flight - retry next cadence\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL));
            return;
        }
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L54_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L54_STUB_VA && slot_cur != 0x90822e40) {
            fprintf(stderr, "MMCS-L74CR: t=%" PRId64 "ms slot evt 0x320 "
                    "busy (%08x) - retry next cadence\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), slot_cur);
            return;
        }
        if (mmcs_l74cr_diag) {
            fprintf(stderr, "MMCS-L74CR(diag): shape STABLE — would "
                    "transfer [%08x] := %08x and v9-wake %08x; diag mode, "
                    "no delivery\n", r10 + 4, h3c, tva);
            return;
        }
        /* DELIVER: THE TRANSFER (one write — the deadlock break; the
         * woken waiter's own enter tail reads [r10+4] == its current
         * handle and exits the loop as the owner through vendor
         * code) + THE V9 WAKE (the L54 recipe verbatim) */
        cpu_physical_memory_write(r10 - 0x80000000 + 4, &h3c, 4);
        cpu_physical_memory_write(0x1F00E600, mmcs_l54_stub,
                                  sizeof mmcs_l54_stub);
        cpu_physical_memory_write(0x1F00E600 + 0x88, &tva, 4);
        cpu_physical_memory_write(0x1F00E600 + 0x84,
                                  &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 }, 4);
        cpu_physical_memory_write(0x1F00E6F0,
                                  &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 }, 4);
        if (slot_cur != MMCS_L54_STUB_VA) {
            cpu_physical_memory_write(MMCS_L54_SLOT_PA,
                                      &(uint32_t){ MMCS_L54_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[7];
        e->evt_va = tva;
        e->stub_va = MMCS_L54_STUB_VA;
        e->evt_code = 0x320;
        e->slot_pa = MMCS_L54_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l74cr_total++;
        fprintf(stderr, "MMCS-L74CR: t=%" PRId64 "ms reentrant API-lock "
                "deadlock broken %u/%u: waiter %08x takes the lock "
                "([%08x] := %08x, was the owner pcur %08x's %08x) + the "
                "v9 wake; the servant services the call -> the event SET "
                "path (markers at %08x)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l74cr_total,
                mmcs_l74cr_max_deliv, tva, r10 + 4, h3c, pcur, owner_h,
                MMCS_L54_STUB_VA + 0xf0);
        return;                     /* one delivery per cadence */
    }
}


static void mmcs_l59_scan(void)
{
    if (!mmcs_l59_armed || mmcs_l59_pulses >= 6) {
        return;
    }
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    if (pcur < 0x90680000 || pcur >= 0x90780000) {
        return;                       /* not an arena thread */
    }
    uint32_t f1f8 = 0, wobj = 0;
    cpu_physical_memory_read(pcur - 0x80000000 + 0x1F8, &f1f8, 4);
    cpu_physical_memory_read(pcur - 0x80000000 + 0x14C, &wobj, 4);
    if (!f1f8 || wobj < 0xD0000000 || wobj >= 0xDC000000) {
        return;
    }
    uint32_t obj = 0;
    for (uint32_t wi = 0; wi <= 0x80; wi += 4) {
        uint32_t pa1 = mmcs_l32_stack_pa(wobj + wi + 0x14);
        uint32_t w1 = 0;
        if (!pa1) {
            continue;
        }
        cpu_physical_memory_read(pa1, &w1, 4);
        if (w1 != pcur) {
            continue;
        }
        uint32_t pa2 = mmcs_l32_stack_pa(wobj + wi + 0xC);
        if (pa2) {
            cpu_physical_memory_read(pa2, &obj, 4);
        }
        break;
    }
    if (obj < 0x90680000 || obj >= 0x90780000) {
        return;
    }
    /* THE CONSUMABLE CLASS: {8D==0, 8E==0, +0x90==0} — the retired
     * event (post-L58); the sticky classes belong to L56/L58 */
    uint8_t sig59 = 1, sticky = 1, z90 = 1;
    cpu_physical_memory_read(obj - 0x80000000 + 0x8d, &sig59, 1);
    cpu_physical_memory_read(obj - 0x80000000 + 0x8e, &sticky, 1);
    cpu_physical_memory_read(obj - 0x80000000 + 0x90, &z90, 1);
    if ((sig59 & 1) || sticky != 0 || z90 != 0) {
        return;
    }
    /* MMCS fork (L60/S210): THE SIGNALSTARTED SERVER-SIDE SYNTHESIS —
     * the s209 static lane's decode: the stock advance needs BOTH the
     * dependency's started bit (table[ord].+4 := 1; table =
     * [c00d1250], stride 0x4c0) AND the event SET (EventModify). The
     * L59 pulse alone satisfies the wait but the entry INDEX does not
     * advance (the walker re-checks the bit). The c00 module region
     * maps PA = VA - 0xB0000000 (live-proven: c00d5250 -> 106d5250). */
    if (mmcs_l60_armed) {
        uint32_t tbase = 0;
        uint32_t pa_cell = mmcs_l32_stack_pa(0xC00D1250);
        if (pa_cell) {
            cpu_physical_memory_read(pa_cell, &tbase, 4);
        }
        static int nl60diag;
        if (nl60diag < 6) {
            nl60diag++;
            fprintf(stderr, "MMCS-L60: diag: [c00d1250] pa %08x -> "
                    "tbase %08x\n", pa_cell, tbase);
        }
        if (tbase >= 0x00010000u && tbase < 0xE0000000u
            && !(tbase & 3)) {
            /* v2: the walk checks DEPENDENCIES' started bits
             * (entry[j].+4 where j = the scan index of the dep's
             * ordinal — NOT the ordinal itself). Mark ALL entries'
             * bits (k = 0..7, bounded; the LMEM_ZEROINIT buffer's
             * empty slots stay harmless): the walk then launches
             * every entry in order (the REAL CreateProcessW calls)
             * and exits to PSLNotify + EventModify(SystemStarted) —
             * the milestone. */
            for (uint32_t k = 0; k < 8; k++) {
                /* v3: read/write through the LIVE TLB (the current
                 * context IS filesys — the heap's owner): the pgown
                 * table misses the later heap pages (d0251000+);
                 * cpu_memory_rw_debug translates via the running
                 * context's page tables — the same path the gdbstub
                 * kernel-context reads proved. */
                uint32_t bit = 0;
                int rdbit = mmcs_cpu
                    ? cpu_memory_rw_debug(CPU(mmcs_cpu),
                                          tbase + 0x254 * k + 4,
                                          (void *)&bit, 4, 0) : -1;
                uint32_t ord = 0;
                int rdord = mmcs_cpu
                    ? cpu_memory_rw_debug(CPU(mmcs_cpu),
                                          tbase + 0x250 * k,
                                          (void *)&ord, 4, 0) : -1;
                static int nl60dump;
                if (nl60dump < 16) {
                    nl60dump++;
                    if (k == 0) {
                        uint16_t key = 0;
                        cpu_physical_memory_read(0x1069525C, &key, 2);
                        fprintf(stderr, "MMCS-L60: live scan key = %04x "
                                "(the CURRENT dep ordinal)\n", key);
                        /* the 0x4c0-stride entry ordinals */
                        for (uint32_t e = 0; e < 6; e++) {
                            uint32_t o4 = 0, b4 = 0;
                            int r1 = cpu_memory_rw_debug(
                                CPU(mmcs_cpu), tbase + 0x4c0 * e,
                                (void *)&o4, 4, 0);
                            int r2b = cpu_memory_rw_debug(
                                CPU(mmcs_cpu), tbase + 0x4c0 * e + 4,
                                (void *)&b4, 4, 0);
                            fprintf(stderr, "MMCS-L60: e4[%u] "
                                    "ord=%08x(%d) bit=%08x(%d)\n",
                                    e, o4, r1, b4, r2b);
                        }
                    }
                    fprintf(stderr, "MMCS-L60: dump: entry[%u] ord=%08x "
                            "(rd %d) bit=%08x (rd %d)\n",
                            k, ord, rdord, bit, rdbit);
                    if (k == 0) {
                        /* the layout scan: the first 24 nonzero words
                         * in the table block (find the real stride) */
                        int shown = 0;
                        for (uint32_t off = 0x40;
                             off < 0x2400 && shown < 24; off += 4) {
                            uint32_t w = 0;
                            if (cpu_memory_rw_debug(
                                    CPU(mmcs_cpu), tbase + off,
                                    (void *)&w, 4, 0) == 0 && w) {
                                fprintf(stderr, "MMCS-L60: layout: "
                                        "+%04x = %08x\n", off, w);
                                shown++;
                            }
                        }
                    }
                }
                if (rdbit) {
                    continue;
                }
                if (bit == 0) {
                    uint32_t one = 1;
                    if (!cpu_memory_rw_debug(
                            CPU(mmcs_cpu), tbase + 0x254 * k + 4,
                            (void *)&one, 4, 1)) {
                        fprintf(stderr, "MMCS-L60: t=%" PRId64 "ms "
                                "SignalStarted synthesis: table[%u]+4 "
                                ":= 1 (tbase %08x — the started bits "
                                "marked; the walk advances and LAUNCHES "
                                "each entry)\n",
                                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL),
                                k, tbase);
                    }
                }
            }
        }
    }
    /* THE PULSE (one word; the cycling eval consumes it) */
    uint8_t one = 1;
    cpu_physical_memory_write(obj - 0x80000000 + 0x8d, &one, 1);
    mmcs_l59_pulses++;
    fprintf(stderr, "MMCS-L59: t=%" PRId64 "ms completion-forward "
            "pulse %u/6: obj %08x [8D]:=1 (th %08x — the cycling eval "
            "consumes the SET: one pulse = one completion; the "
            "counter walks to limit and the launch loop exits)\n",
            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l59_pulses,
            obj, pcur);
}

/* MMCS fork (L37): MMCS_L37EV — the KCall-exit lost-preempt CLASS
 * daemon (the generic requeue fix at the vendor switcher boundary,
 * decoded 2026-11-20).
 *
 * THE RECURRING CLASS (L36's successor fixed point, reproduced live
 * with SCHEDTRACE in the successor combo + MMCS_L36EV armed): after the
 * L36 delivery the requeued WIN32 servant RUNS one scheduling quantum
 * (t=14263: q0=pick=pCurTh=servant, the MakeRun enqueue + the stub's
 * protocol pick visible) and at t=14273 — one tick later, at a KCall
 * exit (kcallflags cNest toggling back) — the vendor reschedule DEQUEUES
 * it (q0->0) and recomputes pick=0: the switcher's KCNextThread path
 * (0x90827452, entered from drain2 0x90827148 when dwKCRes[0x88679888]
 * is set) clears wInfo&3 and dequeues the current thread, and the
 * re-enqueue half never runs — the thread is left RUNNING(0)-but-not-
 * queued, pCurTh keeps it, OEMIdle spins forever. The stock guarantee
 * "a preempted runnable thread re-enters the runnable set" is lost at
 * EVERY such switch.
 *
 * WHY THE STOCK PATH NEVER SELF-HEALS (premise VERIFIED live at the
 * park, plain-run probes — no debugger): the vendor interrupt-exit
 * nested-reschedule check `if((cNest==1)&&(bResched==1))` (0x90823066,
 * the shexcept.src ieh48 mirror, word compare 0x0101 against
 * KData+0x84) needs SOMEBODY to set bResched — the timer ISR chain
 * (SetReschedule on quantum expiry). Under emulation that chain is
 * dead: the OAL timer table slots ([0x8867aa08]-0x48/-0x4c, the fn1/
 * fn2 indirection the timer ISR entry 0x90809d78 walks) read erased
 * (0x1010101), and the scheduler time cells dwReschedTime[0x8867ef88]/
 * dwPrevReschedTime[0x8867ef84]/CurMSec stay FROZEN at 0 across ticks
 * (probe: identical 0x0 before and after 3s of live ticks) — the
 * quantum-expiry compare in drain1 (0x9082702c, [table-0x38]-[-0x3c])
 * never sees time pass, bResched latches only from our own daemon
 * protocol stores, PendEvents1[0x886798b8] stays 0. A cNest underflow
 * (0xff00, t=65s in the repro) shows the nesting counter itself
 * drifting once the outermost-exit protocol is the only live half.
 *
 * FIX = the CLASS daemon: the same 100%-vendor requeue sequence as
 * L36EV (MakeRun 0x90825ee4 + the resched protocol stores + pick +
 * the vendor switcher 0x90822b68; stub guard state16&3 == 0), but the
 * host scan drops every per-site qualifier: ANY arena thread with a
 * D0 kstack whose state16 run-state is RUNNING(0)-out-of-queue, that
 * is not pCurTh, not a kill-epilogue grave (ctx pc 0x9083c102), not
 * zombie/dead-shaped, and whose saved ctx pc sits in a REAL code
 * window (kernel+XIP [0x90800000,0x908C0000) excluding the OAL idle
 * window [0x90808000,0x9080a000), the k.coredll servant window
 * [0xC0021000,0xC0083000), or the user window [0x40000000,0x48000000)
 * — the L36 scan's kernel-only window is why the recurrence parked:
 * the dropped servant resumes mid-k.coredll, outside its filter).
 * Gates: pick==0 && pRunnable==0 (nothing queued at all), the shared
 * movement signature (quiet-park trigger, 60 quiet scans park,
 * movement re-arms), one delivery per cadence (MMCS_L37EV_MS default
 * 2000), hard cap MMCS_L37EV_MAX (default 16). Delivery verified by
 * GUEST-WRITTEN MARKER READBACK (stage markers 1-5 at stub+0xF0) and
 * the requeued thread's state16|1 readback — never breakpoint hits.
 * Supersession scope (honest, A/B-recorded): the scan is a superset
 * of the L19TH-v5/L36 per-site requeue shapes ONLY — the L16EV/L19EV
 * event-wake class and the L26EV/L32EV BLOCKED-orphan classes are NOT
 * subsumed (their targets sit at state16&3 != 0).
 * Stub at KILLSTK 0xBF00EE00, dispatch slot evt 0x2C0 (PA 0x0867A058,
 * idx 4; skip when MMCS_L16EV is armed). Needs MMCS_KILLSTK +
 * MMCS_TICK. */
static uint8_t mmcs_l37_stub[] = {
    0x22, 0x4f, 0xe6, 0x2f, 0x19, 0xd4, 0x43, 0x50,  /* +00 */
    0x03, 0xc9, 0x00, 0x88, 0x02, 0x89, 0x25, 0xa0,  /* +08 */
    0x09, 0x00, 0x01, 0xe2, 0x14, 0xd2, 0x12, 0x22,  /* +10 */
    0x15, 0xd3, 0x0b, 0x43, 0x09, 0x00, 0x02, 0xe2,  /* +18 */
    0x11, 0xd2, 0x12, 0x22, 0x01, 0xe1, 0x09, 0x00,  /* +20 */
    0x12, 0xd2, 0x12, 0x22, 0x01, 0xe1, 0x09, 0x00,  /* +28 */
    0x11, 0xd2, 0x12, 0x22, 0x03, 0xe2, 0x09, 0x00,  /* +30 */
    0x0b, 0xd2, 0x12, 0x22, 0x0b, 0xd4, 0x09, 0x00,  /* +38 */
    0x0e, 0xd2, 0x42, 0x22, 0x0e, 0xd2, 0x20, 0x5e,  /* +40 */
    0x04, 0xe2, 0x09, 0x00, 0x06, 0xd2, 0x12, 0x22,  /* +48 */
    0x0c, 0xd3, 0x0b, 0x43, 0x09, 0x00, 0x05, 0xe2,  /* +50 */
    0x03, 0xd2, 0x12, 0x22, 0xf6, 0x6e, 0x26, 0x4f,  /* +58 */
    0x00, 0xe0, 0x0b, 0x00, 0x09, 0x00, 0x09, 0x00,  /* +60 */
    /* pool */
    0x00, 0x00, 0x00, 0x00,   /* +0x68 .Lm: marker cell VA (patched) */
    0x00, 0xd0, 0x6d, 0x90,   /* +0x6c .Lt: thread VA (patched) */
    0xe4, 0x5e, 0x82, 0x90,   /* .Lmk: 0x90825ee4 MakeRun */
    0x84, 0x98, 0x67, 0x88,   /* .Lf: 0x88679884 resched byte */
    0x88, 0x98, 0x67, 0x88,   /* .Lf2: 0x88679888 drain2 word */
    0xa4, 0xef, 0x67, 0x88,   /* .Lpick: 0x8867efa4 */
    0x94, 0x98, 0x67, 0x88,   /* .Lpcur: 0x88679894 */
    0x68, 0x2b, 0x82, 0x90,   /* .Lsw: 0x90822b68 switcher */
};
#define MMCS_L37_STUB_VA   0xBF00EE00
#define MMCS_L37_SLOT_PA   0x0867A058   /* evt 0x2C0, idx 4 */
#define MMCS_L37_QUIET_PARK 60
static uint32_t mmcs_l37_total;
static uint32_t mmcs_l37_quiet;
static uint8_t mmcs_l37_sig[MMCS_L19_NSIG];
static int mmcs_l37_sig_have;

/* MMCS fork (L41): MMCS_L41EV — the told-waiter WAIT-RETURN requeue
 * (S185, decoded 2026-11-21). The L40 frontier decode: the requeued
 * launcher 906ddacc dies because its preempted ctx (pc 0x9083b682,
 * the post-jsr retry site inside FUN_9083b668 — the KCall-backed
 * wait-submit wrapper, KCall fn 0x90826b88 via the trampoline
 * 0x908230e6) returns through `lds.l @r15+,pr; rts` at 0x9083b696-9a
 * with pr = kstack [sp+0x10] — and that cell is CLOBBERED: the
 * process-death observation tell planted its S131 marshal block
 * (0xe4 bytes, copier 0xc00360f4, planted at ~sp-0x1bc) over the
 * wrapper frame while the thread sat preempted (three runs, three
 * run-varying kernel-RAM data-page pointers: 0x88f3a000 / 0x88c7e000
 * / 0x88cb8000 / 0x88e6f000 — the pr cell and the retry frame are
 * unrecoverable; on HW the preemption window is microseconds and the
 * frame is intact). The rts lands in a kernel-RAM data page, the
 * illegal (pc < 0xFFFF8000, not retagged) forwards as 0xC000001D
 * through the c004dba2 stub -> the marshal 0x90825694 -> the CRT
 * filter -> ExitThread -> KillThread: the "requeued launcher dies in
 * the death cascade" of L40 §4. THE FIX — the stock semantics for a
 * waiter whose waited process died is the CLEAN WAIT-RETURN: rewrite
 * the requeue to resume the thread at its own wait-return site
 * (0x9083e24e, the instruction after the launcher lane's
 * `jsr 0x90837fa8` — the wait trampoline) with the stock post-wait
 * register state, through the exact struct cells the vendor switcher
 * restores (r8 +0x94 / r9 +0x98 / r10 +0x9c / sp +0xb0 / pc +0xb4;
 * verified cell-for-cell against the live resume register dump).
 * The RunApps frame anchor: the fn's saved-pr cell at [sp_site+0x10]
 * (= preempt-sp + 0x50) must read a k.coredll window address — the
 * live guard that the anchor frame survived the clobber (otherwise
 * fall back to the plain requeue). Site constants: r8=0x8867ed24
 * (pSignalStarted cell), r9=0x8867aa00, r10=arg (the creation arg =
 * hProc 0x00400002), sp_site = preempt_sp + 0x40. The continuation:
 * 0x9084b9c8 (close) -> 0x9083dff8 -> jsr [pSignalStarted] ->
 * 0x9082daa8 -> 0x9084887c -> the vendor KillThread tail — 100%
 * vendor code, the launch loop the S156 matrix pre-decoded.
 * Env MMCS_L41EV (default off; rides the L37 daemon's delivery). */
static int mmcs_l41_armed;
static uint32_t mmcs_l41_rewrites;

/* the ctx-pc acceptance windows (VA): kernel+XIP, k.coredll servants,
 * user — with the OAL idle loop AND the switcher machinery carved out
 * (a thread parked inside the OAL window is the idle context, and a
 * ctx pc inside the resched-entry/switcher/idle block 0x90822a80..
 * 0x90822c80 or the KCall-exit protocol window means the thread was
 * mid-switch — KCNextThread already dequeued it; MakeRun-ing it would
 * resume a half-switched context — live-caught in the cen1 park dump:
 * the freed 0x906ddaa0 shape, ctx b4=0x9082bbf4 = the switcher's own
 * per-switch callback) */
static bool mmcs_l37_pc_ok(uint32_t pc)
{
    if (pc >= 0x90800000 && pc < 0x908C0000) {
        if (pc >= 0x90808000 && pc < 0x9080A000) {
            return false;              /* OAL idle/timer window */
        }
        if (pc >= 0x90822a80 && pc < 0x90822c80) {
            return false;              /* resched entry + switcher + idle */
        }
        if (pc >= 0x908230a0 && pc < 0x90823160) {
            return false;              /* rte-exit family + KCall wrapper */
        }
        return true;
    }
    if (pc >= 0xC0021000 && pc < 0xC0083000) {
        return true;                   /* k.coredll servant window */
    }
    return pc >= 0x40000000 && pc < 0x48000000;
}

static void mmcs_l37_scan(void)
{
    uint8_t sig[MMCS_L19_NSIG];

    if (mmcs_l37_total >= mmcs_l37_max_deliv) {
        if (mmcs_l37_armed) {
            fprintf(stderr, "MMCS-L37: hard cap %u deliveries reached - "
                    "daemon parked\n", mmcs_l37_total);
            mmcs_l37_armed = 0;
        }
        return;
    }    mmcs_l19_signature(sig);
    bool moved = mmcs_l37_sig_have
                 && memcmp(sig, mmcs_l37_sig, MMCS_L19_NSIG) != 0;
    memcpy(mmcs_l37_sig, sig, MMCS_L19_NSIG);
    mmcs_l37_sig_have = 1;
    if (moved) {
        mmcs_l37_quiet = 0;
        if (!mmcs_l37_armed) {
            mmcs_l37_armed = 1;
            fprintf(stderr, "MMCS-L37: t=%" PRId64 "ms movement while "
                    "parked - re-armed (%u deliveries used)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l37_total);
        }
    } else if (mmcs_l37_armed && ++mmcs_l37_quiet >= MMCS_L37_QUIET_PARK) {
        fprintf(stderr, "MMCS-L37: t=%" PRId64 "ms %u quiet scans - "
                "daemon parked at %u deliveries\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l37_quiet,
                mmcs_l37_total);
        mmcs_l37_armed = 0;
        mmcs_l37_quiet = 0;
    }
    if (!mmcs_l37_armed) {
        return;
    }
    /* the whole-system-blocked gate: nothing queued at all */
    uint32_t pick = 0, prun = 0;
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    if (pick != 0 || prun != 0) {
        return;
    }
    /* the CLASS arena scan: ANY alive D0-kstack thread left
     * RUNNING(0)-but-not-queued by a KCall-exit switch */
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    uint32_t cand = 0, cand_pc = 0, cand_sp = 0, cand_st = 0;
    for (uint32_t o = 0; o + 0x200 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, pc0, pc1;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&pc0, arena + o + 0xb0, 4);
        memcpy(&pc1, arena + o + 0xb4, 4);
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000) {
            continue;
        }
        uint32_t tva = 0x90680000 + o;
        /* the kill-epilogue graves (both ctx save points) */
        if (pc0 == 0x9083c102 || pc1 == 0x9083c102) {
            continue;
        }
        if (cand || tva == pcur) {
            continue;
        }
        /* the class state: RUNNING(0)-out-of-queue, not dead (bit 3
         * is the L18 DEAD marker), not zombie-shaped */
        if ((st16 & 3) != 0 || (st16 & 8) != 0
            || (st16 & 0x02000000) != 0) {
            continue;
        }
        /* the ctx must sit in a real code window */
        uint32_t pc = mmcs_l37_pc_ok(pc0) ? pc0
                    : mmcs_l37_pc_ok(pc1) ? pc1 : 0;
        if (!pc) {
            continue;
        }
        cand = tva;
        cand_pc = pc;
        cand_sp = (pc == pc0) ? pc1 : pc0;
        cand_st = st16;
    }
    if (!cand) {
        return;                       /* not the lost-preempt park shape */
    }
    /* L41: the told-waiter wait-return rewrite — when the preempted ctx
     * is exactly the FUN_9083b668 post-jsr retry site, the wrapper's
     * return frame is tell-clobbered (see the block comment above);
     * resume the thread at its own stock wait-return site instead */
    uint32_t l41_new_pc = 0;
    if (mmcs_l41_armed && cand_pc == 0x9083b682) {
        uint32_t th_pa = cand - 0x80000000;
        uint32_t arg = 0, anchor = 0;
        cpu_physical_memory_read(th_pa + 0x88, &arg, 4);
        /* the surviving-frame guard: the RunApps fn's saved-pr cell
         * (D0 kstack VA — resolve through the PGOWN/FILEVIEW tables) */
        uint32_t sp_site = cand_sp + 0x40;
        uint32_t anchor_pa = mmcs_l32_stack_pa(sp_site + 0x10);
        if (anchor_pa) {
            cpu_physical_memory_read(anchor_pa, &anchor, 4);
        }
        if (arg == 0x00400002
            && anchor >= 0xC0021000 && anchor < 0xC0083000) {
            uint32_t rgprs[3];
            rgprs[0] = 0x8867ed24;        /* r8  +0x94 */
            rgprs[1] = 0x8867aa00;        /* r9  +0x98 */
            rgprs[2] = arg;               /* r10 +0x9c */
            cpu_physical_memory_write(th_pa + 0x94, rgprs, sizeof rgprs);
            cpu_physical_memory_write(th_pa + 0xb0,
                                       &(uint32_t){ sp_site }, 4);
            cpu_physical_memory_write(th_pa + 0xb4,
                                       &(uint32_t){ 0x9083e24e }, 4);
            l41_new_pc = 0x9083e24e;
            mmcs_l41_rewrites++;
        } else {
            fprintf(stderr, "MMCS-L41: told-waiter rewrite SKIPPED for "
                    "thread %08x (arg %08x anchor %08x - frame guard "
                    "failed, plain requeue)\n", cand, arg, anchor);
        }
    }
    /* deliver: install, THEN patch the pool (.Lt +0x6c thread VA, .Lm
     * +0x68 marker-cell VA) — the .Lt patch-order bug class (L36
     * finding): patch-then-install silently restores the default .Lt */
    cpu_physical_memory_write(0x1F00EE00, mmcs_l37_stub,
                              sizeof mmcs_l37_stub);
    cpu_physical_memory_write(0x1F00EE00 + 0x6c, &cand, 4);
    cpu_physical_memory_write(0x1F00EE00 + 0x68,
                              &(uint32_t){ MMCS_L37_STUB_VA + 0xf0 }, 4);
    cpu_physical_memory_write(0x1F00EEF0,
                              &(uint32_t){ MMCS_L37_STUB_VA + 0xf0 }, 4);
    uint32_t slot_cur = 0;
    cpu_physical_memory_read(MMCS_L37_SLOT_PA, &slot_cur, 4);
    if (slot_cur != MMCS_L37_STUB_VA) {
        if (slot_cur != 0x90822e40) {
            fprintf(stderr, "MMCS-L37: slot evt 0x2c0 busy (%08x) - "
                    "scan skipped\n", slot_cur);
            return;
        }
        cpu_physical_memory_write(MMCS_L37_SLOT_PA,
                                  &(uint32_t){ MMCS_L37_STUB_VA }, 4);
    }
    struct mmcs_l16_ent *e = &mmcs_l16_ents[4];
    e->evt_va = cand;
    e->stub_va = MMCS_L37_STUB_VA;
    e->evt_code = 0x2C0;
    e->slot_pa = MMCS_L37_SLOT_PA;
    e->daemon = 1;
    e->pending = 1;
    mmcs_l37_total++;
    fprintf(stderr, "MMCS-L37: t=%" PRId64 "ms lost-preempt requeue thread "
            "%08x (state16 %08x, ctx pc %08x sp %08x, delivery %u/%u%s)\n",
            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), cand, cand_st,
            l41_new_pc ? l41_new_pc : cand_pc, cand_sp,
            mmcs_l37_total, mmcs_l37_max_deliv,
            l41_new_pc ? "; L41 told-waiter wait-return rewrite applied"
                       : "");
}


/* MMCS fork (L19): MMCS_L19TH=threadVA@ms[,threadVA@ms] — the THREAD-
 * level enqueue completion (v5 stub; the original decode comment was
 * truncated by the L32 block insertion — see git history for the full
 * text; mechanism summary: MakeRun(pThread) + the resched protocol
 * stores + pick=pThread + r14=pCurTh + jsr the vendor switcher). */
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
    bool moved = mmcs_l19_sig_have
                 && memcmp(sig, mmcs_l19_sig, MMCS_L19_NSIG) != 0;
    memcpy(mmcs_l19_sig, sig, MMCS_L19_NSIG);
    mmcs_l19_sig_have = 1;
    if (moved) {
        mmcs_l19_quiet = 0;
        if (!mmcs_l19_armed) {
            mmcs_l19_armed = 1;
            fprintf(stderr, "MMCS-L19: t=%" PRId64 "ms movement while "
                    "parked - re-armed (%u deliveries used)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l19_total);
        }
    } else if (mmcs_l19_armed && ++mmcs_l19_quiet >= MMCS_L19_QUIET_PARK) {
        fprintf(stderr, "MMCS-L19: t=%" PRId64 "ms %u quiet scans - "
                "daemon parked at %u deliveries\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l19_quiet,
                mmcs_l19_total);
        mmcs_l19_armed = 0;
        mmcs_l19_quiet = 0;
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
        if (++mmcs_l19_nopick % 60 == 1) {
            fprintf(stderr, "MMCS-L19: t=%" PRId64 "ms no lost wake in "
                    "the arena (scan %u)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l19_nopick);
        }
        return;               /* nothing wake-pending: stay silent */
    }
    mmcs_l19_nopick = 0;
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
    if (getenv("MMCS_L32EV")) {
        if (getenv("MMCS_L19TH")) {
            fprintf(stderr, "MMCS-L32: shares slot idx 0 (evt 0x220) "
                    "with MMCS_L19TH — drop L19TH; not arming L32\n");
        } else {
            mmcs_l32_cadence_ms =
                atoi(getenv("MMCS_L32EV_MS") ? : "2000");
            if (!mmcs_l32_cadence_ms) {
                mmcs_l32_cadence_ms = 2000;
            }
            mmcs_l32_max_deliv = atoi(getenv("MMCS_L32EV_MAX") ? : "64");
            if (!mmcs_l32_max_deliv) {
                mmcs_l32_max_deliv = 64;
            }
            mmcs_l32_armed = 1;
            fprintf(stderr, "MMCS-L32: create-completion event daemon "
                    "armed (cadence %ums, cap %u; stub %08x slot evt "
                    "0x220 wired on first delivery)\n",
                    mmcs_l32_cadence_ms, mmcs_l32_max_deliv,
                    MMCS_L32_STUB_VA);
        }
    }
    /* L46: the create-interlock SPLIT repair (one-shot; shares the
     * L32 slot machinery, pending/slot-guarded — see mmcs_l46_scan) */
    if (getenv("MMCS_L46FIX")) {
        if (getenv("MMCS_L19TH")) {
            fprintf(stderr, "MMCS-L46: shares slot idx 0 (evt 0x220) "
                    "with MMCS_L19TH — drop L19TH; not arming L46\n");
        } else {
            mmcs_l46_cadence_ms =
                atoi(getenv("MMCS_L46FIX_MS") ? : "2000");
            if (!mmcs_l46_cadence_ms) {
                mmcs_l46_cadence_ms = 2000;
            }
            mmcs_l46_armed = 1;
            fprintf(stderr, "MMCS-L46: create-interlock SPLIT repair "
                    "armed (one-shot, cadence %ums; stock completion "
                    "SET + v7 wake on the walker's own waited "
                    "object)\n", mmcs_l46_cadence_ms);
        }
    }
    /* L47: the true-base wake-eval ctx repair (repeating, capped;
     * shares the L32 slot machinery, pending/slot-guarded — see
     * mmcs_l47_scan) */
    if (getenv("MMCS_L47FIX")) {
        if (getenv("MMCS_L19TH")) {
            fprintf(stderr, "MMCS-L47: shares slot idx 0 (evt 0x220) "
                    "with MMCS_L19TH — drop L19TH; not arming L47\n");
        } else {
            mmcs_l47_cadence_ms =
                atoi(getenv("MMCS_L47FIX_MS") ? : "2000");
            if (!mmcs_l47_cadence_ms) {
                mmcs_l47_cadence_ms = 2000;
            }
            mmcs_l47_max_deliv =
                atoi(getenv("MMCS_L47FIX_MAX") ? : "8");
            if (!mmcs_l47_max_deliv) {
                mmcs_l47_max_deliv = 8;
            }
            mmcs_l47_armed = 1;
            fprintf(stderr, "MMCS-L47: true-base wake-eval ctx repair "
                    "armed (repeating, cadence %ums, cap %u; entry base "
                    "wobj+8 + type byte 4 + result cell 0 + stock SET + "
                    "v7 wake)\n", mmcs_l47_cadence_ms, mmcs_l47_max_deliv);
        }
    }
    /* L50: the create-retry exit tape (READ-ONLY diagnostic — no
     * guest writes; safe to combine with everything) */
    if (getenv("MMCS_L50DBG")) {
        mmcs_l50_cadence_ms =
            atoi(getenv("MMCS_L50DBG_MS") ? : "250");
        if (!mmcs_l50_cadence_ms) {
            mmcs_l50_cadence_ms = 250;
        }
        mmcs_l50_max_lines =
            atoi(getenv("MMCS_L50DBG_MAX") ? : "600");
        if (!mmcs_l50_max_lines) {
            mmcs_l50_max_lines = 600;
        }
        mmcs_l50_armed = 1;
        fprintf(stderr, "MMCS-L50: create-retry exit tape armed "
                "(read-only, cadence %ums, max %u lines)\n",
                mmcs_l50_cadence_ms, mmcs_l50_max_lines);
        if (getenv("MMCS_L55DBG")) {
            mmcs_l55dbg_armed = 1;
            fprintf(stderr, "MMCS-L55: psi-array resolve diagnostic "
                    "armed (read-only, rides the L50 lines)\n");
        }
    }
    /* L36: the post-exit requeue daemon — slot idx 3 (evt 0x2A0)
     * would collide with MMCS_L16EV list entries >= 3 */
    if (getenv("MMCS_L36EV")) {
        if (getenv("MMCS_L16EV")) {
            fprintf(stderr, "MMCS-L36: shares slot idx 3 (evt 0x2a0) "
                    "with MMCS_L16EV — drop L16EV; not arming L36\n");
        } else {
            mmcs_l36_cadence_ms =
                atoi(getenv("MMCS_L36EV_MS") ? : "2000");
            if (!mmcs_l36_cadence_ms) {
                mmcs_l36_cadence_ms = 2000;
            }
            mmcs_l36_max_deliv = atoi(getenv("MMCS_L36EV_MAX") ? : "16");
            if (!mmcs_l36_max_deliv) {
                mmcs_l36_max_deliv = 16;
            }
            mmcs_l36_armed = 1;
            fprintf(stderr, "MMCS-L36: post-exit requeue daemon armed "
                    "(cadence %ums, cap %u; stub %08x slot evt 0x2a0 "
                    "wired on first delivery)\n",
                    mmcs_l36_cadence_ms, mmcs_l36_max_deliv,
                    MMCS_L36_STUB_VA);
        }
    }
    /* L37: the KCall-exit lost-preempt CLASS daemon — slot idx 4
     * (evt 0x2C0) would collide with MMCS_L16EV list entries >= 4 */
    if (getenv("MMCS_L37EV")) {
        if (getenv("MMCS_L16EV")) {
            fprintf(stderr, "MMCS-L37: shares slot idx 4 (evt 0x2c0) "
                    "with MMCS_L16EV — drop L16EV; not arming L37\n");
        } else {
            mmcs_l37_cadence_ms =
                atoi(getenv("MMCS_L37EV_MS") ? : "2000");
            if (!mmcs_l37_cadence_ms) {
                mmcs_l37_cadence_ms = 2000;
            }
            mmcs_l37_max_deliv = atoi(getenv("MMCS_L37EV_MAX") ? : "16");
            if (!mmcs_l37_max_deliv) {
                mmcs_l37_max_deliv = 16;
            }
            mmcs_l37_armed = 1;
            fprintf(stderr, "MMCS-L37: lost-preempt class requeue daemon "
                    "armed (cadence %ums, cap %u; stub %08x slot evt "
                    "0x2c0 wired on first delivery)\n",
                    mmcs_l37_cadence_ms, mmcs_l37_max_deliv,
                    MMCS_L37_STUB_VA);
            if (getenv("MMCS_L41EV")) {
                mmcs_l41_armed = 1;
                fprintf(stderr, "MMCS-L41: told-waiter wait-return requeue "
                        "armed (the 0x9083b682 class resumes at its own "
                        "wait-return site 0x9083e24e)\n");
            }
        }
    }
    /* L52: the post-completion resched hand-off — slot idx 5
     * (evt 0x2E0) would collide with MMCS_L16EV list entries >= 5 */
    if (getenv("MMCS_L52EV")) {
        if (getenv("MMCS_L16EV")) {
            fprintf(stderr, "MMCS-L52: shares slot idx 5 (evt 0x2e0) "
                    "with MMCS_L16EV — drop L16EV; not arming L52\n");
        } else {
            mmcs_l52_cadence_ms =
                atoi(getenv("MMCS_L52EV_MS") ? : "2000");
            if (!mmcs_l52_cadence_ms) {
                mmcs_l52_cadence_ms = 2000;
            }
            mmcs_l52_max_deliv = atoi(getenv("MMCS_L52EV_MAX") ? : "4");
            if (!mmcs_l52_max_deliv) {
                mmcs_l52_max_deliv = 4;
            }
            mmcs_l52_armed = 1;
            fprintf(stderr, "MMCS-L52: post-completion resched hand-off "
                    "armed (cadence %ums, cap %u; stub %08x slot evt "
                    "0x2e0 wired on first delivery; the pCurTh-frozen-"
                    "at-epilogue class)\n",
                    mmcs_l52_cadence_ms, mmcs_l52_max_deliv,
                    MMCS_L52_STUB_VA);
        }
    }
    /* L53: the completion-helper spin chain-end restore — a pure
     * one-word write, no stub, no slot, no L16EV interaction */
    if (getenv("MMCS_L53EV")) {
        mmcs_l53_cadence_ms =
            atoi(getenv("MMCS_L53EV_MS") ? : "2000");
        if (!mmcs_l53_cadence_ms) {
            mmcs_l53_cadence_ms = 2000;
        }
        mmcs_l53_max_deliv = atoi(getenv("MMCS_L53EV_MAX") ? : "4");
        if (!mmcs_l53_max_deliv) {
            mmcs_l53_max_deliv = 4;
        }
        mmcs_l53_armed = 1;
        fprintf(stderr, "MMCS-L53: completion-helper spin chain-end "
                "restore armed (cadence %ums, cap %u; the cleanup-loop "
                "self-loop [E+16]:=0 class — no stub, no slot)\n",
                mmcs_l53_cadence_ms, mmcs_l53_max_deliv);
    }
    /* L54: the stale-pCurTh re-park wake — slot idx 7 (evt 0x320)
     * would collide with MMCS_L16EV list entries >= 4 (evt 0x300 is
     * reserved for the L18 self-registered ISR) */
    if (getenv("MMCS_L54EV")) {
        if (getenv("MMCS_L16EV")) {
            fprintf(stderr, "MMCS-L54: shares slot idx 7 (evt 0x320) "
                    "with MMCS_L16EV — drop L16EV; not arming L54\n");
        } else {
            mmcs_l54_cadence_ms =
                atoi(getenv("MMCS_L54EV_MS") ? : "2000");
            if (!mmcs_l54_cadence_ms) {
                mmcs_l54_cadence_ms = 2000;
            }
            mmcs_l54_max_deliv = atoi(getenv("MMCS_L54EV_MAX") ? : "4");
            if (!mmcs_l54_max_deliv) {
                mmcs_l54_max_deliv = 4;
            }
            mmcs_l54_armed = 1;
            fprintf(stderr, "MMCS-L54: stale-pCurTh re-park wake armed "
                    "(cadence %ums, cap %u; stub %08x slot evt 0x320 "
                    "wired on first delivery; the L47 satisfy for "
                    "tva==pcur in the dead-idle world)\n",
                    mmcs_l54_cadence_ms, mmcs_l54_max_deliv,
                    MMCS_L54_STUB_VA);
            if (getenv("MMCS_L55EV")) {
                fprintf(stderr, "MMCS-L54: L55EV also set — standing "
                        "down (the L55 multi-satisfy is a superset)\n");
                mmcs_l54_armed = 0;
            }
        }
    }
    /* L55: the WAIT-ALL chained dual-entry multi-satisfy — same slot
     * discipline as L54 (idx 7 / evt 0x320, the v9 stub shared) */
    if (getenv("MMCS_L55EV")) {
        if (getenv("MMCS_L16EV")) {
            fprintf(stderr, "MMCS-L55: shares slot idx 7 (evt 0x320) "
                    "with MMCS_L16EV — drop L16EV; not arming L55\n");
        } else {
            mmcs_l55_cadence_ms =
                atoi(getenv("MMCS_L55EV_MS") ? : "2000");
            if (!mmcs_l55_cadence_ms) {
                mmcs_l55_cadence_ms = 2000;
            }
            mmcs_l55_max_deliv = atoi(getenv("MMCS_L55EV_MAX") ? : "4");
            if (!mmcs_l55_max_deliv) {
                mmcs_l55_max_deliv = 4;
            }
            mmcs_l55_armed = 1;
            fprintf(stderr, "MMCS-L55: manual-reset delivery armed "
                    "(cadence %ums, cap %u; stub %08x slot evt 0x320 "
                    "wired on first delivery; the {8d,8e} stock shape "
                    "+ the ghost sig for the S203 cycling wait)\n",
                    mmcs_l55_cadence_ms, mmcs_l55_max_deliv,
                    MMCS_L54_STUB_VA);
        }
    }
    /* L56: the post-return sticky-orphan pulse — same slot
     * discipline as L54/L55 (idx 7 / evt 0x320, the v9 stub
     * shared; the channel guard keeps one delivery in flight) */
    if (getenv("MMCS_L56EV")) {
        if (getenv("MMCS_L16EV")) {
            fprintf(stderr, "MMCS-L56: shares slot idx 7 (evt 0x320) "
                    "with MMCS_L16EV — drop L16EV; not arming L56\n");
        } else {
            mmcs_l56_cadence_ms =
                atoi(getenv("MMCS_L56EV_MS") ? : "2000");
            if (!mmcs_l56_cadence_ms) {
                mmcs_l56_cadence_ms = 2000;
            }
            mmcs_l56_max_deliv = atoi(getenv("MMCS_L56EV_MAX") ? : "2");
            if (!mmcs_l56_max_deliv) {
                mmcs_l56_max_deliv = 2;
            }
            mmcs_l56_armed = 1;
            fprintf(stderr, "MMCS-L56: sticky-orphan pulse armed "
                    "(cadence %ums, cap %u; stub %08x slot evt 0x320 "
                    "wired on first delivery; the unmark + the walker "
                    "pulse + the L54 plants + the v9 wake for the "
                    "S205 post-return sibling)\n",
                    mmcs_l56_cadence_ms, mmcs_l56_max_deliv,
                    MMCS_L54_STUB_VA);
            if (getenv("MMCS_L57EV")) {
                mmcs_l57_armed = 1;
                fprintf(stderr, "MMCS-L57: interrupted-current requeue "
                        "armed (the L56 delivery plants the v10 stub: "
                        "after MakeRun(target), old := [0x88679894]; "
                        "old != target -> MakeRun(old) — the stock "
                        "preempt's missing requeue, S206)\n");
            }
        }
    }
    if (getenv("MMCS_L58EV")) {
        mmcs_l58_cadence_ms =
            atoi(getenv("MMCS_L58EV_MS") ? : "2000");
        if (!mmcs_l58_cadence_ms) {
            mmcs_l58_cadence_ms = 2000;
        }
        mmcs_l58_armed = 1;
        fprintf(stderr, "MMCS-L58: residual-sticky cleanup "
                "armed (cadence %ums, cap 8 objects; the "
                "post-return {8D&1,8E=1,+0x90=0} residue on "
                "pcur's waited object with the standing "
                "completed head -> [8E]:=0 once per object; "
                "the L55 plant interlocked — S207; independent "
                "of MMCS_L56EV)\n",
                mmcs_l58_cadence_ms);
    }
    if (getenv("MMCS_L59EV")) {
        mmcs_l59_cadence_ms =
            atoi(getenv("MMCS_L59EV_MS") ? : "2000");
        if (!mmcs_l59_cadence_ms) {
            mmcs_l59_cadence_ms = 2000;
        }
        mmcs_l59_armed = 1;
        fprintf(stderr, "MMCS-L59: completion-forward pulse armed "
                "(cadence %ums, cap 6 — one synthetic completion per "
                "cadence on the retired consumable create event; the "
                "counter walks to limit and the launch loop exits — "
                "S210, going forwards)\n",
                mmcs_l59_cadence_ms);
        if (getenv("MMCS_L60EV")) {
            mmcs_l60_armed = 1;
            fprintf(stderr, "MMCS-L60: SignalStarted synthesis armed "
                    "(table[10]+4 := 1 before each pulse — the s209 "
                    "decode: the stock advance needs the started bit "
                    "AND the event SET)\n");
        }
    }
    if (getenv("MMCS_L62EV")) {
        mmcs_l62_cadence_ms =
            atoi(getenv("MMCS_L62EV_MS") ? : "2000");
        if (!mmcs_l62_cadence_ms) {
            mmcs_l62_cadence_ms = 2000;
        }
        mmcs_l62_max_deliv =
            atoi(getenv("MMCS_L62EV_MAX") ? : "2");
        if (!mmcs_l62_max_deliv) {
            mmcs_l62_max_deliv = 2;
        }
        mmcs_l62_diag = getenv("MMCS_L62EV_DIAG") != NULL;
        mmcs_l62_armed = 1;
        fprintf(stderr, "MMCS-L62: dead-owner crit release armed "
                "(cadence %ums, cap %u%s — the R23 m3-close shape: "
                "the OWNED crit {CINFO 908220a0, state 0x8000xxxx, "
                "lpcs on the D0 grave} + the queued BLOCKED heir at "
                "the enter face 90840814 -> the stock release writes "
                "+ the v9 wake; S213)\n",
                mmcs_l62_cadence_ms, mmcs_l62_max_deliv,
                mmcs_l62_diag ? ", DIAGNOSE-ONLY" : "");
    }
    if (getenv("MMCS_L64EV")) {
        mmcs_l64_cadence_ms =
            atoi(getenv("MMCS_L64EV_MS") ? : "2000");
        if (!mmcs_l64_cadence_ms) {
            mmcs_l64_cadence_ms = 2000;
        }
        mmcs_l64_max_deliv =
            atoi(getenv("MMCS_L64EV_MAX") ? : "2");
        if (!mmcs_l64_max_deliv) {
            mmcs_l64_max_deliv = 2;
        }
        mmcs_l64_diag = getenv("MMCS_L64EV_DIAG") != NULL;
        mmcs_l64_armed = 1;
        fprintf(stderr, "MMCS-L64: Pacific-event aftermath wake armed "
                "(cadence %ums, cap %u%s — the R24 generalized "
                "standing-completed lane: the BLOCKED generic-face "
                "waiter with the vendor completion pair {f1f8, "
                "t1fc=1000} whose object is an EVNT {CINFO 90822040, "
                "8E clear}; the v9 WAKE-ONLY, no plants; runs AFTER "
                "L56/L62 per the tick-order contract)\n",
                mmcs_l64_cadence_ms, mmcs_l64_max_deliv,
                mmcs_l64_diag ? ", DIAGNOSE-ONLY" : "");
    }
    /* L72: the post-park completion hand-off — shares slot idx 5
     * (evt 0x2E0) + the stub base with MMCS_L52EV (the shapes are
     * exclusive: L52 the FROZEN epilogue, L72 the BLOCKED
     * consumed-completion eval tail); both collide with
     * MMCS_L16EV list entries >= 5 */
    if (getenv("MMCS_L72EV")) {
        if (getenv("MMCS_L16EV")) {
            fprintf(stderr, "MMCS-L72: shares slot idx 5 (evt 0x2e0) "
                    "with MMCS_L16EV — drop L16EV; not arming L72\n");
        } else {
            mmcs_l72_cadence_ms =
                atoi(getenv("MMCS_L72EV_MS") ? : "2000");
            if (!mmcs_l72_cadence_ms) {
                mmcs_l72_cadence_ms = 2000;
            }
            mmcs_l72_max_deliv = atoi(getenv("MMCS_L72EV_MAX") ? : "2");
            if (!mmcs_l72_max_deliv) {
                mmcs_l72_max_deliv = 2;
            }
            mmcs_l72_armed = 1;
            fprintf(stderr, "MMCS-L72: post-park completion hand-off "
                    "armed (cadence %ums, cap %u; stub %08x slot evt "
                    "0x2e0 wired on first delivery; the pCurTh-BLOCKED "
                    "consumed-completion eval-tail class)\n",
                    mmcs_l72_cadence_ms, mmcs_l72_max_deliv,
                    MMCS_L72_STUB_VA);
        }
    }
    if (getenv("MMCS_L75TX") && !getenv("MMCS_L16EV")) {
        mmcs_l75ho_cadence_ms = atoi(getenv("MMCS_L75HO_MS") ? : "500");
        if (!mmcs_l75ho_cadence_ms) {
            mmcs_l75ho_cadence_ms = 500;
        }
        mmcs_l75ho_max_deliv = atoi(getenv("MMCS_L75HO_MAX") ? : "4");
        if (!mmcs_l75ho_max_deliv) {
            mmcs_l75ho_max_deliv = 4;
        }
        mmcs_l75ho_armed = 1;
        fprintf(stderr, "MMCS-L75TX: post-kill orphan hand-off armed "
                "(cadence %ums, cap %u; pCurTh := the orphan behind a killed "
                "zombie, then the standing MMCS_L72EV daemon delivers — needs "
                "MMCS_L72EV budget)\n",
                mmcs_l75ho_cadence_ms, mmcs_l75ho_max_deliv);
    }
    if (getenv("MMCS_L76EV") && !getenv("MMCS_L16EV")) {
        mmcs_l76_cadence_ms = atoi(getenv("MMCS_L76EV_MS") ? : "500");
        if (!mmcs_l76_cadence_ms) {
            mmcs_l76_cadence_ms = 500;
        }
        mmcs_l76_max_deliv = atoi(getenv("MMCS_L76EV_MAX") ? : "4");
        if (!mmcs_l76_max_deliv) {
            mmcs_l76_max_deliv = 4;
        }
        mmcs_l76_armed = 1;
        fprintf(stderr, "MMCS-L76: equal-priority starvation re-arm armed "
                "(cadence %ums, cap %u; the ONE-BYTE cNest [0x88679885] := 1 "
                "when a RUNNABLE equal/lower-prio band head starves behind a "
                "monopolist with pick==0 — the vendor KCall-return gate does "
                "the rest)\n",
                mmcs_l76_cadence_ms, mmcs_l76_max_deliv);
    }
    if (getenv("MMCS_L77EV") && !getenv("MMCS_L16EV")) {
        mmcs_l77_cadence_ms = atoi(getenv("MMCS_L77EV_MS") ? : "500");
        if (!mmcs_l77_cadence_ms) {
            mmcs_l77_cadence_ms = 500;
        }
        mmcs_l77_max_deliv = atoi(getenv("MMCS_L77EV_MAX") ? : "4");
        if (!mmcs_l77_max_deliv) {
            mmcs_l77_max_deliv = 4;
        }
        mmcs_l77_armed = 1;
        fprintf(stderr, "MMCS-L77: kill-path API-lock cleanup release armed "
                "(cadence %ums, cap %u; the ONE-WORD [pCurTh+0x164] := 0 "
                "when a DYING current thread (code 0xC000xxxx, st16 bit 8) "
                "holds a crit whose transfer condition stands false — the "
                "vendor zero-path exit completes the death)\n",
                mmcs_l77_cadence_ms, mmcs_l77_max_deliv);
    }
    if (getenv("MMCS_L78EV") && !getenv("MMCS_L16EV")) {
        mmcs_l78_cadence_ms = atoi(getenv("MMCS_L78EV_MS") ? : "500");
        if (!mmcs_l78_cadence_ms) {
            mmcs_l78_cadence_ms = 500;
        }
        mmcs_l78_max_deliv = atoi(getenv("MMCS_L78EV_MAX") ? : "4");
        if (!mmcs_l78_max_deliv) {
            mmcs_l78_max_deliv = 4;
        }
        mmcs_l78_armed = 1;
        fprintf(stderr, "MMCS-L78: lost-MakeRun requeue armed "
                "(cadence %ums, cap %u; the stock empty-queue head-path "
                "words {band head, pRunnable, dwKCRes} for a RUNNABLE-marked "
                "self-linked off-queue wait-face thread — the vendor idle-"
                "drain pick scan and switcher resume do the rest)\n",
                mmcs_l78_cadence_ms, mmcs_l78_max_deliv);
    }
    if (getenv("MMCS_L79EV") && !getenv("MMCS_L16EV")) {
        mmcs_l79_cadence_ms = atoi(getenv("MMCS_L79EV_MS") ? : "500");
        if (!mmcs_l79_cadence_ms) {
            mmcs_l79_cadence_ms = 500;
        }
        mmcs_l79_max_deliv = atoi(getenv("MMCS_L79EV_MAX") ? : "4");
        if (!mmcs_l79_max_deliv) {
            mmcs_l79_max_deliv = 4;
        }
        mmcs_l79_armed = 1;
        fprintf(stderr, "MMCS-L79: walker dead-owner loop-exit armed "
                "(cadence %ums, cap %u; the KData wait-node owner word "
                "[0x8867eaa0+4] := the runner's hTh + the requeue when a "
                "DYING BLOCKED runner sits at the termination-walker face "
                "and the node's owner names a PARKED thread — the vendor "
                "tail compare, exit call and node self-clear do the rest)\n",
                mmcs_l79_cadence_ms, mmcs_l79_max_deliv);
    }
    if (getenv("MMCS_L42KILL")) {
        mmcs_l42_cadence_ms = atoi(getenv("MMCS_L42KILL_MS") ? : "500");
        if (!mmcs_l42_cadence_ms) {            mmcs_l42_cadence_ms = 500;
        }
        mmcs_l42_armed = 1;
        fprintf(stderr, "MMCS-L42KILL: impossible-user-forward spin kill "
                "armed (cadence %ums, sustain 3, cap 4 dispatches; the "
                "90822dbe-class spin routes into the vendor kill "
                "continuation 9083be50)\n", mmcs_l42_cadence_ms);
    }
    /* L73: the churn livelock release — the stale sleep-node unlink */
    if (getenv("MMCS_L73EV")) {
        mmcs_l73_cadence_ms = atoi(getenv("MMCS_L73EV_MS") ? : "1000");
        if (!mmcs_l73_cadence_ms) {
            mmcs_l73_cadence_ms = 1000;
        }
        mmcs_l73_max_deliv = atoi(getenv("MMCS_L73EV_MAX") ? : "12");
        if (!mmcs_l73_max_deliv) {
            mmcs_l73_max_deliv = 4;
        }
        mmcs_l73_armed = 1;
        fprintf(stderr, "MMCS-L73: churn livelock release armed (cadence "
                "%ums, cap %u; the pCurTh self-linked-on-sleep-list class; "
                "host-side unlink [0x8867ef8c]/[th+0x144])\n",
                mmcs_l73_cadence_ms, mmcs_l73_max_deliv);
    }
    /* L74: the standing expiry reap (the S225 item (i) OR branch) */
    if (getenv("MMCS_L74EV")) {
        mmcs_l74_cadence_ms = atoi(getenv("MMCS_L74EV_MS") ? : "100");
        if (!mmcs_l74_cadence_ms) {
            mmcs_l74_cadence_ms = 100;
        }
        mmcs_l74_max_deliv = atoi(getenv("MMCS_L74EV_MAX") ? : "0");
        mmcs_l74_armed = 1;
        fprintf(stderr, "MMCS-L74: standing expiry reap armed (cadence %ums, "
                "cap %u = %s; the RUNNING+own-node-at-sleep-head signature "
                "at any tick flavor; drain1's only caller is the switcher "
                "- the fn2 lane refuted statically)\n",
                mmcs_l74_cadence_ms, mmcs_l74_max_deliv,
                mmcs_l74_max_deliv ? "capped" : "STANDING/uncapped");
    }
    /* L74CR: the reentrant API-set-lock deadlock break (S225 item (ii)) */
    if (getenv("MMCS_L74CR")) {
        mmcs_l74cr_cadence_ms = atoi(getenv("MMCS_L74CR_MS") ? : "2000");
        if (!mmcs_l74cr_cadence_ms) {
            mmcs_l74cr_cadence_ms = 2000;
        }
        mmcs_l74cr_max_deliv = atoi(getenv("MMCS_L74CR_MAX") ? : "2");
        if (!mmcs_l74cr_max_deliv) {
            mmcs_l74cr_max_deliv = 2;
        }
        mmcs_l74cr_diag = getenv("MMCS_L74CR_DIAG") != NULL;
        mmcs_l74cr_armed = 1;
        fprintf(stderr, "MMCS-L74CR: reentrant API-lock deadlock break "
                "armed (cadence %ums, cap %u%s; the double-dispatch-spill "
                "witness + the transfer [waiter r10+4] := waiter handle + "
                "the v9 wake)\n",
                mmcs_l74cr_cadence_ms, mmcs_l74cr_max_deliv,
                mmcs_l74cr_diag ? "; DIAG" : "");
    }
    /* L74S4: the set-84 slot stock-clear (S225 item (iii)) */
    if (getenv("MMCS_L74S4")) {
        mmcs_l74s4_armed = 1;
        fprintf(stderr, "MMCS-L74S4: set-84 slot stock-clear armed "
                "(one-shot; [0x8867eed0] := 0 on the zeroed byte-reversed "
                "block -> the dispatch's own null path returns 0, the "
                "stock dead-server outcome)\n");
    }
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
            if (getenv("MMCS_L26M")) {
                mmcs_l26m_armed = 1;
                fprintf(stderr, "MMCS-L26M: marked-entry guard armed "
                        "(skip the wedge class: wait entries whose "
                        "+0x18 type byte is 0xff)\n");
            }
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

/* MMCS fork (S159, MLD-HANDOFF): the loader no-update path -> the OS launch,
 * one continuous boot. DECODE (this lane; mld-mem pseudo-c + disasm + the
 * live park serial): the v2.21 M-Loader's post-splash decision tree is
 * main (0x88932350: FLROM target-name walk -> InitDispLib(2,0,~) splash ->
 * DiscLoadmain(0x08000000,0x40000000)) -> DiscLoadmain (0x889366b0) ->
 * DiscLibProcess (0x889389a4; 12-row state table @0x889232b8
 * {state,fn,next_ok,next_ng}): state 1 disc_init_dev (0x8893a334) opens the
 * ctx devices (\SDC dev1, \USB dev2, HD2/HDD dev0 = absent on this unit)
 * and returns 1 only when some device yields a driver handle; with the
 * SDHI empty-slot semantics (EVD_NOMEDIA -> SD_EJECT 0x200; live serial
 * 'SDDDInit NG' / 'SDDDInit SD_EJECT') and the USB RST/PLL miss NO device
 * opens -> state 10 disc_error_end -> return 2 -> 'Bad value of return
 * code the DiscLibProcess() ! : 00000002' -> the subcpu error sequence
 * ('Disc Loading Error', parks in the receive-error loop; live park pcs
 * 0x8893bd1a + 0x88936020 + 0x88935f88). THE OS LAUNCH is 0x88935590
 * (optional ' Skip SubCPU message ' + ' <Launch> 0x%x' -> 0x88935be8:
 * clear 0xFF802000 bit25 -> SR.BL -> CFI read-array reset @0xA001C000 ->
 * VBR := 0x889355dc -> set bit25 -> jmp @r4, never returns) and is only
 * reachable from DiscLibProcess state 9 (a COMPLETED load: state 2
 * dispatches SearchTable Act codes {1,2,5}->load pipeline, {3,4}->state 11
 * normal-end; the launch cell 0x88b34c5c is filled by GetLaunchInfo
 * 0x88947840 off the loaded B000FF image) — on real HW this binary never
 * runs cold without media (the J-11 capture launches it only after a
 * checksummed SD load); the RESIDENT NOR first stage (bytes absent) owns
 * the no-card boot. HANDOFF: our boot stub IS the resident-stage stand-in
 * — once the loader has CONCLUDED its scan (the park windows below,
 * debounced), regain control and drive the loader's OWN launcher
 * (pc := 0x88935590, r4 := MMCS_ENTRY): the serial seam is the real
 * ' <Launch> 0x908066b0' print and the jump runs the loader's own
 * trampoline. The trampoline's CFI reset polls for 9/9 at NOR+0x1C000
 * (RAM read-back never leaves status mode) — pre-seed the two words so it
 * takes its skip branch (the real flash sits in the array state). SDRAM
 * residue: the loader image at 0x08900000 etc is LEFT IN PLACE (on HW the
 * kernel boots FROM the loader's jump with the loader resident inside the
 * kernel pool 0x08600000-0x10700000) — jump for real; the one NOT
 * tolerated shape is retired at the seam (the FLROM window, see the
 * launch fn). Env MMCS_HANDOFF=1 (needs MMCS_MLD + MMCS_FLROM + -bios),
 * default off. */
static SuperHCPU *mmcs_handoff_cpu;
static QEMUTimer *mmcs_handoff_timer;
static QEMUTimer *mmcs_handoff_retire_timer;
static int mmcs_handoff_hits;
static int mmcs_handoff_fired;
/* the FLROM MR (retired at the seam unless MMCS_HANDOFF_KEEPFLROM=1) */
static MemoryRegion *mmcs_handoff_flrom_mr;
static MemoryRegion *mmcs_handoff_sysmem;

/* S159: the L26 P1 servant-alias hook (target/sh4/helper.c) claims
 * kernel-mode P1 [0x80000000,0x81000000) = phys [0,16MB) — exactly the
 * NOR FLROM window in MLD mode. In the default boot that phys space is
 * unassigned so the hook only ever served the C0 servants; with the
 * FLROM mapped the loader's own P1 NOR reads (the Opening BMP at
 * 0x80100000) get hijacked to manifest scratch (live: DispLoadBitmap
 * 'bfType = 0' with SRVPGTAB+IATFIX+C0ARM armed). Cleared while the
 * FLROM is mapped (MLD modes), restored at the seam-time FLROM
 * retirement. */
int mmcs_p1_alias_enabled = 1;

static void mmcs_handoff_retire_flrom(void *opaque)
{
    if (mmcs_handoff_flrom_mr && mmcs_handoff_sysmem) {
        memory_region_del_subregion(mmcs_handoff_sysmem,
                                    mmcs_handoff_flrom_mr);
        mmcs_p1_alias_enabled = 1;
        fprintf(stderr, "MMCS: HANDOFF FLROM window retired — phys "
                "[0,16MB) back to the WinCE-mode (unassigned) shape; "
                "SDRAM loader residue left in place\n");
    }
}

static bool mmcs_handoff_park_pc(uint32_t pc)
{
    /* the no-update terminal park: the subcpu receive-error loop (live
     * samples; the cycle alternates between the SCIF wait at 0x8893bd1a
     * and the HALFCHECK driver at 0x88935f88-0x88936020) */
    return (pc >= 0x88935f80u && pc < 0x88936030u) ||
           (pc >= 0x8893bd00u && pc < 0x8893bd30u);
}

static void mmcs_handoff_launch(CPUState *cs, run_on_cpu_data data)
{
    SuperHCPU *cpu = SUPERH_CPU(cs);
    CPUSH4State *env = &cpu->env;

    if (mmcs_handoff_fired) {
        return;
    }
    mmcs_handoff_fired = 1;
    /* THE RESIDUE RECONCILIATION (verified by A/B this lane): the kernel's
     * FIRST USER PROCESS runs its initial thread with the user stack in
     * the LOW identity window (live evidence: child sp r15=0x0002fd90,
     * spc=0x40021784) — under the default WinCE boot phys 0x2fd90 is
     * UNASSIGNED (reads 0, writes dropped) and the child completes its
     * startup; with the 16 MB FLROM MR present the stack reads the NOR
     * seed bytes (LOADING.KWI garbage) and the child dies before its
     * first callback return — the create-completion interlock breaks and
     * the launch loop degenerates into a user slot-call retry storm
     * (pc=ffff55d3 x5.1M/110s). On real HW phys [0,16MB) is the NOR the
     * kernel never stacks into; the default-mode unassigned window is
     * the kernel-tolerated shape, so at the seam we retire the FLROM
     * window (the loader is done with the NOR; its post-boot reader, the
     * DRF flash driver, is fail-soft on reads-0 exactly as the default
     * boot). Retired 100 ms after the poke (the trampoline's CFI reset
     * runs in that window against the still-mapped NOR). The L26 P1
     * servant-alias hook re-arms with it. MMCS_HANDOFF_KEEPFLROM=1
     * disables the retirement for A/B. */
    if (mmcs_handoff_flrom_mr && !getenv("MMCS_HANDOFF_KEEPFLROM")) {
        timer_mod(mmcs_handoff_retire_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 100);
    }
    /* the CFI skip-branch pre-seed (see the block comment) — MUST precede
     * the FLROM retirement (the trampoline's CFI window leaves with it) */
    uint16_t nine = 9;
    cpu_physical_memory_write(0x001C000, &nine, 2);
    cpu_physical_memory_write(0x001C002, &nine, 2);
    fprintf(stderr, "MMCS: HANDOFF seam — loader scan concluded (park pc "
            "%08x, %d poll hits); driving the loader's own launcher "
            "0x88935590(r4=%08x): serial ' <Launch> 0x%x' + trampoline "
            "0x88935be8 jmp; SDRAM residue left in place\n",
            env->pc, mmcs_handoff_hits, MMCS_ENTRY, MMCS_ENTRY);
    /* r4 is a BANKED register (r0-r7, SR.RB=1 in the loader: gregs index
     * XOR 0x10 per target/sh4/translate.c REG(x); the bank bit comes from
     * env->sr, not env->flags) — the launcher moves it to r8 (unbanked)
     * and back before the trampoline jmp @r4 */
    unsigned bank = (env->sr & (1u << SR_RB)) ? 0x10u : 0u;
    env->gregs[4 ^ bank] = MMCS_ENTRY;
    env->pc = 0x88935590u;      /* the loader's launcher (own print) */
    env->pr = 0;
    env->in_sleep = 0;
    env->flags &= ~TB_FLAG_DELAY_SLOT_MASK;
}

static void mmcs_handoff_poll(void *opaque)
{
    if (mmcs_handoff_fired || !mmcs_handoff_cpu) {
        return;
    }
    /* benign u32 sample of the live pc (the established daemon pattern);
     * the mutation itself runs in vCPU context via run_on_cpu */
    uint32_t pc = mmcs_handoff_cpu->env.pc;
    if (mmcs_handoff_park_pc(pc)) {
        if (++mmcs_handoff_hits >= 8) {
            run_on_cpu(CPU(mmcs_handoff_cpu), mmcs_handoff_launch,
                       RUN_ON_CPU_NULL);
            return;             /* one-shot; timer not rearmed */
        }
    } else {
        mmcs_handoff_hits = 0;
    }
    timer_mod(mmcs_handoff_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 250);
}

/* ===================== savestate (snapshot lane) =====================
 * MMCS fork (savestate lane): vmstate for the machine's host-side
 * state so `migrate exec:` + `-incoming exec:` snapshots work (the
 * iteration-speed multiplier: boot-to-frontier once, then restore).
 *
 * DESIGN (the inventory — what must be saved vs. what is derived):
 *  - GUEST RAM is auto-migrated: every region here is a
 *    memory_region_init_ram block (mmcs.sdram/ram2/ram3/fileview/
 *    killstk/srvpg/fsvt/flash/bootrom/lowslot, mld.*) — the RAM
 *    migration streams them by name; the ROM-backed flash MR is
 *    streamed too (it carries the env-gated BOOTFS/BOOTLD/REGFIX
 *    patches + FILESHADOW overlay, which the re-run machine init
 *    would re-apply, but streamed content is authoritative anyway).
 *  - env-knob latches (mmcs_iatfix_on, c0arm, uwarm, fsvt_armed,
 *    pgown_armed, the CPU env mmcs_*_active bits) are REBUILT from
 *    the identical env at restore (documented requirement: the
 *    restore process must launch with the same env + sidecar files;
 *    the harness records them alongside the snapshot).
 *  - static host tables that map VAs to backing pages MUST stream —
 *    losing them would allocate FRESH scratch pages on the first
 *    post-restore fault and re-seed stale init content over the
 *    live guest state: the SRVPG map (VA->mmcs.srvpg page), the
 *    PGOWN write-sticky table, the FILEVIEW/COWFIX maps (helper.c,
 *    its own "mmcs/helper" vmsd).
 *  - the REGVT hive tree is mutated at runtime (RegSetValueExW
 *    applies, handle allocation) — flattened/rebuilt by the
 *    "mmcs/regvt" vmsd below.
 *  - the sh7777.c CMT/INTC/CPG model is NOT wired into this machine
 *    (mmcs.c implements its own polled syscon at the same bases);
 *    only the chanflash blocks are live (vmstate in sh7777.c).
 *  - the L16/L18/L19 one-shot fire timers and the TICK/HDEVT/RINGNOP
 *    delayed arms all live below the park point; the tick CHAIN
 *    itself is free-floating (not a device timer) and is re-armed in
 *    post_load. Diagnostics-only timers (census/schedtrace/dump/
 *    jitfix sweeps) are not re-armed (log-only state).
 */
struct MmcsSnap {
    uint32_t syscon[64];
    uint32_t pfc[4];
    uint32_t vintc[64];
    uint32_t vintc_evt;
    struct Mmcs2dgState dg;
    uint32_t srvpg_map[1024][2];
    uint32_t nsrvpg, srvpg_nxt;
    struct mmcs_pgown_ent pgown[MMCS_PGOWN_SLOTS];
    uint32_t pgown_nins, pgown_npin, pgown_novr;
    struct mmcs_l16_ent l16[MMCS_L16_MAX];
    int32_t l19_armed, l26_armed, l32_armed, l36_armed, l37_armed;
    uint32_t l19_cadence, l26_cadence, l32_cadence, l36_cadence;
    uint32_t l37_cadence;
    uint32_t l19_max, l26_max, l32_max, l36_max, l37_max;
    uint32_t l19_total, l26_total, l32_total, l36_total, l37_total;
    uint8_t l19_sig[MMCS_L19_NSIG];
    uint8_t l26_sig[MMCS_L19_NSIG];
    uint8_t l32_sig[MMCS_L19_NSIG];
    uint8_t l36_sig[MMCS_L19_NSIG];
    uint8_t l37_sig[MMCS_L19_NSIG];
    int32_t l19_have, l26_have, l32_have, l36_have, l37_have;
    uint32_t l19_quiet, l19_nopick, l26_quiet, l32_quiet, l36_quiet;
    uint32_t l37_quiet;
    uint64_t tick_l19, tick_l26, tick_l32, tick_l36, tick_l37;
    int32_t tick_live, hdevt_pending;
};
static struct MmcsSnap mmcs_snap;

static int mmcs_machine_pre_save(void *opaque)
{
    struct MmcsSnap *s = opaque;
    memcpy(s->syscon, syscon_c080, sizeof s->syscon);
    memcpy(s->pfc, pfc_usb_st, sizeof s->pfc);
    memcpy(s->vintc, mmcs_vintc_regs, sizeof s->vintc);
    s->vintc_evt = mmcs_vintc_evt_code;
    s->dg = mmcs_2dg;
    memcpy(s->srvpg_map, mmcs_srvpg_map, sizeof s->srvpg_map);
    s->nsrvpg = mmcs_nsrvpg;
    s->srvpg_nxt = mmcs_srvpg_nxt;
    memcpy(s->pgown, mmcs_pgown, sizeof s->pgown);
    s->pgown_nins = mmcs_pgown_nins;
    s->pgown_npin = mmcs_pgown_npin;
    s->pgown_novr = mmcs_pgown_novr;
    memcpy(s->l16, mmcs_l16_ents, sizeof s->l16);
    s->l19_armed = mmcs_l19_armed;
    s->l26_armed = mmcs_l26_armed;
    s->l32_armed = mmcs_l32_armed;
    s->l36_armed = mmcs_l36_armed;
    s->l37_armed = mmcs_l37_armed;
    s->l19_cadence = mmcs_l19_cadence_ms;
    s->l26_cadence = mmcs_l26_cadence_ms;
    s->l32_cadence = mmcs_l32_cadence_ms;
    s->l36_cadence = mmcs_l36_cadence_ms;
    s->l37_cadence = mmcs_l37_cadence_ms;
    s->l19_max = mmcs_l19_max_deliv;
    s->l26_max = mmcs_l26_max_deliv;
    s->l32_max = mmcs_l32_max_deliv;
    s->l36_max = mmcs_l36_max_deliv;
    s->l37_max = mmcs_l37_max_deliv;
    s->l19_total = mmcs_l19_total;
    s->l26_total = mmcs_l26_total;
    s->l32_total = mmcs_l32_total;
    s->l36_total = mmcs_l36_total;
    s->l37_total = mmcs_l37_total;
    memcpy(s->l19_sig, mmcs_l19_sig, MMCS_L19_NSIG);
    memcpy(s->l26_sig, mmcs_l26_sig, MMCS_L19_NSIG);
    memcpy(s->l32_sig, mmcs_l32_sig, MMCS_L19_NSIG);
    memcpy(s->l36_sig, mmcs_l36_sig, MMCS_L19_NSIG);
    memcpy(s->l37_sig, mmcs_l37_sig, MMCS_L19_NSIG);
    s->l19_have = mmcs_l19_sig_have;
    s->l26_have = mmcs_l26_sig_have;
    s->l32_have = mmcs_l32_sig_have;
    s->l36_have = mmcs_l36_sig_have;
    s->l37_have = mmcs_l37_sig_have;
    s->l19_quiet = mmcs_l19_quiet;
    s->l19_nopick = mmcs_l19_nopick;
    s->l26_quiet = mmcs_l26_quiet;
    s->l32_quiet = mmcs_l32_quiet;
    s->l36_quiet = mmcs_l36_quiet;
    s->l37_quiet = mmcs_l37_quiet;
    s->tick_l19 = mmcs_tick_l19;
    s->tick_l26 = mmcs_tick_l26;
    s->tick_l32 = mmcs_tick_l32;
    s->tick_l36 = mmcs_tick_l36;
    s->tick_l37 = mmcs_tick_l37;
    s->tick_live = mmcs_tick_live;
    s->hdevt_pending = mmcs_hdevt_pending;
    return 0;
}

/* MMCS fork (L66/S218): THE LOW-ARENA STOCKER — the complete stock
 * _InterlockedAPIs block (shexcept.src listing verbatim, assembled
 * with sh4-linux-gnu-as; mdsh3.c MDInitialize copies these 0x80 bytes
 * to KData+FIRST_INTERLOCK (nkshx.h: 0x380) = VA 0x5B80..0x5C00 on
 * the KData user page, phys 0x0C020B80..0x0C020BFF).
 *
 * L66 decode (2026-11-23): the S122 ILKFIX lazy seeds are BYTE-
 * POISONED — every rts halfword was transcribed 00 0b (0x0b00,
 * illegal) instead of 0b 00, and CAS's bf as 8b 00 (0x008b) instead
 * of 00 8b. The L65 continuation-death fault pcs {0x5bd4,0x5be8,
 * 0x5bf8} are exactly the flipped bf/rts offsets: the arena was
 * POISON-stocked, not zero-stocked. This stocker writes the correct
 * block under MMCS_L66STK (env-gated, default off), per 16-byte
 * granule: all-zero granules stocked; granules byte-equal to a known
 * poisoned S122 seed REPAIRED; anything else (live vendor runtime
 * data) left alone and reported (the S122 read-before-write law).
 * Called at machine init AND after snapshot restore (the incoming
 * RAM load must not wipe it — the S214DBG trapa re-apply precedent).
 * With the block stocked, kernel/user interlocked calls execute real
 * stock code and never fault; the do_interrupt emulation stays as
 * the fallback for busy granules. */
static const uint8_t mmcs_l66_block[0x80] = {
    /* +0x00 ILMaskByte */
    0x40,0x60,0x59,0x20,0x6b,0x20,0x00,0x24,0x0b,0x00,0x09,0x00,0x09,0x00,0x09,0x00,
    /* +0x10 ILPopList (empty path) */
    0x42,0x60,0x09,0x00,0x08,0x20,0x05,0x8b,0x0b,0x00,0x09,0x00,0x09,0x00,0x09,0x00,
    /* +0x20 bra ILPopList (interrupt-restart) / +0x24 popx tail */
    0xf6,0xaf,0x09,0x00,0x02,0x61,0x12,0x24,0x0b,0x00,0x09,0x00,0x09,0x00,0x09,0x00,
    /* +0x30 ILPushList */
    0x42,0x60,0x09,0x00,0x02,0x25,0x52,0x24,0x0b,0x00,0x09,0x00,0x09,0x00,0x09,0x00,
    /* +0x40 ILExchange */
    0x42,0x60,0x09,0x00,0x09,0x00,0x52,0x24,0x0b,0x00,0x09,0x00,0x09,0x00,0x09,0x00,
    /* +0x50 ILCmpExchange */
    0x42,0x60,0x00,0x36,0x00,0x8b,0x52,0x24,0x0b,0x00,0x09,0x00,0x09,0x00,0x09,0x00,
    /* +0x60 ILIncrement */
    0x42,0x60,0x09,0x00,0x01,0x70,0x02,0x24,0x0b,0x00,0x09,0x00,0x09,0x00,0x09,0x00,
    /* +0x70 ILXAdd */
    0x42,0x60,0x53,0x61,0x0c,0x31,0x12,0x24,0x0b,0x00,0x09,0x00,0x09,0x00,0x09,0x00,
};

/* The S122 poisoned seed granules (target/sh4/helper.c tlb_fill) for
 * the repair match — each differs from the correct block ONLY at the
 * byte-swapped rts (and CAS's bf) halfwords. */
static const uint8_t mmcs_l66_poison[5][16] = {
    {0x40,0x60,0x59,0x20,0x6b,0x20,0x00,0x24,0x00,0x0b,0x09,0x00,0x09,0x00,0x09,0x00},
    {0x42,0x60,0x09,0x00,0x08,0x20,0x05,0x8b,0x00,0x0b,0x09,0x00,0x09,0x00,0x09,0x00},
    {0x42,0x60,0x00,0x36,0x8b,0x00,0x52,0x24,0x00,0x0b,0x09,0x00,0x09,0x00,0x09,0x00},
    {0x42,0x60,0x09,0x00,0x01,0x70,0x02,0x24,0x00,0x0b,0x09,0x00,0x09,0x00,0x09,0x00},
    {0x42,0x60,0x53,0x61,0x0c,0x31,0x12,0x24,0x00,0x0b,0x09,0x00,0x09,0x00,0x09,0x00},
};

void mmcs_l66_stock_arena(const char *when);

void mmcs_l66_stock_arena(const char *when)
{
    int stocked = 0, repaired = 0, busy = 0;
    /* L68/S219: under MMCS_L68KD the block's home is the LIVE KData
     * page (KData+0x380), not the legacy scratch page 0x0C020000. */
    uint32_t base = 0x0C020B80;
    uint32_t l68pa = mmcs_l68_kd_on() ? mmcs_l68_kdata_page_pa() : 0;
    if (l68pa) {
        base = l68pa + 0xB80;
    }
    for (int off = 0; off < 0x80; off += 16) {
        uint8_t cur[16];
        cpu_physical_memory_read(base + off, cur, 16);
        bool zero = true, poison = false;
        for (int j = 0; j < 16; j++) {
            if (cur[j]) { zero = false; break; }
        }
        if (!zero) {
            for (int k = 0; k < 5; k++) {
                if (memcmp(cur, mmcs_l66_poison[k], 16) == 0) {
                    poison = true;
                    break;
                }
            }
        }
        if (zero || poison) {
            cpu_physical_memory_write(base + off,
                                      mmcs_l66_block + off, 16);
            if (poison) {
                repaired++;
            } else {
                stocked++;
            }
        } else {
            busy++;
            fprintf(stderr, "MMCS-L66: granule VA 0x%04x busy (live vendor "
                    "data, left alone):", 0x5B80 + off);
            for (int j = 0; j < 16; j++) {
                fprintf(stderr, " %02x", cur[j]);
            }
            fprintf(stderr, "\n");
        }
    }
    fprintf(stderr, "MMCS-L66: arena stocked %s (base %08x: stocked %d, "
            "poison-repaired %d, busy-left %d)\n", when, base, stocked,
            repaired, busy);
}

/* MMCS fork (L68/S219): MMCS_L68KD — THE LIVE KDATA USER PAGE (env-
 * gated, default off).
 *
 * THE DECODE (2026-11-24, the l66-park-crit world): the KData user
 * page (VA 0x5000-0x5FFF; lpvTls at 0x5800, the _InterlockedAPIs
 * block at 0x5B80) IS THE LIVE KDATA PAGE. The vendor kernel maps it
 * itself (the guest's own UTLB carries the shared entry VA 0x5000 ->
 * phys 0x08679000, asid-independent, monitor `info tlb` verified) and
 * KData = *[0x8867ed64] = 0x88679800 lives there with a LIVE
 * lpvTls/hCurThread/pCurTh and the vendor's own complete stock
 * _InterlockedAPIs block at KData+0x380 (byte-identical to the L66
 * block; the stock mdsh3.c MDInitialize copy DID run). The S122
 * ILKFIX hook, however, resolves every fault on that page to a DEAD
 * zero scratch page (phys 0x0C020000 — S112/S117's "KData" guess:
 * the nk.exe image's stale copy, 0 nonzero bytes at the park) and its
 * kernel-mode fetch gate (KILK / the L66STK arming repair) installs
 * that dead page for the kernel TCG index too — so kernel-side
 * TlsGetValue reads lpvTls = 0 and every TLS deref faults at NULL.
 * THE L66 PARK'S ENGINE: the device.dll thread 9068f0c0 died exactly
 * there (TlsGetValue(1): r2=[0x5800]=0, r8=[r2+4] -> TEA 4, the
 * S214DBG TH-EXC tape), the kernel exception path nested into the
 * BL=1 ring loop at 0x908089fe and froze the CPU (0 guest bytes
 * changed in a 60s plain run) — the heir wake on the old loader crit
 * never got scheduled.
 *
 * THE FIX (stock-faithful, one page): under MMCS_L68KD the ILKFIX
 * hook resolves VA page 0x5000 to the LIVE KData page (derived from
 * the vendor's own KData pointer cell 0x8867ed64 at run time), seeds
 * nothing (the vendor's block is the stock), and at snapshot post-
 * load re-pins the PGOWN entry for the page (class 2, the shared key)
 * to the live page so the pinned-backing override cannot keep serving
 * the dead page. Default off: the legacy dead page + seeds stand. */
int mmcs_l68_kd_on(void)
{
    static int on = -1;
    if (on < 0) {
        on = getenv("MMCS_L68KD") != NULL;
    }
    return on;
}

/* The live KData page PA (the 4K page holding KData), 0 unresolved. */
uint32_t mmcs_l68_kdata_page_pa(void)
{
    uint32_t kdptr = 0;
    cpu_physical_memory_read(0x0867ED64, &kdptr, 4);
    if ((kdptr & 0xF0000000u) != 0x80000000u || (kdptr & 0x7FFu)) {
        return 0;
    }
    return (kdptr & 0x1FFFFFFFu) & ~0xFFFu;
}

void mmcs_l68_repin_kdata_page(void)
{
    uint32_t kdptr = 0, pa = mmcs_l68_kdata_page_pa();
    struct mmcs_pgown_ent *e;
    uint8_t cur[16];
    cpu_physical_memory_read(0x0867ED64, &kdptr, 4);
    if (!pa) {
        fprintf(stderr, "MMCS-L68: KData pointer unresolved ([8867ed64] = "
                "%08x) - KData user page NOT re-pinned\n", kdptr);
        return;
    }
    e = mmcs_pgown_find(0x5000, MMCS_PGOWN_ASID_SHARED);
    if (e) {
        fprintf(stderr, "MMCS-L68: KData user page pin %08x (pinned %d) "
                "-> the live KData page %08x ([8867ed64] = %08x)\n",
                e->pa, e->pinned, pa, kdptr);
    } else {
        e = mmcs_pgown_insert(0x5000, MMCS_PGOWN_ASID_SHARED, pa);
        fprintf(stderr, "MMCS-L68: KData user page pin created -> the live "
                "KData page %08x ([8867ed64] = %08x)\n", pa, kdptr);
    }
    if (e) {
        e->pa = pa;
        e->pinned = 1;
    }
    cpu_physical_memory_read(pa + 0xB80, cur, 16);
    fprintf(stderr, "MMCS-L68: live KData+0x380 granule:");
    for (int j = 0; j < 16; j++) {
        fprintf(stderr, " %02x", cur[j]);
    }
    fprintf(stderr, "\n");
}

/* MMCS fork (L69/S220): MMCS_L69AP — THE APPVERIFIER REGISTRY
 * SHORT-CIRCUIT (env-gated, default off). THE DECODE (L69, ROM disasm
 * + the CE6 mirror + the live SYSTRACE tape): the new user process's
 * coredll init calls, as its LAST gate before main(), the appverifier
 * check (PRIVATE/WINCEOS/COREOS/CORE/DLL/appverifier.cpp
 * IsAppVerifierEnabled): WaitForAPIReady(84) (the runtime-registered
 * filesys registry API set — returns 0 = READY in the K world) then
 * RegOpenKeyExW(HKEY_LOCAL_MACHINE=0x80000002, L"ShimEngine", 0,
 * KEY_ALL_ACCESS=0x000F003F) through the user PSL trampoline — slot
 * 0xffff55d3 = set 84 method 23 (the ksshx.h arithmetic: index
 * (0xFFFFFE01-pc)/2 = 0x5417, set 0x54, method 0x17). In our world the
 * set-84 dispatch never completes (the PerformCallBack continuation
 * class, [pTh+0x1C]==0 — the CBRET family): the slot fetch re-faults
 * 6.5M times (the L68 "shell-park spin", hot pc 0x40023156 = the
 * trampoline itself), blocking EVERY user process at init. THE STOCK
 * OUTCOME (the retail hive carries no HKLM\ShimEngine key — corpus
 * default.reg, Verified negative): RegOpenKeyExW returns
 * ERROR_FILE_NOT_FOUND (2), the wrapper's `tst r0,r0; bf' skips to
 * its common return with appverif_enabled left FALSE (the appverifier
 * .cpp else-path byte-matched at ROM 0x9089cdca-0x9089cdf4), coredll
 * init completes, main() runs. DELIVERY (the CBRET class — consume
 * the trap at the boundary): at the 0x0e0 slot fetch in USER mode
 * with the set-84/method-23 decode AND the surgical arg fingerprint
 * (r4 == HKEY_LOCAL_MACHINE, r7 == KEY_ALL_ACCESS, pr in the user
 * coredll window), consume the exception, r0 := 2, pc := pr (the jsr
 * site's own return address — live-verified pr=0x4005adc8 = ROM
 * 0x9089cdc8). Capped: MMCS_L69AP_MAX deliveries (default 8). */
int mmcs_l69ap_on(void)
{
    static int on = -1;
    if (on < 0) {
        on = getenv("MMCS_L69AP") != NULL;
    }
    return on;
}

/* MMCS fork (L70/S221): MMCS_L70KS — the kernel kstack-arena P3
 * window refill (env MMCS_L70KS, default off).
 *
 * THE ASCII-DISPATCH DEATH ROOT (tape-verified this session, the
 * l70_firstexc TH-EXC tape + cellwatch): the launcher's wait-cleanup
 * block-chain walk (0x90837d38 `mov.l @(4,r12),r8`, the L51/L53
 * block-walk family) follows a stale link into the FREED kstack P3
 * window of an exited sibling thread (TEA 0xd007fd70, the kbase
 * d0070000 TCB census row) — the kernel dropped the UTLB entry at
 * thread exit, the straggler load DTLB-read-misses (MMU_DTLB_MISS_
 * READ = evt 0x040 in this fork's raise table), and the vendor
 * exception path declares it FATAL: the exception report
 * (OEMWriteDebugString = OEMGLOBAL+0x10 = 0x90807364, called via the
 * formatter 0x908320f0) runs with sp in the kernel STATIC POOL
 * (0x886026d8, the stack region 0x886025b0..0x886028d0 under the OAL
 * tables), its copy loop stores the "Exception %03x Thread=%08x
 * PC=%08x" string at r14+8 = 0x886025b8 — DIRECTLY OVER the tail of
 * the OEM function table (g_pOemGlobal = *[0x8867f03c] = 0x88602580:
 +0x38 pfnGetTickCount, +0x44 pfnNotifyReschedule, +0x4C pfnUpdate-
 * ReschedTime). The ASCII makes [+0x4C] nonzero, so every later
 * GETCURRTICK (drain2 0x90827158: `[+0x4C] ? fn_0x90823964() :
 * CurMSec`) dispatches fn_90823964 = `jmp @[[0x8867f03c]+0x38]` =
 * "Exce" as code (pc 0x65637845) — the L69/S220 blocker — and the
 * report tail's ring-writer call with r4 = [0x88602d30] = 0xeb41
 * (the unbound OAL cell) faults at 0x90807562 nesting into the
 * BL=1 ring freeze.
 *
 * THE FIX (the L68KD live-page family): the D0 kstack window IS the
 * vendor's own top-of-RAM arena — VA = PA + 0xC0000000 over the RAM
 * top region (dwMainMemoryEndAddress 0x90700000 -> PA 0x10700000;
 * observed kbases d0010000..d0280000, 0x10000 pages, kstacks AND the
 * wait-block arena share the window — the blocks d00bf3xx live on
 * the waiting thread's own kstack page). A kernel-mode data miss in
 * the window = a straggler walk over a FREED window whose backing
 * RAM still holds the vendor's own stale data: refill PA = VA -
 * 0xC0000000 and let the vendor code read its own arena (stock-
 * faithful: the page is real, the vendor's own allocator state, and
 * the stock cleanup dispatches stale blocks harmlessly — the L53
 * early-return class). Fetches are NOT served (executing stack data
 * stays a real bug); the window top derives from the vendor's own
 * OEMGLOBAL cell at run time. */
int mmcs_l70ks_on(void)
{
    static int on = -1;
    if (on < 0) {
        on = getenv("MMCS_L70KS") != NULL;
    }
    return on;
}

static int mmcs_machine_post_load(void *opaque, int version_id)
{
    struct MmcsSnap *s = opaque;
    memcpy(syscon_c080, s->syscon, sizeof s->syscon);
    memcpy(pfc_usb_st, s->pfc, sizeof s->pfc);
    memcpy(mmcs_vintc_regs, s->vintc, sizeof s->vintc);
    mmcs_vintc_evt_code = s->vintc_evt;
    mmcs_2dg = s->dg;
    memcpy(mmcs_srvpg_map, s->srvpg_map, sizeof s->srvpg_map);
    mmcs_nsrvpg = s->nsrvpg;
    mmcs_srvpg_nxt = s->srvpg_nxt;
    memcpy(mmcs_pgown, s->pgown, sizeof s->pgown);
    mmcs_pgown_nins = s->pgown_nins;
    mmcs_pgown_npin = s->pgown_npin;
    mmcs_pgown_novr = s->pgown_novr;
    memcpy(mmcs_l16_ents, s->l16, sizeof s->l16);
    mmcs_l19_armed = s->l19_armed;
    mmcs_l26_armed = s->l26_armed;
    mmcs_l32_armed = s->l32_armed;
    mmcs_l36_armed = s->l36_armed;
    mmcs_l37_armed = s->l37_armed;
    mmcs_l19_cadence_ms = s->l19_cadence;
    mmcs_l26_cadence_ms = s->l26_cadence;
    mmcs_l32_cadence_ms = s->l32_cadence;
    mmcs_l36_cadence_ms = s->l36_cadence;
    mmcs_l37_cadence_ms = s->l37_cadence;
    mmcs_l19_max_deliv = s->l19_max;
    mmcs_l26_max_deliv = s->l26_max;
    mmcs_l32_max_deliv = s->l32_max;
    mmcs_l36_max_deliv = s->l36_max;
    mmcs_l37_max_deliv = s->l37_max;
    mmcs_l19_total = s->l19_total;
    mmcs_l26_total = s->l26_total;
    mmcs_l32_total = s->l32_total;
    mmcs_l36_total = s->l36_total;
    mmcs_l37_total = s->l37_total;
    memcpy(mmcs_l19_sig, s->l19_sig, MMCS_L19_NSIG);
    memcpy(mmcs_l26_sig, s->l26_sig, MMCS_L19_NSIG);
    memcpy(mmcs_l32_sig, s->l32_sig, MMCS_L19_NSIG);
    memcpy(mmcs_l36_sig, s->l36_sig, MMCS_L19_NSIG);
    memcpy(mmcs_l37_sig, s->l37_sig, MMCS_L19_NSIG);
    mmcs_l19_sig_have = s->l19_have;
    mmcs_l26_sig_have = s->l26_have;
    mmcs_l32_sig_have = s->l32_have;
    mmcs_l36_sig_have = s->l36_have;
    mmcs_l37_sig_have = s->l37_have;
    mmcs_l19_quiet = s->l19_quiet;
    mmcs_l19_nopick = s->l19_nopick;
    mmcs_l26_quiet = s->l26_quiet;
    mmcs_l32_quiet = s->l32_quiet;
    mmcs_l36_quiet = s->l36_quiet;
    mmcs_l37_quiet = s->l37_quiet;
    mmcs_tick_l19 = s->tick_l19;
    mmcs_tick_l26 = s->tick_l26;
    mmcs_tick_l32 = s->tick_l32;
    mmcs_tick_l36 = s->tick_l36;
    mmcs_tick_l37 = s->tick_l37;
    mmcs_tick_live = s->tick_live;
    mmcs_hdevt_pending = s->hdevt_pending;
    mmcs_snap_restored = 1;   /* L43: TSTR reads 0 after restore (tmu012
                               * has no vmstate) — the TICK_EVT sub-gate
                               * skips, see mmcs_tick_evt */

    /* Re-arm the free-floating tick chain (the scheduler tick + every
     * daemon scan rides it; anonymous QEMUTimers are not migrated).
     * The one-shot arms (VINTC/HDEVT/RINGNOP/L16/L18 lists) live
     * below the park point and are intentionally NOT re-armed. */
    if (mmcs_tick_live) {
        QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_tick_deliver,
                                    NULL);
        timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1);
        fprintf(stderr, "MMCS-SNAP: tick chain re-armed after restore\n");
    }
    /* Re-target the live console at the presented surface (a pure
     * host-side display pointer — the guest-side surface registers
     * were restored with the 2dg model above). */
    if (mmcs_2dg.armed && (mmcs_2dg.surf_a || mmcs_2dg.tex)) {
        mmcs_2dg_last = 0;
        mmcs_2dg_present_console(mmcs_2dg.surf_a
                                 ? (mmcs_2dg.surf_a & 0x1FFFFFFF)
                                 : (mmcs_2dg.tex & 0x1FFFFFFF));
    }
    /* L64: re-apply the S214 death-site trapa AFTER the restore — the
     * incoming migration RAM load overwrites the flash image (the patch
     * applied at machine-init is gone), and no TBs exist yet post-
     * migration, so the patched site re-translates clean. */
    if (getenv("MMCS_S214DBG")) {
        uint16_t trapa72 = 0xC372;
        hwaddr off = (0x90a82000 - 0x90800000) + (0xc02cdbee - 0xc02c1000);
        cpu_physical_memory_write(MMCS_FLASH_BASE + off, &trapa72, 2);
        fprintf(stderr, "MMCS-SNAP: S214 death-site trapa re-applied "
                "post-restore\n");
    }
    /* L66/S218: re-apply the low-arena stock AFTER the restore — the
     * incoming migration RAM load carries whatever the save run left
     * (poisoned S122 seeds / zeros / vendor data); no TBs exist yet
     * post-migration, so the stocked block re-translates clean. */
    if (getenv("MMCS_L66STK")) {
        mmcs_l66_stock_arena("post-restore");
    }
    /* L68/S219: the KData user page re-pinned to the LIVE KData page
     * (after the RAM load, so the vendor's KData pointer is valid). */
    if (mmcs_l68_kd_on()) {
        mmcs_l68_repin_kdata_page();
    }
    fprintf(stderr, "MMCS-SNAP: machine state restored (srvpg=%d "
            "pgown ins/pin=%u/%u, l16[0] pending=%d daemon=%d, "
            "l26/l32 armed=%d/%d totals=%u/%u)\n",
            mmcs_nsrvpg, mmcs_pgown_nins, mmcs_pgown_npin,
            mmcs_l16_ents[0].pending, mmcs_l16_ents[0].daemon,
            mmcs_l26_armed, mmcs_l32_armed, mmcs_l26_total,
            mmcs_l32_total);
    return 0;
}

static const VMStateDescription vmstate_mmcs_l16_ent = {
    .name = "mmcs/l16_ent",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(evt_va, struct mmcs_l16_ent),
        VMSTATE_UINT32(stub_va, struct mmcs_l16_ent),
        VMSTATE_UINT32(evt_code, struct mmcs_l16_ent),
        VMSTATE_UINT32(slot_pa, struct mmcs_l16_ent),
        VMSTATE_INT32(pending, struct mmcs_l16_ent),
        VMSTATE_INT32(daemon, struct mmcs_l16_ent),
        VMSTATE_INT32(strikes, struct mmcs_l16_ent),
        VMSTATE_UINT32(ndeliv, struct mmcs_l16_ent),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_mmcs_pgown_ent = {
    .name = "mmcs/pgown_ent",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(va, struct mmcs_pgown_ent),
        VMSTATE_UINT32(asid, struct mmcs_pgown_ent),
        VMSTATE_UINT32(pa, struct mmcs_pgown_ent),
        VMSTATE_UINT32(pinned, struct mmcs_pgown_ent),
        VMSTATE_UINT32(nremap, struct mmcs_pgown_ent),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_mmcs_snap = {
    .name = "mmcs/machine",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = mmcs_machine_pre_save,
    .post_load = mmcs_machine_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32_ARRAY(syscon, struct MmcsSnap, 64),
        VMSTATE_UINT32_ARRAY(pfc, struct MmcsSnap, 4),
        VMSTATE_UINT32_ARRAY(vintc, struct MmcsSnap, 64),
        VMSTATE_UINT32(vintc_evt, struct MmcsSnap),
        VMSTATE_INT32(dg.armed, struct MmcsSnap),
        VMSTATE_UINT32(dg.dl_base, struct MmcsSnap),
        VMSTATE_UINT32(dg.surf_a, struct MmcsSnap),
        VMSTATE_UINT32(dg.surf_b, struct MmcsSnap),
        VMSTATE_UINT32(dg.mode, struct MmcsSnap),
        VMSTATE_UINT32(dg.ctl, struct MmcsSnap),
        VMSTATE_UINT32(dg.du00, struct MmcsSnap),
        VMSTATE_UINT32(dg.du04, struct MmcsSnap),
        VMSTATE_UINT32(dg.du_done, struct MmcsSnap),
        VMSTATE_UINT32(dg.du0c, struct MmcsSnap),
        VMSTATE_UINT32(dg.du18, struct MmcsSnap),
        VMSTATE_UINT32_ARRAY(dg.ch, struct MmcsSnap, 0x400),
        VMSTATE_UINT32(dg.tex, struct MmcsSnap),
        VMSTATE_UINT32(dg.tex_w, struct MmcsSnap),
        VMSTATE_UINT32(dg.tex_h, struct MmcsSnap),
        VMSTATE_INT32(dg.nlog, struct MmcsSnap),
        VMSTATE_UINT32(nsrvpg, struct MmcsSnap),
        VMSTATE_UINT32(srvpg_nxt, struct MmcsSnap),
        VMSTATE_UINT32_2DARRAY(srvpg_map, struct MmcsSnap, 1024, 2),
        VMSTATE_STRUCT_ARRAY(pgown, struct MmcsSnap, MMCS_PGOWN_SLOTS, 1,
                             vmstate_mmcs_pgown_ent, struct mmcs_pgown_ent),
        VMSTATE_UINT32(pgown_nins, struct MmcsSnap),
        VMSTATE_UINT32(pgown_npin, struct MmcsSnap),
        VMSTATE_UINT32(pgown_novr, struct MmcsSnap),
        VMSTATE_STRUCT_ARRAY(l16, struct MmcsSnap, MMCS_L16_MAX, 1,
                             vmstate_mmcs_l16_ent, struct mmcs_l16_ent),
        VMSTATE_INT32(l19_armed, struct MmcsSnap),
        VMSTATE_INT32(l26_armed, struct MmcsSnap),
        VMSTATE_INT32(l32_armed, struct MmcsSnap),
        VMSTATE_INT32(l36_armed, struct MmcsSnap),
        VMSTATE_INT32(l37_armed, struct MmcsSnap),
        VMSTATE_UINT32(l19_cadence, struct MmcsSnap),
        VMSTATE_UINT32(l26_cadence, struct MmcsSnap),
        VMSTATE_UINT32(l32_cadence, struct MmcsSnap),
        VMSTATE_UINT32(l36_cadence, struct MmcsSnap),
        VMSTATE_UINT32(l37_cadence, struct MmcsSnap),
        VMSTATE_UINT32(l19_max, struct MmcsSnap),
        VMSTATE_UINT32(l26_max, struct MmcsSnap),
        VMSTATE_UINT32(l32_max, struct MmcsSnap),
        VMSTATE_UINT32(l36_max, struct MmcsSnap),
        VMSTATE_UINT32(l37_max, struct MmcsSnap),
        VMSTATE_UINT32(l19_total, struct MmcsSnap),
        VMSTATE_UINT32(l26_total, struct MmcsSnap),
        VMSTATE_UINT32(l32_total, struct MmcsSnap),
        VMSTATE_UINT32(l36_total, struct MmcsSnap),
        VMSTATE_UINT32(l37_total, struct MmcsSnap),
        VMSTATE_UINT8_ARRAY(l19_sig, struct MmcsSnap, MMCS_L19_NSIG),
        VMSTATE_UINT8_ARRAY(l26_sig, struct MmcsSnap, MMCS_L19_NSIG),
        VMSTATE_UINT8_ARRAY(l32_sig, struct MmcsSnap, MMCS_L19_NSIG),
        VMSTATE_UINT8_ARRAY(l36_sig, struct MmcsSnap, MMCS_L19_NSIG),
        VMSTATE_UINT8_ARRAY(l37_sig, struct MmcsSnap, MMCS_L19_NSIG),
        VMSTATE_INT32(l19_have, struct MmcsSnap),
        VMSTATE_INT32(l26_have, struct MmcsSnap),
        VMSTATE_INT32(l32_have, struct MmcsSnap),
        VMSTATE_INT32(l36_have, struct MmcsSnap),
        VMSTATE_INT32(l37_have, struct MmcsSnap),
        VMSTATE_UINT32(l19_quiet, struct MmcsSnap),
        VMSTATE_UINT32(l19_nopick, struct MmcsSnap),
        VMSTATE_UINT32(l26_quiet, struct MmcsSnap),
        VMSTATE_UINT32(l32_quiet, struct MmcsSnap),
        VMSTATE_UINT32(l36_quiet, struct MmcsSnap),
        VMSTATE_UINT32(l37_quiet, struct MmcsSnap),
        VMSTATE_UINT64(tick_l19, struct MmcsSnap),
        VMSTATE_UINT64(tick_l26, struct MmcsSnap),
        VMSTATE_UINT64(tick_l32, struct MmcsSnap),
        VMSTATE_UINT64(tick_l36, struct MmcsSnap),
        VMSTATE_UINT64(tick_l37, struct MmcsSnap),
        VMSTATE_INT32(tick_live, struct MmcsSnap),
        VMSTATE_INT32(hdevt_pending, struct MmcsSnap),
        VMSTATE_END_OF_LIST()
    }
};


static void mmcs_vmstate_register(void)
{
    vmstate_register(NULL, 0, &vmstate_mmcs_snap, &mmcs_snap);
    mmcs_regvt_vmstate_register();
    mmcs_helper_vmstate_register();
}

/* MMCS fork (L35/Linux lane): sh vmlinux ELF program headers carry
 * p_paddr == p_vaddr (P1-linked; the linker script places sections with
 * AT(ADDR(.)) so the load address IS the P1 virtual address). The SH
 * P1/P2 windows translate to phys by masking the top bits — translate
 * the segment addresses for load_elf so the kernel lands in the SDRAM
 * MR at 0x08000000+. */
static uint64_t mmcs_linux_elf_translate(void *opaque, uint64_t addr)
{
    return addr & 0x1fffffff;
}

static void mmcs_init(MachineState *machine)
{
    SuperHCPU *cpu;
    MemoryRegion *sdram, *flash, *bootrom;
    uint8_t *boot_stub;

    cpu = SUPERH_CPU(cpu_create(machine->cpu_type));

    /* savestate lane: register the machine/host-side vmstate (must
     * precede both boot paths so snapshots work for the OS boot and
     * the MLD acceptance mode alike). The restore process re-runs
     * this init under the SAME env (see scripts/emul/snapshot.sh —
     * the env is recorded with the snapshot). */
    mmcs_vmstate_register();

    /* MMCS_SH4A (MLD-splash lane, 2026-11-18): the SoC is an SH-4A core
     * (SH7777 per dmac_sh7777.dll); the resident M-Loader's startup
     * executes SH-4A-only instructions (icbi 0x00e3 at 0x889333de right
     * after the CCR/P2 switch — plus movco/movli/prefi/synco throughout
     * the loader body). The default SH7751R CPU model raises
     * reserved-instruction on them; with SR.BL=1 the exception is
     * blocked and the CPU parks forever. Arm the SH-4A decode
     * (additive, default off; matches the real core's ISA). */
    if (mmcs_env_on("MMCS_SH4A")) {
        cpu->env.features |= SH_FEATURE_SH4A;
    }

    /* SDRAM at 0x08000000 (unit RAM window; covers MLD + framebuffer) */
    sdram = g_new(MemoryRegion, 1);
    memory_region_init_ram(sdram, NULL, "mmcs.sdram", MMCS_SDRAM_SIZE,
                           &error_fatal);
    memory_region_add_subregion(get_system_memory(), MMCS_SDRAM_BASE, sdram);
    mmcs_sdram_mr = sdram;
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

    /* MMCS_KILLSTK: 64KB RAM at phys 0x1F00000 — the daemon stub page
     * provider (HDEVT stub P2 0xBF00F000, L16EV, L26EV 0xBF00E200,
     * L32EV 0xBF00EC00; the L11 kill-dispatch hook that also used the
     * top page 0xBF00FF00 was deleted 2026-11-19 by the retirement
     * lane S173 — inert in the successor world, fidelity scorecard
     * §1.10/§B3; the knob now provides ONLY this page). Must
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
    /* MMCS_REGVT (L29): arm the FileSys api-set registry-methods service
     * (hive from the real default.reg; see the mmcs_regvt block above —
     * the hook proper lives in target/sh4/helper.c do_interrupt, the
     * FSVT class). Env = path to the .reg hive. */
    if (getenv("MMCS_REGVT")) {
        mmcs_regvt_load(getenv("MMCS_REGVT"));
    }
    if (getenv("MMCS_KSLOT")) {
        cpu->env.mmcs_kslot_active = 1;
    }
    if (getenv("MMCS_L39KILL")) {
        cpu->env.mmcs_l39kill_active = 1;
    }

    /* MMCS fork (L21): MMCS_PGOWN=1 — arm the write-sticky page-ownership
     * table (see the pgown block above; hooks at the tlb_set_page sites in
     * target/sh4/helper.c::superh_cpu_tlb_fill). */
    if (mmcs_env_on("MMCS_PGOWN")) {
        mmcs_pgown_armed = 1;
        fprintf(stderr, "MMCS: PGOWN write-sticky page ownership armed "
                "(user windows per-ASID, C0/stack/KData shared)\n");
    }

    /* MMCS fork (input lane, 2026-11-19): MMCS_INPUT=1 — the SCIF1
     * Micon injector (hw/sh4/mmcs-input.c): the sub-CPU link SCIF at
     * 0xFFE41000 with an RX frame feeder, the VNC-pointer-as-touch-
     * panel input handler, and the mmcs_touch/mmcs_swipe/mmcs_key/
     * mmcs_reverse HMP verbs. Called before the world branches so it
     * arms in every mode (the MLD loader world — the earliest live
     * consumer of the link, its subcpu_recv_req loop is the injection
     * oracle — the handoff dual-world, and the default WinCE boot).
     * Default off; the default boot never creates the SCIF. */
    mmcs_input_init();

    /* MMCS_SDHI: the drafted SDHI0/1 empty-slot model. The creation gate
     * lives at TOP LEVEL (hoisted from the MMCS_LINUX block 2026-11-23,
     * the device-qtest lane): default OFF => zero behavior change in
     * every world; MMCS_SDHI=1 now arms the model outside the Linux
     * loader so the qtest contract (tests/qtest/mmcs-sdhi-test.c) runs. */
    if (mmcs_env_on("MMCS_SDHI")) {
        mmcs_sdhi_init();
    }

    /* MLD acceptance-test mode (env MMCS_MLD=1): skip the OS boot entirely —
     * map the loader RAM image, our payload, and the test stub at phys 0.
     * MMCS_PAYLOAD = container file (mapped at phys 0x0A000000),
     * MMCS_STUB    = assembled stub binary (mapped at phys 0, is the boot). */
    if (getenv("MMCS_MLD")) {
        MemoryRegion *mr;
        const char *pay = getenv("MMCS_PAYLOAD") ?: "/dev/null";
        const char *stub = getenv("MMCS_STUB") ?: "/dev/null";
        /* MMCS fork (S159): MMCS_HANDOFF=1 — one continuous car boot: the
         * loader paints + scans + concludes, then the OS launches (see the
         * mmcs_handoff block above for the full decode). Requires the
         * kernel XIP image (-bios; loaded by the shared tail below) and
         * the NOR FLROM (the stub's home + the trampoline's CFI window). */
        const int mld_handoff = mmcs_env_on("MMCS_HANDOFF");
        if (mld_handoff) {
            if (!machine->firmware) {
                error_report("MMCS_HANDOFF needs -bios (the kernel XIP "
                             "image for the post-handoff OS boot)");
                exit(1);
            }
            if (!getenv("MMCS_FLROM")) {
                error_report("MMCS_HANDOFF needs MMCS_FLROM (the NOR the "
                             "loader boots/launches from)");
                exit(1);
            }
        }
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
        /* MMCS_FLROM=<file> (MLD-splash lane, 2026-11-18): seed the NOR
         * FLROM window (Area 0, phys 0x00000000-0x00FFFFFF, P2 alias
         * 0xA0000000) with the unit's NOR bytes. Geometry live-proven this
         * lane (the resume lane's killer): GetBackupInfoOpeningBMP's table
         * ptr DAT_8894749c = 0xa00e0000 -> phys 0x000e0000 = NOR +0xE0000
         * (QEMU's GETPHYSDBG print caught the loader reading 0xa00e0000
         * and the P2 mask resolving 0x000e0000 — the earlier 0x00e00000
         * placement was a factor-of-16 misread), and SetOpeningImage's
         * image start DAT_889477a4 = 0xa0100000 -> phys 0x00100000, the
         * validated NOR [1 MB, 2 MB) burn window. Seed layout (corpus
         * scripts/emul/build_mld_flrom.py): BMP @+0x100000, info table
         * @+0xE0000. The MR covers the whole 16 MB window INCLUDING phys 0,
         * so the separate stub MR below is skipped and the boot stub is
         * written into the NOR MR at +0 (the real NOR boots from here). */
        const char *flrom = getenv("MMCS_FLROM");
        if (flrom) {
            MemoryRegion *fr = g_new(MemoryRegion, 1);
            memory_region_init_ram(fr, NULL, "mld.flrom", 0x1000000,
                                   &error_fatal);
            memory_region_add_subregion(get_system_memory(),
                                        0x00000000, fr);
            /* S159: while the NOR owns phys [0,16MB) the L26 P1
             * servant-alias hook must stay off (see
             * mmcs_p1_alias_enabled) + the MR is captured for the
             * seam-time retirement (handoff mode) */
            mmcs_p1_alias_enabled = 0;
            if (mld_handoff) {
                mmcs_handoff_flrom_mr = fr;
                mmcs_handoff_sysmem = get_system_memory();
            }
            /* write through the RAM pointer (the L27/L14 lesson: ROM
             * blobs apply at reset AFTER machine init and would stomp
             * the stub written at NOR +0 below) */
            gsize flen = 0;
            uint8_t *fbuf = NULL;
            if (!g_file_get_contents(flrom, (gchar **)&fbuf, &flen, NULL)
                || !fbuf || flen == 0 || flen > 0x1000000) {
                error_report("MMCS_MLD: cannot load FLROM seed %s", flrom);
                exit(1);
            }
            cpu_physical_memory_write(0, fbuf, flen);
            g_free(fbuf);
            fprintf(stderr, "MMCS: MLD FLROM seed at phys 0x00000000 "
                    "(%s; BMP@+0x100000, info table@+0xE0000)\n", flrom);
        }
        /* MMCS_OCIRAM (MLD-splash lane, 2026-11-18): the loader's own
         * startup loads r15 = 0xE5204000 (the literal at 0x88933424,
         * decoded via QEMU's own TB disasm) BEFORE calling the pre-main
         * init at 0x88932344. 0xE5204000 is P4 space — the SH7777's
         * on-chip RAM, the classic boot-loader stack before SDRAM init.
         * Without it the loader's pushes/readbacks hit unassigned memory
         * (stores dropped) and the .data region walker reads an empty
         * frame -> memcpy with garbage args (the observed park at
         * 0x889353b8). 64 KB at P4 0xE5200000; MLD-branch-only.
         * MMCS_RAM2EXT_MB (default 32): second-SDRAM-bank window above
         * the stock ram2 (the loader scans/uses the 0x04800000+ span). */
        {
            const char *oir = getenv("MMCS_OCIRAM");
            unsigned oir_kb = oir ? (unsigned)atoi(oir) : 64;
            if (oir_kb) {
                MemoryRegion *oc = g_new(MemoryRegion, 1);
                memory_region_init_ram(oc, NULL, "mld.ociram",
                                       (uint64_t)oir_kb * KiB, &error_fatal);
                memory_region_add_subregion(get_system_memory(),
                                            0xE5200000, oc);
                fprintf(stderr, "MMCS: MLD on-chip RAM %u KB at P4 "
                        "0xE5200000 (loader stack 0xE5204000)\n", oir_kb);
            }
            const char *r2 = getenv("MMCS_RAM2EXT_MB");
            unsigned r2n = r2 ? (unsigned)atoi(r2) : 32;
            if (r2n) {
                MemoryRegion *r2m = g_new(MemoryRegion, 1);
                memory_region_init_ram(r2m, NULL, "mld.ram2ext",
                                       (uint64_t)r2n * MiB, &error_fatal);
                memory_region_add_subregion(get_system_memory(),
                                            0x04800000, r2m);
                fprintf(stderr, "MMCS: MLD RAM2 extension %u MB at phys "
                        "0x04800000\n", r2n);
            }
        }
        if (!flrom) {
            mr = g_new(MemoryRegion, 1);
            memory_region_init_ram(mr, NULL, "mld.stub", 0x1000, &error_fatal);
            memory_region_add_subregion(get_system_memory(), 0, mr);
            if (load_image_targphys(stub, 0, 0x1000) < 0) {
                error_report("MMCS_MLD: cannot load stub %s", stub);
                exit(1);
            }
            memory_region_set_readonly(mr, true);
        } else {
            /* FLROM owns phys 0: the boot stub lives at NOR +0, written
             * through the FLROM MR's RAM backing directly (NOT a ROM
             * blob — rom_check_and_register_reset hard-fails on the
             * overlapping FLROM+stub ranges). */
            gsize slen = 0;
            uint8_t *sbuf = NULL;
            if (!g_file_get_contents(stub, (gchar **)&sbuf, &slen, NULL)
                || !sbuf || slen == 0 || slen > 0x1000) {
                error_report("MMCS_MLD: cannot load stub %s", stub);
                exit(1);
            }
            cpu_physical_memory_write(0, sbuf, slen);
            g_free(sbuf);
        }
        /* debug SCIF below still wires; skip kernel flash/bootrom path.
         * (S159 handoff: the shared tail below provides sh7750 + the SCIF
         * + the kernel flash + every env-gated service — skip the MLD
         * block's duplicates so they are created exactly once.) */
        if (!mld_handoff) {
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
        }
        /* MMCS_2DG (MLD-splash lane): the 2DG/DU-system/DU-channel carves
         * — overlap priority 1 shadows the sh7750 SCIF claim at
         * 0xFFE80000 (P4) and its A7 alias at 0x1FE80000 (the known
         * serial collision; the sh_serial device itself stays alive,
         * only its MMIO window is claimed by the real engine). */
        if (mmcs_env_on("MMCS_2DG")) {
            mmcs_2dg_carve();
        }
        {
            const char *ds = getenv("MMCS_DUMP");
            if (ds && !mld_handoff) {
                /* (the shared tail below arms its own dump timer) */
                QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_dump_ram, NULL);
                timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + atoi(ds) * 1000);
            }
        }
        if (mld_handoff) {
            /* S159: arm the no-update conclusion detector; the fall-through
             * below runs the FULL default-boot tail (kernel XIP flash +
             * every env-gated service + INTC/tick daemons) so the machine
             * is simultaneously the loader's world and the kernel's world */
            mmcs_handoff_cpu = cpu;
            mmcs_handoff_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                              mmcs_handoff_poll, NULL);
            timer_mod(mmcs_handoff_timer,
                      qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
                      + atoi(getenv("MMCS_HANDOFF_MIN") ? : "3000"));
            mmcs_handoff_retire_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                                    mmcs_handoff_retire_flrom,
                                                    NULL);
            fprintf(stderr, "MMCS: HANDOFF armed — the loader's no-update "
                    "park (pc windows 88935f80/8893bd00, 8x250ms debounce) "
                    "launches the OS through the loader's own 0x88935590 "
                    "launcher (min %sms)\n",
                    getenv("MMCS_HANDOFF_MIN") ? : "3000");
        } else {
            mmcs_usb_setup();
            return;
        }
    }

    /* MMCS fork (L35/Linux lane, 2026-11-18): MMCS_LINUX=1 — second-OS
     * oracle mode. Boots a plain Linux/sh kernel (v6.1 LTS, sh4 LE, built
     * with CPU_SUBTYPE_SH7751R + MEMORY_START=0x08000000/128M, busybox
     * initramfs embedded) into the SDRAM MR above, instead of the WinCE
     * image — an independent OS exercising the sh7750 INTC/TMU/SCI models
     * the WinCE boot path also rides (every divergence = a machine-model
     * bug; see the lane report). The world: SDRAM (mapped above) + the
     * full sh7750 SoC model (INTC w/ IPRA@0xffd00004, TMU012@0x1fd80000
     * + its P4 alias, TMU34@0x1e100000, SCI@0xffe00000 serial0, SCIF@
     * 0xffe80000 serial1 = the kernel's console=ttySC1, FRQCR/BCS) + the
     * proven debug SCIF at 0xFFE40000 (serial 2). NO XIP flash, NO vintc/
     * chanflash services beyond what ran above, NO evt/tick daemons —
     * the WinCE tail below is skipped entirely (additive, default off;
     * the default boot is unchanged).
     * Env:
     *   MMCS_LINUX_KERNEL   vmlinux ELF (EM_SH; entry from e_entry) or a
     *                       flat binary (zImage/vmlinux.bin — loaded at
     *                       MMCS_LINUX_BASE, entered at MMCS_LINUX_ENTRY)
     *                       default /tmp/mmcs-linux-vmlinux
     *   MMCS_LINUX_BASE     hex phys base for flat images (default
     *                       0x08001000 = MEMORY_START+ZERO_PAGE_OFFSET)
     *   MMCS_LINUX_ENTRY    hex entry override (default: ELF e_entry or
     *                       the flat base)
     *   MMCS_LINUX_CMDLINE  written at PARAM+0x100 (phys 0x08001100, the
     *                       empty_zero_page COMMAND_LINE slot the SH
     *                       kernel reads with CONFIG_CMDLINE_EXTEND) */
    if (mmcs_env_on("MMCS_LINUX")) {
        uint64_t entry = 0, low = 0, high = 0;
        const char *kern = getenv("MMCS_LINUX_KERNEL")
                           ? : "/tmp/mmcs-linux-vmlinux";
        const char *cml = getenv("MMCS_LINUX_CMDLINE");
        hwaddr flat_base = 0x08001000;
        uint8_t hdr[4] = { 0, 0, 0, 0 };
        FILE *kf;
        int is_elf = 0;
        ssize_t klen;
        /* the SoC: INTC + TMU + RTC + SCI/SCIF + BSC/CPG (identical to
         * the default-boot tail's sh7750_init — the Linux setup-sh7750.c
         * device/intc tables are a register-for-register match). */
        sh7750_init(cpu, get_system_memory());
        /* the kernel's debug SCIF at 0xFFE40000 (serial 2; the proven
         * port — kept available for earlycon-style polling) */
        {
            DeviceState *dev = qdev_new(TYPE_SH_SERIAL);
            SysBusDevice *sb = SYS_BUS_DEVICE(dev);
            dev->id = g_strdup("mmcs-dbg-scif");
            qdev_prop_set_chr(dev, "chardev", serial_hd(2));
            qdev_prop_set_uint8(dev, "features", SH_SERIAL_FEAT_SCIF);
            sysbus_realize_and_unref(sb, &error_fatal);
            sysbus_mmio_map(sb, 0, 0xffe40000);
        }
        /* P4 aliases: the sh7750 model maps TMU012 only at phys
         * 0x1fd80000 and TMU34 at 0x1e100000, but the SH kernel
         * addresses on-chip blocks P4-style (its platform resources are
         * 0xffd80000 / 0xfe100000 / 0xffc80000) — same p4map pattern as
         * the tail below, plus TMU34 which the tail never needed. */
        {
            struct { hwaddr p4, phys; const char *name; } l4map[] = {
                { 0xFFD80000, 0x1FD80000, "mmcs.linux-tmu-p4" },
                { 0xFFC80000, 0x1FC80000, "mmcs.linux-rtc-p4" },
                { 0xFE100000, 0x1E100000, "mmcs.linux-tmu34-p4" },
            };
            for (unsigned i = 0; i < ARRAY_SIZE(l4map); i++) {
                MemoryRegionSection sec = memory_region_find(
                    get_system_memory(), l4map[i].phys, 4);
                if (sec.mr && sec.mr != get_system_memory()) {
                    MemoryRegion *al = g_new(MemoryRegion, 1);
                    memory_region_init_alias(al, NULL, l4map[i].name,
                                             sec.mr, 0, 0x100);
                    memory_region_add_subregion_overlap(
                        get_system_memory(), l4map[i].p4, al, 0);
                }
            }
        }

        /* MMCS_SDHI (L35/Linux lane): the drafted SDHI0/1 host model at
         * 0xFFE4C000/0xFFE4D000 (car-research emul-drafts/mmcs-sdhi.c,
         * spec 2026-11-17-sdhi-device-spec.md; empty-slot v1). The
         * kernel side registers a sh_mobile_sdhi platform device at
         * 0xffe4c000 + evt2irq(0xAE0) — the tmio/renesas_sdhi driver
         * probing our empty-slot model is the designed-semantics
         * oracle (clean enumeration, no card). */
        /* (gate hoisted to top-level init, 2026-11-23) */

        /* load the kernel: ELF (paddr from program headers) or flat bin */
        kf = fopen(kern, "rb");
        if (kf) {
            size_t n = fread(hdr, 1, sizeof hdr, kf);
            fclose(kf);
            is_elf = (n == sizeof hdr && hdr[0] == 0x7f && hdr[1] == 'E'
                      && hdr[2] == 'L' && hdr[3] == 'F');
        }
        if (is_elf) {
            /* load_rom=false: a ROM blob would be re-applied at system
             * reset and restore the image bytes over the boot-param
             * cmdline written below (the L27 ROM-blob-vs-RAM-pointer
             * lesson, in ELF form). */
            klen = load_elf_ram(kern, NULL, mmcs_linux_elf_translate, NULL,
                                &entry, &low, &high,
                                NULL, 0, 42 /* EM_SH */, 0, 0,
                                NULL, false);
            if (klen < 0) {
                error_report("MMCS_LINUX: cannot load ELF kernel %s "
                             "(%s)", kern, load_elf_strerror(klen));
                exit(1);
            }
        } else {
            const char *b = getenv("MMCS_LINUX_BASE");
            if (b) {
                flat_base = (hwaddr)strtoul(b, NULL, 16);
            }
            klen = load_image_targphys(kern, flat_base,
                                       MMCS_SDRAM_SIZE - 0x1000);
            if (klen < 0) {
                error_report("MMCS_LINUX: cannot load flat kernel %s "
                             "at %" HWADDR_PRId, kern, flat_base);
                exit(1);
            }
            low = flat_base;
            high = flat_base + klen;
            entry = flat_base;
        }
        {
            const char *e = getenv("MMCS_LINUX_ENTRY");
            if (e) {
                entry = (uint64_t)strtoul(e, NULL, 16);
            }
        }
        fprintf(stderr, "MMCS: LINUX oracle mode — kernel %s (%s) "
                "phys %08llx-%08llx entry %08llx\n",
                kern, is_elf ? "ELF" : "flat",
                (unsigned long long)low, (unsigned long long)high,
                (unsigned long long)entry);
        /* boot-param cmdline at PARAM+0x100 (the empty_zero_page starts
         * at phys MEMORY_START+ZERO_PAGE_OFFSET = 0x08001000; the SH
         * kernel reads COMMAND_LINE from +0x100 with CMDLINE_EXTEND) */
        if (cml && *cml) {
            size_t cl = strlen(cml);
            if (cl >= 0x800) {
                error_report("MMCS_LINUX_CMDLINE too long (%zu)", cl);
                exit(1);
            }
            cpu_physical_memory_write(0x08001100, cml, cl + 1);
            fprintf(stderr, "MMCS: LINUX cmdline at 0x08001100: %s\n",
                    cml);
        }

        /* boot ROM stub at phys 0: reset PC is 0xA0000000 (P2 alias of
         * phys 0); jump to the kernel entry. mov.l @(1,pc),r0 reads the
         * pool at +8 (past the jmp delay slot + nop — the delay slot
         * must NOT be the pool word: the stock stub's pool rides the
         * delay slot and executes as an instruction; an arbitrary entry
         * literal is not guaranteed harmless there). */
        bootrom = g_new(MemoryRegion, 1);
        memory_region_init_ram(bootrom, NULL, "mmcs.linuxrom", 0x1000,
                               &error_fatal);
        boot_stub = memory_region_get_ram_ptr(bootrom);
        boot_stub[0] = 0x01; boot_stub[1] = 0xD0;   /* mov.l @(1,pc),r0 */
        boot_stub[2] = 0x2B; boot_stub[3] = 0x40;   /* jmp @r0          */
        boot_stub[4] = 0x09; boot_stub[5] = 0x00;   /* nop (delay slot) */
        boot_stub[6] = 0x09; boot_stub[7] = 0x00;   /* nop (pool pad)   */
        boot_stub[8] = entry & 0xff;                /* pool @+8: EA =   */
        boot_stub[9] = (entry >> 8) & 0xff;         /* (pc+4)&~3 + 4    */
        boot_stub[10] = (entry >> 16) & 0xff;
        boot_stub[11] = (entry >> 24) & 0xff;
        memory_region_set_readonly(bootrom, true);
        memory_region_add_subregion(get_system_memory(), 0, bootrom);

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
        if (getenv("MMCS_S214DBG")) {
            /* L64: THE RunApps DEATH SITE catch (diagnostic, default
             * off) — fsdmgr.dll's FSD-interface forwarder thunk at
             * runtime c02cdbc0 (ROM 90a8ebc2); its jsr @r3 at runtime
             * c02cdbee (ROM 90a8ebee) becomes trapa #0x72. helper.c
             * prints the live register file + the descriptor dump and
             * reconstructs the stock jsr exactly (pr := site+4,
             * pc := r3) — passive tape, the world runs on. */
            uint16_t trapa72 = 0xC372;
            /* fsdmgr .text ROM dataptr = 0x90a82000, VA base 0xc02c1000 */
            hwaddr off = (0x90a82000 - 0x90800000)
                       + (0xc02cdbee - 0xc02c1000);
            cpu_physical_memory_write(MMCS_FLASH_BASE + off, &trapa72, 2);
            fprintf(stderr, "MMCS: S214 death-site trapa hook "
                    "@ROM 0x90a8ebee\n");
        }
        if (getenv("MMCS_ILKFIX")) {
            /* Arm the ILKFIX interlocked-op emulation (see helper.c
             * do_interrupt + tlb_fill hooks): KData page seeding/map +
             * exception-boundary emulation for slots holding live vendor
             * data. */
            cpu->env.mmcs_ilkfix_active = 1;
        }
        if (getenv("MMCS_L66STK")) {
            /* L66/S218: THE LOW-ARENA STOCKER — stock the complete
             * stock _InterlockedAPIs block (see mmcs_l66_stock_arena
             * above) eagerly at boot; the lazy ILKFIX seed stays as
             * the re-arm path if a guest zero-sweep clears it later. */
            mmcs_l66_stock_arena("machine-init");
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
        /* (MMCS_APIRET arm deleted 2026-11-19, retirement lane S173 —
         * inert in the successor world, fidelity scorecard §1.9/§B3.) */
        if (getenv("MMCS_CBRET")) {
            /* Arm the L33 callback-return completion (helper.c: the -1
             * marker slot 0xfffffdff = the vendor's PerformCallBack
             * return; with the launch-side continuation lost
             * ([pTh+0x1C]==0) the plain-API face cycles into the
             * user-mode P1 fetch death — synthesize the pending
             * ThreadStart setup continuation so the vendor's own
             * 0x908236f8 resume face runs; see the L33 decode there). */
            cpu->env.mmcs_cbret_active = 1;
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
         * (MMCS_NONOP=1 disables for A/B comparison).
         *
         * L35 (S166) EXEMPTION — the USER-COREDLL XIP window. The patcher
         * was built in the S2 epoch against the KERNEL-ROM sentinel sites
         * (the 0x9080d8b0 error-printer jsr@0xfffffbeb class) where a
         * live kernel-mode slot fetch reads P4-bus zeros in this SH4 model
         * (the L12 recursion march). But the same sweep also NOP'd every
         * DIRECT `mov.w <negative-slot>; jsr @r3` call site inside the
         * fixed-slot USER coredll .text (XIP at ROM 0x90853000,
         * 0x625ba bytes = 123 sites, e.g. ROM 0x9086eb04 = user VA
         * 0x4002cb04 = coredll ExitThread's NKTerminateThread terminator).
         * L33 proved those slot calls ARE the real CE5 syscall mechanism
         * (the vendor exception entry decodes (SPC-0xfffffe01)>>1 and the
         * PSL trampoline dispatches the method); NOP'ing them makes every
         * direct-jsr API a silent no-op-return: ExitThread(0) "returns",
         * the callback unwinds to the 0xfffffdff marker, the ThreadStart
         * continuation re-launches it, the 0x90835fbe delay-slot store
         * faults with r9=1, the raise machinery delivers
         * ThreadExceptionExit(STATUS_STACK_OVERFLOW) which calls
         * ExitThread again — the S164/S165 x276 exception-exit loop (the
         * user-mode fetch at the odd slot VA raises the 0x0e0 address
         * error exactly as on silicon, so these sites work natively once
         * left alone; the fixed-slot jmp-stub forms were never touched
         * and always worked). Exempt the window when MMCS_USERJSR=1
         * (the L35 exit fix, armed by the standing combo); the default
         * keeps the blanket sweep byte-identical (GOLDEN-proven: the
         * un-gated exemption shifted the default boot's SRD ring +
         * 422 framebuffer pixels — the default path reads the changed
         * flash bytes). MMCS_NOPALL=1 + MMCS_USERJSR=1 restores the
         * blanket sweep for A/B. */
        bool exempt_user = getenv("MMCS_USERJSR") != NULL
                           && getenv("MMCS_NOPALL") == NULL;
        if (!getenv("MMCS_NONOP")) {
            mmcs_nop_marker_jsrs(memory_region_get_ram_ptr(flash), len,
                                 0x90800000, !exempt_user);
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
                const char *ev = getenv("MMCS_TICK_EVT");
                fprintf(stderr, "MMCS: TICK evt %s every 1ms "
                        "(delay %sms)%s\n",
                        (ev && *ev && strcmp(ev, "0")) ? ev : "440",
                        getenv("MMCS_TICK_DELAY") ? : "12000",
                        (ev && *ev && strcmp(ev, "0")
                         && strtoul(ev, NULL, 16) != 0x440)
                        ? " — L43 selection, arm-time gates at first tick"
                        : "");
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
                    || getenv("MMCS_L19EV") || getenv("MMCS_L19TH")
                    || getenv("MMCS_L26EV") || getenv("MMCS_L32EV")
                    || getenv("MMCS_L36EV") || getenv("MMCS_L37EV")) {
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
     * Reset PC on SH4 is 0xA0000000 (P2 mirror of physical 0).
     * (MLD mode — including the S159 handoff — owns phys 0: the FLROM MR
     * with the boot stub at NOR+0; skip the mask-ROM stub.) */
    if (!getenv("MMCS_MLD")) {
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
    }

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
