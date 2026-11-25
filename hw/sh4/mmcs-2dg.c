/*
 * MMCS fork (device split lane, 2026-11-25 — peer review M2c): the
 * SH7777 2D Graphic Accelerator + DU-system/DU-channel display engine,
 * extracted VERBATIM from hw/sh4/mmcs.c (pure code motion, zero behavior
 * change — the extraction was validated by tests/qtest/mmcs-2dg-test.c
 * and the byte-stability gates: golden / fidelity-quick / standing-combo).
 * History + decode: the S155/S158 MLD-splash lanes.
 *
 * The carve (mmcs_2dg_carve) creates the three MMIO windows
 * (0xFFE80000 + A7 alias, DU 0xFFF80000, DU-channel 0xFE540000) with
 * overlap priority 1 — it must run AFTER the sh7750/SCIF wiring in
 * mmcs.c's MLD path (it shadows the serial claim at 0xFFE80000).
 */
#include "qemu/osdep.h"
#include "hw/sh4/mmcs-2dg.h"
#include "exec/address-spaces.h"
#include "exec/cpu-common.h"

MemoryRegion *mmcs_sdram_mr;  /* for MMCS_2DG console retarget */

/* MMCS_2DG: re-point the live console at the presented surface (the
 * splash's DU scanout base — 2DG+0x50 plane surface or, for the
 * single-surface design, the DL's Poly4AA texture). Direct SDRAM
 * pointer into the RAM MR backing (phys < MMCS_SDRAM_BASE+size). */
hwaddr mmcs_2dg_last;   /* savestate lane: file-scope */
void mmcs_2dg_present_console(hwaddr pa)
{
    /* mmcs_2dg_last: hoisted to file scope (savestate lane — the
     * post_load console re-target must reset it) */
    if (!mmcs_con || pa == mmcs_2dg_last) {
        return;
    }
    if (pa < MMCS_SDRAM_BASE
        || pa + 800 * 480 * 2 > MMCS_SDRAM_BASE + MMCS_SDRAM_SIZE) {
        fprintf(stderr, "MMCS-2DG: presented surface %08x outside SDRAM "
                "- console not retargeted\n", (unsigned)pa);
        return;
    }
    if (!mmcs_sdram_mr) {
        return;
    }
    uint8_t *fb = memory_region_get_ram_ptr(mmcs_sdram_mr)
                  + (pa - MMCS_SDRAM_BASE);
    DisplaySurface *s = qemu_create_displaysurface_from(
        800, 480, PIXMAN_r5g6b5, 800 * 2, fb);
    dpy_gfx_replace_surface(mmcs_con, s);
    mmcs_2dg_last = pa;
    fprintf(stderr, "MMCS-2DG: console retargeted to presented surface "
            "phys %08x\n", (unsigned)pa);
}

/* ---- MMCS_2DG (MLD-splash lane, 2026-11-18): the SH7777 2D Graphic
 * Accelerator register window at 0xFFE80000 (0x1000) + the DU-system
 * register file at 0xFFF80000 (0x1000) + the DU channel regs at
 * 0xFE540000 (0x1000, logging/latch only) — the minimal splash model
 * per the 2DG research lane (corpus docs/lane-reports/
 * 2026-11-18-2dg-research.md §4), all semantics Verified from the MLD
 * disasm:
 *
 *   - every splash PIXEL is CPU-produced (DispLoadBitmap BMP->RGB565 +
 *     centering copy into the work surface) before the first 2DG write;
 *   - the 2DG window owns the DU plane-surface registers (+0x50/+0x5C
 *     = DuRendrStart's plane surface publish) and the display-list base
 *     (+0x48, RAM DL model, no FIFO);
 *   - the kick is 2DG+0x08=1 then 2DG+0x00=1 (after DU+0x0C =
 *     (1<<(plane-1))|0x800); completion is DU+0x08 bits 0-5 vs the
 *     armed mask 1<<(plane-1) (FUN_88937b0c, 500-unit timeout
 *     NON-FATAL); the G2dLibInit gate reads DU+0x00 with
 *     (v & 0x001103F0) == 0x00090280 and DU+0x04 with
 *     (v & 0x1F0FF1C0) == 0;
 *   - no IRQ in the loader path (the loader polls).
 *
 * The model: read-seeds + latches + kick fast-complete (done bits set
 * from the last DU+0x0C plane mask). No blit engine is modeled: for the
 * SINGLE-surface design (work surface == plane surface, §3.4) this is
 * pixel-complete; MMCS_FB capture retargets to the latched 2DG+0x50
 * surface A when armed. */
struct Mmcs2dgState mmcs_2dg;

/* Walk the display list at dl_base (RAM DL model — corpus 2DG research
 * lane §2.3): Wpr (0x18xxxxxx, skip pattern words), Lcofs (0x40xxxxxx),
 * Polygon4C (0x80xxxxxx: color + 3-4 coord words), the textured
 * Polygon4AA (0x82xxxxxx: word1 = texture source ptr, word2 = {w,h}
 * u16 pair, word3 = 0, 4 vertex words), Jump (0x28xxxxxx, word1 target
 * & 0x1ffffffc — stop when the target walks off the list tail). Live
 * decoded from the loader's own splash DL at 0x09832800. */
static void mmcs_2dg_walk_dl(uint32_t dl_base)
{
    uint32_t words[64];
    if (!dl_base) {
        return;
    }
    uint32_t pa = dl_base & 0x1FFFFFFF;
    cpu_physical_memory_read(pa, words, sizeof words);
    unsigned i = 0;
    while (i < 64) {
        uint32_t w0 = words[i];
        if ((w0 & 0xFE000000) == 0x82000000 && i + 8 < 64) {
            mmcs_2dg.tex = words[i + 1];
            mmcs_2dg.tex_w = words[i + 2] >> 16;   /* {x=w, y=h} u16 pair */
            mmcs_2dg.tex_h = words[i + 2] & 0xFFFF;
            fprintf(stderr, "MMCS-2DG: Poly4AA texture %08x %ux%u\n",
                    mmcs_2dg.tex, mmcs_2dg.tex_w, mmcs_2dg.tex_h);
            i += 9;
            continue;
        }
        if ((w0 & 0xFE000000) == 0x80000000) {
            i += 6;            /* Polygon4C: color + coords */
            continue;
        }
        if ((w0 & 0xFF000000) == 0x81000000) {
            i += 7;            /* Polygon4B */
            continue;
        }
        if ((w0 & 0xFF000000) == 0x18000000) {
            /* Wpr: word1 = patternNo<<16|first; pattern words follow
             * (count not in the DL — the builder appends; the observed
             * splash lists are 2 words each, next word not 0x18xx = a
             * new command boundary; scan forward to the next known
             * word0 class). */
            i += 2;
            while (i < 64) {
                uint32_t w = words[i];
                if ((w & 0xFE000000) == 0x80000000
                    || (w & 0xFE000000) == 0x82000000
                    || (w & 0xFF000000) == 0x81000000
                    || (w & 0xFF000000) == 0x40000000
                    || (w & 0xFF000000) == 0x18000000
                    || (w & 0xFF000000) == 0x28000000) {
                    break;
                }
                i++;
            }
            continue;
        }
        if ((w0 & 0xFF000000) == 0x40000000) {
            i += 2;            /* Lcofs */
            continue;
        }
        if ((w0 & 0xFF000000) == 0x28000000) {
            /* Jump: follow once (the splash tail jumps to the zero
             * terminator); stop on out-of-list/zero targets. */
            uint32_t t = words[i + 1] & 0x1FFFFFFC;
            if (t == (pa & ~3) || t >= (pa & ~3) + sizeof words || !t) {
                break;
            }
            uint32_t npa = t & 0x1FFFFFFF;
            if (npa == pa) {
                break;
            }
            cpu_physical_memory_read(npa, words, sizeof words);
            pa = npa;
            i = 0;
            continue;
        }
        break;                  /* unknown/zero = end of list */
    }
}

static uint64_t mmcs_2dg_read(void *opaque, hwaddr off, unsigned sz)
{
    switch (off) {
    case 0x00: return 0;            /* idle (never busy) */
    case 0x04: return 0;            /* no error (bit 2 clear) */
    case 0x08: return 0;            /* idle */
    case 0x48: return mmcs_2dg.dl_base;
    case 0x50: return mmcs_2dg.surf_a;
    case 0x5C: return mmcs_2dg.surf_b;
    case 0xC0: return mmcs_2dg.mode;
    }
    return 0;
}

static void mmcs_2dg_write(void *opaque, hwaddr off, uint64_t v, unsigned sz)
{
    switch (off) {
    case 0x48:
        mmcs_2dg.dl_base = v;
        break;
    case 0x50:
        mmcs_2dg.surf_a = v;
        if (mmcs_2dg.nlog++ < 64) {
            fprintf(stderr, "MMCS-2DG: plane surface A = %08llx\n",
                    (unsigned long long)v);
        }
        break;
    case 0x5C:
        mmcs_2dg.surf_b = v;
        if (mmcs_2dg.nlog++ < 64) {
            fprintf(stderr, "MMCS-2DG: plane surface B = %08llx\n",
                    (unsigned long long)v);
        }
        break;
    case 0xC0:
        mmcs_2dg.mode = v;
        break;
    case 0x08:
        if (v == 1) {
            /* KICK: fast-complete — done bits from the last DU+0x0C
             * plane mask (bits 0-4); the wait reads DU+0x08 & 0x3F.
             * Then the presentation: walk the DL for the textured
             * blit; single-surface design (plane surface 0) presents
             * the texture itself, two-surface copies it into the
             * latched plane surface A (1:1 — the splash dest rect is
             * full-screen). */
            mmcs_2dg.du_done |= (mmcs_2dg.du0c & 0x3F);
            mmcs_2dg_walk_dl(mmcs_2dg.dl_base);
            mmcs_2dg_present_console(mmcs_2dg.surf_a
                                     ? (mmcs_2dg.surf_a & 0x1FFFFFFF)
                                     : (mmcs_2dg.tex & 0x1FFFFFFF));
            if (mmcs_2dg.tex && mmcs_2dg.surf_a
                && mmcs_2dg.tex_w && mmcs_2dg.tex_w <= 2048
                && mmcs_2dg.tex_h <= 2048) {
                hwaddr sp = mmcs_2dg.surf_a & 0x1FFFFFFF;
                hwaddr tp = mmcs_2dg.tex & 0x1FFFFFFF;
                uint32_t row = mmcs_2dg.tex_w * 2;
                for (uint32_t y = 0; y < mmcs_2dg.tex_h; y++) {
                    uint8_t lbuf[4096];
                    uint32_t n = MIN(row, sizeof lbuf);
                    cpu_physical_memory_read(tp + (hwaddr)y * row,
                                             lbuf, n);
                    cpu_physical_memory_write(sp + (hwaddr)y * row,
                                              lbuf, n);
                }
                fprintf(stderr, "MMCS-2DG: blit %ux%u texture -> "
                        "surface A phys %08x\n", mmcs_2dg.tex_w,
                        mmcs_2dg.tex_h, (unsigned)sp);
            }
            if (mmcs_2dg.nlog++ < 64) {
                fprintf(stderr, "MMCS-2DG: KICK dl_base=%08x surf_a=%08x "
                        "surf_b=%08x mode=%08x du0c=%08x -> done=%08x "
                        "tex=%08x\n",
                        mmcs_2dg.dl_base, mmcs_2dg.surf_a, mmcs_2dg.surf_b,
                        mmcs_2dg.mode, mmcs_2dg.du0c, mmcs_2dg.du_done,
                        mmcs_2dg.tex);
            }
        }
        break;
    case 0x00:
        mmcs_2dg.ctl = v;
        break;
    default:
        if (mmcs_2dg.nlog++ < 32) {
            fprintf(stderr, "MMCS-2DG: write +%03llx = %08llx\n",
                    (unsigned long long)off, (unsigned long long)v);
        }
        break;
    }
}

static const MemoryRegionOps mmcs_2dg_ops = {
    .read = mmcs_2dg_read,
    .write = mmcs_2dg_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
};

static uint64_t mmcs_dusys_read(void *opaque, hwaddr off, unsigned sz)
{
    switch (off) {
    case 0x00: return mmcs_2dg.du00;    /* seed 0x00090280 (G2dLibInit) */
    case 0x04: return mmcs_2dg.du04;
    case 0x08: return mmcs_2dg.du_done;
    case 0x0C: return mmcs_2dg.du0c;
    case 0x18: return mmcs_2dg.du18;
    }
    return 0;
}

static void mmcs_dusys_write(void *opaque, hwaddr off, uint64_t v, unsigned sz)
{
    switch (off) {
    case 0x00:
        /* G2dLibInit seed stays (accept the setup writes 0/0x100) */
        if (mmcs_2dg.nlog++ < 64) {
            fprintf(stderr, "MMCS-2DG: DU+00 write %08llx (seed kept "
                    "%08x)\n", (unsigned long long)v, mmcs_2dg.du00);
        }
        return;
    case 0x0C:
        mmcs_2dg.du0c = v;
        break;
    case 0x18:
        mmcs_2dg.du18 = v;
        if (mmcs_2dg.nlog++ < 64) {
            fprintf(stderr, "MMCS-2DG: DU+18 plane-enable %08llx\n",
                    (unsigned long long)v);
        }
        break;
    case 0x40:
    case 0x48:
        if (mmcs_2dg.nlog++ < 64) {
            fprintf(stderr, "MMCS-2DG: DU+%02llx clip advance %08llx\n",
                    (unsigned long long)off, (unsigned long long)v);
        }
        return;
    }
}

static const MemoryRegionOps mmcs_dusys_ops = {
    .read = mmcs_dusys_read,
    .write = mmcs_dusys_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
};

static uint64_t mmcs_duch_read(void *opaque, hwaddr off, unsigned sz)
{
    return off < sizeof(mmcs_2dg.ch) ? mmcs_2dg.ch[off / 4] : 0;
}

static void mmcs_duch_write(void *opaque, hwaddr off, uint64_t v, unsigned sz)
{
    if (off < sizeof(mmcs_2dg.ch)) {
        mmcs_2dg.ch[off / 4] = v;
    }
    if ((off == 0x26 || off == 0x1C || off == 0x1E) && mmcs_2dg.nlog++ < 64) {
        fprintf(stderr, "MMCS-2DG: DU-channel +%02llx = %08llx "
                "(%s = %08x)\n", (unsigned long long)off,
                (unsigned long long)v,
                off == 0x26 ? "bpp" : "SA0R",
                mmcs_2dg.ch[off / 4]);
    }
}

static const MemoryRegionOps mmcs_duch_ops = {
    .read = mmcs_duch_read,
    .write = mmcs_duch_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
};

/* ---- the machine-init carve (called from mmcs.c's MLD path) ---------- */

void mmcs_2dg_carve(void)
{
            mmcs_2dg.armed = 1;
            mmcs_2dg.du00 = 0x00090280;   /* G2dLibInit ID gate */
            MemoryRegion *dg = g_new(MemoryRegion, 1);
            memory_region_init_io(dg, NULL, &mmcs_2dg_ops, NULL,
                                  "mld.2dg", 0x1000);
            memory_region_add_subregion_overlap(get_system_memory(),
                                                0xFFE80000, dg, 1);
            MemoryRegion *dga = g_new(MemoryRegion, 1);
            memory_region_init_alias(dga, NULL, "mld.2dg-a7", dg, 0, 0x1000);
            memory_region_add_subregion_overlap(get_system_memory(),
                                                0x1FE80000, dga, 1);
            MemoryRegion *du = g_new(MemoryRegion, 1);
            memory_region_init_io(du, NULL, &mmcs_dusys_ops, NULL,
                                  "mld.dusys", 0x1000);
            memory_region_add_subregion_overlap(get_system_memory(),
                                                0xFFF80000, du, 1);
            MemoryRegion *ch = g_new(MemoryRegion, 1);
            memory_region_init_io(ch, NULL, &mmcs_duch_ops, NULL,
                                  "mld.duch", 0x1000);
            memory_region_add_subregion_overlap(get_system_memory(),
                                                0xFE540000, ch, 1);
            fprintf(stderr, "MMCS: 2DG window 0xFFE80000 + DU-system "
                    "0xFFF80000 + DU-channel 0xFE540000 carved "
                    "(fast-complete model)\n");
}
