/*
 * MMCS fork (device split lane, 2026-11-26 — peer review M2c, split #6):
 * the framebuffer console (MMCS_FBCON=1, the live screen) + the
 * deterministic RAM-dump family (MMCS_DUMP / MMCS_FB / MMCS_FB_INTERVAL
 * PPM stream with the 2DG capture retarget / MMCS_FINDPAT /
 * MMCS_TLBDUMP / MMCS_POKE) — extracted VERBATIM from hw/sh4/mmcs.c
 * (pure code motion, zero behavior change; validated by the
 * byte-stability gates + the golden/splash pipelines that exercise the
 * moved capture path). The JITFIX block stayed in mmcs.c between the
 * two chunks.
 */
#include "qemu/osdep.h"
#include "hw/sh4/mmcs-fb.h"
#include "hw/sh4/mmcs-2dg.h"
#include "hw/sh4/mmcs-vintc.h"
#include "hw/sh4/sh.h"
#include "cpu.h"
#include "qemu/timer.h"
#include "exec/address-spaces.h"

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

void mmcs_fbcon_init(MemoryRegion *sdram_mr)
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




void mmcs_dump_ram(void *opaque)
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
