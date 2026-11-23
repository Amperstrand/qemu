/*
 * MMCS fork qtest (peer-review M3 follow-up, 2026-11-23): the 2DG
 * display-list engine + DU-system contract (hw/sh4/mmcs.c, S155/S158
 * decode; env MMCS_2DG=1).
 *
 * 2DG @0xFFE80000 (32-bit only):
 *   +0x00/+0x04/+0x08 read 0 (never busy, no error, idle);
 *   +0x48 DL base, +0x50/+0x5C plane surfaces, +0xC0 mode: latch + readback;
 *   +0x08 write 1 = KICK — fast-complete, then the DL walk + the textured
 *   blit: a Polygon4AA (0x82xxxxxx) carrying {tex ptr, w<<16|h} copies the
 *   texture into the latched plane surface A (RAM, byte-exact).
 * DU-system @0xFFF80000:
 *   +0x00 reads the G2dLibInit ID seed 0x00090280 (setup writes keep it);
 *   +0x0C plane mask latches; +0x08 = done bits — a KICK ORs the last
 *   plane mask (bits 0-5) into done.
 */
#include "qemu/osdep.h"
#include "libqtest-single.h"

#define DG      0xFFE80000
#define DU      0xFFF80000

/* SDRAM (phys 0x08000000 window) scratch — VA==PA under qtest */
#define TEX_PA  0x08001000
#define DL_PA   0x08001100
#define SURF_PA 0x08001200

static uint32_t r32(uint64_t addr)
{
    return qtest_readl(global_qtest, addr);
}

static void w32(uint64_t addr, uint32_t v)
{
    qtest_writel(global_qtest, addr, v);
}

static void start_2dg(void)
{
    /* the 2DG carve lives inside the MLD machine-init branch (the
     * MLD-splash lane's world): MMCS_MLD=1 arms it with the default
     * /dev/null stub+payload — no external files, CPU never runs under
     * qtest, only the device carve + register contract matter */
    setenv("MMCS_MLD", "1", 1);
    setenv("MMCS_2DG", "1", 1);
    qtest_start("-machine mmcs");
}

static void test_2dg_reset_and_latches(void)
{
    start_2dg();
    /* the fast-complete engine is never busy, never in error, idle */
    g_assert_cmphex(r32(DG + 0x00), ==, 0);
    g_assert_cmphex(r32(DG + 0x04), ==, 0);
    g_assert_cmphex(r32(DG + 0x08), ==, 0);
    /* the DL base / plane surfaces / mode latch and read back */
    w32(DG + 0x48, DL_PA);
    g_assert_cmphex(r32(DG + 0x48), ==, DL_PA);
    w32(DG + 0x50, SURF_PA);
    g_assert_cmphex(r32(DG + 0x50), ==, SURF_PA);
    w32(DG + 0x5C, SURF_PA + 0x1000);
    g_assert_cmphex(r32(DG + 0x5C), ==, SURF_PA + 0x1000);
    w32(DG + 0xC0, 0x00090280);
    g_assert_cmphex(r32(DG + 0xC0), ==, 0x00090280);
    qtest_end();
}

static void test_2dg_kick_completes_idle(void)
{
    start_2dg();
    w32(DG + 0x48, 0);            /* no DL: the kick completes quietly */
    w32(DG + 0x08, 1);
    g_assert_cmphex(r32(DG + 0x00), ==, 0);   /* still never busy */
    g_assert_cmphex(r32(DG + 0x08), ==, 0);   /* still idle */
    qtest_end();
}

static void test_2dg_textured_blit(void)
{
    start_2dg();
    /* a 2x2 RGB565 texture with a known pattern */
    w32(TEX_PA + 0, 0xF80007E0);          /* row0: red, green */
    w32(TEX_PA + 4, 0x001F0000);          /* row1: -, blue */

    /* display list: one textured Polygon4AA then the zero terminator
     * (word0 0x82xxxxxx, word1 texture ptr, word2 {w<<16|h}, word3 0,
     * then 4 vertex words + the sub-word tail — stride 9) */
    w32(DL_PA + 0x00, 0x82000001);
    w32(DL_PA + 0x04, TEX_PA);
    w32(DL_PA + 0x08, (2u << 16) | 2u);   /* {x=2, y=2} u16 pair */
    w32(DL_PA + 0x0c, 0);
    w32(DL_PA + 0x10, 0); w32(DL_PA + 0x14, 0);
    w32(DL_PA + 0x18, 0); w32(DL_PA + 0x1c, 0);
    w32(DL_PA + 0x20, 0);                 /* zero = end of list */

    /* the destination carries a marker the blit must overwrite */
    w32(SURF_PA + 0, 0xDEADBEEF);
    w32(SURF_PA + 4, 0xFEEDFACE);

    w32(DG + 0x50, SURF_PA);              /* latched plane surface A */
    w32(DG + 0x48, DL_PA);                /* DL base */
    w32(DG + 0x08, 1);                    /* KICK */

    /* the blit contract: the texture lands in surface A byte-exact */
    g_assert_cmphex(r32(SURF_PA + 0), ==, 0xF80007E0);
    g_assert_cmphex(r32(SURF_PA + 4), ==, 0x001F0000);
    qtest_end();
}

static void test_du_system_seed_and_done(void)
{
    start_2dg();
    /* the G2dLibInit ID gate reads the seed (and keeps it despite the
     * setup writes the driver makes) */
    g_assert_cmphex(r32(DU + 0x00), ==, 0x00090280);
    w32(DU + 0x00, 0x00000100);           /* a setup write */
    g_assert_cmphex(r32(DU + 0x00), ==, 0x00090280);   /* seed kept */

    /* the plane mask latches */
    w32(DU + 0x0C, 0x1F);
    g_assert_cmphex(r32(DU + 0x0C), ==, 0x1F);

    /* a KICK ORs the plane mask into the done bits (fast-complete) */
    g_assert_cmphex(r32(DU + 0x08), ==, 0);
    w32(DG + 0x48, 0);                    /* no DL */
    w32(DG + 0x08, 1);                    /* KICK */
    g_assert_cmphex(r32(DU + 0x08), ==, 0x1F);
    qtest_end();
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/mmcs/2dg/reset_and_latches", test_2dg_reset_and_latches);
    qtest_add_func("/mmcs/2dg/kick_completes_idle", test_2dg_kick_completes_idle);
    qtest_add_func("/mmcs/2dg/textured_blit", test_2dg_textured_blit);
    qtest_add_func("/mmcs/2dg/du_system_seed_and_done",
                   test_du_system_seed_and_done);
    return g_test_run();
}
