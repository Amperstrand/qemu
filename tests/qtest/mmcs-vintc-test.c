/*
 * MMCS fork qtest (peer-review M3 part 3, 2026-11-23): the vendor-INTC
 * register-file contract (hw/sh4/mmcs.c mmcs_vintc_ops) — a 64KB window
 * at 0xF4000000 (unconditional at machine init) whose first 256 bytes
 * (64 x u32) are live storage; the decode-critical detail is the DROP:
 * the kernel's 0xF4001000/0xF4003000 data-table references and the
 * loader's zero-sweeps land in the dead part of the window and must
 * never alias the live block (S134/L17: the live controller block sits
 * at struct base 0xF4007F48 + 0xB8).
 */
#include "qemu/osdep.h"
#include "libqtest-single.h"

#define VINTC 0xF4000000
#define LIVE_SZ 256

static uint32_t r32(uint64_t addr)
{
    return qtest_readl(global_qtest, addr);
}

static void w32(uint64_t addr, uint32_t v)
{
    qtest_writel(global_qtest, addr, v);
}

static void test_vintc_live_block_storage(void)
{
    qtest_start("-machine mmcs");
    /* the live 64-word block: reset reads zero, writes stick, sub-word
     * access works at byte granularity */
    g_assert_cmphex(r32(VINTC + 0x00), ==, 0);
    g_assert_cmphex(r32(VINTC + 0xB8), ==, 0);      /* the live INTC face */
    w32(VINTC + 0xB8, 0xdeadbeef);
    g_assert_cmphex(r32(VINTC + 0xB8), ==, 0xdeadbeef);
    w32(VINTC + 0xFC, 0x12345678);                  /* last live word */
    g_assert_cmphex(r32(VINTC + 0xFC), ==, 0x12345678);
    qtest_writew(global_qtest, VINTC + 0x40, 0xBEEF);
    g_assert_cmphex(qtest_readw(global_qtest, VINTC + 0x40), ==, 0xBEEF);
    qtest_writeb(global_qtest, VINTC + 0x41, 0x55);
    g_assert_cmphex(qtest_readw(global_qtest, VINTC + 0x40), ==, 0x55EF);
    /* independent words do not alias */
    g_assert_cmphex(r32(VINTC + 0xB8), ==, 0xdeadbeef);
    qtest_end();
}

static void test_vintc_dead_window_drops(void)
{
    qtest_start("-machine mmcs");
    /* beyond the live block: writes never store, reads return zero —
     * the kernel's 0xF4001000/0xF4003000 sweeps and the window tail are
     * sink-only (the S73 4.3M zero-writes class) */
    w32(VINTC + 0x1000, 0xfeedface);
    g_assert_cmphex(r32(VINTC + 0x1000), ==, 0);
    w32(VINTC + 0x3000, 0x0badf00d);
    g_assert_cmphex(r32(VINTC + 0x3000), ==, 0);
    w32(VINTC + 0x10000 - 4, 0xffffffff);
    g_assert_cmphex(r32(VINTC + 0x10000 - 4), ==, 0);
    /* and the dead writes never disturbed the live block */
    g_assert_cmphex(r32(VINTC + 0x00), ==, 0);
    qtest_end();
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/mmcs/vintc/live_block_storage", test_vintc_live_block_storage);
    qtest_add_func("/mmcs/vintc/dead_window_drops", test_vintc_dead_window_drops);
    return g_test_run();
}
