/*
 * MMCS fork qtest (L82/S292): the ram4 P1/P0 bank contract
 * (hw/sh4/mmcs.c — the vendor's second SDRAM bank as the guest
 * sees it: phys 0x01000000-0x01FFFFFF, 16MB, env MMCS_RAM4_MB,
 * default 16, 0 disables). The L82/S252 decode: the ring-writer's
 * stores land at P0-identity VA 0x010f3471 — the bank must exist
 * and hold data; the 0-arm must drop (the unassigned-write class
 * the sh7750 log+drop handles).
 *
 * The fill-service half (MMCS_P0RING, the TLB-level virtual-mode
 * window) is not physical-addressable from qtest and is covered
 * by the census A/Bs instead (the S253 record: the 3360x class
 * eliminated live).
 */
#include "qemu/osdep.h"
#include "libqtest-single.h"

static uint32_t r32(uint64_t addr)
{
    return qtest_readl(global_qtest, addr);
}

static void w32(uint64_t addr, uint32_t v)
{
    qtest_writel(global_qtest, addr, v);
}

static void test_ram4_bank_storage(void)
{
    qtest_start("-machine mmcs");
    /* the bank's head, the ring-writer's target page, the last word */
    w32(0x01000000, 0x600df00d);
    g_assert_cmphex(r32(0x01000000), ==, 0x600df00d);
    w32(0x010f3471 & ~3u, 0x52534e47);              /* the tea page, aligned */
    g_assert_cmphex(r32(0x010f3471 & ~3u), ==, 0x52534e47);
    w32(0x01FFFFFC, 0x4c415354);
    g_assert_cmphex(r32(0x01FFFFFC), ==, 0x4c415354);
    qtest_quit(global_qtest);
}

static void test_ram4_default_on(void)
{
    /* no env set: the default 16MB arm — the bank is present */
    qtest_start("-machine mmcs");
    w32(0x01000000, 0xabcdef01);
    g_assert_cmphex(r32(0x01000000), ==, 0xabcdef01);
    qtest_quit(global_qtest);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/sh4/mmcs/ram4/bank_storage", test_ram4_bank_storage);
    qtest_add_func("/sh4/mmcs/ram4/default_on", test_ram4_default_on);
    return g_test_run();
}
