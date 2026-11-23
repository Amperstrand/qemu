/*
 * MMCS fork qtest (peer-review M3, 2026-11-23): the channel-flash blocks —
 * the AMD-family NOR protocol contract (hw/sh4/sh7777.c chanflash).
 *
 * Device under test: 5 x 128KB blocks at 0xF40000..0xFCFFFF, unconditional
 * at machine init. The Observed protocol (the unit's own driver traffic):
 *   write16 0x30 @ block base = erase confirm (block -> all 0xFF,
 *                                    autoselect cleared)
 *   write16 0x90 anywhere     = autoselect (reads +0 maker, +2 device,
 *                                    +4 block-protect)
 *   write16 0xF0 anywhere     = reset to read mode
 *   any other write           = program, AND into existing (NOR clears)
 * Reset content: erased 0xFF except the loader-written sigstruct at +0
 * (m[0]=0xffffffff, m[12]=0, m[13]=0xffffffff, m[14]=0, m[15]=0xffffffff,
 * m[23]=0 — 16-bit words at +0/+0x30/+0x34/+0x38/+0x3c/+0x5c).
 */
#include "qemu/osdep.h"
#include "libqtest-single.h"

#define CH0 0xF40000
#define CH4 0xFC0000

static uint16_t r16(uint64_t addr)
{
    return qtest_readw(global_qtest, addr);
}

static void w16(uint64_t addr, uint16_t v)
{
    qtest_writew(global_qtest, addr, v);
}

static void test_chanflash_reset_content(void)
{
    /* the loader-written sigstruct: erased word at +0, programmed zeros at
     * +0x30/+0x38, erased again at +0x34/+0x3c, zero at +0x5c */
    qtest_start("-machine mmcs");
    g_assert_cmphex(r16(CH0 + 0x00), ==, 0xffff);
    g_assert_cmphex(r16(CH0 + 0x30), ==, 0x0000);
    g_assert_cmphex(r16(CH0 + 0x34), ==, 0xffff);
    g_assert_cmphex(r16(CH0 + 0x38), ==, 0x0000);
    g_assert_cmphex(r16(CH0 + 0x3c), ==, 0xffff);
    g_assert_cmphex(r16(CH0 + 0x5c), ==, 0x0000);
    /* beyond the sigstruct: erased */
    g_assert_cmphex(r16(CH0 + 0x1000), ==, 0xffff);
    /* the last block carries the same shape */
    g_assert_cmphex(r16(CH4 + 0x00), ==, 0xffff);
    g_assert_cmphex(r16(CH4 + 0x30), ==, 0x0000);
    qtest_end();
}

static void test_chanflash_program_and(void)
{
    qtest_start("-machine mmcs");
    /* program: the value ANDs into erased 0xFF */
    w16(CH0 + 0x1000, 0xf0f0);
    g_assert_cmphex(r16(CH0 + 0x1000), ==, 0xf0f0);
    w16(CH0 + 0x1000, 0x0ff0);
    g_assert_cmphex(r16(CH0 + 0x1000), ==, 0x00f0); /* NOR clears bits only */
    /* blocks are independent */
    g_assert_cmphex(r16(CH4 + 0x1000), ==, 0xffff);
    w16(CH4 + 0x1000, 0x1234);
    g_assert_cmphex(r16(CH4 + 0x1000), ==, 0x1234);
    g_assert_cmphex(r16(CH0 + 0x1000), ==, 0x00f0);
    qtest_end();
}

static void test_chanflash_erase(void)
{
    qtest_start("-machine mmcs");
    w16(CH0 + 0x1000, 0x00f0);
    /* erase confirm at the block base */
    w16(CH0 + 0x00, 0x30);
    g_assert_cmphex(r16(CH0 + 0x1000), ==, 0xffff);
    /* the erase also wipes the sigstruct (+0 back to erased) and clears
     * any autoselect mode (the 0x30 write happened while in read mode) */
    g_assert_cmphex(r16(CH0 + 0x30), ==, 0xffff);
    qtest_end();
}

static void test_chanflash_autoselect(void)
{
    qtest_start("-machine mmcs");
    /* enter autoselect (any offset), read the ID window */
    w16(CH0 + 0x0aaa, 0x90);
    g_assert_cmphex(r16(CH0 + 0x00), ==, 0x0001); /* AMD maker */
    g_assert_cmphex(r16(CH0 + 0x02), ==, 0x227e); /* device (r2d mirror) */
    g_assert_cmphex(r16(CH0 + 0x04), ==, 0x0000); /* block protect */
    /* outside the ID window: array content */
    g_assert_cmphex(r16(CH0 + 0x30), ==, 0x0000);
    /* reset to read mode */
    w16(CH0 + 0x00, 0xf0);
    g_assert_cmphex(r16(CH0 + 0x00), ==, 0xffff);
    g_assert_cmphex(r16(CH0 + 0x02), ==, 0xffff);
    qtest_end();
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/mmcs/chanflash/reset_content", test_chanflash_reset_content);
    qtest_add_func("/mmcs/chanflash/program_and", test_chanflash_program_and);
    qtest_add_func("/mmcs/chanflash/erase", test_chanflash_erase);
    qtest_add_func("/mmcs/chanflash/autoselect", test_chanflash_autoselect);
    return g_test_run();
}
