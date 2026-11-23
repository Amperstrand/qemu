/*
 * MMCS fork qtest (peer-review M3, 2026-11-23): the SH-Mobile/tmio SDHI
 * empty-slot model contract (hw/sh4/mmcs-sdhi.c) — SDHI0 @0xFFE4C000,
 * SDHI1 @0xFFE4D000, env MMCS_SDHI=1.
 *
 * The v1 contract (spec 2026-11-17-sdhi-device-spec.md §3):
 *   - power-on register defaults incl. the TMIO mask defaults 0x031d /
 *     0x837f and the ISR reset defaults 0x002A / 0x475F
 *   - INFO1 (card present, bit5) stays CLEAR: the empty slot
 *   - SOFT_RST release gate: commands ignored while held in reset
 *   - SD_CMD: CMD0 completes silently; any other index -> INFO2.CMDTIMEOUT
 *   - SD_CLK_CTRL bit8 SCLKEN: INFO2.SCLKDIVEN busy window, then clears
 *   - INFO1/2 are 0-to-clear; the present line is hardware-owned
 *   - the response file + VERSION are read-only
 */
#include "qemu/osdep.h"
#include "libqtest-single.h"

#define SDHI0 0xFFE4C000
#define SDHI1 0xFFE4D000

#define SD_CMD        0x00
#define SD_RSP10      0x0c
#define SD_INFO1      0x1c
#define SD_INFO2      0x1e
#define SD_INFO1_MASK 0x20
#define SD_INFO2_MASK 0x22
#define SD_CLK_CTRL   0x24
#define EXT_SDIO_MASK 0x42
#define EXTB_MASK     0xb2
#define SOFT_RST      0xe0
#define SD_VERSION    0xe2

#define INFO1_CRRESP   0x0001
#define INFO1_SIGSTATE 0x0020
#define INFO2_CMDTIMEOUT 0x0040
#define INFO2_SCLKDIVEN  0x2000

static uint16_t r16(uint64_t base, uint64_t off)
{
    return qtest_readw(global_qtest, base + off);
}

static void w16(uint64_t base, uint64_t off, uint16_t v)
{
    qtest_writew(global_qtest, base + off, v);
}

/* The SDHI creation gate (mmcs.c: "MMCS_SDHI (L35/Linux lane)") currently
 * sits INSIDE the MMCS_LINUX loader block, so MMCS_SDHI=1 alone does not
 * create the device outside that world. The gate hoist to top-level init
 * (2 lines, default-off => zero behavior change) is owned by the device
 * lane — mmcs.c carries its in-flight WIP, so this test must not edit it.
 * Until the hoist lands, these tests SKIP with this reason; the moment it
 * does, the same binary enforces the full contract unmodified. */
static bool sdhi_armed(void)
{
    /* VERSION reads the model's code (0x0001); an absent window reads 0 */
    return r16(SDHI0, SD_VERSION) == 0x0001;
}

#define SDHI_SKIP_IF_UNARMED() \
    do { \
        if (!sdhi_armed()) { \
            g_test_skip("SDHI creation gate nested under MMCS_LINUX " \
                        "(mmcs.c ~9849); hoist to top-level init " \
                        "(default-off, no behavior change) to arm " \
                        "device-level tests"); \
            return; \
        } \
    } while (0)

static void test_sdhi_poweron_defaults(void)
{
    setenv("MMCS_SDHI", "1", 1);
    qtest_start("-machine mmcs");
    SDHI_SKIP_IF_UNARMED();

    for (uint64_t base = SDHI0; base <= SDHI1; base += (SDHI1 - SDHI0)) {
        /* the SD unit powers up HELD in reset (SOFT_RST bit0 = 0) */
        g_assert_cmphex(r16(base, SOFT_RST), ==, 0x0000);
        /* the TMIO chip-reset mask defaults (kernel tmio_mmc mining) */
        g_assert_cmphex(r16(base, SD_INFO1_MASK), ==, 0x031d);
        g_assert_cmphex(r16(base, SD_INFO2_MASK), ==, 0x837f);
        /* the vendor ISR reset defaults */
        g_assert_cmphex(r16(base, EXT_SDIO_MASK), ==, 0x002a);
        g_assert_cmphex(r16(base, EXTB_MASK), ==, 0x475f);
        /* the empty slot: no card-present, no CRRESP */
        g_assert_cmphex(r16(base, SD_INFO1) & (INFO1_SIGSTATE | INFO1_CRRESP),
                        ==, 0);
        /* VERSION reads a code; nothing gates on it */
        g_assert_cmphex(r16(base, SD_VERSION), ==, 0x0001);
    }
    qtest_end();
}

static void test_sdhi_reset_release_and_cmd(void)
{
    setenv("MMCS_SDHI", "1", 1);
    qtest_start("-machine mmcs");
    SDHI_SKIP_IF_UNARMED();

    /* held in reset: command writes are ignored (no timeout raised) */
    w16(SDHI0, SD_CMD, 0x0041);
    g_assert_cmphex(r16(SDHI0, SD_INFO2) & INFO2_CMDTIMEOUT, ==, 0);

    /* release the SD unit */
    w16(SDHI0, SOFT_RST, 0x0001);
    g_assert_cmphex(r16(SDHI0, SOFT_RST), ==, 0x0001);

    /* CMD0 (index 0) completes silently in the empty-slot world */
    w16(SDHI0, SD_CMD, 0x0000);
    g_assert_cmphex(r16(SDHI0, SD_INFO2) & INFO2_CMDTIMEOUT, ==, 0);

    /* any other index without a card: CMDTIMEOUT, CMDBUS not left set */
    w16(SDHI0, SD_CMD, 0x0041);
    g_assert_cmphex(r16(SDHI0, SD_INFO2) & INFO2_CMDTIMEOUT, !=, 0);
    g_assert_cmphex(r16(SDHI0, SD_INFO2) & 0x4000, ==, 0);
    qtest_end();
}

static void test_sdhi_clock_divider_busy(void)
{
    setenv("MMCS_SDHI", "1", 1);
    qtest_start("-machine mmcs");
    SDHI_SKIP_IF_UNARMED();

    w16(SDHI0, SOFT_RST, 0x0001);
    /* a clock change with SCLKEN: divider-busy asserts ... */
    w16(SDHI0, SD_CLK_CTRL, 0x0100);
    g_assert_cmphex(r16(SDHI0, SD_INFO2) & INFO2_SCLKDIVEN, !=, 0);
    /* ... and clears after the deterministic window (virtual time) */
    qtest_clock_step(global_qtest, 200000);
    g_assert_cmphex(r16(SDHI0, SD_INFO2) & INFO2_SCLKDIVEN, ==, 0);

    /* turning the clock off cancels a pending window immediately */
    w16(SDHI0, SD_CLK_CTRL, 0x0100);
    g_assert_cmphex(r16(SDHI0, SD_INFO2) & INFO2_SCLKDIVEN, !=, 0);
    w16(SDHI0, SD_CLK_CTRL, 0x0000);
    g_assert_cmphex(r16(SDHI0, SD_INFO2) & INFO2_SCLKDIVEN, ==, 0);
    qtest_end();
}

static void test_sdhi_status_write_semantics(void)
{
    setenv("MMCS_SDHI", "1", 1);
    qtest_start("-machine mmcs");
    SDHI_SKIP_IF_UNARMED();
    w16(SDHI0, SOFT_RST, 0x0001);

    /* 0-to-clear: raising a timeout, then clearing exactly it */
    w16(SDHI0, SD_CMD, 0x0041);
    g_assert_cmphex(r16(SDHI0, SD_INFO2) & INFO2_CMDTIMEOUT, !=, 0);
    w16(SDHI0, SD_INFO2, ~INFO2_CMDTIMEOUT);
    g_assert_cmphex(r16(SDHI0, SD_INFO2) & INFO2_CMDTIMEOUT, ==, 0);

    /* the card-present line is hardware-owned: the empty slot ignores
     * guest attempts to raise SIGSTATE or CRRESP */
    w16(SDHI0, SD_INFO1, INFO1_SIGSTATE | INFO1_CRRESP);
    g_assert_cmphex(r16(SDHI0, SD_INFO1) &
                    (INFO1_SIGSTATE | INFO1_CRRESP), ==, 0);
    qtest_end();
}

static void test_sdhi_readonly_regions(void)
{
    setenv("MMCS_SDHI", "1", 1);
    qtest_start("-machine mmcs");
    SDHI_SKIP_IF_UNARMED();
    w16(SDHI0, SOFT_RST, 0x0001);

    /* the response file and VERSION ignore writes */
    w16(SDHI0, SD_RSP10, 0xdead);
    g_assert_cmphex(r16(SDHI0, SD_RSP10), ==, 0x0000);
    w16(SDHI0, SD_RSP10 + 2, 0xbeef);
    g_assert_cmphex(r16(SDHI0, SD_RSP10 + 2), ==, 0x0000);
    w16(SDHI0, SD_VERSION, 0xffff);
    g_assert_cmphex(r16(SDHI0, SD_VERSION), ==, 0x0001);
    qtest_end();
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/mmcs/sdhi/poweron_defaults", test_sdhi_poweron_defaults);
    qtest_add_func("/mmcs/sdhi/reset_release_and_cmd",
                   test_sdhi_reset_release_and_cmd);
    qtest_add_func("/mmcs/sdhi/clock_divider_busy",
                   test_sdhi_clock_divider_busy);
    qtest_add_func("/mmcs/sdhi/status_write_semantics",
                   test_sdhi_status_write_semantics);
    qtest_add_func("/mmcs/sdhi/readonly_regions",
                   test_sdhi_readonly_regions);
    return g_test_run();
}
