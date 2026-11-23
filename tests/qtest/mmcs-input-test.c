/*
 * MMCS fork qtest (peer-review M3, 2026-11-23): the SCIF1 Micon injector
 * contract (hw/sh4/mmcs-input.c) — env MMCS_INPUT=1.
 *
 * The contract under test is the FRAME BUILDER + RING ORDERING (the exact
 * bytes the guest's own receiver checks validate): every HMP verb must
 * produce, in order, the Verified SHORT sub-CPU frame
 *     LEN | cmd0 cmd1 | cdb | payload[LEN-6] | ETX(0x03) | CS
 * on the input SCIF's RX FIFO (SCIF1 @0xFFE41000; FRDR +0x14, FSR +0x10),
 * with CS = the additive byte sum of all preceding bytes incl. ETX.
 *
 * Drain protocol = the Micon loader's own (input_oracle.sh-proven): poll
 * FSR.RDF (bit1), pop FRDR, write FSR=0 to clear — the fork's live-RDF
 * semantics re-assert while FIFO count >= trigger, so multi-frame
 * sequences drain in order. The 16-byte FIFO forces the 1 ms ring pump
 * timer for frames > 16 bytes: virtual clock_step between polls.
 */
#include "qemu/osdep.h"
#include "libqtest-single.h"

#define SCIF1       0xFFE41000
#define SCSCR       0x08
#define SCFSR       0x10
#define SCFRDR      0x14
#define FSR_RDF     0x0002
#define SCSCR_RE    0x0010

#define ETX         0x03

/* the verified touch geometry: the identity-mapped 800x480 panel */
#define RES_X       800
#define RES_Y       480

static uint16_t r16(uint64_t addr)
{
    return qtest_readw(global_qtest, addr);
}

static void w16(uint64_t addr, uint16_t v)
{
    qtest_writew(global_qtest, addr, v);
}

/* pop one byte following the loader's protocol; steps the virtual clock
 * (the ring pump's 1 ms retry) while waiting for FIFO space to free */
static uint8_t pop_byte(void)
{
    int tries;
    for (tries = 0; tries < 200; tries++) {
        if (r16(SCIF1 + SCFSR) & FSR_RDF) {
            uint8_t b = r16(SCIF1 + SCFRDR) & 0xff;
            w16(SCIF1 + SCFSR, 0);          /* clear RDF; live-RDF re-arms */
            return b;
        }
        qtest_clock_step(global_qtest, 1000000);   /* 1 ms */
    }
    g_assert_not_reached();
}

static void drain_frame(uint8_t *out, int len)
{
    for (int i = 0; i < len; i++) {
        out[i] = pop_byte();
    }
}

/* build the expected SHORT frame for a payload and verify it on the FIFO */
static void expect_frame(const uint8_t *payload, int plen,
                         uint8_t cmd_hi, uint8_t cmd_lo, uint8_t cdb)
{
    uint8_t exp[3 + 247 + 2], got[3 + 247 + 2];
    unsigned cs = 0;
    int n = 0, len = plen + 6;

    exp[n++] = len;
    exp[n++] = cmd_hi;
    exp[n++] = cmd_lo;
    exp[n++] = cdb;
    memcpy(exp + n, payload, plen);
    n += plen;
    exp[n++] = ETX;
    for (int i = 0; i < n; i++) {
        cs += exp[i];
    }
    exp[n++] = cs & 0xff;

    drain_frame(got, n);
    for (int i = 0; i < n; i++) {
        if (got[i] != exp[i]) {
            g_test_message("frame byte %d: got %02x want %02x",
                           i, got[i], exp[i]);
            g_assert_cmpint(got[i], ==, exp[i]);
        }
    }
}

static void input_start(void)
{
    setenv("MMCS_INPUT", "1", 1);
    qtest_start("-machine mmcs");
    /* enable the SCIF receiver so the ring pump may inject */
    w16(SCIF1 + SCSCR, SCSCR_RE);
}

static void test_input_touch_down_frame(void)
{
    uint8_t pl[21];
    int n = 0;

    input_start();
    qtest_hmp(global_qtest, "mmcs_touch 400 240 down");

    pl[n++] = 0xEB;
    pl[n++] = RES_X & 0xff; pl[n++] = RES_X >> 8;       /* 800 LE = 20 03 */
    pl[n++] = RES_Y & 0xff; pl[n++] = RES_Y >> 8;       /* 480 LE = e0 01 */
    pl[n++] = 1;                                        /* count: one contact */
    memset(pl + n, 0, 9); n += 9;                       /* status[9] */
    pl[n++] = 400 & 0xff; pl[n++] = 400 >> 8;           /* x = 90 01 */
    pl[n++] = 240 & 0xff; pl[n++] = 240 >> 8;           /* y = f0 00 */
    pl[n++] = 1; pl[n++] = 1;
    g_assert_cmpint(n, ==, 21);

    expect_frame(pl, n, 0x59, 0x03, 0x00);   /* the default carrier cmd */
    qtest_end();
}

static void test_input_touch_up_frame(void)
{
    uint8_t pl[15];
    int n = 0;

    input_start();
    qtest_hmp(global_qtest, "mmcs_touch 400 240 up");

    /* pen-up: the count=0 deliverable empty record */
    pl[n++] = 0xEB;
    pl[n++] = RES_X & 0xff; pl[n++] = RES_X >> 8;
    pl[n++] = RES_Y & 0xff; pl[n++] = RES_Y >> 8;
    pl[n++] = 0;
    memset(pl + n, 0, 9); n += 9;
    g_assert_cmpint(n, ==, 15);

    expect_frame(pl, n, 0x59, 0x03, 0x00);
    qtest_end();
}

static void test_input_key_and_ordering(void)
{
    uint8_t down[4] = { 0xE2, 0x45, 0x00, 0x00 };   /* key 0x45, phase down */
    uint8_t up[4]   = { 0xE2, 0x45, 0x00, 0x01 };   /* phase up */

    input_start();
    /* two frames back-to-back: the ring must preserve the order */
    qtest_hmp(global_qtest, "mmcs_key 0x45 down");
    qtest_hmp(global_qtest, "mmcs_key 0x45 up");

    expect_frame(down, sizeof down, 0x59, 0x03, 0x00);
    expect_frame(up, sizeof up, 0x59, 0x03, 0x00);
    qtest_end();
}

static void test_input_reverse_gear_frame(void)
{
    uint8_t pl[1] = { 0x01 };       /* the default MMCS_INPUT_GEAR_R */

    input_start();
    qtest_hmp(global_qtest, "mmcs_reverse on");
    /* the S169 byte-exact wire form: 07 12 0F 00 01 03 cs on cmd 0x120F */
    expect_frame(pl, 1, 0x12, 0x0F, 0x00);
    qtest_end();
}

static void test_input_rejects_out_of_panel(void)
{
    char *rsp;

    input_start();
    rsp = qtest_hmp(global_qtest, "mmcs_touch 900 100 down");
    g_assert_nonnull(strstr(rsp, "outside the 800x480 panel"));
    g_free(rsp);
    /* no frame was built: the FIFO stays empty across a pump window */
    g_assert_cmphex(r16(SCIF1 + SCFSR) & FSR_RDF, ==, 0);
    qtest_clock_step(global_qtest, 3000000);
    g_assert_cmphex(r16(SCIF1 + SCFSR) & FSR_RDF, ==, 0);
    qtest_end();
}

static void test_input_info_verb(void)
{
    char *rsp;

    input_start();
    rsp = qtest_hmp(global_qtest, "mmcs_input_info");
    g_assert_nonnull(strstr(rsp, "SCIF1 @0xffe41000"));
    g_assert_nonnull(strstr(rsp, "cmd=5903"));
    g_free(rsp);
    qtest_end();
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/mmcs/input/touch_down_frame", test_input_touch_down_frame);
    qtest_add_func("/mmcs/input/touch_up_frame", test_input_touch_up_frame);
    qtest_add_func("/mmcs/input/key_and_ordering", test_input_key_and_ordering);
    qtest_add_func("/mmcs/input/reverse_gear_frame", test_input_reverse_gear_frame);
    qtest_add_func("/mmcs/input/rejects_out_of_panel", test_input_rejects_out_of_panel);
    qtest_add_func("/mmcs/input/info_verb", test_input_info_verb);
    return g_test_run();
}
