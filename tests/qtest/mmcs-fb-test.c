/*
 * MMCS fork qtest (device split #6's contract — the family rule: every
 * moved device model lands with its test): the FBCON console + the
 * MMCS_FB / MMCS_DUMP PPM emission machinery (hw/sh4/mmcs-fb.c).
 *
 * Under qtest the CPU never runs, so the framebuffer carries no guest
 * paint — the CONTRACT is the emission + format layer: the dump timer
 * (virtual-time armed by MMCS_DUMP) writes fb-NNN.ppm files of the
 * machine's 800x480 RGB565 surface, and the FBCON console block arms
 * under its env without touching the default world.
 */
#include "qemu/osdep.h"
#include "libqtest-single.h"

#define FB_DIR "/tmp/mmcs-fb-qtest"

static void test_fb_ppm_emission(void)
{
    setenv("MMCS_FB", FB_DIR "/fb", 1);  /* base: files land as fb-NNN.ppm */
    setenv("MMCS_FB_INTERVAL", "3", 1);
    setenv("MMCS_DUMP", "1", 1);
    qtest_start("-machine mmcs");
    /* advance virtual time past the dump arm + one capture */
    qtest_clock_step(global_qtest, 3000000000LL);
    {
        int rc = system("test -s " FB_DIR "/fb-000.ppm && "
                        "head -2 " FB_DIR "/fb-000.ppm | "
                        "grep -q 'P6' && "
                        "sed -n 2p " FB_DIR "/fb-000.ppm | "
                        "grep -q '800 480'");
        g_assert_cmpint(rc, ==, 0);
    }
    qtest_end();
}

static void test_fbcon_env_gate_armed(void)
{
    setenv("MMCS_FBCON", "1", 1);
    qtest_start("-machine mmcs");
    /* the console block arms under the env; the machine stays operable
     * (the MMIO layer answers a probe) — the ops are host-side only */
    g_assert_cmphex(qtest_readl(global_qtest, 0x08679810), !=, 0xdeadbeef);
    qtest_end();
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    if (system("rm -rf " FB_DIR " && mkdir -p " FB_DIR)) {
        return 1;
    }
    qtest_add_func("/mmcs/fb/ppm_emission", test_fb_ppm_emission);
    qtest_add_func("/mmcs/fb/fbcon_env_gate_armed", test_fbcon_env_gate_armed);
    return g_test_run();
}
