/*
 * MMCS fork qtest (fleet-coordination unit, 2026-11-25): the L76-L79
 * event-delivery KNOB family contracts (hw/sh4/mmcs.c mmcs_l7x scans —
 * the coordinator's ask: the boot gates only exercise default-off, so
 * the knob paths were unguarded while the split lane moves code around
 * them).
 *
 * Pattern: every daemon scans GUEST RAM on the 1 ms tick chain (armed by
 * MMCS_TICK=1; delay forced to 1 ms) — under qtest the CPU never runs:
 * fixture TCBs/KData cells are written via MMIO, virtual time advances
 * with clock_step past the 2-cadence stability window, and the DELIVERY
 * (a guest-RAM write) is read back. Shapes per the lane reports
 * (L76/S227, L77/S228, L78/S229, L79/S230 — the guard fields cited in
 * the scan sources).
 */
#include "qemu/osdep.h"
#include "libqtest-single.h"

/* KData cells (phys) */
#define PCUR   0x08679894
#define KD84   0x08679884          /* cNest byte at +1 */
#define CNEST  0x08679885
#define KD88   0x08679888          /* dwKCRes */
#define PRUN   0x0867EFA0
#define PICK   0x0867EFA4
#define BAND   0x0867EFA8

/* fixture TCBs (VA-0x80000000 == PA; the kernel-arena window) */
#define TCB_A_VA 0x88700000u       /* pCurTh */
#define TCB_A    0x08700000u
#define TCB_B_VA 0x88710000u
#define TCB_B    0x08710000u
#define CRIT_VA  0x88720000u
#define CRIT     0x08720000u
#define POWN_VA  0x88730000u
#define POWN     0x08730000u

/* the L78/L79 TCB arena (RAM3, default 16 MB at phys 0x10000000) */
#define ARENA   0x10680000u
#define AR0_VA  0x90680000u
#define AR1_VA  0x90681000u        /* pCurTh for L79 */
#define AR2_VA  0x90682000u        /* obj */
#define AR3_VA  0x90683000u        /* the parked owner thread */
#define AR4_VA  0x90684000u        /* the dying runner */
#define NODE_VA 0x8867EAA0u
#define NODE    0x0867EAA0u

static void w32(uint64_t pa, uint32_t v)
{
    qtest_writel(global_qtest, pa, v);
}

static uint32_t r32(uint64_t pa)
{
    return qtest_readl(global_qtest, pa);
}

static void knob_start(const char *knob)
{
    setenv(knob, "1", 1);
    /* the L7x arms live inside mmcs_l16_boot_parse — the family gate
     * needs one L16-family env + the KILLSTK stub-page provider + the
     * tick chain (the standing combos always carry these) */
    setenv("MMCS_KILLSTK", "1", 1);
    setenv("MMCS_L26EV", "1", 1);        /* the family gate (its own
                                            daemon scans a different
                                            shape: our fixtures don't
                                            match it) */
    setenv("MMCS_TICK", "1", 1);
    setenv("MMCS_TICK_DELAY", "1", 1);   /* default 12000ms — bypass */
    setenv("MMCS_TICK_EVT", "0", 1);     /* silent ticks */
    qtest_start("-machine mmcs");
}

/* past the 2-cadence stability window (default cadence 500 ms) */
static void settle(void)
{
    qtest_clock_step(global_qtest, 2600000000LL);
}

/* ---- L76/S227: the equal-priority starvation re-arm ------------------- */

static void fixture_l76(void)
{
    w32(PCUR, TCB_A_VA);
    w32(PRUN, TCB_B_VA);
    w32(PICK, 0);
    w32(KD84, 0);                        /* cNest byte == 0 */
    /* pCurTh: running-ish, prio 0xfb */
    w32(TCB_A + 0x0C, 0x00000008);
    w32(TCB_A + 0x40, 0x0000fb00);
    /* band head: RUNNABLE, EQUAL priority (the starvation shape) */
    w32(TCB_B + 0x0C, 0x00000001);
    w32(TCB_B + 0x40, 0x0000fb00);
}

static void test_l76_starvation_rearm(void)
{
    knob_start("MMCS_L76EV");
    fixture_l76();
    settle();
    /* DELIVERY: cNest [0x88679885] := 1 — the vendor KCall-return gate */
    g_assert_cmphex(qtest_readb(global_qtest, CNEST), ==, 1);
    qtest_end();
}

static void test_l76_negative_without_env(void)
{
    /* envs accumulate within the process: clear every L7x knob so the
     * ONLY variable is the knob under test */
    {
        const char *ks[] = {"MMCS_L76EV", "MMCS_L77EV", "MMCS_L78EV",
                            "MMCS_L79EV", NULL};
        for (int i = 0; ks[i]; i++) {
            unsetenv(ks[i]);
        }
    }
    setenv("MMCS_KILLSTK", "1", 1);
    setenv("MMCS_L26EV", "1", 1);
    setenv("MMCS_TICK", "1", 1);
    setenv("MMCS_TICK_DELAY", "1", 1);
    setenv("MMCS_TICK_EVT", "0", 1);
    qtest_start("-machine mmcs");
    fixture_l76();
    settle();
    /* L7x knob off: the shape is ignored, cNest untouched */
    g_assert_cmphex(qtest_readb(global_qtest, CNEST), ==, 0);
    qtest_end();
}

/* ---- L77/S228: the kill-path API-lock cleanup release ------------------ */

static void fixture_l77(void)
{
    w32(PCUR, TCB_A_VA);
    /* the dying thread: exception code + DYING bit + a crit ownership */
    w32(TCB_A + 0x0C, 0x02000008);       /* st16: bit3 DYING */
    w32(TCB_A + 0x38, 0xC0000005);       /* the death code */
    w32(TCB_A + 0x3C, 0x005c0003);       /* hTh */
    /* the API-lock cell: pre = the crit VA (the scan window-checks it;
     * delivery writes 0 here) */
    w32(TCB_A + 0x164, CRIT_VA);
    /* the crit object: the stale waiter mark + the owner pair */
    qtest_writew(global_qtest, CRIT + 0x96, 0x8000);
    w32(CRIT + 0x98, POWN_VA);
    w32(POWN + 4, 0);                    /* != (hth|1): transfer false */
}

static void test_l77_killpath_cleanup(void)
{
    knob_start("MMCS_L77EV");
    fixture_l77();
    settle();
    /* DELIVERY: [pCurTh+0x164] := 0 (the vendor zero-path exit) */
    g_assert_cmphex(r32(TCB_A + 0x164), ==, 0);
    qtest_end();
}

/* ---- L78/S229: the lost-MakeRun requeue -------------------------------- */

static void fixture_l78(void)
{
    w32(PCUR, TCB_A_VA);                 /* any valid current thread */
    w32(PRUN, 0);
    w32(PICK, 0);
    /* the RUNNABLE self-linked arena thread at the wait face */
    w32(ARENA + 0x0C, 0x00000001);       /* RUNNABLE */
    w32(ARENA + 0xB4, 0x90837D00);       /* ctxpc: the wait face window */
    w32(ARENA + 0x74, 0);                /* satisfied verdict: clear */
    w32(ARENA + 0x154, AR0_VA);          /* self-linked */
    w32(ARENA + 0x158, AR0_VA);
    w32(ARENA + 0x41 - 1, 0x00001000);   /* prio byte [0x41] = 0x10 */
    /* band 2 (0x10>>3) head free */
    w32(BAND + 4 * (0x10 >> 3), 0);
}

static void test_l78_lost_makerun_requeue(void)
{
    knob_start("MMCS_L78EV");
    fixture_l78();
    settle();
    /* DELIVERY: the stock empty-queue head-path words */
    g_assert_cmphex(r32(PRUN), ==, AR0_VA);            /* pRunnable */
    g_assert_cmphex(r32(BAND + 4 * (0x10 >> 3)), ==, AR0_VA);
    g_assert_cmphex(r32(KD88), ==, 1);                 /* dwKCRes */
    g_assert_cmphex(r32(ARENA + 0x148), ==, 0);        /* queue-side link */
    qtest_end();
}

/* ---- L79/S230: the termination walker's dead-owner loop-exit ----------- */

static void fixture_l79(void)
{
    w32(PCUR, AR1_VA);                   /* pCurTh inside the arena */
    w32(PRUN, 0);
    w32(PICK, 0);
    /* the KData wait-node: obj + owner */
    w32(NODE + 8, AR2_VA);
    w32(NODE + 4, AR3_VA);
    w32(ARENA + 0x2000 + 0x98, NODE_VA); /* [obj+0x98] gate == node */
    /* the owner: a PARKED (BLOCKED) arena thread whose hth == owner */
    w32(ARENA + 0x3000 + 0x0C, 0x00000002);
    w32(ARENA + 0x3000 + 0x3C, AR3_VA);
    /* the runner: BLOCKED + DYING at the walker face, self-linked */
    w32(ARENA + 0x4000 + 0x0C, 0x0200000A);
    w32(ARENA + 0x4000 + 0xB4, 0x90840800); /* the walker window */
    w32(ARENA + 0x4000 + 0x3C, 0x00e80002); /* rhth (hth != owner) */
    w32(ARENA + 0x4000 + 0x154, AR4_VA);
    w32(ARENA + 0x4000 + 0x158, AR4_VA);
    w32(ARENA + 0x4000 + 0x41 - 1, 0x00002000); /* prio byte 0x20 */
    w32(BAND + 4 * (0x20 >> 3), 0);          /* band 4 head free */
}

static void test_l79_walker_dead_owner_exit(void)
{
    knob_start("MMCS_L79EV");
    fixture_l79();
    settle();
    /* DELIVERY: the loop-exit word + the requeue */
    g_assert_cmphex(r32(NODE + 4), ==, 0x00e80002);   /* owner := rhth */
    g_assert_cmphex(r32(ARENA + 0x4000 + 0x0C) & 3, ==, 1);  /* RUNNABLE */
    g_assert_cmphex(r32(ARENA + 0x4000 + 0x148), ==, 0);
    g_assert_cmphex(r32(PRUN), ==, AR4_VA);
    g_assert_cmphex(r32(BAND + 4 * (0x20 >> 3)), ==, AR4_VA);
    g_assert_cmphex(r32(KD88), ==, 1);
    qtest_end();
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    /* the negative runs FIRST: no knob env was ever set in this
     * process — the only variable is the knob itself */
    qtest_add_func("/mmcs/l7xev/l76_negative_without_env",
                   test_l76_negative_without_env);
    qtest_add_func("/mmcs/l7xev/l76_starvation_rearm", test_l76_starvation_rearm);
    qtest_add_func("/mmcs/l7xev/l77_killpath_cleanup", test_l77_killpath_cleanup);
    qtest_add_func("/mmcs/l7xev/l78_lost_makerun_requeue",
                   test_l78_lost_makerun_requeue);
    qtest_add_func("/mmcs/l7xev/l79_walker_dead_owner_exit",
                   test_l79_walker_dead_owner_exit);
    return g_test_run();
}
