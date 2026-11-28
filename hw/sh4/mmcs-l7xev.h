/*
 * MMCS fork (device split lane, 2026-11-28 — peer review M2c, split #8):
 * the L7x/L84 event-delivery SCAN bodies' interface, extracted verbatim
 * from hw/sh4/mmcs.c (pure code motion, the minimal-cut shape: the scan
 * FUNCTIONS move; the state, the tick cadence counters, and the
 * mmcs_l16_boot_parse arms stay in mmcs.c — the rung's edit zones —
 * and are extern'd below per the pollsys register-file pattern).
 *
 * Implementation: hw/sh4/mmcs-l7xev.c. The l7xev qtest
 * (tests/qtest/mmcs-l7xev-test.c) exercises the moved scans end-to-end.
 */
#ifndef HW_SH4_MMCS_L7XEV_H
#define HW_SH4_MMCS_L7XEV_H

#include "qemu/osdep.h"

/* the shared L16 injection channel (owned by mmcs.c; the layout is the
 * pollsys law — field order frozen, the vmsd streams it positionally) */
#define MMCS_L16_MAX 8
struct mmcs_l16_ent {
    uint32_t evt_va;
    uint32_t stub_va;
    uint32_t evt_code;
    uint32_t slot_pa;
    int pending;
    /* L19: daemon-mode entries (MMCS_L19EV) — the wake-cadence engine
     * re-arms per pump iteration instead of a one-shot chain. */
    int daemon;
    int strikes;
    uint32_t ndeliv;
};
extern struct mmcs_l16_ent mmcs_l16_ents[MMCS_L16_MAX];

/* the v9 stub template (owned by mmcs.c's L54 family) — 16 bytes, the
 * layout the L54/L62/L72/L84 recipes write */
#define MMCS_L54_STUB_VA   0xBF00E600
#define MMCS_L54_SLOT_PA   0x0867A064   /* evt 0x320, idx 7 */
#define MMCS_L72_STUB_VA   0xBF00E400   /* KILLSTK-shared with L52 */
#define MMCS_L72_SLOT_PA   0x0867A05C   /* evt 0x2E0, idx 5 (L52-shared) */
extern uint8_t mmcs_l54_stub[189];

/* the per-daemon state (owned by mmcs.c; the arms + tick cadence live
 * there — the scans read armed/total/max and write key/stable) */
extern int mmcs_l84cr_armed;
extern uint32_t mmcs_l84cr_total;
extern uint32_t mmcs_l84cr_max_deliv;
extern int mmcs_l84sr_armed;
extern uint32_t mmcs_l84sr_total;
extern uint32_t mmcs_l84sr_key;
extern uint32_t mmcs_l84sr_stable;
extern uint32_t mmcs_l84sr_max_deliv;
extern int mmcs_l72_armed;
extern uint32_t mmcs_l72_total;
extern uint32_t mmcs_l72_key;
extern uint32_t mmcs_l72_stable;
extern uint32_t mmcs_l72_max_deliv;
extern int mmcs_l75ho_armed;
extern uint32_t mmcs_l75ho_total;
extern uint32_t mmcs_l75ho_key;
extern uint32_t mmcs_l75ho_max_deliv;
extern int mmcs_l76_armed;
extern uint32_t mmcs_l76_total;
extern uint32_t mmcs_l76_key;
extern uint32_t mmcs_l76_stable;
extern uint32_t mmcs_l76_max_deliv;
extern int mmcs_l77_armed;
extern uint32_t mmcs_l77_total;
extern uint32_t mmcs_l77_key;
extern uint32_t mmcs_l77_stable;
extern uint32_t mmcs_l77_max_deliv;
extern int mmcs_l78_armed;
extern uint32_t mmcs_l78_total;
extern uint32_t mmcs_l78_key;
extern uint32_t mmcs_l78_stable;
extern uint32_t mmcs_l78_max_deliv;
extern int mmcs_l79_armed;
extern uint32_t mmcs_l79_total;
extern uint32_t mmcs_l79_key;
extern uint32_t mmcs_l79_stable;
extern uint32_t mmcs_l79_max_deliv;
extern int mmcs_l73_armed;
extern uint32_t mmcs_l73_total;
extern uint32_t mmcs_l73_key;
extern uint32_t mmcs_l73_stable;
extern uint32_t mmcs_l73_max_deliv;
extern int mmcs_l74_armed;
extern uint32_t mmcs_l74_total;
extern uint32_t mmcs_l74_key;
extern uint32_t mmcs_l74_stable;
extern uint32_t mmcs_l74_max_deliv;
extern int mmcs_l74cr_armed;
extern uint32_t mmcs_l74cr_total;
extern uint32_t mmcs_l74cr_key;
extern uint32_t mmcs_l74cr_stable;
extern uint32_t mmcs_l74cr_max_deliv;
extern uint32_t mmcs_l84cr_rej[11];
extern int mmcs_l74cr_diag;
extern uint32_t mmcs_l75ho_stable;

/* the scan bodies (called from mmcs.c's mmcs_tick_deliver cadence
 * blocks — the tick-order comments there are load-bearing) */
void mmcs_l84cr_scan(void);
void mmcs_l84sr_scan(void);
void mmcs_l72_scan(void);
void mmcs_l75ho_scan(void);
void mmcs_l76_scan(void);
void mmcs_l77_scan(void);
void mmcs_l78_scan(void);
void mmcs_l79_scan(void);
void mmcs_l73_scan(void);
void mmcs_l74_scan(void);
void mmcs_l74cr_scan(void);

#endif /* HW_SH4_MMCS_L7XEV_H */
