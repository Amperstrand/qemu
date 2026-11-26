/*
 * MMCS fork (device split lane, 2026-11-25 — peer review M2c, split #3):
 * the vendor-INTC (vintc) interface, extracted verbatim from hw/sh4/mmcs.c
 * (pure code motion). The register file backs the MmcsSnap vmstate copies
 * in mmcs.c (externs below); the machine-init carve + the VINTC_EVT/IRQ
 * experiment arms stay at their call sites in mmcs.c.
 *
 * Implementation + the L18 access census: hw/sh4/mmcs-vintc.c.
 */
#ifndef HW_SH4_MMCS_VINTC_H
#define HW_SH4_MMCS_VINTC_H

#include "qemu/osdep.h"
#include "exec/memory.h"

/* the live register file + the experiment state (vmstate-copied in mmcs.c) */
extern uint32_t mmcs_vintc_regs[64];
extern uint32_t mmcs_vintc_evt_code;
extern qemu_irq mmcs_vintc_irl;        /* wired at the mmcs.c init site */

/* the MMIO ops + the periodic-injection experiment callbacks (armed from
 * mmcs.c's machine init) */
extern const MemoryRegionOps mmcs_vintc_ops;
void mmcs_vintc_evt_deliver(void *opaque);
void mmcs_vintc_pulse(void *opaque);

/* the L18 access census (env MMCS_VINTC_CENSUS=1; set at the mmcs.c arm) */
extern int mmcs_vi_census;
void mmcs_vi_note(int is_w, hwaddr off, uint32_t val);
void mmcs_vi_census_dump(void);
void mmcs_vi_census_tick(void *opaque);

#endif /* HW_SH4_MMCS_VINTC_H */
