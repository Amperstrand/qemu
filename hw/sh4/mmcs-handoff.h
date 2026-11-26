/*
 * MMCS fork (device split lane, 2026-11-26 — peer review M2c, split #7b):
 * the S159 MLD->OS handoff interface, extracted verbatim from
 * hw/sh4/mmcs.c (pure code motion). The MLD-branch init in mmcs.c
 * (requirements gate, FLROM capture, timer arming) stays at its call
 * sites, referencing the externs below; target/sh4/helper.c's local
 * extern of mmcs_p1_alias_enabled stays textually identical.
 */
#ifndef HW_SH4_MMCS_HANDOFF_H
#define HW_SH4_MMCS_HANDOFF_H

#include "qemu/osdep.h"
#include "hw/sh4/sh.h"
#include "exec/memory.h"

#define MMCS_ENTRY      0x908066b0   /* kernel entry from image first record */

/* the handoff state (written by mmcs.c's MLD init branch) */
extern SuperHCPU *mmcs_handoff_cpu;
extern int mmcs_handoff_hits, mmcs_handoff_fired;
extern int mmcs_p1_alias_enabled;

/* the timer callbacks (armed from mmcs.c's init branch) */
void mmcs_handoff_poll(void *opaque);
void mmcs_handoff_set_flrom(MemoryRegion *fr);
void mmcs_handoff_arm(SuperHCPU *cpu);
void mmcs_handoff_retire_flrom(void *opaque);

#endif /* HW_SH4_MMCS_HANDOFF_H */
