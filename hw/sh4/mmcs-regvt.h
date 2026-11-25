/*
 * MMCS fork (device split lane, 2026-11-25 — peer review M2c, split #2):
 * the REGVT registry-virtualization interface, extracted verbatim from
 * hw/sh4/mmcs.c (pure code motion). The hive ("the fdf IS the hive":
 * S103/S149) backs the kernel-side registry API-set cell dispatch from
 * target/sh4/helper.c (trapa#0x73 FSVT-cluster + the L29v2 cell-fault
 * hook) — those call sites and their local prototypes stay textually
 * identical (this header mirrors them verbatim; switching helper.c to
 * include this header is a follow-up, not part of the motion).
 *
 * Implementation + the "mmcs/regvt" vmstate: hw/sh4/mmcs-regvt.c.
 */
#ifndef HW_SH4_MMCS_REGVT_H
#define HW_SH4_MMCS_REGVT_H

#include "qemu/osdep.h"
#include "exec/memory.h"

typedef struct CPUState CPUState;

/* called from mmcs.c's machine-init env gate */
void mmcs_regvt_load(const char *path);

/* moved from mmcs.c (both TUs use them) */
#define MMCS_FSVT_PAGE   0x1F020000u
#define MMCS_FSVT_P1     0x9F020000u
#define MMCS_FSVT_STUB   (MMCS_FSVT_P1 + 0xF00u)

/* the SRVT manifest accessors (owned by mmcs.c) */
extern uint8_t *mmcs_srvt_blob;
const void *mmcs_srvt_find(uint32_t tag);
hwaddr mmcs_rom_pa(uint32_t va);

/* vmstate hook (the "mmcs/regvt" vmsd stays private to the .c) */
void mmcs_regvt_vmstate_register(void);

#endif /* HW_SH4_MMCS_REGVT_H */
