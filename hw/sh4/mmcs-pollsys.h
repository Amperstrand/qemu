/*
 * MMCS fork (device split lane, 2026-11-25 — peer review M2c, split #4):
 * the polled syscon + PFC-USB register blocks, extracted verbatim from
 * hw/sh4/mmcs.c (pure code motion). The register files stay extern for
 * mmcs.c's MmcsSnap vmstate copies; the MMIO carves stay at their init
 * call sites.
 *
 * Implementation: hw/sh4/mmcs-pollsys.c. Decode history: S133 (the
 * 0xFF8040xx syscon window) + L26 (the PFC USB handshake).
 */
#ifndef HW_SH4_MMCS_POLLSYS_H
#define HW_SH4_MMCS_POLLSYS_H

#include "qemu/osdep.h"
#include "exec/memory.h"
#include "qemu/timer.h"

extern uint32_t syscon_c080[64];
extern uint32_t pfc_usb_st[4];

extern const MemoryRegionOps mmcs_syscon_c080_ops;
extern const MemoryRegionOps mmcs_pfc_usb_ops;

#endif /* HW_SH4_MMCS_POLLSYS_H */
