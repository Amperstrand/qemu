/*
 * MMCS fork (device split lane, 2026-11-26 — peer review M2c, split #6):
 * the framebuffer console + the RAM-dump/diagnostic machinery interface,
 * extracted verbatim from hw/sh4/mmcs.c (pure code motion). mmcs_con is
 * the declaration of record (mmcs-2dg.h points here); the console init
 * and the dump timer are armed from mmcs.c's init sites (env gates stay
 * there); the 2DG capture-retarget seam reads the 2DG model via
 * mmcs-2dg.h.
 *
 * Implementation: hw/sh4/mmcs-fb.c. Decode history: S110 (FBCON),
 * S158 (the 2DG capture retarget), the MLD result-word lane.
 */
#ifndef HW_SH4_MMCS_FB_H
#define HW_SH4_MMCS_FB_H

#include "qemu/osdep.h"
#include "ui/console.h"
#include "exec/memory.h"

extern QemuConsole *mmcs_con;            /* the live FBCON console */
void mmcs_fbcon_init(MemoryRegion *sdram_mr);
void mmcs_dump_ram(void *opaque);

/* owned by mmcs.c's PGOWN block; called from the dump census */
void mmcs_pgown_census(void);

#endif /* HW_SH4_MMCS_FB_H */
