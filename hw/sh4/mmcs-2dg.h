/*
 * MMCS fork (device split lane, 2026-11-25 — peer review M2c): the
 * 2DG/DU-system model's interface, extracted verbatim from hw/sh4/mmcs.c
 * (pure code motion; the vmstate struct member order is FROZEN — the
 * MmcsSnap embed streams it positionally).
 *
 * Model + implementation: hw/sh4/mmcs-2dg.c. Consumers: mmcs.c (the
 * machine init carve call, the FB capture retarget, the savestate
 * embed/copies, the post_load console re-target).
 */
#ifndef HW_SH4_MMCS_2DG_H
#define HW_SH4_MMCS_2DG_H

#include "qemu/osdep.h"
#include "ui/console.h"
#include "exec/memory.h"

/* moved from mmcs.c (both files use them via this include) */
#define MMCS_SDRAM_BASE 0x08000000
#define MMCS_SDRAM_SIZE 0x8800000  /* 0x08000000..0x10800000: kernel RAM 0x88600000-0x90700000 (ROMHDR) + margin */

struct Mmcs2dgState {
    int armed;
    uint32_t dl_base, surf_a, surf_b, mode, ctl;
    uint32_t du00, du04, du_done, du0c, du18;
    uint32_t ch[0x400];
    /* DL walk (kick-time): the Polygon4AA that carries the splash */
    uint32_t tex, tex_w, tex_h;
    int nlog;
};

/* the live model state (vmstate-embedded in mmcs.c's MmcsSnap) */
extern struct Mmcs2dgState mmcs_2dg;
extern hwaddr mmcs_2dg_last;
extern MemoryRegion *mmcs_sdram_mr;   /* assigned by mmcs.c's mmcs_init */
/* mmcs_con: declared in hw/sh4/mmcs-fb.h (the FBCON block's home) */

void mmcs_2dg_present_console(hwaddr pa);
void mmcs_2dg_carve(void);            /* the MMCS_2DG machine-init carve */

#endif /* HW_SH4_MMCS_2DG_H */
