/*
 * MMCS fork (device split lane, 2026-11-26 — peer review M2c, split #5):
 * the channel-flash blocks interface, extracted verbatim from
 * hw/sh4/sh7777.c (pure code motion — the sh7777 file is cold vs the
 * rung's mmcs.c streak). mmcs.c's machine init calls mmcs_chanflash_init()
 * at its existing site.
 */
#ifndef HW_SH4_MMCS_CHANFLASH_H
#define HW_SH4_MMCS_CHANFLASH_H

#include "qemu/osdep.h"
#include "exec/memory.h"

/* mmcs_chanflash_init() is declared in hw/sh4/sh7777.h (the original
 * declaration moved with the family's home) */
#include "hw/sh4/sh7777.h"

#endif /* HW_SH4_MMCS_CHANFLASH_H */
