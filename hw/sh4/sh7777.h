#ifndef HW_SH4_SH7777_H
#define HW_SH4_SH7777_H
/* SH7777-class peripherals for the MMCS E12 machine: CMT/DMA block at
 * 0xFFC08000, INTC banks at 0xFFC4xxxx, CPG (PLL-lock status) at
 * 0xFFE70000. Implemented in hw/sh4/sh7777.c. */
#include "hw/irq.h"
void sh7777_init(qemu_irq cpu_irq);
void mmcs_chanflash_init(void);
/* MMCS fork (L35/Linux lane): drafted SDHI0/1 host-controller model
 * (car-research emul-drafts/mmcs-sdhi.c; env MMCS_SDHI, default off) */
void mmcs_sdhi_init(void);
/* MMCS fork (input lane, 2026-11-19): the SCIF1 Micon injector
 * (hw/sh4/mmcs-input.c; env MMCS_INPUT, default off) */
void mmcs_input_init(void);
#endif
