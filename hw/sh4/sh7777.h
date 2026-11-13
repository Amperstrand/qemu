#ifndef HW_SH4_SH7777_H
#define HW_SH4_SH7777_H
/* SH7777-class peripherals for the MMCS E12 machine: CMT/DMA block at
 * 0xFFC08000, INTC banks at 0xFFC4xxxx, CPG (PLL-lock status) at
 * 0xFFE70000. Implemented in hw/sh4/sh7777.c. */
#include "hw/irq.h"
void sh7777_init(qemu_irq cpu_irq);
void mmcs_chanflash_init(void);
#endif
