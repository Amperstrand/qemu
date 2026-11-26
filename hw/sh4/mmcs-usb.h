/*
 * MMCS fork (device split lane, 2026-11-26 — peer review M2c, split #7a):
 * the USB OHCI setup interface, extracted verbatim from hw/sh4/mmcs.c
 * (pure code motion; the three env-gated init call sites stay there).
 */
#ifndef HW_SH4_MMCS_USB_H
#define HW_SH4_MMCS_USB_H

void mmcs_usb_setup(void);

#endif /* HW_SH4_MMCS_USB_H */
