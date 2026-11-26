/*
 * MMCS fork (device split lane, 2026-11-25 — peer review M2c, split #4):
 * the machine's two polled register blocks — the syscon window
 * (MMCS_SYSCON @0xFF804000-class) and the L26 PFC USB handshake at
 * 0xFFE70800 — extracted VERBATIM from hw/sh4/mmcs.c (pure code motion,
 * zero behavior change; validated by the byte-stability gates).
 */
#include "qemu/osdep.h"
#include "hw/sh4/mmcs-pollsys.h"

uint32_t syscon_c080[64];
static uint64_t mmcs_syscon_c080_read(void *opaque, hwaddr addr, unsigned size)
{
    if (addr == 0xf4) {
        return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 16000000; /* ~62.5 Hz tick */
    }
    if (addr / 4 < 64) {
        return syscon_c080[addr / 4];
    }
    return 0;
}
static void mmcs_syscon_c080_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    if (addr / 4 < 64) {
        syscon_c080[addr / 4] = val;
    }
}
const MemoryRegionOps mmcs_syscon_c080_ops = {
    .read = mmcs_syscon_c080_read,
    .write = mmcs_syscon_c080_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4, .valid.max_access_size = 4,
};

/* MMCS fork (L26): the [UsbCommonInit] PFC USB handshake — the OTHER
 * polled register block the vendor kernel hits at boot.
 *
 * Decoded 2026-11-17 (L26 park walk): the kernel's USB common init
 * (nk.exe 0x908098c0-lane) writes the PFC USB mux config at
 * 0xFFE70804 (|= 1, then |= 3), then POLLS 0xFFE70808 for
 * (val & 0xC0000000) == 0xC0000000 with a 0x515900-try timeout;
 * on timeout it takes the error lane — the wide-string print
 * '//// [UsbCommonInit] register(USBST=0x%X) check error ////'
 * (ROM 0x90802750) — whose printer-thunk loop (0x90809b40 jsr +
 * 0x90809b48 lds.l @r15+,pr) was the KData-IST-stack ASCII caught
 * by the L26 bp probe, the serial '//\r\n' remnant, and the
 * return-to-garbage deaths that end the kernel launch cascade
 * before filesys's phase chain ever runs. On HW the USBST status
 * bits (+0x808 top two bits) come up once the port pins are muxed
 * (+0x804 low bits) — model exactly that: read-back storage for
 * the block, +0x808 reads OR ((stored+0x804 & 3) << 30).
 * Env MMCS_USBST=1, default off. */
uint32_t pfc_usb_st[4];
static uint64_t mmcs_pfc_usb_read(void *opaque, hwaddr addr, unsigned size)
{
    if (addr == 0x808) {
        return pfc_usb_st[2] | ((pfc_usb_st[1] & 3) << 30);
    }
    if (addr / 4 < 4) {
        return pfc_usb_st[addr / 4];
    }
    return 0;
}
static void mmcs_pfc_usb_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size)
{
    if (addr / 4 < 4) {
        pfc_usb_st[addr / 4] = (uint32_t)val;
    }
}
const MemoryRegionOps mmcs_pfc_usb_ops = {
    .read = mmcs_pfc_usb_read,
    .write = mmcs_pfc_usb_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4, .valid.max_access_size = 4,
};
