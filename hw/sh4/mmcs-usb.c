/*
 * MMCS fork (device split lane, 2026-11-26 — peer review M2c, split #7a):
 * the USB OHCI at the SH7777's on-chip base (S70 register map, env-gated
 * MMCS_USB) — extracted VERBATIM from hw/sh4/mmcs.c (pure code motion,
 * zero behavior change; validated by the byte-stability gates + the MLD
 * acceptance path).
 */
#include "qemu/osdep.h"
#include "hw/sh4/mmcs-usb.h"
#include "hw/qdev-core.h"
#include "hw/sysbus.h"
#include "qapi/error.h"
#include "hw/qdev-properties.h"
#include "hw/irq.h"
#include "chardev/char.h"


/* USB OHCI at the SH7777's on-chip base (S70 register map, env-gated
 * via MMCS_USB for A/B testing). qemu's stock sysbus-ohci model provides
 * real OHCI register semantics for MLSIDK USB driver development. Called
 * from BOTH boot paths (full OS boot and MMCS_MLD payload mode). */
void mmcs_usb_setup(void)
{
    if (!getenv("MMCS_USB")) {
        return;
    }
    DeviceState *ohci = qdev_new("sysbus-ohci");
    qdev_prop_set_uint32(ohci, "num-ports", 2);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(ohci), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(ohci), 0, 0xFFE70400);
    /* IRQ: the SH7777 OHCI sysintr 53-class mapping is Unknown; route to a
     * sink IRQ for now (polling driver, no guest IRQ needed yet). */
    qemu_irq ohci_irq = qemu_allocate_irq(
        (void (*)(void *, int, int))qemu_set_irq, NULL, 0);
    sysbus_connect_irq(SYS_BUS_DEVICE(ohci), 0, ohci_irq);
    fprintf(stderr, "MMCS: USB OHCI at 0xFFE70400 (env-gated)\n");

    /* Optional attached device for enumeration testing: the OHCI's USB bus
     * is created here (machine init), too late for -device CLI resolution,
     * so attach programmatically. MMCS_USB_DEV names the guest-visible USB
     * device (default: usb-storage). */
    const char *usb_dev = getenv("MMCS_USB_DEV");
    if (!usb_dev) {
        usb_dev = "usb-kbd";   /* self-contained HID: no drive/net backend */
    }
    /* the OHCI's USB bus is a child bus of the controller device (the
     * controller itself is NOT a USBDevice — do not USB_DEVICE() cast it) */
    BusState *usb_bus = qdev_get_child_bus(ohci, "usb-bus");
    if (!usb_bus) {
        /* fall back to the first child bus if unnamed */
        usb_bus = QLIST_FIRST(&ohci->child_bus);
    }
    assert(usb_bus);
    /* usb-cdc-acm takes a "chardev" property; the backend is created via
     * CLI: -chardev socket,id=mlsdkusb,path=...,server=on,wait=off and
     * looked up by that fixed id. */
    DeviceState *udev = qdev_new(usb_dev);
    if (strcmp(usb_dev, "usb-cdc-acm") == 0 || strcmp(usb_dev, "usb-serial") == 0) {
        Chardev *chr = qemu_chr_find("mlsdkusb");
        if (chr) {
            qdev_prop_set_chr(udev, "chardev", chr);
        } else {
            fprintf(stderr, "MMCS: usb-cdc-acm: no chardev id 'mlsdkusb' "
                    "(-chardev socket,id=mlsdkusb,...)\n");
        }
    }
    qdev_realize_and_unref(udev, usb_bus, &error_fatal);
    fprintf(stderr, "MMCS: USB device '%s' attached to port 1\n", usb_dev);
}
