/*
 * QEMU USB CDC-ACM device — virtual COM port for transport testing
 *
 * Implements the USB Communications Device Class / Abstract Control Model
 * subclass with a chardev-backed data interface (bulk IN/OUT endpoints).
 * Used by the MMCS machine (MMCS_USB_DEV=usb-cdc-acm) as the guest-side
 * counterpart of a phone link: bytes the guest bulk-OUTs appear on the
 * chardev; bytes the host writes to the chardev are bulk-IN'd to the guest.
 *
 * Modeled on dev-serial.c (chardev flow) and dev-network.c (CDC class
 * descriptor layout). Full-speed only.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "hw/usb.h"
#include "migration/vmstate.h"
#include "desc.h"
#include "chardev/char-fe.h"
#include "chardev/char-socket.h"
#include "io/channel-socket.h"
#include "qemu/timer.h"
#include "qom/object.h"
#include "trace.h"

#define RECV_BUF 4096

/* CDC class-specific requests (bRequest values) */
#define USB_CDC_REQ_SET_LINE_CODING       0x20
#define USB_CDC_REQ_GET_LINE_CODING       0x21
#define USB_CDC_REQ_SET_CONTROL_LINE_STATE 0x22

/* CDC functional descriptor subtypes */
#define USB_CDC_HEADER_TYPE               0x00
#define USB_CDC_CALL_MANAGEMENT_TYPE      0x01
#define USB_CDC_ACM_TYPE                  0x02
#define USB_CDC_UNION_TYPE                0x06

struct USBCDCACMState {
    USBDevice dev;
    USBEndpoint *bulk_in;
    QEMUTimer *pull_timer;
    uint8_t recv_buf[RECV_BUF];
    uint16_t recv_ptr;
    uint16_t recv_used;
    uint8_t line_coding[7];      /* dwDTERate le32, bCharFormat, bParity, bDataBits */
    uint16_t ctrl_line_state;    /* DTR | RTS */
    CharBackend cs;
};

#define TYPE_USB_CDC_ACM "usb-cdc-acm"
OBJECT_DECLARE_SIMPLE_TYPE(USBCDCACMState, USB_CDC_ACM)

enum {
    STR_MANUFACTURER = 1,
    STR_PRODUCT,
    STR_SERIALNUMBER,
};

static const USBDescStrings desc_strings = {
    [STR_MANUFACTURER] = "QEMU",
    [STR_PRODUCT]      = "QEMU CDC-ACM Port",
    [STR_SERIALNUMBER] = "1",
};

static const USBDescIface desc_iface_cdc[] = {
    {
        /* CDC Control Interface */
        .bInterfaceNumber   = 0,
        .bNumEndpoints      = 1,
        .bInterfaceClass    = USB_CLASS_COMM,
        .bInterfaceSubClass = 2,    /* ACM subclass */
        .bInterfaceProtocol = 0,
        .ndesc              = 4,
        .descs = (USBDescOther[]) {
            {
                /* Header Descriptor */
                .data = (uint8_t[]) {
                    0x05,                   /* u8   bLength */
                    USB_DT_CS_INTERFACE,    /* u8   bDescriptorType */
                    USB_CDC_HEADER_TYPE,    /* u8   bDescriptorSubType */
                    0x10, 0x01,             /* le16 bcdCDC (1.10) */
                },
            },{
                /* Call Management Descriptor */
                .data = (uint8_t[]) {
                    0x05,                   /* u8   bLength */
                    USB_DT_CS_INTERFACE,
                    USB_CDC_CALL_MANAGEMENT_TYPE,
                    0x00,                   /* u8   bmCapabilities */
                    0x01,                   /* u8   bDataInterface */
                },
            },{
                /* ACM Descriptor */
                .data = (uint8_t[]) {
                    0x04,                   /* u8   bLength */
                    USB_DT_CS_INTERFACE,
                    USB_CDC_ACM_TYPE,
                    0x02,                   /* u8   bmCapabilities: line coding */
                },
            },{
                /* Union Descriptor */
                .data = (uint8_t[]) {
                    0x05,                   /* u8   bLength */
                    USB_DT_CS_INTERFACE,
                    USB_CDC_UNION_TYPE,
                    0x00,                   /* u8   bMasterInterface0 */
                    0x01,                   /* u8   bSlaveInterface0 */
                },
            },
        },
        .eps = (USBDescEndpoint[]) {
            {
                /* notification endpoint (unused: we never send notices) */
                .bEndpointAddress = USB_DIR_IN | 0x01,
                .bmAttributes     = USB_ENDPOINT_XFER_INT,
                .wMaxPacketSize   = 16,
                .bInterval        = 10,
            },
        },
    },{
        /* CDC Data Interface */
        .bInterfaceNumber   = 1,
        .bNumEndpoints      = 2,
        .bInterfaceClass    = USB_CLASS_CDC_DATA,
        .bInterfaceSubClass = 0,
        .bInterfaceProtocol = 0,
        .eps = (USBDescEndpoint[]) {
            {
                .bEndpointAddress = USB_DIR_OUT | 0x02,
                .bmAttributes     = USB_ENDPOINT_XFER_BULK,
                .wMaxPacketSize   = 64,
            },{
                .bEndpointAddress = USB_DIR_IN | 0x02,
                .bmAttributes     = USB_ENDPOINT_XFER_BULK,
                .wMaxPacketSize   = 64,
            },
        },
    },
};

static const USBDescDevice desc_device = {
    .bcdUSB             = 0x0110,
    .bMaxPacketSize0    = 64,     /* MLSIDK driver assumes 64 */
    .bNumConfigurations = 1,
    .confs = (USBDescConfig[]) {
        {
            .bNumInterfaces        = 2,
            .bConfigurationValue   = 1,
            .iConfiguration        = 0,
            .bmAttributes          = USB_CFG_ATT_ONE | USB_CFG_ATT_SELFPOWER,
            .bMaxPower             = 50,
            .nif                   = ARRAY_SIZE(desc_iface_cdc),
            .ifs                   = desc_iface_cdc,
        },
    },
};

static const USBDesc desc_cdc_acm = {
    .id = {
        .idVendor          = 0x0525,   /* NetChip (QEMU convention) */
        .idProduct         = 0xa4a7,   /* CDC-ACM */
        .bcdDevice         = 0x0100,
        .iManufacturer     = STR_MANUFACTURER,
        .iProduct          = STR_PRODUCT,
        .iSerialNumber     = STR_SERIALNUMBER,
    },
    .full = &desc_device,
    .str  = desc_strings,
};

static void usb_cdc_acm_handle_control(USBDevice *dev, USBPacket *p,
                                       int request, int value, int index,
                                       int length, uint8_t *data)
{
    USBCDCACMState *s = USB_CDC_ACM(dev);
    int ret;

    ret = usb_desc_handle_control(dev, p, request, value, index, length, data);
    if (ret >= 0) {
        return;
    }

    switch (request) {
    case ClassInterfaceOutRequest | USB_CDC_REQ_SET_LINE_CODING:
        if (length == 7) {
            memcpy(s->line_coding, data, 7);
            trace_usb_cdc_acm_line_coding(
                ldl_le_p(data), data[4], data[5], data[6]);
        }
        break;
    case ClassInterfaceRequest | USB_CDC_REQ_GET_LINE_CODING:
        if (length >= 7) {
            memcpy(data, s->line_coding, 7);
            p->actual_length = 7;
        }
        break;
    case ClassInterfaceOutRequest | USB_CDC_REQ_SET_CONTROL_LINE_STATE:
        s->ctrl_line_state = value;
        trace_usb_cdc_acm_ctrl_line(value);
        break;
    default:
        p->status = USB_RET_STALL;
        break;
    }
}

static void usb_cdc_acm_handle_data(USBDevice *dev, USBPacket *p)
{
    USBCDCACMState *s = USB_CDC_ACM(dev);
    uint8_t devep = p->ep->nr;
    struct iovec *iov;
    int i, len;

    switch (p->pid) {
    case USB_TOKEN_OUT:
        if (devep != 2) {
            goto fail;
        }
        for (i = 0; i < p->iov.niov; i++) {
            iov = p->iov.iov + i;
            qemu_chr_fe_write_all(&s->cs, iov->iov_base, iov->iov_len);
        }
        p->actual_length = p->iov.size;
        break;

    case USB_TOKEN_IN:
        if (devep == 1) {
            /* notification endpoint: nothing to report */
            p->status = USB_RET_NAK;
            break;
        }
        if (devep != 2) {
            goto fail;
        }
        if (s->recv_used == 0) {
            p->status = USB_RET_NAK;
            break;
        }
        len = MIN(p->iov.size, s->recv_used);
        /* ring-buffer drain (may wrap once) */
        {
            int first = MIN(len, RECV_BUF - s->recv_ptr);
            usb_packet_copy(p, s->recv_buf + s->recv_ptr, first);
            if (len > first) {
                usb_packet_copy(p, s->recv_buf, len - first);
            }
        }
        s->recv_ptr = (s->recv_ptr + len) % RECV_BUF;
        s->recv_used -= len;
        break;

    default:
    fail:
        p->status = USB_RET_STALL;
        break;
    }
}

static int usb_cdc_acm_can_read(void *opaque)
{
    USBCDCACMState *s = opaque;

    if (getenv("OHCI_DEBUG_DMA")) {
        fprintf(stderr, "CDC_ACM can_read attached=%d space=%d\n",
                s->dev.attached, RECV_BUF - s->recv_used);
    }
    if (!s->dev.attached) {
        return 0;
    }
    return RECV_BUF - s->recv_used;
}

static void usb_cdc_acm_read(void *opaque, const uint8_t *buf, int size)
{
    USBCDCACMState *s = opaque;
    int first, start;

    if (size > (RECV_BUF - s->recv_used)) {
        size = RECV_BUF - s->recv_used;
    }

    start = s->recv_ptr + s->recv_used;
    first = RECV_BUF - (start % RECV_BUF);
    if (first > size) {
        first = size;
    }
    memcpy(s->recv_buf + (start % RECV_BUF), buf, first);
    if (size > first) {
        memcpy(s->recv_buf, buf + first, size - first);
    }
    s->recv_used += size;

    if (getenv("OHCI_DEBUG_DMA")) {
        fprintf(stderr, "CDC_ACM read %d bytes, used=%d -> wakeup\n",
                size, s->recv_used);
    }
    usb_wakeup(s->bulk_in, 0);
}

/* Host-clock pull timer: the socket chardev's glib-watch dispatch proved
 * unreliable in this TCG setup (main loop runs at 2kHz, can_read polled
 * 1M+ times, the child watch attached, yet tcp_chr_read dispatched only
 * ~once per run). TEST-HARNESS WORKAROUND (layering violation, accepted
 * for this emulation-only device): drain the chardev's socket fd directly
 * with a nonblocking recv() every 10ms host time and feed the receive
 * ring through the same handler the push path uses. */
static void usb_cdc_acm_pull(void *opaque)
{
    USBCDCACMState *s = opaque;
    Chardev *chr = s->cs.chr;

    if (chr && OBJECT(chr)->class &&
        object_dynamic_cast(OBJECT(chr), TYPE_CHARDEV_SOCKET)) {
        SocketChardev *sch = SOCKET_CHARDEV(chr);
        if (sch->ioc && sch->state == TCP_CHARDEV_STATE_CONNECTED) {
            QIOChannelSocket *sioc = QIO_CHANNEL_SOCKET(sch->ioc);
            int fd = sioc->fd;
            uint8_t buf[512];
            int n = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
            if (n > 0) {
                int space = RECV_BUF - s->recv_used;
                if (n > space) n = space;
                if (n > 0) {
                    usb_cdc_acm_read(s, buf, n);
                }
            }
        }
    }
    if (getenv("OHCI_DEBUG_DMA")) {
        static unsigned long pf;
        if (!(++pf % 1000)) {
            fprintf(stderr, "CDC_PULL x%lu\n", pf);
        }
    }
    timer_mod(s->pull_timer, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + 10);
}

static void usb_cdc_acm_event(void *opaque, QEMUChrEvent event)
{
    USBCDCACMState *s = opaque;

    switch (event) {
    case CHR_EVENT_OPENED:
        /* re-kick the chardev read handlers (dev-serial pattern: without
         * this the socket-chardev read watch is not armed for the FE) */
        qemu_chr_fe_accept_input(&s->cs);
        break;
    case CHR_EVENT_CLOSED:
    case CHR_EVENT_BREAK:
    default:
        break;
    }
}

static void usb_cdc_acm_realize(USBDevice *dev, Error **errp)
{
    USBCDCACMState *s = USB_CDC_ACM(dev);

    usb_desc_create_serial(dev);
    usb_desc_init(dev);

    if (!qemu_chr_fe_backend_connected(&s->cs)) {
        error_setg(errp, "chardev property not set");
        return;
    }
    qemu_chr_fe_set_handlers(&s->cs, usb_cdc_acm_can_read,
                             usb_cdc_acm_read, usb_cdc_acm_event,
                             NULL, s, NULL, true);
    s->pull_timer = timer_new_ms(QEMU_CLOCK_REALTIME, usb_cdc_acm_pull, s);
    timer_mod(s->pull_timer, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + 10);
    s->bulk_in = usb_ep_get(dev, USB_TOKEN_IN, 2);
}

static void usb_cdc_acm_unrealize(USBDevice *dev)
{
    USBCDCACMState *s = USB_CDC_ACM(dev);

    qemu_chr_fe_deinit(&s->cs, false);
}

static void usb_cdc_acm_handle_reset(USBDevice *dev)
{
    USBCDCACMState *s = USB_CDC_ACM(dev);

    s->recv_ptr = 0;
    s->recv_used = 0;
    /* 115200 8N1 */
    stl_le_p(s->line_coding, 115200);
    s->line_coding[4] = 0;
    s->line_coding[5] = 0;
    s->line_coding[6] = 8;
    s->ctrl_line_state = 0;
}

static const VMStateDescription vmstate_usb_cdc_acm = {
    .name = "usb-cdc-acm",
    .unmigratable = 1,
};

static Property cdc_acm_properties[] = {
    DEFINE_PROP_CHR("chardev", USBCDCACMState, cs),
    DEFINE_PROP_END_OF_LIST(),
};

static void usb_cdc_acm_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    USBDeviceClass *uc = USB_DEVICE_CLASS(klass);

    uc->realize        = usb_cdc_acm_realize;
    uc->unrealize      = usb_cdc_acm_unrealize;
    uc->handle_reset   = usb_cdc_acm_handle_reset;
    uc->handle_control = usb_cdc_acm_handle_control;
    uc->handle_data    = usb_cdc_acm_handle_data;
    uc->product_desc   = "QEMU CDC-ACM";
    uc->usb_desc       = &desc_cdc_acm;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);
    device_class_set_props(dc, cdc_acm_properties);
    dc->vmsd = &vmstate_usb_cdc_acm;
}

static const TypeInfo cdc_acm_info = {
    .name          = TYPE_USB_CDC_ACM,
    .parent        = TYPE_USB_DEVICE,
    .instance_size = sizeof(USBCDCACMState),
    .class_init    = usb_cdc_acm_class_init,
};

static void usb_cdc_acm_register_types(void)
{
    type_register_static(&cdc_acm_info);
}

type_init(usb_cdc_acm_register_types)
