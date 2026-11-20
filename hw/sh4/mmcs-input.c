/*
 * MMCS fork (input lane, 2026-11-19): the SCIF1 Micon injector —
 * interactive input for the emulated head unit.
 *
 * DECODE BASIS (car-research spec 2026-11-18-input-touch-buttons-spec.md
 * + S169 reverse-camera + S170 vehicle-signal matrix; frame builders
 * cross-checked against scripts/virtual_vehicle/micon_frame.py whose
 * frames round-trip the guest's own checks):
 *
 *  - The unit has NO local touch controller (no ADS7843/SPI/I2C/ADC
 *    touch block, no HARDWARE\DEVICEMAP\TOUCH registry key, no touch
 *    driver among the 41 BuiltIn DLLs — S160 §1.1). The 800x480 panel
 *    and the hard buttons are scanned by the SUB-CPU (Micon) and
 *    delivered as messages on the sub-CPU link: SCIF1 @ 0xFFE41000
 *    (SUBCPU_SCIF.dll "SUB2:", ch1 hard-coded; the MLD loader's own
 *    channel table (ch-0x1c0)*0x1000 pins the same base).
 *
 *  - Wire frame (SHORT, both links, Verified): LEN:u8 | cmd0 | cmd1 |
 *    cdb | payload[LEN-6] | ETX(0x03) | CS:u8 — LEN = payload_len+6
 *    (window 4..0xFD), CS = additive byte sum of all preceding frame
 *    bytes incl. ETX.
 *
 *  - Touch tag 0xEB packet (the S170-corrected layout: NINE status
 *    bytes, contacts at data[15]): EB | resX:u16LE | resY:u16LE |
 *    count:u8 | status[9] | count x {x:u16LE, y:u16LE, u8 a, u8 b};
 *    receiver gates (NEventWatcher FUN_0007d304): len-1 > 13,
 *    len-1 >= count*6+14, resX/resY != 0 (else ConvertToGraphicsXY
 *    drops the event). Reporting resX=800/resY=480 makes the guest's
 *    rational raw->graphics map IDENTITY — mouse pixel == panel point.
 *    count==0 is a deliverable empty record (pen-up encoding Unknown;
 *    the S160 §5 open row — count=0 chosen for v1).
 *
 *  - Buttons: tags 0xe1..0xea on the same link (NRmtCtl* key queue).
 *    Key CODE VALUES are Unknown (S160 §2.3) — the injector takes raw
 *    codes. v1 rides tag 0xE2 {key:u16LE, u8} with the third byte
 *    carrying the phase (0=down/1=up; the field's true semantics =
 *    the "modifier" byte per the decompile — Unknown, this is the
 *    documented pinning vehicle).
 *
 *  - Reverse gear (S169 Verified): cmd 0x120F = NSUBCPU_CMD_ID_
 *    TRANSMISSION, 1-byte gear record -> NSensorDeviceSubCpuShiftPos
 *    -> NCarSigInfoEvent.shiftR -> HMIManager ModeRRCamera preemption.
 *    Wire frame documented byte-exact: 07 12 0F 00 <u8 gear> 03 <cs>.
 *    The gear byte VALUES are Unknown (S169 §5 row 1) — env-tunable.
 *
 *  - The private NSUB cmd id that carries the 0xe1..0xeb input tags is
 *    the standing open decode (0x59xx page prime suspect; S170 §5) —
 *    MMCS_INPUT_CMD (default 0x5903, the dry-run's documented
 *    placeholder; the MLD loader oracle consumes any well-formed
 *    frame regardless of cmd).
 *
 * LIVE ORACLE RESULT (the MLD loader park, this lane): every injected
 * frame class drains through the loader's own SCIF byte protocol —
 * trace-proven SCFRDR pops of the exact frame bytes in order, the
 * loader's per-byte FSR/SPTR clear protocol, and its link ACK (TX
 * 0x15 mid-frame; baseline boots never pop one byte). The receive-
 * error RETRY cycle persists by CONTENT: the loader's directed-message
 * handshake awaits specific response cmds through its BLD state layer
 * (expected table {0131/08, 0212/10, 0404/20} decoded this lane) =
 * the specced sub-CPU-responder lane, out of scope here. Framing
 * variants swept live at this gate (CS window excluding LEN; LEN
 * excluding itself): NO loader behavior change — the corpus-Verified
 * default stays.
 *
 * Also fixed this lane (hw/char/sh_serial.c): SCFSR.RDF is a LIVE
 * status on silicon (re-asserts while FIFO count >= trigger); the
 * stock model latched it at push time only, stranding FIFO data
 * behind the loader's post-pop RDF clear (live-caught: injected 7-byte
 * frame drained exactly one byte before the fix, all bytes after).
 *
 * Design: model the LINK, not a chip (S160 §3.0) — the guest runs its
 * real SUBCPU_SCIF driver / loader subcpu engine / NSUB parser /
 * ConvertToGraphicsXY. Message-level injection inherits the sub-CPU's
 * sampling/debounce/pressure filtering as a black box; the only gates
 * the injector must satisfy are the decoded receiver checks above.
 *
 * Env (default OFF — the A/B rule; the default boot never creates the
 * SCIF at 0xFFE41000 and is byte-identical):
 *   MMCS_INPUT=1          arm the injector (SCIF1 + input handler)
 *   MMCS_INPUT_TRACE=1    log every built frame (hex) to stderr
 *   MMCS_INPUT_CMD=0xNNNN carrier cmd for touch/key tags (default 5903)
 *   MMCS_INPUT_EVT=0xNNN  RXI stopgap: inject vendor-INTC EVT on every
 *                         RX IRQ edge through the proven mmcs_inject_evt
 *                         (EVT = 0x200 + id*0x20, the S83 formula; the
 *                         true SCIF1 IRQ id is the S131-page open decode)
 *   MMCS_INPUT_GEAR_R / MMCS_INPUT_GEAR_OFF   the 0x120F gear bytes for
 *                         mmcs_reverse on/off (enum Unknown — S169; dry
 *                         run used 0x01)
 *   MMCS_INPUT_RATE_MS   drag keep-sample cadence (default 25, the S160
 *                         donor-observable report-rate default)
 *   MMCS_INPUT_JITTER    move suppression in px (default 2)
 *
 * HMP (the ux_drive.py verbs):
 *   mmcs_touch x y down|up|tap [ms]     tap hold default 80ms
 *   mmcs_swipe x1 y1 x2 y2 [ms] [steps]
 *   mmcs_key <0xNN|dec> down|up|press [ms]
 *   mmcs_reverse on|off
 *   mmcs_input_info
 */

#include "qemu/osdep.h"
#include "hw/sh4/sh.h"
#include "hw/sh4/sh7777.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/qdev-core.h"
#include "hw/qdev-properties.h"
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qemu/bswap.h"
#include "qemu/timer.h"
#include "qemu/cutils.h"
#include "monitor/hmp.h"
#include "monitor/monitor.h"
#include "ui/console.h"
#include "ui/input.h"

#define MMCS_INPUT_SCIF_BASE   0xFFE41000

/* wire constants (Verified framing) */
#define MMCS_IN_ETX            0x03
#define MMCS_IN_MAX_PAYLOAD    (0xFD - 6)       /* 247 B SHORT ceiling */
#define MMCS_IN_TAG_TOUCH      0xEB
#define MMCS_IN_TAG_KEY_U16U8  0xE2
#define MMCS_IN_CMD_REVERSE    0x120F           /* NSUBCPU_CMD_ID_TRANSMISSION */

/* touch geometry: report the panel native resolution so the guest-side
 * ConvertToGraphicsXY rational map collapses to identity (S160 §1.4) */
#define MMCS_IN_RES_X          800
#define MMCS_IN_RES_Y          480

/* pending ring: frames wait here when the guest RX FIFO is full or the
 * receiver is not enabled yet (SCSCR.RE); a 1 ms virtual timer pumps. */
#define MMCS_IN_RING           1024

static DeviceState *mmcs_in_scif;
static QEMUTimer *mmcs_in_pump_timer;
static uint8_t mmcs_in_ring[MMCS_IN_RING];
static unsigned mmcs_in_rhead, mmcs_in_rtail, mmcs_in_rcnt;
static unsigned long mmcs_in_frames, mmcs_in_bytes, mmcs_in_drops;
static int mmcs_in_trace;
static unsigned mmcs_in_cmd = 0x5903;
static unsigned mmcs_in_gear_r = 1, mmcs_in_gear_off = 0;
static uint32_t mmcs_in_evt;

static int mmcs_in_env_on(const char *name)
{
    const char *v = getenv(name);
    return v && *v && strcmp(v, "0") != 0;
}

/* ---- RX pacing: feed the SCIF FIFO at the receiver's own pace -------- */

static void mmcs_in_pump_now(void);

static void mmcs_in_pump_cb(void *opaque)
{
    mmcs_in_pump_now();
}

static void mmcs_in_pump_now(void)
{
    while (mmcs_in_rcnt) {
        unsigned chunk = mmcs_in_rcnt;
        int n;

        if (mmcs_in_rtail + chunk > MMCS_IN_RING) {
            chunk = MMCS_IN_RING - mmcs_in_rtail;
        }
        n = sh_serial_rx_inject(mmcs_in_scif, &mmcs_in_ring[mmcs_in_rtail],
                                chunk);
        if (n <= 0) {
            if (!mmcs_in_pump_timer) {
                mmcs_in_pump_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                                  mmcs_in_pump_cb, NULL);
            }
            timer_mod(mmcs_in_pump_timer,
                      qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1);
            return;
        }
        mmcs_in_rtail = (mmcs_in_rtail + n) % MMCS_IN_RING;
        mmcs_in_rcnt -= n;
    }
}

/* ---- frame builder + builders (the Verified wire formats) ----------- */

/* one SHORT sub-CPU frame: LEN|cmd0|cmd1|cdb|payload|ETX|CS */
static void mmcs_in_frame(uint16_t cmd, uint8_t cdb,
                          const uint8_t *payload, int plen)
{
    uint8_t f[1 + 3 + MMCS_IN_MAX_PAYLOAD + 2];
    unsigned cs = 0;
    int n = 0, len = plen + 6, i;

    if (plen > MMCS_IN_MAX_PAYLOAD) {
        fprintf(stderr, "MMCS-INPUT: frame cmd=%04x payload %d too long\n",
                cmd, plen);
        return;
    }
    f[n++] = len;
    f[n++] = cmd >> 8;
    f[n++] = cmd & 0xff;
    f[n++] = cdb;
    memcpy(f + n, payload, plen);
    n += plen;
    f[n++] = MMCS_IN_ETX;
    for (i = 0; i < n; i++) {
        cs += f[i];
    }
    f[n++] = cs & 0xff;

    if (mmcs_in_rcnt + n > MMCS_IN_RING) {
        mmcs_in_drops++;
        fprintf(stderr, "MMCS-INPUT: ring full (%u/%u) — frame dropped\n",
                mmcs_in_rcnt, MMCS_IN_RING);
        return;
    }
    for (i = 0; i < n; i++) {
        mmcs_in_ring[mmcs_in_rhead] = f[i];
        mmcs_in_rhead = (mmcs_in_rhead + 1) % MMCS_IN_RING;
    }
    mmcs_in_rcnt += n;
    mmcs_in_frames++;
    mmcs_in_bytes += n;

    if (mmcs_in_trace) {
        fprintf(stderr, "MMCS-INPUT: frame cmd=%04x cdb=%02x plen=%d [",
                cmd, cdb, plen);
        for (i = 0; i < n; i++) {
            fprintf(stderr, "%02x", f[i]);
        }
        fprintf(stderr, "]\n");
    }
    mmcs_in_pump_now();
}

/* 0xEB touch sample: identity-mapped 800x480 panel coordinates.
 * down: N=1 contact {x,y,1,1} (the {a,b} fields Unknown — the dry-run
 * constants); up: the count=0 empty record. */
static void mmcs_input_touch(int x, int y, int down)
{
    uint8_t pl[15 + 6];
    int n = 0;

    x = MAX(0, MIN(x, MMCS_IN_RES_X - 1));
    y = MAX(0, MIN(y, MMCS_IN_RES_Y - 1));

    pl[n++] = MMCS_IN_TAG_TOUCH;
    stw_le_p(pl + n, MMCS_IN_RES_X); n += 2;
    stw_le_p(pl + n, MMCS_IN_RES_Y); n += 2;
    pl[n++] = down ? 1 : 0;
    memset(pl + n, 0, 9);                     /* status[9] (Unknown) */
    n += 9;
    if (down) {
        stw_le_p(pl + n, x); n += 2;
        stw_le_p(pl + n, y); n += 2;
        pl[n++] = 1;
        pl[n++] = 1;
    }
    mmcs_in_frame(mmcs_in_cmd, 0, pl, n);
}

/* 0xE2 key record {key:u16LE, u8 phase} (tag table S160 §1.4; the u8's
 * true semantics Unknown — the documented pinning vehicle) */
static void mmcs_input_key(int code, int down)
{
    uint8_t pl[4];

    pl[0] = MMCS_IN_TAG_KEY_U16U8;
    stw_le_p(pl + 1, code & 0xffff);
    pl[3] = down ? 0 : 1;
    mmcs_in_frame(mmcs_in_cmd, 0, pl, sizeof pl);
}

/* S169: the gear record — cmd 0x120F, 1-byte TRANSMISSION payload */
static void mmcs_input_reverse(int on)
{
    uint8_t pl[1];

    pl[0] = on ? mmcs_in_gear_r : mmcs_in_gear_off;
    mmcs_in_frame(MMCS_IN_CMD_REVERSE, 0, pl, sizeof pl);
}

/* ---- scripted sequences (tap / swipe / key press) -------------------- */

enum {
    MMCS_IN_SEQ_NONE = 0,
    MMCS_IN_SEQ_TAP,          /* step 0: touch down; step 1 (+hold): up   */
    MMCS_IN_SEQ_KEYPRESS,     /* step 0: key down;   step 1 (+hold): up   */
    MMCS_IN_SEQ_SWIPE,        /* steps 0..n-1: interpolated samples while
                                 held; final step: pen up                 */
};

static QEMUTimer *mmcs_in_seq_timer;
static int mmcs_in_seq_kind;
static int mmcs_in_seq_step, mmcs_in_seq_steps, mmcs_in_seq_dt;
static int mmcs_in_seq_x1, mmcs_in_seq_y1, mmcs_in_seq_x2, mmcs_in_seq_y2;
static int mmcs_in_seq_code;

static void mmcs_in_seq_cb(void *opaque)
{
    int k = mmcs_in_seq_step;

    switch (mmcs_in_seq_kind) {
    case MMCS_IN_SEQ_TAP:
        if (k == 0) {
            mmcs_input_touch(mmcs_in_seq_x1, mmcs_in_seq_y1, 1);
        } else {
            mmcs_input_touch(mmcs_in_seq_x1, mmcs_in_seq_y1, 0);
            mmcs_in_seq_kind = MMCS_IN_SEQ_NONE;
            return;
        }
        break;
    case MMCS_IN_SEQ_KEYPRESS:
        if (k == 0) {
            mmcs_input_key(mmcs_in_seq_code, 1);
        } else {
            mmcs_input_key(mmcs_in_seq_code, 0);
            mmcs_in_seq_kind = MMCS_IN_SEQ_NONE;
            return;
        }
        break;
    case MMCS_IN_SEQ_SWIPE:
        if (k < mmcs_in_seq_steps) {
            int x = mmcs_in_seq_x1 + (mmcs_in_seq_x2 - mmcs_in_seq_x1) * k
                    / (mmcs_in_seq_steps - 1);
            int y = mmcs_in_seq_y1 + (mmcs_in_seq_y2 - mmcs_in_seq_y1) * k
                    / (mmcs_in_seq_steps - 1);
            mmcs_input_touch(x, y, 1);
        } else {
            mmcs_input_touch(mmcs_in_seq_x2, mmcs_in_seq_y2, 0);
            mmcs_in_seq_kind = MMCS_IN_SEQ_NONE;
            return;
        }
        break;
    default:
        return;
    }
    mmcs_in_seq_step++;
    if (!mmcs_in_seq_timer) {
        mmcs_in_seq_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                         mmcs_in_seq_cb, NULL);
    }
    timer_mod(mmcs_in_seq_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + mmcs_in_seq_dt);
}

static void mmcs_in_seq_start(int kind, int steps, int step_ms,
                              int x1, int y1, int x2, int y2, int code)
{
    if (mmcs_in_seq_kind != MMCS_IN_SEQ_NONE) {
        return;    /* one scripted sequence at a time (HMP is serial) */
    }
    mmcs_in_seq_kind = kind;
    mmcs_in_seq_step = 0;
    mmcs_in_seq_steps = steps;
    mmcs_in_seq_dt = MAX(1, step_ms);
    mmcs_in_seq_x1 = x1;
    mmcs_in_seq_y1 = y1;
    mmcs_in_seq_x2 = x2;
    mmcs_in_seq_y2 = y2;
    mmcs_in_seq_code = code;
    mmcs_in_seq_cb(NULL);
}

/* ---- QEMU input-core wiring (VNC/SDL mouse = finger, keys = buttons) - */

/* round-to-nearest inverse of the input core's ABS scaling: VNC sends
 * console pixel p, the core floors value = p*32767/res (ui/input.c
 * qemu_input_queue_abs), so pixel = round(value*res/32767) recovers p
 * EXACTLY (double-flooring without this skews every coordinate by
 * ~1px: live-caught 400->399, 300->299). */
static int mmcs_in_abs_to_pixel(int value, int res)
{
    int p = (int)(((int64_t)value * res + 16383) / 32767);

    return MAX(0, MIN(p, res - 1));
}

static QemuInputHandlerState *mmcs_in_ihs;
static int mmcs_in_absx = -1, mmcs_in_absy = -1;
static int mmcs_in_btn, mmcs_in_pen;
static int mmcs_in_lastx, mmcs_in_lasty;
static int mmcs_in_rate_ms = 25, mmcs_in_jitter = 2;
static QEMUTimer *mmcs_in_rate_timer;

static void mmcs_in_rate_cb(void *opaque)
{
    if (mmcs_in_pen) {
        mmcs_input_touch(mmcs_in_lastx, mmcs_in_lasty, 1);
        timer_mod(mmcs_in_rate_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + mmcs_in_rate_ms);
    }
}

/* absolute pointer + LEFT button = the pen; KEY events = hard buttons
 * (code = the QKeyCode index stand-in until the donor table is pinned). */
static void mmcs_in_input_event(DeviceState *dev, QemuConsole *src,
                                InputEvent *evt)
{
    switch (evt->type) {
    case INPUT_EVENT_KIND_ABS:
        if (evt->u.abs.data->axis == INPUT_AXIS_X) {
            mmcs_in_absx = mmcs_in_abs_to_pixel(evt->u.abs.data->value,
                                                MMCS_IN_RES_X);
        } else if (evt->u.abs.data->axis == INPUT_AXIS_Y) {
            mmcs_in_absy = mmcs_in_abs_to_pixel(evt->u.abs.data->value,
                                                MMCS_IN_RES_Y);
        }
        break;
    case INPUT_EVENT_KIND_BTN:
        if (evt->u.btn.data->button == INPUT_BUTTON_LEFT) {
            mmcs_in_btn = evt->u.btn.data->down;
        }
        break;
    case INPUT_EVENT_KIND_KEY:
        if (evt->u.key.data->key->type == KEY_VALUE_KIND_QCODE) {
            int code = (int)evt->u.key.data->key->u.qcode.data;
            mmcs_input_key(code, evt->u.key.data->down);
        }
        break;
    default:
        break;
    }
}

static void mmcs_in_input_sync(DeviceState *dev)
{
    int x = mmcs_in_absx < 0 ? 0 : mmcs_in_absx;
    int y = mmcs_in_absy < 0 ? 0 : mmcs_in_absy;

    if (mmcs_in_btn && !mmcs_in_pen) {
        mmcs_in_pen = 1;
        mmcs_in_lastx = x;
        mmcs_in_lasty = y;
        mmcs_input_touch(x, y, 1);
        if (!mmcs_in_rate_timer) {
            mmcs_in_rate_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                              mmcs_in_rate_cb, NULL);
        }
        timer_mod(mmcs_in_rate_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + mmcs_in_rate_ms);
    } else if (!mmcs_in_btn && mmcs_in_pen) {
        mmcs_in_pen = 0;
        if (mmcs_in_rate_timer) {
            timer_del(mmcs_in_rate_timer);
        }
        mmcs_input_touch(x, y, 0);
    } else if (mmcs_in_pen &&
               (abs(x - mmcs_in_lastx) > mmcs_in_jitter ||
                abs(y - mmcs_in_lasty) > mmcs_in_jitter)) {
        mmcs_in_lastx = x;
        mmcs_in_lasty = y;
        mmcs_input_touch(x, y, 1);
    }
}

static QemuInputHandler mmcs_in_input_handler = {
    .name  = "mmcs-subcpu-touch",
    .mask  = INPUT_EVENT_MASK_BTN | INPUT_EVENT_MASK_ABS |
             INPUT_EVENT_MASK_KEY,
    .event = mmcs_in_input_event,
    .sync  = mmcs_in_input_sync,
};

/* ---- RXI EVT stopgap (S160 §3.2; MMCS_INPUT_EVT=0x..) --------------- */

extern void mmcs_inject_evt(uint32_t evt);

static void mmcs_in_rxi_evt(void *opaque, int n, int level)
{
    if (level && mmcs_in_evt) {
        mmcs_inject_evt(mmcs_in_evt);
    }
}

/* ---- machine-init hook (called from hw/sh4/mmcs.c, every world) ----- */

void mmcs_input_init(void)
{
    DeviceState *dev;
    const char *e;

    if (!mmcs_in_env_on("MMCS_INPUT")) {
        return;
    }
    mmcs_in_trace = mmcs_in_env_on("MMCS_INPUT_TRACE");
    if ((e = getenv("MMCS_INPUT_CMD")) && *e) {
        mmcs_in_cmd = strtoul(e, NULL, 0);
    }
    if ((e = getenv("MMCS_INPUT_GEAR_R")) && *e) {
        mmcs_in_gear_r = strtoul(e, NULL, 0) & 0xff;
    }
    if ((e = getenv("MMCS_INPUT_GEAR_OFF")) && *e) {
        mmcs_in_gear_off = strtoul(e, NULL, 0) & 0xff;
    }
    if ((e = getenv("MMCS_INPUT_EVT")) && *e) {
        mmcs_in_evt = strtoul(e, NULL, 0);
    }
    if ((e = getenv("MMCS_INPUT_RATE_MS")) && *e) {
        mmcs_in_rate_ms = MAX(1, atoi(e));
    }
    if ((e = getenv("MMCS_INPUT_JITTER")) && *e) {
        mmcs_in_jitter = atoi(e);
    }

    /* the sub-CPU link SCIF itself: a stock sh_serial SCIF instance at
     * the Verified ch1 base (the S160 §3.1 shape — "SCIF1 = copy of
     * the fork's SCIF serial model"). No host chardev: RX comes from
     * the frame builder, TX has no peer (drains nowhere, v1). The
     * dev->id set mirrors the mmcs-dbg-scif pattern — sh_serial's
     * realize asserts on a NULL id. */
    dev = qdev_new(TYPE_SH_SERIAL);
    dev->id = g_strdup("mmcs-input-scif");
    qdev_prop_set_uint8(dev, "features", SH_SERIAL_FEAT_SCIF);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, MMCS_INPUT_SCIF_BASE);
    mmcs_in_scif = dev;

    if (mmcs_in_evt) {
        qemu_irq rxi = qemu_allocate_irq(mmcs_in_rxi_evt, NULL, 0);
        qdev_connect_gpio_out_named(dev, "rxi", 0, rxi);
    }

    /* VNC/SDL pointer -> panel: the handler's ABS mask makes
     * qemu_input_is_absolute() true, so VNC advertises the absolute
     * pointer type and routes pixel-space events here (identity map). */
    mmcs_in_ihs = qemu_input_handler_register(NULL, &mmcs_in_input_handler);
    qemu_input_handler_activate(mmcs_in_ihs);

    fprintf(stderr, "MMCS: INPUT armed — SCIF1 @0x%08x (Micon injector), "
            "cmd=%04x gear r/off=%02x/%02x evt=%03x%s — VNC pointer = "
            "touch panel, mmcs_touch/mmcs_swipe/mmcs_key/mmcs_reverse "
            "HMP verbs live\n",
            MMCS_INPUT_SCIF_BASE, mmcs_in_cmd, mmcs_in_gear_r,
            mmcs_in_gear_off, mmcs_in_evt, mmcs_in_trace ? " trace" : "");
}

/* ---- HMP commands (the ux_drive.py verbs) ---------------------------- */

static int mmcs_in_hmp_ready(Monitor *mon)
{
    if (mmcs_in_scif) {
        return 1;
    }
    monitor_printf(mon, "mmcs input not armed (boot with MMCS_INPUT=1)\n");
    return 0;
}

void hmp_mmcs_touch(Monitor *mon, const QDict *qdict)
{
    int x = qdict_get_int(qdict, "x");
    int y = qdict_get_int(qdict, "y");
    const char *ph = qdict_get_str(qdict, "phase");
    int ms = qdict_haskey(qdict, "ms") ? qdict_get_int(qdict, "ms") : 80;

    if (!mmcs_in_hmp_ready(mon)) {
        return;
    }
    if (x < 0 || x >= MMCS_IN_RES_X || y < 0 || y >= MMCS_IN_RES_Y) {
        monitor_printf(mon, "mmcs_touch: %d,%d outside the 800x480 panel\n",
                       x, y);
        return;
    }
    if (!strcmp(ph, "down")) {
        mmcs_input_touch(x, y, 1);
    } else if (!strcmp(ph, "up")) {
        mmcs_input_touch(x, y, 0);
    } else if (!strcmp(ph, "tap")) {
        mmcs_in_seq_start(MMCS_IN_SEQ_TAP, 2, ms, x, y, x, y, 0);
    } else {
        monitor_printf(mon, "mmcs_touch: phase must be down|up|tap\n");
    }
}

void hmp_mmcs_swipe(Monitor *mon, const QDict *qdict)
{
    int x1 = qdict_get_int(qdict, "x1");
    int y1 = qdict_get_int(qdict, "y1");
    int x2 = qdict_get_int(qdict, "x2");
    int y2 = qdict_get_int(qdict, "y2");
    int ms = qdict_haskey(qdict, "ms") ? qdict_get_int(qdict, "ms") : 300;
    int steps = qdict_haskey(qdict, "steps") ? qdict_get_int(qdict, "steps")
                                             : 0;

    if (!mmcs_in_hmp_ready(mon)) {
        return;
    }
    if (x1 < 0 || x1 >= MMCS_IN_RES_X || x2 < 0 || x2 >= MMCS_IN_RES_X ||
        y1 < 0 || y1 >= MMCS_IN_RES_Y || y2 < 0 || y2 >= MMCS_IN_RES_Y) {
        monitor_printf(mon, "mmcs_swipe: endpoint outside the 800x480 "
                       "panel\n");
        return;
    }
    if (x1 == x2 && y1 == y2) {
        monitor_printf(mon, "mmcs_swipe: endpoints identical\n");
        return;
    }
    if (steps < 2) {
        steps = MAX(2, ms / mmcs_in_rate_ms);
    }
    mmcs_in_seq_start(MMCS_IN_SEQ_SWIPE, steps, ms / steps,
                      x1, y1, x2, y2, 0);
}

void hmp_mmcs_key(Monitor *mon, const QDict *qdict)
{
    const char *cs = qdict_get_str(qdict, "code");
    const char *ph = qdict_get_str(qdict, "phase");
    int ms = qdict_haskey(qdict, "ms") ? qdict_get_int(qdict, "ms") : 80;
    uint64_t code;

    if (!mmcs_in_hmp_ready(mon)) {
        return;
    }
    if (parse_uint(cs, NULL, 0, &code) || code > 0xffff) {
        monitor_printf(mon, "mmcs_key: code %s not hex/dec (named keys "
                       "wait on the donor key table — S160 open row)\n", cs);
        return;
    }
    if (!strcmp(ph, "down")) {
        mmcs_input_key(code, 1);
    } else if (!strcmp(ph, "up")) {
        mmcs_input_key(code, 0);
    } else if (!strcmp(ph, "press")) {
        mmcs_in_seq_start(MMCS_IN_SEQ_KEYPRESS, 2, ms, 0, 0, 0, 0, code);
    } else {
        monitor_printf(mon, "mmcs_key: phase must be down|up|press\n");
    }
}

void hmp_mmcs_reverse(Monitor *mon, const QDict *qdict)
{
    const char *st = qdict_get_str(qdict, "state");

    if (!mmcs_in_hmp_ready(mon)) {
        return;
    }
    if (!strcmp(st, "on")) {
        mmcs_input_reverse(1);
    } else if (!strcmp(st, "off")) {
        mmcs_input_reverse(0);
    } else {
        monitor_printf(mon, "mmcs_reverse: state must be on|off\n");
    }
}

void hmp_mmcs_input_info(Monitor *mon, const QDict *qdict)
{
    if (!mmcs_in_hmp_ready(mon)) {
        return;
    }
    monitor_printf(mon, "mmcs input: SCIF1 @0x%08x cmd=%04x "
                   "gear r/off=%02x/%02x evt=%03x rate=%dms jitter=%dpx\n",
                   MMCS_INPUT_SCIF_BASE, mmcs_in_cmd, mmcs_in_gear_r,
                   mmcs_in_gear_off, mmcs_in_evt, mmcs_in_rate_ms,
                   mmcs_in_jitter);
    monitor_printf(mon, "frames=%lu bytes=%lu dropped=%lu pending=%u "
                   "pen=%d seq=%d\n",
                   mmcs_in_frames, mmcs_in_bytes, mmcs_in_drops,
                   mmcs_in_rcnt, mmcs_in_pen, mmcs_in_seq_kind);
}
