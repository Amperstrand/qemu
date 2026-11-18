/*
 * MMCS fork DRAFT (2026-11-17): SH-Mobile/tmio-family SDHI host
 * controllers for the MMCS E12 head unit (SH7777-class, WinCE5/SH4).
 *
 * Spec: car-research vehicles/mitsubishi-outlander-2014/mmcs-e12/docs/
 * lane-reports/2026-11-17-sdhi-device-spec.md — every semantic below
 * cites it. Facts encoded [V] Verified from the unit's corpus unless
 * tagged [I] Inferred / [Unknown].
 *
 *   - Registry [V]: SDHI0 MemBase 0xFFE4C000 Irq 23 SysIntr 39,
 *     SDHI1 MemBase 0xFFE4D000 Irq 24 SysIntr 40, MemLen 0x100.
 *   - sdhi.dll = Renesas "SD Host Control Driver 2.000.02" [V] using
 *     the SH-Mobile SDHI/tmio map: SD_CMD 0x00, SD_ARG0/1 0x04/0x06,
 *     SD_STOP 0x08, SD_BLKCNT 0x0A, SD_RSP* 0x0C-0x1A, SD_INFO1/2
 *     0x1C/0x1E (0-TO-CLEAR status), masks 0x20/0x22 (bit=1 masked),
 *     SD_CLK_CTRL 0x24 (bit8 SCLKEN), SD_SIZE 0x26, SD_BUF0 0x30,
 *     EXT pairs 0x40/0x42 + 0xB0/0xB2, DMA_ENABLE 0xD8, SOFT_RST 0xE0,
 *     VERSION 0xE2.
 *   - IRQ [V]: level line on ((info1 & ~mask1) != 0) || ((info2 &
 *     ~mask2) != 0). Until the vendor INTC model exists, an assert is
 *     delivered through the L13-proven EVT injection: 0xAE0 (SDHI0) ->
 *     thunk 0x9080caec -> IISR chain[23], 0xB00 (SDHI1) ->
 *     0x9080cb08 -> chain[24]; the IISR (sdhi_isr.dll) acks by OR-ing
 *     the pending bits into the mask regs, which drops the level here.
 *   - v1 = the EMPTY-SLOT model (spec §3.3/§3.4): INFO1 bit5
 *     (SIGSTATE, card-present) stays clear, so sdhi.dll's card-detect
 *     gate (c09a7898) errors -36 before issuing any command and the
 *     CE5 storage stack never enumerates. No card-insert events are
 *     modeled (spec §3.6: AutoMount=0, insertion is a later,
 *     owner-approved stage). The three v1 behaviors: soft-reset
 *     release, INFO1 "no card", quiet IRQ line.
 *
 * Env knobs (creation gate lives in mmcs.c, default OFF):
 *   MMCS_SDHI=1              create the two instances
 *   MMCS_TRACE_SDHI=1        log every MMIO access (sh7777-trace style)
 *   MMCS_SDHI_TESTIRQ=<ms>   acceptance-test hook (spec §3.7-2/4): force
 *                            one CRRESP (INFO1 bit0) on SDHI0 <ms>
 *                            virtual-ms after creation to exercise the
 *                            level-IRQ -> EVT 0xAE0 -> IISR ack path.
 *
 * Stage 2 (NOT this file): the virtual-card bus side (CID/CSD/SCR
 * answers + sector streaming, spec §3.4/§3.5) once the empty-slot
 * model has proven SHC_Init completes.
 */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "hw/irq.h"
#include "hw/sysbus.h"
#include "qemu/error-report.h"
#include "exec/address-spaces.h"

/* the L13-proven EVT injector, implemented in mmcs.c */
void mmcs_inject_evt(uint32_t evt);

#define MMCS_SDHI_N   2
#define MMCS_SDHI_WIN 0x100

/* register offsets (spec §2/§3.2) */
#define SD_CMD        0x00    /* WO issue: latch cmd/arg, start transfer */
#define SD_ARG0       0x04
#define SD_ARG1       0x06
#define SD_STOP       0x08    /* bit0 STP, bit8 SEC */
#define SD_BLKCNT     0x0a
#define SD_RSP10      0x0c    /* response file, RO */
#define SD_RSPDC      0x18
#define SD_INFO1      0x1c    /* status, 0-to-clear */
#define SD_INFO2      0x1e    /* status, 0-to-clear */
#define SD_INFO1_MASK 0x20    /* bit=1 -> masked */
#define SD_INFO2_MASK 0x22
#define SD_CLK_CTRL   0x24    /* bit8 SCLKEN, [7:0] divider */
#define SD_SIZE       0x26
#define SD_OPTION     0x28
#define SD_BUF0       0x30    /* PIO FIFO port (v1: plain storage) */
#define EXT_SDIO_STAT 0x40    /* inert status/mask pairs (spec §6-3) */
#define EXT_SDIO_MASK 0x42    /* reset 0x002A [V ISR default] */
#define EXTB_STAT     0xb0
#define EXTB_MASK     0xb2    /* reset 0x475F [V ISR default] */
#define DMA_ENABLE    0xd8    /* WAR; driver &= 0x2802 around reset */
#define SOFT_RST      0xe0    /* bit0 SD unit: 0 = held in reset */
#define SD_VERSION    0xe2    /* RO; no driver read observed yet */

/* SD_INFO1 bits */
#define INFO1_CRRESP    0x0001    /* command response received */
#define INFO1_SIGSTATE  0x0020    /* card-present line (NOT W1C) */
/* v1 empty slot: the present line reads 0. Stage 2 turns this into
 * (INFO1_CRDINS | INFO1_SIGSTATE) statically at probe (spec §3.3). */
#define INFO1_PRESENT_BITS 0x0000

/* SD_INFO2 bits */
#define INFO2_CMDTIMEOUT 0x0040
#define INFO2_SCLKDIVEN  0x2000    /* clock-divider busy, polled == 0 */
#define INFO2_CMDBUS     0x4000

#define CLK_SCLKEN   0x0100
#define SOFT_RST_SD  0x0001

/* [Unknown] plausible SH7777 SDHI version code — no driver read
 * observed in the disasm (spec §2: do not gate anything on it) */
#define MMCS_SDHI_VERSION_CODE 0x0001

/* divider-busy window after a CLK_CTRL write (spec §3.2: "for N cycles
 * then clears"; the driver polls bit13==0 with up to 10 x 100 ms) */
#define MMCS_SDHI_DIV_BUSY_NS 100000

typedef struct MmcsSdhiState {
    uint16_t regs[MMCS_SDHI_WIN / 2];
    QEMUTimer *div_timer;
    qemu_irq irq;
    int idx;
    hwaddr base;
    uint32_t evt;       /* EVT 0xAE0 / 0xB00 */
    int irq_src;        /* INTC source 23 / 24 */
    int div_pending;    /* INFO2 bit13 driven by the div timer */
    int injected;       /* one EVT per line-assertion episode */
} MmcsSdhiState;

static MmcsSdhiState mmcs_sdhi[MMCS_SDHI_N];

static const struct {
    hwaddr base;
    uint32_t evt;
    int src;
} mmcs_sdhi_tbl[MMCS_SDHI_N] = {
    { 0xFFE4C000, 0xAE0, 23 },
    { 0xFFE4D000, 0xB00, 24 },
};

static int mmcs_sdhi_trace(void)
{
    static int on = -1;
    if (on < 0) {
        on = getenv("MMCS_TRACE_SDHI") != NULL;
    }
    return on;
}

/* ---- level IRQ: assert while any unmasked INFO status bit ---- */
static void mmcs_sdhi_update_irq(MmcsSdhiState *s)
{
    uint16_t pend1 = s->regs[SD_INFO1 / 2] & ~s->regs[SD_INFO1_MASK / 2];
    uint16_t pend2 = s->regs[SD_INFO2 / 2] & ~s->regs[SD_INFO2_MASK / 2];
    int level = (pend1 != 0) || (pend2 != 0);

    if (s->irq) {
        qemu_set_irq(s->irq, level);
    }
}

/* The qemu_irq sink: an assert delivers ONE EVT injection through the
 * proven path (the vendor INTC model does not exist yet). Deassertion
 * needs no action — the IISR's ack ORs the pending bits into the mask
 * regs, whose write re-runs mmcs_sdhi_update_irq and drops the level. */
static void mmcs_sdhi_irq_handler(void *opaque, int n, int level)
{
    MmcsSdhiState *s = opaque;

    (void)n;
    if (level) {
        if (!s->injected) {
            s->injected = 1;
            if (mmcs_sdhi_trace()) {
                fprintf(stderr, "MMCS-SDHI%d: line assert -> EVT %03x "
                        "(irq src %d)\n", s->idx, s->evt, s->irq_src);
            }
            mmcs_inject_evt(s->evt);
        }
    } else {
        s->injected = 0;
    }
}

/* ---- SOFT_RST assert = the SD unit's power-on state (spec §3.2/§3.3) */
static void mmcs_sdhi_reset_unit(MmcsSdhiState *s)
{
    /* status/cmd/response/clock/masks cleared; the EXT pairs and
     * DMA_ENABLE live outside the SD unit and keep their values (the
     * driver itself gates DMA_ENABLE around its reset walk). */
    memset(s->regs, 0, sizeof s->regs);
    s->regs[EXT_SDIO_MASK / 2] = 0x002a;    /* ISR reset default [V] */
    s->regs[EXTB_MASK / 2] = 0x475f;        /* ISR reset default [V] */
    /* Mask regs reset to the chip's power-on defaults, NOT zero: TMIO_MASK_ALL
     * 0x837f031d (kernel tmio_mmc: INFO1_MASK=0x031d, INFO2_MASK=0x837f at
     * chip reset — the 2026-11-18 kernel-mining lane; a zero mask would let
     * every reset-time status bit fire the level IRQ immediately). */
    s->regs[SD_INFO1_MASK / 2] = 0x031d;
    s->regs[SD_INFO2_MASK / 2] = 0x837f;
    s->regs[SD_INFO1 / 2] = INFO1_PRESENT_BITS;
    s->div_pending = 0;
    if (s->div_timer) {
        timer_del(s->div_timer);
    }
}

static void mmcs_sdhi_div_done(void *opaque)
{
    MmcsSdhiState *s = opaque;

    s->div_pending = 0;
    s->regs[SD_INFO2 / 2] &= ~INFO2_SCLKDIVEN;
    mmcs_sdhi_update_irq(s);
}

/* ---- SD_CMD issue: the v1 empty-slot column only (spec §3.4) ----
 * CMD0 completes silently; any other index without a card fails with
 * CMDTIMEOUT. The driver's card-present gate (INFO1 bit5 == 0 -> the
 * -36 refuse) normally means no command is ever issued, so this is the
 * not-reachable-in-boot safety net. Completes in zero virtual time
 * (busy bits set/cleared inside the write; deterministic under rr). */
static void mmcs_sdhi_issue(MmcsSdhiState *s, uint16_t cmd)
{
    uint16_t *info2 = &s->regs[SD_INFO2 / 2];

    *info2 |= INFO2_CMDBUS;
    if ((cmd & 0x3f) != 0) {
        *info2 |= INFO2_CMDTIMEOUT;
    }
    *info2 &= ~INFO2_CMDBUS;
}

static bool mmcs_sdhi_ro(hwaddr off)
{
    return (off >= SD_RSP10 && off <= SD_RSPDC + 2)   /* response file */
        || off == EXT_SDIO_STAT || off == EXTB_STAT
        || off == SD_VERSION;
}

static uint16_t mmcs_sdhi_read16(MmcsSdhiState *s, hwaddr off)
{
    if (off == SD_VERSION) {
        return MMCS_SDHI_VERSION_CODE;
    }
    return s->regs[off / 2];
}

static void mmcs_sdhi_write16(MmcsSdhiState *s, hwaddr off, uint16_t v)
{
    switch (off) {
    case SD_CMD:
        if (!(s->regs[SOFT_RST / 2] & SOFT_RST_SD)) {
            return;     /* held in reset: command writes ignored */
        }
        s->regs[SD_CMD / 2] = v;
        mmcs_sdhi_issue(s, v);
        return;
    case SD_INFO1:
        /* 0-to-clear (write ~bit clears exactly that bit); the
         * card-present line is owned by hardware, never W1C */
        s->regs[SD_INFO1 / 2] &= v | INFO1_PRESENT_BITS;
        return;
    case SD_INFO2:
        /* 0-to-clear; bit13 is driven while a clock change is in flight */
        s->regs[SD_INFO2 / 2] &= v | (s->div_pending ? INFO2_SCLKDIVEN : 0);
        return;
    case SD_CLK_CTRL:
        s->regs[SD_CLK_CTRL / 2] = v;
        if (v & CLK_SCLKEN) {
            /* clock change in flight: hold the divider-busy bit for a
             * short deterministic window, then clear (the driver polls
             * INFO2 bit13 == 0 before every command) [I: N cycles] */
            s->div_pending = 1;
            s->regs[SD_INFO2 / 2] |= INFO2_SCLKDIVEN;
            timer_mod(s->div_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL)
                      + MMCS_SDHI_DIV_BUSY_NS);
        } else if (s->div_pending) {
            s->div_pending = 0;
            timer_del(s->div_timer);
            s->regs[SD_INFO2 / 2] &= ~INFO2_SCLKDIVEN;
        }
        return;
    case SOFT_RST:
        if (!(v & SOFT_RST_SD)) {
            /* assert: unit reset, clock off, in-flight command void */
            mmcs_sdhi_reset_unit(s);
        }
        s->regs[SOFT_RST / 2] = v;
        return;
    default:
        if (!mmcs_sdhi_ro(off)) {
            s->regs[off / 2] = v;    /* RW / WAR storage */
        }
        return;
    }
}

/* ---- MMIO window ---- */
static uint64_t mmcs_sdhi_read(void *opaque, hwaddr addr, unsigned size)
{
    MmcsSdhiState *s = opaque;
    uint64_t v = 0;

    if (!(addr & 1) && addr + size <= MMCS_SDHI_WIN) {
        v = mmcs_sdhi_read16(s, addr);
        if (size == 4) {
            v |= (uint64_t)mmcs_sdhi_read16(s, addr + 2) << 16;
        }
    }
    if (mmcs_sdhi_trace()) {
        fprintf(stderr, "MMCS-SDHI%d-R off=%03x sz=%u -> %04llx\n",
                s->idx, (unsigned)addr, size, (unsigned long long)v);
    }
    return v;
}

static void mmcs_sdhi_write(void *opaque, hwaddr addr, uint64_t val,
                            unsigned size)
{
    MmcsSdhiState *s = opaque;

    if (mmcs_sdhi_trace()) {
        fprintf(stderr, "MMCS-SDHI%d-W off=%03x sz=%u <- %04llx\n",
                s->idx, (unsigned)addr, size, (unsigned long long)val);
    }
    if (!(addr & 1) && addr + size <= MMCS_SDHI_WIN) {
        mmcs_sdhi_write16(s, addr, val & 0xffff);
        if (size == 4) {
            mmcs_sdhi_write16(s, addr + 2, val >> 16);
        }
        mmcs_sdhi_update_irq(s);
    }
}

static const MemoryRegionOps mmcs_sdhi_ops = {
    .read = mmcs_sdhi_read,
    .write = mmcs_sdhi_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 2,
    .valid.max_access_size = 4,
};

/* ---- acceptance-test hook (spec §3.7-2/4): force CRRESP on SDHI0 ---- */
static void mmcs_sdhi_testirq_fire(void *opaque)
{
    MmcsSdhiState *s = &mmcs_sdhi[0];

    (void)opaque;
    s->regs[SD_INFO1 / 2] |= INFO1_CRRESP;
    fprintf(stderr, "MMCS-SDHI0: TESTIRQ CRRESP forced (info1=%04x "
            "mask=%04x)\n", s->regs[SD_INFO1 / 2],
            s->regs[SD_INFO1_MASK / 2]);
    mmcs_sdhi_update_irq(s);
}

void mmcs_sdhi_init(void);

/* Called from mmcs.c's mmcs_init under `mmcs_env_on("MMCS_SDHI")` —
 * default OFF, A/B-safe: without the env the MMIO window keeps falling
 * through to the unimplemented-stub logging (no behavior change). */
void mmcs_sdhi_init(void)
{
    for (int i = 0; i < MMCS_SDHI_N; i++) {
        MmcsSdhiState *s = &mmcs_sdhi[i];
        MemoryRegion *mr = g_new(MemoryRegion, 1);

        memset(s, 0, sizeof *s);
        s->idx = i;
        s->base = mmcs_sdhi_tbl[i].base;
        s->evt = mmcs_sdhi_tbl[i].evt;
        s->irq_src = mmcs_sdhi_tbl[i].src;
        s->div_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, mmcs_sdhi_div_done,
                                    s);
        mmcs_sdhi_reset_unit(s);
        s->irq = qemu_allocate_irq(mmcs_sdhi_irq_handler, s, 0);
        memory_region_init_io(mr, NULL, &mmcs_sdhi_ops, s,
                              g_strdup_printf("mmcs-sdhi%d", i),
                              MMCS_SDHI_WIN);
        memory_region_add_subregion(get_system_memory(), s->base, mr);
    }

    /* MMCS_SDHI_TESTIRQ=<ms>: one forced CRRESP on SDHI0 — the line
     * asserts, one EVT 0xAE0 is injected, and the IISR's ack (mask OR)
     * must drop it again. Requires chain[23] to be loaded by then
     * (LoadIntChainHandler("sdhi_isr.dll", ..., 23) at busenum time). */
    {
        const char *tq = getenv("MMCS_SDHI_TESTIRQ");
        if (tq && *tq && strcmp(tq, "0") != 0) {
            int ms = atoi(tq);
            QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                        mmcs_sdhi_testirq_fire, NULL);
            timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + ms);
            fprintf(stderr, "MMCS-SDHI: TESTIRQ will force CRRESP on "
                    "SDHI0 in %dms\n", ms);
        }
    }

    fprintf(stderr, "MMCS-SDHI: SDHI0 @%08x (irq %d, EVT %03x) SDHI1 @%08x"
            " (irq %d, EVT %03x) — empty-slot v1 (env MMCS_SDHI)\n",
            (unsigned)mmcs_sdhi_tbl[0].base, mmcs_sdhi_tbl[0].src,
            mmcs_sdhi_tbl[0].evt, (unsigned)mmcs_sdhi_tbl[1].base,
            mmcs_sdhi_tbl[1].src, mmcs_sdhi_tbl[1].evt);
}
