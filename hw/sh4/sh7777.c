/*
 * SH7777-class interrupt/timer block for the MMCS E12 head unit.
 *
 * Addresses (from OAL literals in the XIP kernel):
 *   CMT/timer: 0xFFC080C0/C4/C8/D8/E4/EC/F0/F4 (F4 = live counter, polled)
 *   INTC banks: 0xFFC40004/8/C, 0xFFC41004/C, 0xFFC42004/C, 0xFFC43004/C
 *     read  +04 = pending status (kernel polls this)
 *     +08     = mask (assumed)
 *     write +0C = ack (assumed; semantics confirmed from OAL code)
 *
 * Delivery: CMT expiry sets a pending bit in bank 0 and asserts the CPU IRQ
 * line (borrowed from the stock INTC so the standard INTEVT/VBR path runs).
 * The kernel's dispatcher reads INTEVT, then reads the bank status to find
 * the source, then acks at bank+0x0C which deasserts.
 *
 * All register semantics are provisional until cross-checked with the OAL
 * decompile; MMCS_TRACE_SH7777=1 logs every access so the OAL's programming
 * sequence teaches us the real protocol.
 */
#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/timer.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "qemu/error-report.h"
#include "cpu.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"
#include "sh7777.h"

#define SH7777_CMT_BASE 0xFFC08000
#define SH7777_CMT_SIZE 0x100
#define SH7777_INTC_BANKS 4
#define SH7777_INTC_BASE 0xFFC40000
#define SH7777_INTC_STRIDE 0x1000

typedef struct Sh7777IntcState {
    /* bank[i] pending/mask bitmaps */
    uint32_t pending[SH7777_INTC_BANKS];
    uint32_t mask[SH7777_INTC_BANKS];
    qemu_irq cpu_irq;
} Sh7777IntcState;

typedef struct Sh7777CmtState {
    QEMUTimer *timer;
    Sh7777IntcState *intc;
    uint32_t regs[SH7777_CMT_SIZE / 4]; /* raw register file */
    uint32_t period_ns;
    int64_t last_tick;
    uint32_t irq_bit;    /* bank-0 pending bit for the CMT (provisional 0) */
    int irq_bank;
} Sh7777CmtState;

static Sh7777IntcState sh7777_intc;
static Sh7777CmtState sh7777_cmt;

static int sh7777_trace(void)
{
    static int on = -1;
    if (on < 0) on = getenv("MMCS_TRACE_SH7777") != NULL;
    return on;
}

/* ---- CPU IRQ aggregation: assert while any unmasked pending ---- */
static void sh7777_intc_update(Sh7777IntcState *s)
{
    int level = 0;
    for (int i = 0; i < SH7777_INTC_BANKS; i++) {
        if (s->pending[i] & ~s->mask[i]) { level = 1; break; }
    }
    if (s->cpu_irq) qemu_set_irq(s->cpu_irq, level);
}

/* ---- CMT register file ---- */
static uint64_t sh7777_cmt_read(void *opaque, hwaddr addr, unsigned size)
{
    Sh7777CmtState *c = opaque;
    if (addr == 0xf4) {
        /* live up-counter since timer start, ~microsecond granularity */
        int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        return (uint32_t)((now - c->last_tick) / 1000);
    }
    if (addr / 4 < SH7777_CMT_SIZE / 4) {
        return c->regs[addr / 4];
    }
    return 0;
}

static void sh7777_cmt_tick(void *opaque)
{
    Sh7777CmtState *c = opaque;
    if (c->period_ns) {
        sh7777_intc.pending[c->irq_bank] |= (1u << c->irq_bit);
        sh7777_intc_update(&sh7777_intc);
        timer_mod(c->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + c->period_ns);
    }
}

static void sh7777_cmt_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    Sh7777CmtState *c = opaque;
    if (sh7777_trace()) {
        fprintf(stderr, "SH7777-CMT-W off=%03x val=%08x\n", (unsigned)addr, (unsigned)val);
    }
    if (addr / 4 < SH7777_CMT_SIZE / 4) {
        c->regs[addr / 4] = val;
    }
    /* Provisional start/stop semantics: any write to the "control" cluster
     * (0xC0..0xF0) re-arms the timer at a period derived from the written
     * value; zero stops. Tuned after seeing the OAL's real sequence. */
    if (addr >= 0xc0 && addr <= 0xf0) {
        if (val == 0) {
            c->period_ns = 0;
            timer_del(c->timer);
        } else {
            /* provisional: treat written value as a prescaler/count load;
             * default tick = 1ms until the OAL sequence is decoded */
            c->period_ns = 1000000;
            c->last_tick = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
            timer_mod(c->timer, c->last_tick + c->period_ns);
        }
    }
}

static const MemoryRegionOps sh7777_cmt_ops = {
    .read = sh7777_cmt_read,
    .write = sh7777_cmt_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
};

/* ---- INTC banks ---- */
static uint64_t sh7777_intc_read(void *opaque, hwaddr addr, unsigned size)
{
    Sh7777IntcState *s = opaque;
    unsigned bank = (addr >> 12) & 3;
    if (sh7777_trace()) {
        fprintf(stderr, "SH7777-INTC-R bank=%u off=%03x\n", bank, (unsigned)(addr & 0xfff));
    }
    switch (addr & 0xfff) {
    case 0x04: return s->pending[bank] & ~s->mask[bank];
    case 0x08: return s->mask[bank];
    case 0x0c: return s->pending[bank];
    default:   return 0;
    }
}

static void sh7777_intc_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    Sh7777IntcState *s = opaque;
    unsigned bank = (addr >> 12) & 3;
    if (sh7777_trace()) {
        fprintf(stderr, "SH7777-INTC-W bank=%u off=%03x val=%08x\n",
                bank, (unsigned)(addr & 0xfff), (unsigned)val);
    }
    switch (addr & 0xfff) {
    case 0x08: s->mask[bank] = val; break;
    case 0x0c: /* ack: clear pending bits written as 1 */
        s->pending[bank] &= ~val;
        break;
    default: break;
    }
    sh7777_intc_update(s);
}

static const MemoryRegionOps sh7777_intc_ops = {
    .read = sh7777_intc_read,
    .write = sh7777_intc_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4, .valid.max_access_size = 4,
};

/* ---- CPG at 0xFFE70000: OEMInit's clock-switch-to-533MHz handshake.
 * Writes divisors/ctrl at +0x800/+0x804, then polls +0x808 for the
 * PLL-lock bits (0xC0000000). Stub returned 0 = boot hang. We report
 * always-locked. */
static uint32_t sh7777_cpg_regs[0x1000 / 4];
static uint64_t sh7777_cpg_read(void *opaque, hwaddr addr, unsigned size)
{
    if (addr == 0x808) {
        return sh7777_cpg_regs[0x808 / 4] | 0xC0000000;  /* PLL locked */
    }
    if (addr / 4 < 0x1000 / 4) return sh7777_cpg_regs[addr / 4];
    return 0;
}
static void sh7777_cpg_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    if (addr / 4 < 0x1000 / 4) sh7777_cpg_regs[addr / 4] = val;
}
static const MemoryRegionOps sh7777_cpg_ops = {
    .read = sh7777_cpg_read,
    .write = sh7777_cpg_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
};

void sh7777_init(qemu_irq cpu_irq)
{
    MemoryRegion *mr;
    memset(&sh7777_intc, 0, sizeof sh7777_intc);
    memset(&sh7777_cmt, 0, sizeof sh7777_cmt);
    sh7777_intc.cpu_irq = cpu_irq;
    sh7777_cmt.intc = &sh7777_intc;
    sh7777_cmt.timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, sh7777_cmt_tick, &sh7777_cmt);
    sh7777_cmt.irq_bit = 0;      /* provisional: bank0 bit0 = CMT tick */
    sh7777_cmt.irq_bank = 0;

    {
        MemoryRegion *cpg = g_new(MemoryRegion, 1);
        memory_region_init_io(cpg, NULL, &sh7777_cpg_ops, NULL,
                              "sh7777.cpg", 0x1000);
        /* overlaps the 0xFFE70000 unimplemented stub — replace it */
        memory_region_add_subregion_overlap(get_system_memory(),
                                            0xFFE70000, cpg, 1);
    }

    mr = g_new(MemoryRegion, 1);
    memory_region_init_io(mr, NULL, &sh7777_cmt_ops, &sh7777_cmt,
                          "sh7777.cmt", SH7777_CMT_SIZE);
    memory_region_add_subregion(get_system_memory(), SH7777_CMT_BASE, mr);

    for (int b = 0; b < SH7777_INTC_BANKS; b++) {
        mr = g_new(MemoryRegion, 1);
        memory_region_init_io(mr, NULL, &sh7777_intc_ops, &sh7777_intc,
                              g_strdup_printf("sh7777.intc%d", b), 0x10);
        /* the ops decode bank from addr bits 12-13: map each 0x10 region at
         * its bank offset inside one window covering all four */
        memory_region_add_subregion(get_system_memory(),
                                    SH7777_INTC_BASE + b * SH7777_INTC_STRIDE, mr);
    }
}

/* ---- Channel flash blocks (0xF40000..0xFCFFFF) ----
 * 5 x 128KB AMD-family NOR. Observed protocol (logged): 16-bit
 *   0x30 @ block base = erase confirm (short AMD form, no unlock cycles)
 *   0x90 @ +0xAAA     = autoselect (reads: +0 maker, +2 device)
 *   0xF0 @ anywhere   = reset to read mode
 *   anything else     = program (bit-and)
 * Erase fills 0xFFFFFFFF instantly (driver polls for stable data). */
#define CHAN_N 5
#define CHAN_SZ (128 * 1024)
static uint8_t chan_flash[CHAN_N][CHAN_SZ];
static int chan_autoselect[CHAN_N];
static const hwaddr chan_base_table[CHAN_N] = {
    0xF40000, 0xF60000, 0xF80000, 0xFA0000, 0xFC0000
};

static uint64_t chanflash_read(void *opaque, hwaddr off, unsigned size)
{
    int c = (int)(intptr_t)opaque;
    uint64_t v = 0;
    if (chan_autoselect[c]) {
        if (size == 2) {
            if (off == 0) return 0x0001;        /* AMD maker */
            if (off == 2) return 0x227e;        /* device (mirror r2d ids) */
            if (off == 4) return 0;             /* block protect */
        }
    }
    if (off + size <= CHAN_SZ) memcpy(&v, chan_flash[c] + off, size);
    if (sh7777_trace() && (off < 0x100 || (off & 0xF0000000) == 0)) {
        /* log reads of the sigstruct head (first 0x100 bytes) only */
        if (off < 0x100) {
            fprintf(stderr, "SH7777-CHFL-R c=%d off=%05lx -> %04llx\n",
                    c, (unsigned long)off, (unsigned long long)v);
        }
    }
    return v;
}

static void chanflash_write(void *opaque, hwaddr off, uint64_t val, unsigned size)
{
    int c = (int)(intptr_t)opaque;
    if (sh7777_trace()) {
        fprintf(stderr, "SH7777-CHFL-W c=%d off=%05x val=%04llx\n",
                c, (unsigned)off, (unsigned long long)val);
    }
    if (size == 2) {
        uint16_t v16 = val;
        if (v16 == 0x30 && off == 0) {           /* erase confirm at block base */
            memset(chan_flash[c], 0xff, CHAN_SZ);
            chan_autoselect[c] = 0;
            /* S78/S79: the kernel erases ch0 then awaits a program phase
             * that never arrives (loader's job on real HW). Without a valid
             * sigstruct the channel-walker marks ch0 INVALID and the boot
             * stalls at '//'. Emulate the loader: restore the valid struct
             * right after the erase completes. */
            if (getenv("MMCS_CHAN_AUTORESTORE")) {
                uint32_t *m = (uint32_t *)chan_flash[c];
                memset(chan_flash[c], 0x00, 0x100);
                m[0] = 0xffffffff;
                m[12] = 0; m[13] = 0xffffffff;
                m[14] = 0; m[15] = 0xffffffff;
                m[23] = 0;
                if (sh7777_trace())
                    fprintf(stderr, "SH7777-CHFL c=%d SIGSTRUCT RESTORED\n", c);
            }
            if (sh7777_trace()) fprintf(stderr, "SH7777-CHFL c=%d ERASED\n", c);
            return;
        }
        if (v16 == 0x90) { chan_autoselect[c] = 1; return; }   /* autoselect */
        if (v16 == 0xf0) { chan_autoselect[c] = 0; return; }   /* reset */
    }
    if (off + size > CHAN_SZ) return;
    /* program: AND into existing (NOR can only clear bits) */
    for (unsigned b = 0; b < size && off + b < CHAN_SZ; b++) {
        chan_flash[c][off + b] &= ((uint8_t *)&val)[b];
    }
}

static const MemoryRegionOps chanflash_ops = {
    .read = chanflash_read,
    .write = chanflash_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
};

void mmcs_chanflash_init(void)
{
    for (int c = 0; c < CHAN_N; c++) {
        MemoryRegion *mr = g_new(MemoryRegion, 1);
        uint32_t *m = (uint32_t *)chan_flash[c];
        memset(chan_flash[c], 0xff, CHAN_SZ);
        /* loader-written signature struct at +0 (programmed 0s) */
        memset(chan_flash[c], 0x00, 0x100);
        m[0] = 0xffffffff;
        m[12] = 0; m[13] = 0xffffffff;
        m[14] = 0; m[15] = 0xffffffff;
        m[23] = 0;
        memory_region_init_io(mr, NULL, &chanflash_ops, (void *)(intptr_t)c,
                              g_strdup_printf("mmcs.chan%d", c), CHAN_SZ);
        memory_region_add_subregion(get_system_memory(),
                                    chan_base_table[c], mr);
    }
}
