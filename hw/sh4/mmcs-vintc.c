/*
 * MMCS fork (device split lane, 2026-11-25 — peer review M2c, split #3):
 * the vendor-INTC page @0xF4000000 — the register file + MMIO ops, the
 * VINTC_EVT/VINTC_IRQ periodic-injection experiments, and the L18 access
 * census — extracted VERBATIM from hw/sh4/mmcs.c (pure code motion, zero
 * behavior change; validated by tests/qtest/mmcs-vintc-test.c + the
 * byte-stability gates). Decode history: S73/S134/L17-L18.
 */
#include "qemu/osdep.h"
#include "hw/sh4/mmcs-vintc.h"
#include "hw/sh4/sh.h"
#include "qemu/timer.h"
#include "hw/irq.h"

void mmcs_inject_evt(uint32_t evt);

/* ---- the register file + the experiment state ------------------------ */

uint32_t mmcs_vintc_regs[64];
qemu_irq mmcs_vintc_irl;      /* SH4 IRL line (vendor INTC demux) */
uint32_t mmcs_vintc_evt_code;

void mmcs_vintc_evt_deliver(void *opaque)
{
    mmcs_inject_evt(mmcs_vintc_evt_code);
    QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_vintc_evt_deliver, NULL);
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
              + atoi(getenv("MMCS_VINTC_EVT_MS") ? : "20"));
}

void mmcs_vintc_pulse(void *opaque)
{
    static int level;
    level = !level;
    qemu_set_irq(mmcs_vintc_irl, level & 15);
    QEMUTimer *t __attribute__((unused)) = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_vintc_pulse, NULL);
    /* first pulse waits for the polled boot to settle (early IRQ derails
     * kernel init before filesys launches; verified 10ms+1000ms both die) */
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
              + atoi(getenv("MMCS_VINTC_DELAY") ? : "15000"));
}
static uint64_t mmcs_vintc_read(void *opaque, hwaddr off, unsigned size)
{
    uint64_t v = 0;
    if (off / 4 < 64) memcpy(&v, (uint8_t *)mmcs_vintc_regs + off, size);
    if (getenv("MMCS_TRACE")) {
        fprintf(stderr, "MMCS-VINTC R off=%05llx -> %08llx\n",
                (unsigned long long)off, (unsigned long long)v);
    }
    mmcs_vi_note(0, off, (uint32_t)v);
    return v;
}
static void mmcs_vintc_write(void *opaque, hwaddr off, uint64_t val, unsigned size)
{
    if (getenv("MMCS_TRACE")) {
        fprintf(stderr, "MMCS-VINTC W off=%05llx <- %08llx\n",
                (unsigned long long)off, (unsigned long long)val);
    }
    mmcs_vi_note(1, off, (uint32_t)val);
    if (off / 4 < 64) memcpy((uint8_t *)mmcs_vintc_regs + off, &val, size);
}
const MemoryRegionOps mmcs_vintc_ops = {
    .read = mmcs_vintc_read, .write = mmcs_vintc_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
};


/* MMCS fork (L18): vendor-INTC access census (env MMCS_VINTC_CENSUS=1).
 * DECODE MOTIVATION (S134/L17): the NULL-call caller at 0x908381b8
 * computes r1 = *0x8867ed64 + 0xB8 and the parked dump showed
 * r1 = 0xf4008000 — the vendor global-struct base is 0xF4007F48-class
 * and the register block at +0xB8 = 0xF4008000 is the LIVE interrupt
 * controller (distinct from the loader's 0xF4000000 zero-sweep page and
 * the 0xF4001000/3000 kernel data refs). MMCS_TRACE per-access logging
 * is useless there (the S73 sweeps were 4.3M zero-writes), so this is a
 * bounded per-register histogram: read/write counts, first distinct
 * written values, and a ring of the most recent events — dumped every
 * 60s of virtual time and at MMCS_DUMP time. Ground truth for the
 * status/ack/mask decode without the flood. */
#define MMCS_VI_NT (0x10000u / 4)
static uint32_t mmcs_vi_nr[MMCS_VI_NT], mmcs_vi_nw[MMCS_VI_NT];
static uint32_t mmcs_vi_fv[MMCS_VI_NT][3];   /* first 3 distinct writes */
static uint8_t mmcs_vi_nv[MMCS_VI_NT];
static struct { uint32_t off, val; uint8_t is_w; } mmcs_vi_ring[256];
static int mmcs_vi_ring_i;
int mmcs_vi_census;

void mmcs_vi_note(int is_w, hwaddr off, uint32_t val)
{
    if (!mmcs_vi_census) {
        return;
    }
    unsigned i = off >> 2;
    if (i < MMCS_VI_NT) {
        if (is_w) {
            mmcs_vi_nw[i]++;
            if (mmcs_vi_nv[i] < 3) {
                for (int k = 0; k < mmcs_vi_nv[i]; k++) {
                    if (mmcs_vi_fv[i][k] == val) {
                        goto ring;
                    }
                }
                mmcs_vi_fv[i][mmcs_vi_nv[i]++] = val;
            }
        } else {
            mmcs_vi_nr[i]++;
        }
    }
ring:
    mmcs_vi_ring[mmcs_vi_ring_i].off = (uint32_t)off;
    mmcs_vi_ring[mmcs_vi_ring_i].val = val;
    mmcs_vi_ring[mmcs_vi_ring_i].is_w = (uint8_t)is_w;
    mmcs_vi_ring_i = (mmcs_vi_ring_i + 1) % ARRAY_SIZE(mmcs_vi_ring);
}

void mmcs_vi_census_dump(void)
{
    if (!mmcs_vi_census) {
        return;
    }
    fprintf(stderr, "MMCS-VI-CENSUS t=%" PRId64 "ms\n",
            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL));
    /* per-4K-block summary */
    for (unsigned b = 0; b < 0x10000u / 0x1000u; b++) {
        uint64_t r = 0, w = 0;
        for (unsigned k = 0; k < 0x1000 / 4; k++) {
            r += mmcs_vi_nr[b * 0x400 + k];
            w += mmcs_vi_nw[b * 0x400 + k];
        }
        if (r || w) {
            fprintf(stderr, "  block +%04x: R=%llu W=%llu\n", b * 0x1000,
                    (unsigned long long)r, (unsigned long long)w);
        }
    }
    /* per-register detail, capped */
    int shown = 0, more = 0;
    for (unsigned i = 0; i < MMCS_VI_NT; i++) {
        if (!mmcs_vi_nr[i] && !mmcs_vi_nw[i]) {
            continue;
        }
        if (shown++ < 48) {
            fprintf(stderr, "  reg +%04x: R=%u W=%u vals {", i * 4,
                    mmcs_vi_nr[i], mmcs_vi_nw[i]);
            for (int k = 0; k < mmcs_vi_nv[i]; k++) {
                fprintf(stderr, "%s%08x", k ? "," : "", mmcs_vi_fv[i][k]);
            }
            fprintf(stderr, "}\n");
        } else {
            more++;
        }
    }
    if (more) {
        fprintf(stderr, "  (%d more registers with traffic)\n", more);
    }
    /* ring tail: the most recent 24 events, oldest first */
    fprintf(stderr, "  ring:");
    for (int k = ARRAY_SIZE(mmcs_vi_ring) - 24;
         k < ARRAY_SIZE(mmcs_vi_ring); k++) {
        if (k < 0) {
            continue;
        }
        int idx = (mmcs_vi_ring_i + k) % ARRAY_SIZE(mmcs_vi_ring);
        fprintf(stderr, " %c%04x=%08x", mmcs_vi_ring[idx].is_w ? 'W' : 'R',
                mmcs_vi_ring[idx].off, mmcs_vi_ring[idx].val);
    }
    fprintf(stderr, "\n");
}

void mmcs_vi_census_tick(void *opaque)
{
    mmcs_vi_census_dump();
    QEMUTimer *t = timer_new_ms(QEMU_CLOCK_VIRTUAL, mmcs_vi_census_tick, NULL);
    timer_mod(t, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 60000);
}
