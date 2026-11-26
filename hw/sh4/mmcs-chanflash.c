/*
 * MMCS fork (device split lane, 2026-11-26 — peer review M2c, split #5):
 * the channel-flash blocks (0xF40000..0xFCFFFF, 5 x 128KB AMD-family NOR)
 * — extracted VERBATIM from hw/sh4/sh7777.c (pure code motion, zero
 * behavior change; validated by tests/qtest/mmcs-chanflash-test.c + the
 * byte-stability gates). Decode history: S78/S79 (the ch0 protocol).
 */
#include "qemu/osdep.h"
#include "hw/sh4/mmcs-chanflash.h"
#include "hw/sh4/sh7777.h"
#include "hw/sh4/sh.h"
#include "migration/vmstate.h"
#include "migration/register.h"
#include "exec/address-spaces.h"

/* ---- Channel flash blocks (0xF40000..0xFCFFFF) ----
 * 5 x 128KB AMD-family NOR. Observed protocol (logged): 16-bit
 *   0x30 @ block base = erase confirm (short AMD form, no unlock cycles)
 *   0x90 @ +0xAAA     = autoselect (reads: +0 maker, +2 device)
 *   0xF0 @ anywhere   = reset to read mode
 *   anything else     = program (bit-and)
 * Erase fills 0xFFFFFFFF instantly (driver polls for stable data). */
#define CHAN_N 5
#define CHAN_SZ (128 * 1024)
typedef struct ChanFlashState {
    uint8_t chan_flash[CHAN_N][CHAN_SZ];
    int chan_autoselect[CHAN_N];
} ChanFlashState;
static ChanFlashState chanflash_state;
static const hwaddr chan_base_table[CHAN_N] = {
    0xF40000, 0xF60000, 0xF80000, 0xFA0000, 0xFC0000
};

static uint64_t chanflash_read(void *opaque, hwaddr off, unsigned size)
{
    int c = (int)(intptr_t)opaque;
    uint64_t v = 0;
    if (chanflash_state.chan_autoselect[c]) {
        if (size == 2) {
            if (off == 0) return 0x0001;        /* AMD maker */
            if (off == 2) return 0x227e;        /* device (mirror r2d ids) */
            if (off == 4) return 0;             /* block protect */
        }
    }
    if (off + size <= CHAN_SZ) memcpy(&v, chanflash_state.chan_flash[c] + off, size);
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
            memset(chanflash_state.chan_flash[c], 0xff, CHAN_SZ);
            chanflash_state.chan_autoselect[c] = 0;
            /* S78/S79: the kernel erases ch0 then awaits a program phase
             * that never arrives (loader's job on real HW). Without a valid
             * sigstruct the channel-walker marks ch0 INVALID and the boot
             * stalls at '//'. Emulate the loader: restore the valid struct
             * right after the erase completes. */
            if (getenv("MMCS_CHAN_AUTORESTORE")) {
                uint32_t *m = (uint32_t *)chanflash_state.chan_flash[c];
                memset(chanflash_state.chan_flash[c], 0x00, 0x100);
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
        if (v16 == 0x90) { chanflash_state.chan_autoselect[c] = 1; return; }   /* autoselect */
        if (v16 == 0xf0) { chanflash_state.chan_autoselect[c] = 0; return; }   /* reset */
    }
    if (off + size > CHAN_SZ) return;
    /* program: AND into existing (NOR can only clear bits) */
    for (unsigned b = 0; b < size && off + b < CHAN_SZ; b++) {
        chanflash_state.chan_flash[c][off + b] &= ((uint8_t *)&val)[b];
    }
}

static const MemoryRegionOps chanflash_ops = {
    .read = chanflash_read,
    .write = chanflash_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
};

/* MMCS fork (savestate lane): the channel-flash blocks live in a
 * host-side array (no RAM MemoryRegion), so their content — including
 * kernel erase/program effects and the MMCS_CHAN_AUTORESTORE sigstruct
 * rewrites — must be streamed explicitly. NB: sh7777_init (the
 * CMT/INTC/CPG model above) is NOT wired into the mmcs machine
 * (mmcs.c implements its own polled syscon at the same bases); only
 * the chanflash block is live, so only it gets vmstate. */
static const VMStateDescription vmstate_chanflash = {
    .name = "mmcs/chanflash",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT8_2DARRAY(chan_flash, ChanFlashState, CHAN_N, CHAN_SZ),
        VMSTATE_INT32_ARRAY(chan_autoselect, ChanFlashState, CHAN_N),
        VMSTATE_END_OF_LIST()
    }
};

void mmcs_chanflash_init(void)
{
    for (int c = 0; c < CHAN_N; c++) {
        MemoryRegion *mr = g_new(MemoryRegion, 1);
        uint32_t *m = (uint32_t *)chanflash_state.chan_flash[c];
        memset(chanflash_state.chan_flash[c], 0xff, CHAN_SZ);
        /* loader-written signature struct at +0 (programmed 0s) */
        memset(chanflash_state.chan_flash[c], 0x00, 0x100);
        m[0] = 0xffffffff;
        m[12] = 0; m[13] = 0xffffffff;
        m[14] = 0; m[15] = 0xffffffff;
        m[23] = 0;
        memory_region_init_io(mr, NULL, &chanflash_ops, (void *)(intptr_t)c,
                              g_strdup_printf("mmcs.chan%d", c), CHAN_SZ);
        memory_region_add_subregion(get_system_memory(),
                                    chan_base_table[c], mr);
    }
    vmstate_register(NULL, 0, &vmstate_chanflash, &chanflash_state);
}
