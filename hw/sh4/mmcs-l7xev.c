/*
 * MMCS fork (device split lane, 2026-11-28 — peer review M2c, split #8):
 * the L7x/L84 event-delivery SCAN bodies — the equal-priority starvation
 * re-arm, the kill-path cleanup, the lost-MakeRun requeue, the walker
 * dead-owner loop-exit, the wait-retry churn release, the standing-expiry
 * reap, the G4b create-release — extracted VERBATIM from hw/sh4/mmcs.c
 * (pure code motion, zero behavior change; validated by
 * tests/qtest/mmcs-l7xev-test.c + the byte-stability gates). Decode
 * history: the S219-S267 rung ladder.
 */
#include "qemu/osdep.h"
#include "hw/sh4/mmcs-l7xev.h"
#include "exec/cpu-common.h"
#include "qemu/timer.h"

/* the channel entry layout (the mmcs.c owner defines the struct; this
 * mirror must stay field-compatible — the pollsys law) */

void mmcs_l84cr_scan(void)
{
    if (!mmcs_l84cr_armed || mmcs_l84cr_total >= mmcs_l84cr_max_deliv) {
        return;
    }
    static uint32_t cad;
    if ((++cad & 0x1FF) == 0) {
        fprintf(stderr, "MMCS-L84CR-REJ cad=%u nohrec=%u nocinfo=%u nomagic=%u "
                "noht=%u norefs=%u noobj=%u xchk=%u signed=%u intr=%u notman=%u "
                "linked=%u\n", cad, mmcs_l84cr_rej[0], mmcs_l84cr_rej[1],
                mmcs_l84cr_rej[2], mmcs_l84cr_rej[3], mmcs_l84cr_rej[4],
                mmcs_l84cr_rej[5], mmcs_l84cr_rej[6], mmcs_l84cr_rej[7],
                mmcs_l84cr_rej[8], mmcs_l84cr_rej[9], mmcs_l84cr_rej[10]);
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    if (prun != 0) {
        return;                       /* only a BUSY run queue blocks */
    }
    /* THE V4 SCAN (the static4 child's design: the tightened L26
     * shape + the epoch gate). THE 4-BYTE STRIDE LAW applies. */
    for (uint32_t o = 0x4; o + 0x210 <= sizeof arena; o += 4) {
        uint32_t st16, ctxpc, sp, bf, rec, w1f8;
        memcpy(&st16, arena + o + 0x0c, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&sp, arena + o + 0xb0, 4);
        uint8_t bf_b = arena[o + 0xF];
        bf = bf_b;
        memcpy(&rec, arena + o + 0x14c, 4);
        memcpy(&w1f8, arena + o + 0x1f8, 4);
        uint32_t tva = 0x90680000 + o;
        if (ctxpc != 0x90837cf6 || (st16 & 3) != 2 || bf != 2
            || w1f8 != 0
            || sp < 0xD0000000u || sp >= 0xD1000000u
            || tva == pcur) {
            continue;
        }
        /* THE RECORD-POSITION LAW: [th+0x14C] == sp+0x18 */
        if (rec != sp + 0x18) {
            continue;
        }
        /* THE WB RESOLUTION: wb = [th+0x34]; fallback sp+0x28 */
        uint32_t wb = 0;
        memcpy(&wb, arena + o + 0x34, 4);
        if (wb < sp + 0x28 || wb >= sp + 0xB8) {
            wb = sp + 0x28;
        }
        uint32_t pa_wb_pre = wb - 0xC0000000u;
        /* THE OWNERSHIP WITNESS: [wb+0x1C] == the TCB (the kstack PA
         * read: the wb is a D0 VA) */
        uint32_t owner = 0;
        cpu_physical_memory_read(wb - 0xC0000000u + 0x1C,
                                 (uint8_t *)&owner, 4);
        if (owner != tva) {
            continue;
        }
        /* THE EPOCH GATE: word[wb+0x1A] == word[th+0x42] (the
         * stale-guard + the idempotence) */
        uint16_t wb_epoch = 0, th_epoch = 0;
        cpu_physical_memory_read(wb - 0xC0000000u + 0x1A,
                                 (uint8_t *)&wb_epoch, 2);
        memcpy(&th_epoch, arena + o + 0x42, 2);
        if (wb_epoch != th_epoch) {
            continue;
        }
        /* THE V5 OBJECT LAYER (the static6 child's design — the
         * handle-table entry resolution; the object side FIRST: the
         * v4's re-wait cycle was the UNSIGNALED interlock) */
        uint32_t hrec = 0;
        /* probe the entry cells: [parksp+0xE4] (the single class),
         * [parksp+0xF4] (the multi class, entry[0] — the create-lane) */
        uint32_t pa_sp = sp - 0xC0000000u;
        cpu_physical_memory_read(pa_sp + 0xE4, (uint8_t *)&hrec, 4);
        if (!(hrec >= 0x90680000u && hrec < 0x90800000u)) {
            cpu_physical_memory_read(pa_sp + 0xF4, (uint8_t *)&hrec, 4);
        }
        if (!(hrec >= 0x90680000u && hrec < 0x90800000u)) {
            mmcs_l84cr_rej[0]++; continue;
        }
        uint32_t hrec_pa = 0x10000000u + (hrec - 0x90680000u);
        uint32_t cinfo = 0;
        cpu_physical_memory_read(hrec_pa + 8, (uint8_t *)&cinfo, 4);
        if (!(cinfo >= 0x90820000u && cinfo < 0x90830000u)) {
            mmcs_l84cr_rej[1]++; continue;
        }
        uint32_t magic = 0;
        cpu_physical_memory_read(0x10000000u + (cinfo - 0x90600000u),
                                 (uint8_t *)&magic, 4);
        if (magic != 0x544E5645u) {
            mmcs_l84cr_rej[2]++; continue;
        }
        uint8_t ht_class = 0;
        cpu_physical_memory_read(0x10000000u + (cinfo - 0x90600000u) + 5,
                                 &ht_class, 1);
        if (ht_class != 4) {
            mmcs_l84cr_rej[3]++; continue;
        }
        uint32_t refs = 0;
        cpu_physical_memory_read(hrec_pa + 0x10, (uint8_t *)&refs, 4);
        if (refs < 1) {
            mmcs_l84cr_rej[4]++; continue;
        }
        uint32_t obj = 0;
        cpu_physical_memory_read(hrec_pa + 0xC, (uint8_t *)&obj, 4);
        if (!(obj >= 0x90680000u && obj < 0x90800000u)) {
            mmcs_l84cr_rej[5]++; continue;
        }
        /* THE CROSS-CHECK: obj == [wb+0x14] (the park-time object cell) */
        uint32_t wobj = 0;
        cpu_physical_memory_read(pa_wb_pre + 0x14, (uint8_t *)&wobj, 4);
        if (wobj != obj) {
            mmcs_l84cr_rej[6]++; continue;
        }
        /* THE OWED-SET GATES */
        uint32_t obj_pa = 0x10000000u + (obj - 0x90680000u);
        uint8_t setb = 0, obj8e = 0;
        uint32_t intr = 0, linked = 0;
        cpu_physical_memory_read(obj_pa + 0x8D, &setb, 1);
        cpu_physical_memory_read(obj_pa + 0x8E, &obj8e, 1);
        cpu_physical_memory_read(obj_pa + 0x90, (uint8_t *)&intr, 4);
        cpu_physical_memory_read(obj_pa + 8, (uint8_t *)&linked, 4);
        if (setb != 0) {
            mmcs_l84cr_rej[7]++; continue;
        }
        if (intr != 0) {
            mmcs_l84cr_rej[8]++; continue;
        }
        if ((obj8e & 4) || !(obj8e & 1)) {
            mmcs_l84cr_rej[9]++; continue;
        }
        if (linked != 0) {
            mmcs_l84cr_rej[10]++; continue;
        }
        /* THE OBJECT WRITES (the stock order, the SET FIRST) */
        cpu_physical_memory_write(obj_pa + 0x8D, &(uint8_t){ 1 }, 1);
        uint8_t mark = 0;
        cpu_physical_memory_read(0x0867ABB7, &mark, 1);
        cpu_physical_memory_write(obj_pa + 0x8F, &mark, 1);

        /* THE V4 WRITE SET (the 0x90827bfc BLOCKED-arm set, stock
         * order; all waiter-side — NO object writes) */
        uint32_t pa_th = 0x10000000 + o;
        uint32_t pa_wb = wb - 0xC0000000u;
        uint32_t pa_rec = rec - 0xC0000000u;

        uint32_t lp34 = 0;
        memcpy(&lp34, arena + o + 0x34, 4);
        /* 1. [wb+0xC] := 0 (the unlink mark) */
        cpu_physical_memory_write(pa_wb + 0xC, &(uint32_t){ 0u }, 4);
        /* 2. [record+4] := [th+0x34] (the lpProxy captured) */
        cpu_physical_memory_write(pa_rec + 4, &lp34, 4);
        /* 3. [record+8] := [th+0x1F8] (0) */
        cpu_physical_memory_write(pa_rec + 8, &(uint32_t){ 0u }, 4);
        /* 4. [th+0x34] := 0 (the drain) */
        cpu_physical_memory_write(pa_th + 0x34, &(uint32_t){ 0u }, 4);
        /* 5. word[th+0x42]++ (the epoch bump) */
        uint32_t wc = 0;
        memcpy(&wc, arena + o + 0x42, 4);
        wc++;
        cpu_physical_memory_write(pa_th + 0x42, &wc, 4);
        /* 6. [th+0x74] := 0x1000 (THE VERDICT) */
        cpu_physical_memory_write(pa_th + 0x74,
                                  &(uint32_t){ 0x1000u }, 4);
        /* 7. st16 := (st16 & ~3) | 3 (NEEDSRUN; the wake overwrites) */
        uint32_t st_new = (st16 & ~3u) | 3u;
        cpu_physical_memory_write(pa_th + 0x0C, &st_new, 4);
        /* THE WAKE (the L62/L54 recipe: the stub + the L16-ent) */
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L54_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L54_STUB_VA && slot_cur != 0x90822e40) {
            fprintf(stderr, "MMCS-L84CR: slot busy (%08x) - retry\n",
                    slot_cur);
            return;
        }
        cpu_physical_memory_write(0x1F00E600, mmcs_l54_stub,
                                  sizeof mmcs_l54_stub);
        cpu_physical_memory_write(0x1F00E600 + 0x88, &tva, 4);
        cpu_physical_memory_write(0x1F00E600 + 0x84,
                                  &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 },
                                  4);
        cpu_physical_memory_write(0x1F00E6F0,
                                  &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 },
                                  4);
        if (slot_cur != MMCS_L54_STUB_VA) {
            cpu_physical_memory_write(MMCS_L54_SLOT_PA,
                                      &(uint32_t){ MMCS_L54_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[7];
        e->evt_va = tva;
        e->stub_va = MMCS_L54_STUB_VA;
        e->evt_code = 0x320;
        e->slot_pa = MMCS_L54_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l84cr_total++;
        fprintf(stderr, "MMCS-L84CR: t=%" PRId64 "ms V4 KCall-satisfy "
                "%u/%u: waiter %08x (sp %08x wb %08x rec %08x epoch %u) "
                "- the 0x90827bfc write set + the v9 wake\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL),
                mmcs_l84cr_total, mmcs_l84cr_max_deliv,
                tva, sp, wb, rec, wb_epoch);
        return;                       /* one delivery per cadence */
    }
}

void mmcs_l84sr_scan(void)
{
    if (!mmcs_l84sr_armed || mmcs_l84sr_total >= mmcs_l84sr_max_deliv) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0, pick = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    if (prun != 0) {
        return;   /* L84: only a BUSY run queue blocks the recovery; the
                   * S244 terminal (pick = the arena base, prun = 0) is
                   * exactly the world this knob exists to repair */
    }
    (void)pick;
    (void)pcur;
    /* THE STRIDE LAW (rev2's lesson: ZERO miss-prints = the scan never
     * saw the waiters): the arena's TCBs are 4-byte-scattered
     * (0x...24/0x...0c/0x...18 — heap-style allocation, NO 0x40
     * alignment). Iterate at 4; the shape gates filter. */
    static int ncad;
    if (ncad++ < 10) {
        /* rev3's lesson: STILL zero hits AND zero misses — census the
         * arena's BLOCKED population at the scan time: what ctxpcs the
         * waiters actually sit at in the FRESH-run world (the snapshot
         * showed 0x90837cf6; the run may differ) */
        int nface = 0, nblocked = 0;
        uint32_t first3[3] = {0, 0, 0};
        for (uint32_t o = 0x4; o + 0x200 <= sizeof arena; o += 4) {
            uint32_t st, pc;
            memcpy(&st, arena + o + 0x0c, 4);
            memcpy(&pc, arena + o + 0xb4, 4);
            if ((st & 3) == 2 && st != 0x2 && pc >= 0x90800000u
                && pc < 0x908C0000u) {
                nblocked++;
                if (pc == 0x90837cf6) {
                    nface++;
                }
                for (int k = 0; k < 3; k++) {
                    if (!first3[k]) { first3[k] = pc; break; }
                }
            }
        }
        fprintf(stderr, "MMCS-L84SR(census): t=%" PRId64 "ms arena "
                "BLOCKED(kernel-pc)=%d at-face=%d first-pcs "
                "{%08x %08x %08x}\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL),
                nblocked, nface, first3[0], first3[1], first3[2]);
    }
    int nface_visit = 0;
    for (uint32_t o = 0x4; o + 0x200 <= sizeof arena; o += 4) {
        uint32_t st16, ctxpc, sp, wobj;
        memcpy(&st16, arena + o + 0x0c, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&sp, arena + o + 0xb0, 4);
        memcpy(&wobj, arena + o + 0x148, 4);
        uint32_t tva = 0x90680000 + o;
        /* the waiter shape: BLOCKED at the DoWait face, the D0 kstack,
         * the wait-object linked, NOT the current thread */
        uint32_t w144 = 0;
        memcpy(&w144, arena + o + 0x144, 4);
        /* THE COUNT-DIAG VERDICT (rev4): the fresh world's face-waiters
         * carry EMPTY wait quads (w144/w148 = 0 — the wait state lives
         * on-stack, the L26's node class) and MAIN's object at
         * 0x9060f000 (BELOW the old 0x9066 gate). VARIANT A NEEDS NO
         * OBJECT (no object writes!) — the wait-res gate DROPS; the
         * handle = the w144 (whatever it holds, incl. 0 = the benign
         * unlock arg). THE SHAPE = {face, BLOCKED, D0-sp, != pcur}. */
        if (ctxpc != 0x90837cf6 || (st16 & 3) != 2
            || sp < 0xD0000000u || sp >= 0xD1000000u
            || tva == pcur) {
            if (ctxpc == 0x90837cf6 && (st16 & 3) == 2) {
                nface_visit++;
                if (nface_visit <= 6) {
                    fprintf(stderr, "MMCS-L84SR(miss): t=%" PRId64 "ms th "
                            "%08x SHAPE {sp %08x wobj %08x w144 %08x} "
                            "- sp/pcur gate\n",
                            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva,
                            sp, wobj, w144);
                }
            }
            continue;
        }
        if (wobj < 0x90600000u || wobj >= 0x90780000u) {
            wobj = w144;   /* the empty/low-arena class: the handle cell */
        }
        /* THE WITNESS LAW (rev6): the zero zone = BELOW the sp (the
         * S243 census: [sp-0x30..sp+0x30] zeroed — the wait-frame
         * region); the +0x30 probe hit the intact CALLER frames and
         * rejected every waiter. Probe [sp-0x20..sp+0x10). */
        uint32_t pa_sp = sp - 0xC0000000u;
        uint32_t probe[8] = {0};
        cpu_physical_memory_read(pa_sp - 0x20, probe, 32);
        uint32_t nz = 0;
        for (int i = 0; i < 8; i++) {
            if (probe[i]) { nz++; }
        }
        if (nz != 0) {
            continue;                 /* not the zeroed-frame class */
        }
        /* THE STABILITY LAW (rev5): the pcur ROTATION makes each scan's
         * qualifying waiter DIFFER (the cycling scheduler) — the
         * 2-cadence keyed-single-thread never accumulates. The shape
         * gates ({face, BLOCKED, D0-sp, !=pcur} + the zeroed witness)
         * are the guard; deliver on the first stable sighting. */
        if (mmcs_l84sr_key == tva) {
            mmcs_l84sr_stable++;
        } else {
            mmcs_l84sr_key = tva;
            mmcs_l84sr_stable = 1;
        }
        (void)mmcs_l84sr_stable;
        /* THE CALLER RETURN (the per-waiter class): the start cell
         * [th+0x84]-based fallback; the RunApps/FS family default */
        uint32_t start = 0;
        memcpy(&start, arena + o + 0x84, 4);
        uint32_t caller_ret = 0x9083e250;   /* the RunApps/FS class */
        if (start >= 0x9083e100u && start < 0x9083e900u) {
            caller_ret = 0x9083e250;
        }
        /* VARIANT A — the kstack words */
        cpu_physical_memory_write(pa_sp + 0xB8,
                                  &(uint32_t){ 0x90837f70u }, 4);
        cpu_physical_memory_write(pa_sp + 0xE4, &wobj, 4);
        cpu_physical_memory_write(pa_sp + 0xE8, &caller_ret, 4);
        /* the TCB ctx preloads (the v8/v9 family) */
        cpu_physical_memory_write(0x10000000 + o + 0x94, &tva, 4);
        cpu_physical_memory_write(0x10000000 + o + 0x74,
                                  &(uint32_t){ 0x1000u }, 4);
        cpu_physical_memory_write(0x10000000 + o + 0x98,
                                  &(uint32_t){ sp + 0x28u }, 4);
        cpu_physical_memory_write(0x10000000 + o + 0xA0,
                                  &(uint32_t){ 0x908230e6u }, 4);
        cpu_physical_memory_write(0x10000000 + o + 0xA4,
                                  &(uint32_t){ sp + 0x18u }, 4);
        cpu_physical_memory_write(0x10000000 + o + 0xB8,
                                  &(uint32_t){ 0x40008000u }, 4);
        /* the wInfo NEEDSLEEP clear + the aftermath pair */
        uint16_t wi = 0;
        memcpy(&wi, arena + o + 0x0c, 2);
        wi &= ~(1u << 14);
        cpu_physical_memory_write(0x10000000 + o + 0x0C, &wi, 2);
        cpu_physical_memory_write(0x10000000 + o + 0x1F8,
                                  &(uint32_t){ 0u }, 4);
        cpu_physical_memory_write(0x10000000 + o + 0x1FC,
                                  &(uint32_t){ 0x1000u }, 4);
        cpu_physical_memory_write(0x10000000 + o + 0x34,
                                  &(uint32_t){ 0u }, 4);
        cpu_physical_memory_write(0x10000000 + o + 0xF,
                                  &(uint32_t){ 0u }, 1);
        /* THE v9 WAKE (the L62 recipe verbatim: the L54 stub + the slot
         * + the L16-ent injection) */
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L54_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L54_STUB_VA && slot_cur != 0x90822e40) {
            fprintf(stderr, "MMCS-L84SR: slot evt 0x320 busy (%08x)"
                    " - retry next cadence\n", slot_cur);
            return;
        }
        cpu_physical_memory_write(0x1F00E600, mmcs_l54_stub,
                                  sizeof mmcs_l54_stub);
        cpu_physical_memory_write(0x1F00E600 + 0x88, &tva, 4);
        cpu_physical_memory_write(0x1F00E600 + 0x84,
                                  &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 },
                                  4);
        cpu_physical_memory_write(0x1F00E6F0,
                                  &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 },
                                  4);
        if (slot_cur != MMCS_L54_STUB_VA) {
            cpu_physical_memory_write(MMCS_L54_SLOT_PA,
                                      &(uint32_t){ MMCS_L54_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[7];
        e->evt_va = tva;
        e->stub_va = MMCS_L54_STUB_VA;
        e->evt_code = 0x320;
        e->slot_pa = MMCS_L54_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l84sr_total++;
        mmcs_l84sr_stable = 0;
        fprintf(stderr, "MMCS-L84SR: t=%" PRId64 "ms resume-frame "
                "synthesis %u/%u: waiter %08x (sp %08x obj %08x, the "
                "zeroed frame rebuilt: pr=%08x handle=%08x ret=%08x; "
                "ctx preloaded; the v9 wake armed) face-visits %d\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL),
                mmcs_l84sr_total, mmcs_l84sr_max_deliv,
                tva, sp, wobj, 0x90837f70u, wobj, caller_ret,
                nface_visit);
        return;                       /* one delivery per cadence */
    }
}

/* ... the L72 stub decode comment (the run boundary cut it mid-comment):
 * exclusive: L52 wants the FROZEN epilogue (st16&3)==0 at
 * 0x90837ae8, L72 the BLOCKED consumed-completion eval tail; both
 * write their own copy at delivery), dispatch slot evt 0x2E0
 * (PA 0x0867A05C, ents[5]). Env MMCS_L72EV (default OFF;
 * MMCS_L72EV_MS cadence default 2000; MMCS_L72EV_MAX cap default 2).
 * Needs MMCS_KILLSTK + MMCS_TICK. */
static uint8_t mmcs_l72_stub[] = {
    0x86, 0x2f, 0x96, 0x2f, 0xa6, 0x2f, 0xb6, 0x2f,
    0xc6, 0x2f, 0xd6, 0x2f, 0x22, 0x4f, 0x10, 0xd4,
    0x43, 0x50, 0x02, 0xc8, 0x38, 0x89, 0x01, 0xc8,
    0x36, 0x8b, 0x7e, 0xe0, 0x08, 0x40, 0x4e, 0x02,
    0x28, 0x22, 0x31, 0x8b, 0x10, 0xe1, 0x18, 0x41,
    0x04, 0x70, 0x4e, 0x02, 0x10, 0x32, 0x2b, 0x8b,
    0x25, 0xe0, 0x08, 0x40, 0x4e, 0x08, 0x04, 0x70,
    0x4e, 0x09, 0x04, 0x70, 0x4e, 0x0a, 0x04, 0x70,
    0x4e, 0x0b, 0x04, 0x70, 0x4e, 0x0c, 0x04, 0x70,
    0x4e, 0x0d, 0x03, 0xa0, 0x09, 0x00, 0x09, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0xe2, 0x0d, 0xd1,
    0x22, 0x21, 0x0e, 0xd4, 0x0e, 0xd2, 0x42, 0x22,
    0x0e, 0xd2, 0x22, 0x6e, 0x00, 0xe0, 0x04, 0xe2,
    0x0d, 0xd1, 0x22, 0x21, 0x0d, 0xd2, 0x0b, 0x42,
    0x09, 0x00, 0x05, 0xe2, 0x0c, 0xd1, 0x22, 0x21,
    0x26, 0x4f, 0xf6, 0x6d, 0xf6, 0x6c, 0xf6, 0x6b,
    0xf6, 0x6a, 0xf6, 0x69, 0x0b, 0x00, 0xf6, 0x68,
    0xf6, 0xaf, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe4, 0x5e, 0x82, 0x90, 0x00, 0x00, 0x00, 0x00,
    0xa4, 0xef, 0x67, 0x88, 0x94, 0x98, 0x67, 0x88,
    0x00, 0x00, 0x00, 0x00, 0x68, 0x2b, 0x82, 0x90,
    0x00, 0x00, 0x00, 0x00,
};
#define MMCS_L72_STUB_VA   0xBF00E400
#define MMCS_L72_SLOT_PA   0x0867A05C   /* evt 0x2E0, idx 5 (L52-shared) */

void mmcs_l72_scan(void)
{
    if (!mmcs_l72_armed || mmcs_l72_total >= mmcs_l72_max_deliv) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0, pick = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    for (uint32_t o = 0; o + 0x220 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, ctxpc, ctxsp, f1f8, t1fc;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&ctxsp, arena + o + 0xb0, 4);
        memcpy(&f1f8, arena + o + 0x1f8, 4);
        memcpy(&t1fc, arena + o + 0x1fc, 4);
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000
            || tva != pcur                     /* THE discriminator */
            || (st16 & 3) != 2                 /* BLOCKED */
            || f1f8 != 0                       /* entry consumed */
            || t1fc != 0x1000                  /* cached completion */
            || ctxpc < 0x90837800              /* the wait-eval tail */
            || ctxpc >= 0x90838000             /* window */
            /* the dead-idle world gate: pick==0 (nothing queued) OR
             * pick==tva (the drain2 keep-current bookkeeping) —
             * someone ELSE's pick = vendor world mid-flight, skip */
            || (pick != 0 && pick != tva)
            || prun != 0) {
            continue;
        }
        /* 2-cadence stability keyed {thread,ctxpc} (the L46/L52
         * discipline — the shape must persist across scans) */
        uint32_t key = tva ^ ctxpc;
        if (mmcs_l72_key != key) {
            mmcs_l72_key = key;
            mmcs_l72_stable = 1;
            fprintf(stderr, "MMCS-L72: t=%" PRId64 "ms post-park shape "
                    "seen: th %08x *CUR* BLOCKED st16=%08x ctxpc=%08x "
                    "sp=%08x f1f8=%08x t1fc=%08x (stability %u/2)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, st16,
                    ctxpc, ctxsp, f1f8, t1fc, mmcs_l72_stable);
            return;
        }
        if (++mmcs_l72_stable < 2) {
            return;
        }
        /* DELIVER — first THE LEAK REPAIR (the S223 recipe item (i),
         * live-caught: the L52 hand-off's protocol stores
         * {[0x88679884]:=1, [0x88679888]:=1} STAND LEAKED after the
         * walker's continuation re-parks — every later switcher
         * entry then calls the cNest==1 completion drain 0x90826f4c,
         * whose own MakeRun on the pick re-inserts the still-banded
         * thread; the sorted-insert walk at 0x90825f7e-92 never
         * exits on the equal-priority self-link (the walk spin,
         * 100s+ observed). The park-shape gates make a legit
         * in-flight KCall impossible here (pick==0 && pRunnable==0
         * && the pCurTh-consumed-completion shape) — clear both
         * cells to the stock idle state). Then install, THEN patch
         * the pools (the L36 order). */
        cpu_physical_memory_write(0x08679884, &(uint32_t){ 0 }, 4);
        cpu_physical_memory_write(0x08679888, &(uint32_t){ 0 }, 4);
        cpu_physical_memory_write(0x1F00E400, mmcs_l72_stub,
                                  sizeof mmcs_l72_stub);
        cpu_physical_memory_write(0x1F00E400 + 0x50, &tva, 4);
        cpu_physical_memory_write(0x1F00E400 + 0x94, &tva, 4);
        uint32_t maddr = MMCS_L72_STUB_VA + 0xf0;
        cpu_physical_memory_write(0x1F00E400 + 0x8c, &maddr, 4);
        cpu_physical_memory_write(0x1F00E400 + 0xa0, &maddr, 4);
        cpu_physical_memory_write(0x1F00E400 + 0xa8, &maddr, 4);
        cpu_physical_memory_write(0x1F00E4F0, &maddr, 4);
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L72_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L72_STUB_VA) {
            if (slot_cur != 0x90822e40) {
                fprintf(stderr, "MMCS-L72: slot evt 0x2e0 busy (%08x) - "
                        "scan skipped\n", slot_cur);
                return;
            }
            cpu_physical_memory_write(MMCS_L72_SLOT_PA,
                                      &(uint32_t){ MMCS_L72_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[5];
        e->evt_va = tva;
        e->stub_va = MMCS_L72_STUB_VA;
        e->evt_code = 0x2E0;
        e->slot_pa = MMCS_L72_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l72_total++;
        fprintf(stderr, "MMCS-L72: t=%" PRId64 "ms post-park completion "
                "hand-off %u/%u: th %08x *CUR* BLOCKED ctxpc=%08x "
                "(the leak repair cNest/dwKCRes := 0 + pick + r0:=0 + "
                "the switcher resume; markers at %08x)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l72_total,
                mmcs_l72_max_deliv, tva, ctxpc, MMCS_L72_STUB_VA + 0xf0);
        return;                     /* one delivery per cadence */
    }
    /* no post-park shape this scan — reset the stability tracker */
    mmcs_l72_key = 0;
    mmcs_l72_stable = 0;
}

/* MMCS fork (L75/S226): the POST-KILL ORPHAN HAND-OFF — the daemon half
 * of MMCS_L75TX (the exception-boundary half lives in target/sh4/helper.c:
 * the dying-thread forward's dead address-space exit). DECODE (live, the
 * l75_census2 + l75_ho tapes on the l74-chain restore + MMCS_L75TX): the
 * kill lands and the scheduler IDLES (pc 0x908089fe, CurMSec ~960/s) with
 * pick == 0, pRunnable == 0, sleepHead == 0 — an EMPTY world. pCurTh is
 * the killed ZOMBIE (st16 02000018, ctxpc 0x9083c102 = KillThread's tail,
 * ctxsp on the KILLSTK page: the stock switcher's idle path never touches
 * pCurTh) and the launcher 0x906ca240 is an ORPHANED BLOCKED thread — the
 * L52/L54/L72 class (st16 020000e2, ctxpc 0x908378d8 = the wait-eval
 * tail, the consumed completion {f1f8 0, f1fc 0x1000}, in NO list: slnk 0,
 * wobj 0), byte-identical to its l74-chain cells: the L74CR wake stub took
 * the CPU from the launcher mid sleep-insert (the evt-0x320 interrupt
 * hit it at spc 0x908263e6 inside the insert walk) and its node was never
 * linked. The standing MMCS_L72EV hand-off is gated on tva == pCurTh —
 * behind a zombie it can never fire. DELIVERED HERE: when the world is
 * the dead-idle zombie shape and exactly this orphan park shape stands
 * (2-cadence stability), pCurTh := the orphan (ONE host write to
 * [0x88679894]) and the standing L72 daemon delivers its own hand-off on
 * its next cadence (the L72 stub/recipe verbatim — nothing new runs).
 * Env MMCS_L75TX (default off; needs MMCS_L72EV with budget —
 * MMCS_L72EV_MAX); MMCS_L75HO_MS cadence default 500, MMCS_L75HO_MAX cap
 * default 4. */
void mmcs_l75ho_scan(void)
{
    if (!mmcs_l75ho_armed || mmcs_l75ho_total >= mmcs_l75ho_max_deliv
        || !mmcs_l72_armed) {
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t pcur = 0, pick = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    /* the dead-idle world: nothing queued, nothing picked */
    if (prun != 0 || pick != 0
        || pcur < 0x90680000 || pcur >= 0x90680000 + sizeof arena - 0x220) {
        return;
    }
    /* pCurTh must be the killed zombie: DYING (0x18) with its context
     * parked on the KILLSTK page (the kill continuation's stack) */
    uint32_t po = pcur - 0x90680000;
    uint32_t zst = 0, zsp = 0;
    memcpy(&zst, arena + po + 0xc, 4);
    memcpy(&zsp, arena + po + 0xb0, 4);
    if ((zst & 0x18) != 0x18 || zsp < 0xBF000000 || zsp >= 0xBF010000) {
        return;
    }
    for (uint32_t o = 0; o + 0x220 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, klow, st16, ctxpc, f1f8, t1fc, slnk, wobj;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&klow, arena + o + 0x2c, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&f1f8, arena + o + 0x1f8, 4);
        memcpy(&t1fc, arena + o + 0x1fc, 4);
        memcpy(&slnk, arena + o + 0x144, 4);
        memcpy(&wobj, arena + o + 0x14c, 4);
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || klow < 0xD0000000 || klow >= 0xDC000000
            || tva == pcur
            || (st16 & 3) != 2                 /* BLOCKED */
            || f1f8 != 0                       /* entry consumed */
            || t1fc != 0x1000                  /* cached completion */
            || ctxpc < 0x90837800              /* the wait-eval tail */
            || ctxpc >= 0x90838000             /* window (the L72 pair) */
            || slnk != 0                       /* in no sleep list */
            || wobj != 0) {                   /* no wait object */
            continue;
        }
        /* 2-cadence stability keyed {thread,ctxpc} */
        uint32_t key = tva ^ ctxpc;
        if (mmcs_l75ho_key != key) {
            mmcs_l75ho_key = key;
            mmcs_l75ho_stable = 1;
            fprintf(stderr, "MMCS-L75TX: post-kill orphan shape seen: th %08x "
                    "BLOCKED st16=%08x ctxpc=%08x behind zombie pCurTh %08x "
                    "(stability %u/2)\n", tva, st16, ctxpc, pcur,
                    mmcs_l75ho_stable);
            return;
        }
        if (++mmcs_l75ho_stable < 2) {
            return;
        }
        /* DELIVER — one write: pCurTh := the orphan; the standing L72
         * daemon (same tick chain, after this scan) does the rest */
        cpu_physical_memory_write(0x08679894, &tva, 4);
        mmcs_l75ho_total++;
        fprintf(stderr, "MMCS-L75TX: post-kill orphan hand-off %u/%u: pCurTh "
                "%08x (killed zombie) := %08x (the orphaned launcher park "
                "ctxpc=%08x); the MMCS_L72EV daemon delivers next cadence\n",
                mmcs_l75ho_total, mmcs_l75ho_max_deliv, pcur, tva, ctxpc);
        return;
    }
    mmcs_l75ho_key = 0;
    mmcs_l75ho_stable = 0;
}

/* MMCS fork (L76/S227): MMCS_L76EV — THE EQUAL-PRIORITY STARVATION
 * RE-ARM (the cNest one-byte delivery; decoded 2026-11-24, the
 * recycled-servant lane).
 *
 * THE DECODE (Observed: l76_census2 + probes 1-10 + the hotblocks
 * aggregate on the l75-postkill restore; Verified: ROM disasm + the
 * wince500 mirror): the post-kill world holds TWO threads — the
 * launcher 0x906ca240 (inside the JIT-launch waiter UserDbgTrap/
 * FUN_90839f90, polling SC_ProcGetCode(pi.hProcess) == STILL_ACTIVE
 * with Sleep(250)) and the RECYCLED TCB 0x906a3c38 = the JIT
 * DEBUGGER's primary thread (CreateProcess'd by the launcher's own
 * second-chance set-84 0x234 exception; process Q 0x9068f958, hProc
 * 0x00e70002, start [th+0x150] = ThreadStart 0x90835f14). The
 * debugger thread stands RUNNABLE at prio 0xfb (the launcher's own —
 * inherited, never boosted) at the band-31 head [0x8867F024] with
 * well-formed FIFO links — and NEVER gets the CPU (356/356 samples =
 * the launcher):
 *
 *  (α) the law: equal priority never preempts — MakeRun/CreateThread
 *      write pick only on STRICT outrank (semantics-map §3; the
 *      vendor's FUN_9082611c FIFO-tail insert for equals);
 *  (β) the monopoly: the launcher's KCall'd sleep-insert walk spins
 *      at ~1.6M it/s (the S224 signature; the L74EV reap unlinks the
 *      re-created self-link ~5x/s but the loop re-submits within one
 *      iteration);
 *  (γ) the gate: the OUTER KCall return's resched check at
 *      0x9082304c — cNest [0x88679885] == 1 -> [0x88679884] word :=
 *      1 -> bra 0x90822b0a (the pre-switcher save) -> THE SWITCHER.
 *      Live cNest == 0x00 always, so the bf is taken and the
 *      switcher/drain2/MakeRun/ThreadStart/OEMIdle each executed ZERO
 *      times in a 12 s hotblocks window. Nothing in this world sets
 *      cNest: the tick's resched-consider is dropped at rte, MakeRun
 *      never runs (no wakes), the quantum never expires, and a bare
 *      [0x88679888] := 1 is consumed without a switch (probe9).
 *
 * THE DELIVERY (probe10, live-proven): ONE byte, cNest := 1. The very
 * next outer KCall return takes the vendor's own gate -> the
 * pre-switcher save -> the switcher -> the idle path -> drain2 (floor
 * [0x8867a9fc] = 0xff >= band 0xfb -> pick := the queue head) -> THE
 * STARVED THREAD RUNS. On HW this is the quantum-expiry resched the
 * monopolist's never-completing KCall starves here.
 *
 * GATE (the starvation shape, 2-cadence stable): a RUNNABLE
 * (st16 low2 == 1) thread at the run-band head [0x8867efa0] that is
 * NOT pCurTh, does NOT outrank it (prio byte >= pCurTh's — if it
 * outranked, stock's own outrank tail would have fired), pick == 0
 * and cNest == 0. Both TCBs must live in the kernel-arena VA window
 * (0x88600000..0x90800000, VA-0x80000000 == PA).
 *
 * Env MMCS_L76EV (default off); MMCS_L76EV_MS cadence default 500,
 * MMCS_L76EV_MAX cap default 4. */
void mmcs_l76_scan(void)
{
    if (!mmcs_l76_armed || mmcs_l76_total >= mmcs_l76_max_deliv) {
        return;
    }
    uint32_t pcur = 0, pick = 0, prun = 0, kd84 = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    cpu_physical_memory_read(0x08679884, &kd84, 4);
    /* the starvation shape: a queued non-current candidate, no pick,
     * and the KCall-return gate un-armed */
    if (prun == 0 || prun == pcur || pick != 0
        || ((kd84 >> 8) & 0xff) != 0
        || prun < 0x88600000 || prun >= 0x90800000
        || pcur < 0x88600000 || pcur >= 0x90800000) {
        mmcs_l76_key = 0;
        mmcs_l76_stable = 0;
        return;
    }
    uint32_t pst = 0, pw = 0, cst = 0, cw = 0;
    cpu_physical_memory_read(prun - 0x80000000 + 0x0C, &pst, 4);
    cpu_physical_memory_read(prun - 0x80000000 + 0x40, &pw, 4);
    cpu_physical_memory_read(pcur - 0x80000000 + 0x40, &cw, 4);
    cpu_physical_memory_read(pcur - 0x80000000 + 0x0C, &cst, 4);
    uint8_t cand_prio = (pw >> 8) & 0xff;    /* [th+0x41] */
    uint8_t cur_prio = (cw >> 8) & 0xff;
    /* RUNNABLE candidate that does NOT outrank the current (equal or
     * lower priority; stock handles outrank itself) and a current
     * thread still in the running/transition states (low2 != 2-only
     * parked-blocked is fine — the stale-mark class runs BLOCKED) */
    if ((pst & 3) != 1 || cand_prio < cur_prio || (cst & 3) == 3) {
        mmcs_l76_key = 0;
        mmcs_l76_stable = 0;
        return;
    }
    uint32_t key = pcur ^ prun;
    if (mmcs_l76_key != key) {
        mmcs_l76_key = key;
        mmcs_l76_stable = 1;
        fprintf(stderr, "MMCS-L76: starvation shape seen: pCurTh %08x "
                "(prio %02x, st16 %08x) monopolizes while band head %08x "
                "(prio %02x, st16 %08x) RUNNABLE, pick 0, cNest 0 "
                "(stability %u/2)\n",
                pcur, cur_prio, cst, prun, cand_prio, pst,
                mmcs_l76_stable);
        return;
    }
    if (++mmcs_l76_stable < 2) {
        return;
    }
    /* DELIVER — one byte: cNest := 1; the vendor's own KCall-return
     * gate (0x9082304c) then routes to the pre-switcher save, the
     * switcher, the idle-path drain and pick := the band head */
    uint8_t one = 1;
    cpu_physical_memory_write(0x08679885, &one, 1);
    mmcs_l76_total++;
    fprintf(stderr, "MMCS-L76: equal-priority starvation re-arm %u/%u: "
            "cNest [0x88679885] := 1 (pCurTh %08x prio %02x vs band head "
            "%08x prio %02x) — the vendor KCall-return gate reschedules\n",
            mmcs_l76_total, mmcs_l76_max_deliv, pcur, cur_prio,
            prun, cand_prio);
    mmcs_l76_key = 0;
    mmcs_l76_stable = 0;
}

/* MMCS fork (L77/S228): MMCS_L77EV — THE KILL-PATH API-LOCK CLEANUP
 * RELEASE (the dying thread's lock-ownership clear; decoded
 * 2026-11-24, the userdbgtrap-churn lane).
 *
 * THE DECODE (Observed: l77_census/probes 1-9 + the high-cadence RSP
 * sampling on the l76-rearm restore; Verified: ROM disasm + the
 * wince500 mirror): the L76 world's "UserDbgTrap churn" is NOT in
 * UserDbgTrap — the launcher 0x906ca240 is on ITS OWN DEATH PATH. Its
 * unhandled second-chance set-84 exception (code 0xC0000005 parked at
 * TCB+0x38) ran the vendor chain (exception dispatcher -> UserDbgTrap
 * FUN_90839f90 -> the JIT-debugger CreateProcess + poll), the poll is
 * PAST, and the kill continuation FUN_9083be50 called its API-LOCK
 * CLEANUP fn_9083adfc (xref: the ONLY caller), whose loop
 * KCall(fn_90826f20 = "[pCurTh+0x164] ? that-crit : mark+0") waits for
 * the ownership transfer that fn_90828a08 performs only when the
 * owner cell pair [crit+0x98]+{0,+4} (= 0x8867adf4/0x8867adf4+4, the
 * KData API-lock owner cells) names the CURRENT thread
 * ([KData+8]|1, stocked by the switcher at 0x90822bc4 on every real
 * switch). Live: the cells read {1, 1} (the loop's own mark) vs
 * hCurTh|1 = 0x5c0003 — the E-branch transfer can never fire because
 * NO thread will ever acquire the dead API set's lock again, and the
 * stale waiter mark halfword[crit+0x96] == 0x8000 (the L74-era
 * deadlock residue) keeps the loop on the E branch instead of the
 * no-waiter D branch. The loop spins at KCall rate forever: A PARK
 * INSIDE THE VENDOR'S OWN DEATH MACHINERY.
 *
 * THE DELIVERY (probe8, live-proven): ONE word, [pCurTh+0x164] := 0.
 * The very next poll takes fn_90826f20's own zero path (it sets the
 * released-mark halfword[pCurTh+12] |= 0x10 itself and returns 0), the
 * loop exits through the vendor tail (F = 0x9082bbb4, G = 0x9082bc84),
 * the kill continuation proceeds and the death LANDS (ctxpc reaches
 * the kill-epilogue grave 0x9083c102, st16 0x020000d8) — the world
 * settles into the healthy tick-driven dead-idle (OEMIdle drain
 * cycling, no cascade, no exception storm). On HW the transfer chain
 * completes because live threads re-acquire the API lock constantly;
 * the stock-shape clear is what the vendor machinery reaches through
 * that chain.
 *
 * GATE (2-cadence stable): pCurTh = a kernel-arena TCB carrying a
 * DEATH CODE ([th+0x38] & 0xF0000000 == 0xC0000000, the NTSTATUS
 * fatal class) + the DYING mark (st16 [th+0xC] bit 0x08 — the L75
 * DYING vocabulary) + a standing lock ownership [th+0x164] = an arena
 * crit whose halfword[+0x96] == 0x8000 (the E-branch mark) and whose
 * owner pair [+0x98] lands in KData with the transfer condition
 * standing FALSE ([owner+4] != [th+0x3C]|1 — if it named the current
 * thread, the vendor's own transfer branch would fire; never
 * compete with it).
 *
 * Env MMCS_L77EV (default off); MMCS_L77EV_MS cadence default 500,
 * MMCS_L77EV_MAX cap default 4. */
void mmcs_l77_scan(void)
{
    if (!mmcs_l77_armed || mmcs_l77_total >= mmcs_l77_max_deliv) {
        return;
    }
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    if (pcur < 0x88600000 || pcur >= 0x90800000) {
        mmcs_l77_key = 0;
        mmcs_l77_stable = 0;
        return;
    }
    uint32_t pa = pcur - 0x80000000;
    uint32_t crit = 0, st16 = 0, code = 0, hth = 0;
    cpu_physical_memory_read(pa + 0x164, &crit, 4);
    cpu_physical_memory_read(pa + 0x0C, &st16, 4);
    cpu_physical_memory_read(pa + 0x38, &code, 4);
    cpu_physical_memory_read(pa + 0x3C, &hth, 4);
    /* the dying-with-an-exception witness: the death code + the
     * DYING bit (the L75 0x02000008 vocabulary; the cleanup-world
     * launcher reads 0x020000c8) */
    if (crit < 0x88600000 || crit >= 0x90800000
        || ((code & 0xF0000000) != 0xC0000000)
        || !(st16 & 0x08)) {
        mmcs_l77_key = 0;
        mmcs_l77_stable = 0;
        return;
    }
    uint16_t hw96 = 0;
    uint32_t pown = 0, own2 = 0;
    cpu_physical_memory_read(crit - 0x80000000 + 0x96, &hw96, 2);
    cpu_physical_memory_read(crit - 0x80000000 + 0x98, &pown, 4);
    if (hw96 != 0x8000 || pown < 0x88600000 || pown >= 0x90800000) {
        mmcs_l77_key = 0;
        mmcs_l77_stable = 0;
        return;
    }
    cpu_physical_memory_read(pown - 0x80000000 + 4, &own2, 4);
    /* the transfer condition standing false: if the owner cell already
     * named hCurTh|1 the vendor's own transfer branch (fn_90828a08
     * 0x90828a28) would fire — do not compete with the vendor path */
    if (own2 == ((hth | 1) & 0xFFFFFFFF)) {
        mmcs_l77_key = 0;
        mmcs_l77_stable = 0;
        return;
    }
    uint32_t key = pcur ^ crit;
    if (mmcs_l77_key != key) {
        mmcs_l77_key = key;
        mmcs_l77_stable = 1;
        fprintf(stderr, "MMCS-L77: kill-path cleanup shape seen: pCurTh "
                "%08x (st16 %08x, code %08x) holds crit %08x "
                "{hw96 %04x, owner %08x/%08x vs hTh %08x} "
                "(stability %u/2)\n",
                pcur, st16, code, crit, hw96, pown, own2, hth,
                mmcs_l77_stable);
        return;
    }
    if (++mmcs_l77_stable < 2) {
        return;
    }
    /* DELIVER — one word: [pCurTh+0x164] := 0; the vendor's own next
     * poll (KCall fn_90826f20) takes its zero path (the released-mark
     * halfword |= 0x10 is ITS write), the cleanup loop exits through
     * the vendor tail and the death completes */
    uint32_t zero = 0;
    cpu_physical_memory_write(pa + 0x164, &zero, 4);
    mmcs_l77_total++;
    fprintf(stderr, "MMCS-L77: kill-path cleanup release %u/%u: "
            "[pCurTh+0x164] := 0 (pCurTh %08x crit %08x code %08x; the "
            "vendor zero-path exit -> the death lands)\n",
            mmcs_l77_total, mmcs_l77_max_deliv, pcur, crit, code);
    mmcs_l77_key = 0;
    mmcs_l77_stable = 0;
}

/* MMCS fork (L78/S229): MMCS_L78EV — THE LOST-MAKERUN REQUEUE (the
 * stock empty-queue head-path delivery for a RUNNABLE-marked thread
 * off the run queue; decoded 2026-11-25, the post-dead-world lane).
 *
 * THE DECODE (Observed: l78_census/probe1..3 on the l77-postdeath
 * restore; Verified: ROM disasm of MakeRun 0x90825ee4 + the semantics
 * map §3): the post-death world parks in the healthy tick-driven
 * dead-idle with pCurTh = the zombie launcher, pick = 0 and pRunnable
 * [0x8867efa0] = 0 — while the sibling 0x906dc000 (the KITL worker,
 * start cell [th+0x150] = 0x90845b78 kitl.dll) sits RUNNABLE-marked
 * (st16 low2 == 1) at the multi-wait face 0x90837cf6 (FUN_90837bcc),
 * SELF-LINKED (+0x154/+0x158 == th — the insert's thread-side writes
 * survived) but with EVERY band head cell 0: the second half of its
 * MakeRun (the band-head + pRunnable writes) was lost in the kills'
 * aftermath. The L76EV gate reads prun == 0 so it can never fire.
 * THE STOCK SHAPE (MakeRun's empty-queue head fast path, disasm:
 * [th+0x148] := 0; band_head[prio>>3] := th at 0x8867efa8+4*band;
 * pRunnable := th; SetReschedule dwKCRes := 1 when pick == 0) —
 * delivered, the idle drain's pick scan (FUN_90827148, walks the
 * pRunnable +0x144 chain for the first RUNNABLE) computes pick := th
 * and the switcher 0x90822b68 resumes it through 100% vendor code.
 * LIVE-PROVEN (l78_probe2/3): the sibling runs its wait-return walk
 * and EXITS CLEANLY (the grave 0x9083c102, death code [th+0x38] = 0,
 * no fault, no serial, sp unwound past the kitl start frame, the
 * world stays in the healthy dead-idle).
 *
 * GATE (2-cadence stable): the dead-idle world (pRunnable == 0 and
 * pick in {0, pCurTh}) + an arena TCB, NOT pCurTh, RUNNABLE-marked
 * (st16 low2 == 1), self-linked +0x154/+0x158, its band head cell 0,
 * a sane prio byte — and (the absent-counterparty honesty) the wait
 * face ctxpc in FUN_90837bcc's window [0x90837c00, 0x9083800) with
 * the verdict cell [th+0x74] == 0 (a satisfied/cached wait verdict —
 * the resume is the vendor's own wait-return path). Arena scan
 * 0x90680000..0x90700000, first match.
 *
 * Env MMCS_L78EV (default off); MMCS_L78EV_MS cadence default 500,
 * MMCS_L78EV_MAX cap default 4. */
void mmcs_l78_scan(void)
{
    if (!mmcs_l78_armed || mmcs_l78_total >= mmcs_l78_max_deliv) {
        return;
    }
    uint32_t pcur = 0, pick = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    /* the dead-idle world: nobody queued, nothing picked */
    if (prun != 0 || (pick != 0 && pick != pcur)) {
        mmcs_l78_key = 0;
        mmcs_l78_stable = 0;
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    uint32_t cand = 0, cst16 = 0, cprio = 0;
    for (uint32_t o = 0; o + 0x220 <= sizeof arena; o += 4) {
        uint32_t st16, ctxpc, w74, l154, l158;
        memcpy(&st16, arena + o + 0x0c, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&w74, arena + o + 0x74, 4);
        memcpy(&l154, arena + o + 0x154, 4);
        memcpy(&l158, arena + o + 0x158, 4);
        uint32_t tva = 0x90680000 + o;
        uint8_t prio = arena[o + 0x41];
        if ((st16 & 3) != 1                       /* RUNNABLE-marked */
            || tva == pcur                        /* not the current */
            || l154 != tva || l158 != tva         /* self-linked */
            || prio == 0                          /* sane prio byte */
            || ctxpc < 0x90837C00                 /* the wait face */
            || ctxpc >= 0x90838000
            || w74 != 0) {                        /* satisfied verdict */
            continue;
        }
        uint32_t bh = 0;
        cpu_physical_memory_read(0x0867EFA8 + 4 * (prio >> 3), &bh, 4);
        if (bh != 0) {
            continue;                             /* band occupied */
        }
        cand = tva;
        cst16 = st16;
        cprio = prio;
        break;
    }
    if (!cand) {
        mmcs_l78_key = 0;
        mmcs_l78_stable = 0;
        return;
    }
    if (mmcs_l78_key != cand) {
        mmcs_l78_key = cand;
        mmcs_l78_stable = 1;
        fprintf(stderr, "MMCS-L78: lost-MakeRun shape seen: candidate "
                "%08x (st16 %08x, prio %02x, band %u head 0, pRunnable "
                "0, pick %08x) (stability %u/2)\n",
                cand, cst16, cprio, cprio >> 3, pick, mmcs_l78_stable);
        return;
    }
    if (++mmcs_l78_stable < 2) {
        return;
    }
    /* DELIVER — the stock MakeRun empty-queue head fast path: the
     * thread-side self-links and the RUNNABLE mark are already in
     * place; the missing words are the queue-side ones */
    uint32_t zero = 0, one = 1;
    cpu_physical_memory_write(cand - 0x80000000 + 0x148, &zero, 4);
    cpu_physical_memory_write(0x0867EFA8 + 4 * (cprio >> 3), &cand, 4);
    cpu_physical_memory_write(0x0867EFA0, &cand, 4);
    cpu_physical_memory_write(0x08679888, &one, 4);
    mmcs_l78_total++;
    fprintf(stderr, "MMCS-L78: lost-MakeRun requeue %u/%u: [band%u head] "
            ":= %08x, [pRunnable] := %08x, dwKCRes := 1 (st16 %08x prio "
            "%02x) — the vendor idle-drain pick scan + switcher resume\n",
            mmcs_l78_total, mmcs_l78_max_deliv, cprio >> 3, cand, cand,
            cst16, cprio);
    mmcs_l78_key = 0;
    mmcs_l78_stable = 0;
}

/* MMCS fork (L79/S230): MMCS_L79EV — THE TERMINATION WALKER'S
 * DEAD-OWNER LOOP-EXIT (the sibling's crit-face completion; decoded
 * 2026-11-25, the crit-face lane).
 *
 * THE DECODE (Observed: l79_probe1..6 on the l78-parkedpair restore;
 * Verified: ROM disasm of the walker FUN_90840754): the sibling
 * 0x906dc000 (BLOCKED + DYING, st16 0x0200004a) parks at the crit face
 * 0x90840814 INSIDE the PROCESS-TERMINATION WALKER FUN_90840754 (its
 * ONLY caller FUN_908383c8 = the kill-everything continuation; the
 * entry gate [param_1+0x98] == param_2). The walker walks the thread
 * list terminating threads and its loop tail (0x9084084a-62) compares
 * [param_2+4] (the wait-node's OWNER HANDLE) against [KData+8]
 * (hCurTh, the switcher-stocked current-thread handle) — the loop
 * exits only when the CURRENT thread's handle equals the node's
 * owner. THE REGISTER MAPPING (live-proven, probe5 — the rung-4 note
 * RETRACTED: its save-block words were the CALLEE's registers):
 * r8 = param_1 = 0x906ff75c (the arena thread-proxy object), r10 =
 * param_2 = 0x8867eaa0 = THE KDATA WAIT-NODE GLOBAL {+0 count,
 * +4 owner hTh, +8 obj, ...} — the same object the S127/L8 pool
 * decode found (0x90836014 -> 0x8867eaa0, the 0x908383c8
 * creation/kill family's param_2).
 *
 * THE STALL: the node's owner cell reads 0xe80002 = THE PARKED DBG
 * THREAD's hTh (the L78 parked pair's other half — BLOCKED at its own
 * wait-eval tail, never becoming current), while the walk runs ON THE
 * SIBLING: on every wake the sibling executes the tail with hCurTh =
 * 0x4e0002 != 0xe80002 = the compare NEVER matches and the loop
 * re-enters the blocking KCall — the walker churns at KCall rate
 * (probe5's pc/ctxpc census: the tail's queue-unlink 0x90827964, the
 * wait-submit 0x90828784, the case-1 calls 0x9083d358/0x90828924)
 * with ctxpc pinned at the face. In stock the OWNER thread runs its
 * own walk and the compare matches first-past; our post-kill world
 * shuffled the walk onto the sibling's context (the L75-class
 * ownership divergence).
 *
 * THE DELIVERY (live-proven, probe6): ONE WORD — [0x8867eaa0+4] :=
 * the runner's own hTh — plus the L78-style requeue (the st16
 * RUNNABLE re-mark + band head + pRunnable + dwKCRes). The vendor
 * machinery then does everything: the pick scan switches to the
 * runner (hCurTh := its hTh), the resumed walk executes the tail, the
 * compare MATCHES, the exit call (pool 0x908408b8 = 0x90827b94) runs,
 * the node's owner cell CLEARS ITSELF (the stock wait-node teardown
 * consuming the match — live-caught: 0x4e0002 -> 0), and the
 * termination completes: THE GRAVE 0x9083c102 (st16 0x02000058, sp
 * unwound, no fault, no serial) in ~2 s.
 *
 * GATE (2-cadence stable): the stale-pCurTh world (pCurTh an arena
 * TCB; pRunnable == 0 and pick in {0, pCurTh}) + the self-witnessed
 * node ([0x8867EAA0+8] = an arena object whose [+0x98] ==
 * 0x8867EAA0 — the entry-gate relation) + the owner [0x8867EAA0+4] =
 * the hTh of a PARKED arena thread (found by scan, (st16&3)==2, NOT
 * pCurTh — the owner cannot become current) + a RUNNER arena TCB
 * (scan, first match) with ctxpc in the walker window [0x90840754,
 * 0x90840880), (st16&3)==2 BLOCKED at the walker's blocking KCall,
 * the DYING mark (st16 bit 0x08), a sane prio byte, and its own band
 * head cell 0.
 *
 * Env MMCS_L79EV (default off); MMCS_L79EV_MS cadence default 500,
 * MMCS_L79EV_MAX cap default 4. */
void mmcs_l79_scan(void)
{
    if (!mmcs_l79_armed || mmcs_l79_total >= mmcs_l79_max_deliv) {
        return;
    }
    uint32_t pcur = 0, pick = 0, prun = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    cpu_physical_memory_read(0x0867EFA0, &prun, 4);
    if (pcur < 0x90680000 || pcur >= 0x90780000
        || prun != 0 || (pick != 0 && pick != pcur)) {
        mmcs_l79_key = 0;
        mmcs_l79_stable = 0;
        return;
    }
    /* the self-witnessed KData wait-node */
    uint32_t node = 0x8867EAA0u;
    uint32_t obj = 0, gate = 0, owner = 0;
    cpu_physical_memory_read(node - 0x80000000 + 8, &obj, 4);
    if (obj < 0x90680000 || obj >= 0x90780000) {
        mmcs_l79_key = 0;
        mmcs_l79_stable = 0;
        return;
    }
    cpu_physical_memory_read(obj - 0x80000000 + 0x98, &gate, 4);
    cpu_physical_memory_read(node - 0x80000000 + 4, &owner, 4);
    if (gate != node || owner == 0) {
        mmcs_l79_key = 0;
        mmcs_l79_stable = 0;
        return;
    }
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    /* the owner: a PARKED arena thread (BLOCKED — it cannot execute the
     * walk even when it is the STALE pCurTh, the parked-pair world's
     * exact shape: the DBG parked BLOCKED as the current thread) */
    int owner_parked = 0;
    for (uint32_t o = 0; o + 0x220 <= sizeof arena; o += 4) {
        uint32_t h, st;
        memcpy(&h, arena + o + 0x3c, 4);
        memcpy(&st, arena + o + 0x0c, 4);
        if (h == owner && (st & 3) == 2) {
            owner_parked = 1;
            break;
        }
    }
    if (!owner_parked) {
        mmcs_l79_key = 0;
        mmcs_l79_stable = 0;
        return;
    }
    /* the runner: BLOCKED + DYING at the walker face, off-queue */
    uint32_t runner = 0, rst16 = 0, rprio = 0, rhth = 0;
    for (uint32_t o = 0; o + 0x220 <= sizeof arena; o += 4) {
        uint32_t st16, ctxpc, hth, l154, l158;
        memcpy(&st16, arena + o + 0x0c, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&hth, arena + o + 0x3c, 4);
        memcpy(&l154, arena + o + 0x154, 4);
        memcpy(&l158, arena + o + 0x158, 4);
        uint32_t tva = 0x90680000 + o;
        uint8_t prio = arena[o + 0x41];
        if ((st16 & 3) != 2                       /* BLOCKED */
            || !(st16 & 0x08)                     /* DYING */
            || tva == pcur
            || hth == owner                       /* not the owner */
            || ctxpc < 0x90840754                 /* the walker window */
            || ctxpc >= 0x90840880
            || prio == 0
            || l154 != tva || l158 != tva) {      /* self-linked residue */
            continue;
        }
        uint32_t bh = 0;
        cpu_physical_memory_read(0x0867EFA8 + 4 * (prio >> 3), &bh, 4);
        if (bh != 0) {
            continue;
        }
        runner = tva;
        rst16 = st16;
        rprio = prio;
        rhth = hth;
        break;
    }
    if (!runner) {
        mmcs_l79_key = 0;
        mmcs_l79_stable = 0;
        return;
    }
    if (mmcs_l79_key != runner) {
        mmcs_l79_key = runner;
        mmcs_l79_stable = 1;
        fprintf(stderr, "MMCS-L79: walker dead-owner shape seen: runner "
                "%08x (st16 %08x, prio %02x, hTh %08x) at the face, node "
                "%08x owner %08x (a parked thread) (stability %u/2)\n",
                runner, rst16, rprio, rhth, node, owner, mmcs_l79_stable);
        return;
    }
    if (++mmcs_l79_stable < 2) {
        return;
    }
    /* DELIVER — the loop-exit word + the L78-style requeue */
    uint32_t zero = 0, one = 1;
    uint32_t runnable = (rst16 & 0xFFFF0000) | ((rst16 & 0xFFFC) | 1);
    cpu_physical_memory_write(node - 0x80000000 + 4, &rhth, 4);
    cpu_physical_memory_write(runner - 0x80000000 + 0x0C, &runnable, 4);
    cpu_physical_memory_write(runner - 0x80000000 + 0x148, &zero, 4);
    cpu_physical_memory_write(0x0867EFA8 + 4 * (rprio >> 3), &runner, 4);
    cpu_physical_memory_write(0x0867EFA0, &runner, 4);
    cpu_physical_memory_write(0x08679888, &one, 4);
    mmcs_l79_total++;
    fprintf(stderr, "MMCS-L79: walker dead-owner loop-exit %u/%u: "
            "[node %08x +4] := %08x (the runner's hTh) + the requeue "
            "(st16 %08x -> RUNNABLE, band %u head, pRunnable, dwKCRes) — "
            "the vendor tail compare matches, the exit call runs, the "
            "node owner self-clears, the death lands at the grave\n",
            mmcs_l79_total, mmcs_l79_max_deliv, node, rhth, rst16,
            rprio >> 3);
    mmcs_l79_key = 0;
    mmcs_l79_stable = 0;
}

/* MMCS fork (L73/S224): MMCS_L73EV — THE CHURN LIVELOCK RELEASE (the
 * stale sleep-node self-link unlink; decoded 2026-11-24, the S224
 * wait-retry-churn lane).
 *
 * THE DECODE (Observed: l73_census.py + the hotblocks aggregate on the
 * l73-churn snapshot; Verified: ROM disasm): the L72 hand-off resumes
 * the launcher as the CURRENT thread, but the L52-era stub insert left
 * its node on the SLEEP LIST forever — head [0x8867ef8c] == th AND
 * [th+0x144] == th (the self-link; wake tick [th+0x1E8] = 0x6ffc,
 * ancient) — the same insert artifact whose run-queue half was the
 * L72 walk-spin engine. Every subsequent timed-wait submit
 * (fn_90828164 -> fn_908263cc, the `while (KCall(PutThreadToSleep) ||
 * GET_NEEDSLEEP)` loop face 0x908378ce) walks the sleep list to find
 * the insert position; the walk's tick compare ([cand+0x1E8] <
 * deadline) always advances to the candidate, L6440 sets cursor :=
 * candidate and returns 1 (re-evaluate) — with the candidate's next
 * pointing AT ITSELF the walk NEVER terminates: the launcher spins
 * 1.65M walk iterations/s INSIDE a KCall that never completes, so the
 * KCall tail / resched-now path is never reached — A SCHEDULER
 * MONOPOLY (no other thread can run, interrupts tick CurMSec but
 * bResched is only consumed at the KCall exit). The wait's deadline
 * still expires (fn_90828164 returns 0 when now >= deadline — the
 * observed ~2s re-poll cadence), so the livelock does not stop the
 * poll loop itself; it burns the CPU and starves the world.
 *
 * THE FIX: unlink the impossible-stock state. A CURRENT thread cannot
 * be a member of the sleep list (a sleeping thread is BLOCKED and off
 * pCurTh). Gates: pCurTh == t (an arena TCB) && [0x8867ef8c] == t &&
 * [t+0x144] == t && 2-cadence stability keyed {t, head, nxt}.
 * Delivery: [t+0x144] := 0 and [0x8867ef8c] := 0 host-side. The next
 * wait submit's walk then completes through 100% vendor code: the
 * empty-list insert path (L6532/L6562) parks the thread properly
 * (state16 := BLOCKED|0x20, [t+0x1E8] := deadline, dwReschedTime
 * min-update), dwKCRes := 1 -> the KCall tail resched-now -> the
 * switcher -> the world gets the CPU back. Env MMCS_L73EV (default
 * OFF; MMCS_L73EV_MS cadence default 1000; MMCS_L73EV_MAX cap
 * default 4). Needs MMCS_TICK. */
void mmcs_l73_scan(void)
{
    if (!mmcs_l73_armed || mmcs_l73_total >= mmcs_l73_max_deliv) {
        return;
    }
    uint32_t pcur = 0, pick = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    cpu_physical_memory_read(0x0867EFA4, &pick, 4);
    if (pcur < 0x90680000 || pcur >= 0x90780000) {
        return;                       /* not an arena thread */
    }
    uint32_t tpa = pcur - 0x80000000;
    uint32_t kbase = 0, ksz = 0, klow = 0;
    cpu_physical_memory_read(tpa + 0x20, &kbase, 4);
    cpu_physical_memory_read(tpa + 0x24, &ksz, 4);
    cpu_physical_memory_read(tpa + 0x2c, &klow, 4);
    if (kbase < 0xD0000000 || kbase >= 0xDC000000
        || ksz != 0x10000
        || klow < 0xD0000000 || klow >= 0xDC000000) {
        return;                       /* not a TCB shape */
    }
    uint32_t head = 0, nxt = 0;
    cpu_physical_memory_read(0x0867EF8C, &head, 4);
    cpu_physical_memory_read(tpa + 0x144, &nxt, 4);
    if (head != pcur) {
        mmcs_l73_key = 0;
        mmcs_l73_stable = 0;
        return;
    }
    /* THE UNIFIED STALE-NODE GATE (v4): the current thread is RUNNING
     * ((st16&3)!=2) while its own node sits at the sleep-list head
     * with an EXPIRED wake tick ([th+0x1E8] < CurMSec) — the node the
     * vendor's tick-bottom-half expiry (the fn1/L38TIMER lane) should
     * have reaped. Two live shapes: the L52-era SELF-LINK (nxt==th,
     * the walk-spin engine) and the RESURRECTED clean node (nxt==0,
     * re-created every poll cycle: the expired own node at the head
     * makes each fresh walk's tick-compare advance the cursor onto
     * it, and the r4!=0 insert path re-links th before itself).
     * A future-tick head==pcur belongs to a live park — skip (the
     * thread would be BLOCKED anyway). */
    uint32_t st16 = 0, wtick = 0, now = 0;
    cpu_physical_memory_read(tpa + 0xc, &st16, 4);
    cpu_physical_memory_read(tpa + 0x1E8, &wtick, 4);
    cpu_physical_memory_read(0x0867AAD0, &now, 4);
    int self_link = (nxt == pcur);
    if ((st16 & 3) == 2 || wtick >= now) {
        /* parked with a live node — stock; reset */
        mmcs_l73_key = 0;
        mmcs_l73_stable = 0;
        return;
    }
    uint32_t key = pcur ^ head ^ nxt;
    if (mmcs_l73_key != key) {
        mmcs_l73_key = key;
        mmcs_l73_stable = 1;
        fprintf(stderr, "MMCS-L73: t=%" PRId64 "ms stale sleep node seen: "
                "th %08x *CUR* head %08x nxt %08x%s tick %08x now %08x "
                "(stability %u/2)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), pcur, head, nxt,
                self_link ? " [self-link]" : " [expired-own-node]",
                wtick, now, mmcs_l73_stable);
        return;
    }
    if (++mmcs_l73_stable < 2) {
        return;
    }
    /* DELIVER v2: unlink the list cells AND the in-flight sleeper's
     * walk cursor. (v1 lesson, live-caught in the first A/B: the list
     * unlink alone is undone within ONE submit — the churn's last
     * L6440 left [sleeper+0] == th (the cursor == the thread itself);
     * the next submit's r4!=0 path (L651e -> L652e -> L6562) performs
     * "insert before the cursor": [th+0x144] := pCurTh == th — the
     * SELF-LINK RE-CREATED, then the walk spins against it again. The
     * sleeper is the wait-face frame at [th+0xB0]+0x10 (Verified: the
     * face 0x908378b0 prologue; live: sp 0xd00beaa4 -> sleeper
     * 0xd00beab4); its +0 must equal th for the clear to be safe
     * (self-evidencing gate — a cursor pointing anywhere else belongs
     * to a different, legitimate walk). */
    uint32_t ctxsp = 0, cursor = 0;
    cpu_physical_memory_read(tpa + 0xb0, &ctxsp, 4);
    int cursor_cleared = 0;
    if (ctxsp >= 0xD0000000 && ctxsp < 0xDC000000) {
        uint32_t spa = ctxsp - 0xC0000000 + 0x10;
        cpu_physical_memory_read(spa, &cursor, 4);
        if (cursor == pcur) {
            cpu_physical_memory_write(spa, &(uint32_t){ 0 }, 4);
            cpu_physical_memory_write(spa + 6, &(uint16_t){ 0 }, 2);
            cursor_cleared = 1;
        }
    }
    cpu_physical_memory_write(0x0867EF8C, &(uint32_t){ 0 }, 4);
    cpu_physical_memory_write(tpa + 0x144, &(uint32_t){ 0 }, 4);
    mmcs_l73_total++;
    fprintf(stderr, "MMCS-L73: t=%" PRId64 "ms stale sleep-node unlinked "
            "%u/%u: th %08x *CUR*%s ([0x8867ef8c] := 0, [th+0x144] := 0%s; "
            "the next wait submit parks through vendor code)\n",
            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l73_total,
            mmcs_l73_max_deliv, pcur, self_link ? " [self-link]"
            : " [expired-own-node reaped]",
            cursor_cleared ? ", sleeper cursor+flag := 0" :
            " (sleeper cursor not th — list-only)");
}

void mmcs_l74_scan(void)
{
    if (!mmcs_l74_armed) {
        return;
    }
    if (mmcs_l74_max_deliv && mmcs_l74_total >= mmcs_l74_max_deliv) {
        return;
    }
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    if (pcur < 0x90680000 || pcur >= 0x90780000) {
        return;                       /* not an arena thread */
    }
    uint32_t tpa = pcur - 0x80000000;
    uint32_t kbase = 0, ksz = 0, klow = 0;
    cpu_physical_memory_read(tpa + 0x20, &kbase, 4);
    cpu_physical_memory_read(tpa + 0x24, &ksz, 4);
    cpu_physical_memory_read(tpa + 0x2c, &klow, 4);
    if (kbase < 0xD0000000 || kbase >= 0xDC000000
        || ksz != 0x10000
        || klow < 0xD0000000 || klow >= 0xDC000000) {
        return;                       /* not a TCB shape */
    }
    uint32_t head = 0, nxt = 0;
    cpu_physical_memory_read(0x0867EF8C, &head, 4);
    cpu_physical_memory_read(tpa + 0x144, &nxt, 4);
    if (head != pcur) {
        mmcs_l74_key = 0;
        mmcs_l74_stable = 0;
        return;
    }
    uint32_t st16 = 0;
    cpu_physical_memory_read(tpa + 0xc, &st16, 4);
    /* THE RUNNING+OWN-NODE SIGNATURE (the L74 widening): a current
     * thread at the sleep-list head is impossible-stock at ANY tick
     * flavor. Shape A = the self-link (nxt == th, the walk-spin
     * engine, recreated every submit with a FUTURE [th+0x1E8] — the
     * exact window the L73 v4 expired-tick guard skipped) — NOTE the
     * st16 gate does NOT apply: the L72-resumed launcher carries a
     * STALE BLOCKED mark (live-caught in the first A/B: st16
     * 020000e2 while pCurTh executes the walk spin; the resume never
     * re-marks the state) — pCurTh-at-the-head IS the running fact.
     * Shape B = the expired own node (wtick < now) — the st16 gate
     * HOLDS here: a properly parked BLOCKED thread with a passed
     * deadline is the stock expiry case, not ours to unlink (orphan
     * risk); only the RUNNING mark makes it impossible-stock. */
    int self_link = (nxt == pcur);
    if (!self_link) {
        uint32_t wtick = 0, now = 0;
        if ((st16 & 3) == 2) {
            /* BLOCKED with a live node — a stock park */
            mmcs_l74_key = 0;
            mmcs_l74_stable = 0;
            return;
        }
        cpu_physical_memory_read(tpa + 0x1E8, &wtick, 4);
        cpu_physical_memory_read(0x0867AAD0, &now, 4);
        if (wtick >= now) {
            mmcs_l74_key = 0;
            mmcs_l74_stable = 0;
            return;
        }
    }
    uint32_t key = pcur ^ head ^ nxt;
    if (mmcs_l74_key != key) {
        mmcs_l74_key = key;
        mmcs_l74_stable = 1;
        fprintf(stderr, "MMCS-L74: t=%" PRId64 "ms standing-reap shape "
                "seen: th %08x *CUR* RUNNING head %08x nxt %08x%s "
                "(stability %u/2)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), pcur, head, nxt,
                self_link ? " [self-link]" : " [expired-own-node]",
                mmcs_l74_stable);
        return;
    }
    if (++mmcs_l74_stable < 2) {
        return;
    }
    /* DELIVER — the L73 v2 unlink, with the head SPLICE: a non-self
     * next keeps the tail ([0x8867ef8c] := nxt); the self-link/clean
     * node clears the head outright. The in-flight sleeper's walk
     * cursor ([th+0xB0]+0x10, gated == th — the v2 lesson: the stale
     * cursor re-creates the self-link within ONE submit) is cleared
     * first. */
    uint32_t ctxsp = 0, cursor = 0;
    cpu_physical_memory_read(tpa + 0xb0, &ctxsp, 4);
    int cursor_cleared = 0;
    if (ctxsp >= 0xD0000000 && ctxsp < 0xDC000000) {
        uint32_t spa = ctxsp - 0xC0000000 + 0x10;
        cpu_physical_memory_read(spa, &cursor, 4);
        if (cursor == pcur) {
            cpu_physical_memory_write(spa, &(uint32_t){ 0 }, 4);
            cpu_physical_memory_write(spa + 6, &(uint16_t){ 0 }, 2);
            cursor_cleared = 1;
        }
    }
    uint32_t newhead = self_link ? 0 : nxt;
    cpu_physical_memory_write(0x0867EF8C, &newhead, 4);
    cpu_physical_memory_write(tpa + 0x144, &(uint32_t){ 0 }, 4);
    mmcs_l74_total++;
    fprintf(stderr, "MMCS-L74: t=%" PRId64 "ms standing reap %u%s: th %08x "
            "*CUR* RUNNING%s ([0x8867ef8c] := %08x, [th+0x144] := 0%s; the "
            "walk completes through vendor code)\n",
            qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l74_total,
            mmcs_l74_max_deliv ? " (capped)" : " (standing)",
            pcur, self_link ? " [self-link]" : " [expired-own-node]",
            newhead,
            cursor_cleared ? ", sleeper cursor+flag := 0" :
            " (sleeper cursor not th — list-only)");
}

/* MMCS fork (L74/S225): MMCS_L74CR — THE REENTRANT API-SET-LOCK
 * DEADLOCK BREAK (the S225 recipe item (ii); decoded 2026-11-24 on
 * the l74-reap world). THE DECODE (Observed: the l74_svframe +
 * l74_owner probes; Verified: ROM disasm): the servant/devmgr thread
 * (the event 0x90699d68's owner = the SETTER the launcher's polled
 * wait needs) is BLOCKED at the crit-enter face ctxpc=0x90840814
 * after KCall(fn_90828924) — the block core (state16 low2 := 2,
 * dwKCRes := 1). THE LOCK: the crit record at 0x906ff598
 * {+0/+4: lpcs-self 906ff4ec, +8: 0x8000fb01 OWNED with the PI bytes
 * 0xfb, +0xC: 0x8867adf4 = &the KData owner-handle cell}; the owner
 * handle [0x8867adf8] = 0x005c0002 = THE LAUNCHER'S OWN HANDLE (the
 * ONLY arena TCB carrying it — alive, churning the poll). THE
 * REENTRANCY WITNESS: BOTH threads carry the set-84 dispatch arg
 * spill {[th+0x7C] = [slot84] = 0xd0050260, [th+0x80] = 0x234} and
 * the same saved pr 0x90843240 — the servant's enter sits inside
 * FUN_90843214's ACTIVATEPROC tail (fn_9082bc84 -> 0x90837244) just
 * like the launcher's wait: the caller HOLDS the API-set lock across
 * its PerformCallBack wait while the server-side handler needs the
 * SAME lock to service the call. Stock never holds this lock across
 * the PSL wait — the L63-era acquisition's release was destroyed by
 * the kills' aftermath. THE FIX (the L63 B1 composite, manufactured):
 * transfer the owner cell [waiter_r10 + 4] := the waiter's own
 * handle [th+0x3C] (the enter-tail's own compare: [r10+4] vs
 * [[0x8867ed64]+8] — the current-handle cell — EXITS AS THE OWNER
 * when equal; the woken waiter's own tail then clears [pcur+0x14C]
 * and walks the owned-tail through vendor code) + the v9 WAKE (the
 * L54 stub, evt 0x320, shared-channel guarded). Guards: the waiter
 * shape {arena TCB + ctxpc == 0x90840814 + (st16&3)==2 + the
 * dispatch spill pair} + THE DEADLOCK WITNESS (the owner handle ==
 * the pcur thread's OWN [pcur+0x3C] AND pcur carries the SAME
 * dispatch spill — a live owner that is itself mid-dispatch on the
 * same call: only this reentrant shape is ever released; a plain
 * live owner is NEVER manufactured) + 2-cadence stability. Env
 * MMCS_L74CR (default OFF; MMCS_L74CR_MS cadence default 2000;
 * MMCS_L74CR_MAX cap default 2; MMCS_L74CR_DIAG = the verbose
 * near-miss diag). Needs MMCS_TICK. */

void mmcs_l74cr_scan(void)
{
    if (!mmcs_l74cr_armed || mmcs_l74cr_total >= mmcs_l74cr_max_deliv) {
        return;
    }
    uint32_t pcur = 0;
    cpu_physical_memory_read(0x08679894, &pcur, 4);
    if (pcur < 0x90680000 || pcur >= 0x90780000) {
        return;
    }
    uint32_t po = pcur - 0x90680000;
    /* THE OWNER-SIDE WITNESS FIRST: pcur carries a dispatch spill (a
     * D0-window method-table pointer + the 0x234 offset). NOTE the
     * spill-vs-CELL comparison is deliberately avoided: the L74S4
     * stock-clear may legitimately have cleared the slot cell before
     * this scan's stability completes (the ab3 world-split lesson) —
     * the reentrancy witness is the TWO THREADS' spills matching,
     * whatever the cell reads. */
    uint32_t p_sp7c = 0, p_sp80 = 0, p_h3c = 0;
    cpu_physical_memory_read(0x10680000 + po + 0x7C, &p_sp7c, 4);
    cpu_physical_memory_read(0x10680000 + po + 0x80, &p_sp80, 4);
    cpu_physical_memory_read(0x10680000 + po + 0x3C, &p_h3c, 4);
    if (p_sp7c < 0xD0000000 || p_sp7c >= 0xDC000000 || p_sp80 != 0x234
        || (p_h3c & 0xff000000)) {
        if (mmcs_l74cr_diag) {
            fprintf(stderr, "MMCS-L74CR(diag): t=%" PRId64 "ms pcur %08x "
                    "not mid-dispatch {sp7c %08x sp80 %08x h3c %08x} - skip\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), pcur, p_sp7c,
                    p_sp80, p_h3c);
        }
        return;
    }
    /* scan for the waiter: the crit-enter park with the same spill */
    static uint8_t arena[0x80000];
    cpu_physical_memory_read(0x10680000, arena, sizeof arena);
    for (uint32_t o = 0; o + 0x220 <= sizeof arena; o += 4) {
        uint32_t kbase, ksz, st16, ctxpc, sp7c, sp80, h3c, r10;
        memcpy(&kbase, arena + o + 0x20, 4);
        memcpy(&ksz, arena + o + 0x24, 4);
        memcpy(&st16, arena + o + 0xc, 4);
        memcpy(&ctxpc, arena + o + 0xb4, 4);
        memcpy(&sp7c, arena + o + 0x7c, 4);
        memcpy(&sp80, arena + o + 0x80, 4);
        memcpy(&h3c, arena + o + 0x3c, 4);
        memcpy(&r10, arena + o + 0x9c, 4);
        uint32_t tva = 0x90680000 + o;
        if (kbase < 0xD0000000 || kbase >= 0xDC000000
            || ksz != 0x10000
            || ctxpc != 0x90840814     /* the crit-enter park face */
            || (st16 & 3) != 2
            || arena[o + 0xe] != 0     /* not suspended */
            || sp7c != p_sp7c || sp80 != 0x234
            || (h3c & 0xff000000) != 0
            || tva == pcur) {
            continue;
        }
        /* the owner cell = the waiter's own enter-tail compare cell */
        if (r10 < 0x88600000 || r10 >= 0x88700000) {
            if (mmcs_l74cr_diag) {
                fprintf(stderr, "MMCS-L74CR(diag): t=%" PRId64 "ms waiter "
                        "%08x r10 %08x not KData - skip\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, r10);
            }
            continue;
        }
        uint32_t owner_h = 0;
        cpu_physical_memory_read(r10 - 0x80000000 + 4, &owner_h, 4);
        if (owner_h != p_h3c) {
            /* not the reentrant pair — a foreign/live owner: NEVER
             * manufacture (the L62 law) */
            if (mmcs_l74cr_diag) {
                fprintf(stderr, "MMCS-L74CR(diag): t=%" PRId64 "ms waiter "
                        "%08x owner_h %08x != pcur handle %08x - not the "
                        "reentrant pair, skip\n",
                        qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, owner_h,
                        p_h3c);
            }
            continue;
        }
        /* 2-cadence stability keyed {waiter, owner} */
        uint32_t key = tva ^ (owner_h * 5);
        if (mmcs_l74cr_key != key) {
            mmcs_l74cr_key = key;
            mmcs_l74cr_stable = 1;
            fprintf(stderr, "MMCS-L74CR: t=%" PRId64 "ms reentrant API-lock "
                    "deadlock seen: waiter %08x (crit face, spill {slot84, "
                    "0x234}) vs owner pcur %08x h %08x - ALSO mid-dispatch "
                    "(stability %u/2)\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), tva, pcur, p_h3c,
                    mmcs_l74cr_stable);
            return;
        }
        if (++mmcs_l74cr_stable < 2) {
            return;
        }
        /* channel guards FIRST (the R23 ordering law) */
        if (mmcs_l16_ents[7].pending) {
            fprintf(stderr, "MMCS-L74CR: t=%" PRId64 "ms evt-0x320 wake "
                    "mid-flight - retry next cadence\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL));
            return;
        }
        uint32_t slot_cur = 0;
        cpu_physical_memory_read(MMCS_L54_SLOT_PA, &slot_cur, 4);
        if (slot_cur != MMCS_L54_STUB_VA && slot_cur != 0x90822e40) {
            fprintf(stderr, "MMCS-L74CR: t=%" PRId64 "ms slot evt 0x320 "
                    "busy (%08x) - retry next cadence\n",
                    qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), slot_cur);
            return;
        }
        if (mmcs_l74cr_diag) {
            fprintf(stderr, "MMCS-L74CR(diag): shape STABLE — would "
                    "transfer [%08x] := %08x and v9-wake %08x; diag mode, "
                    "no delivery\n", r10 + 4, h3c, tva);
            return;
        }
        /* DELIVER: THE TRANSFER (one write — the deadlock break; the
         * woken waiter's own enter tail reads [r10+4] == its current
         * handle and exits the loop as the owner through vendor
         * code) + THE V9 WAKE (the L54 recipe verbatim) */
        cpu_physical_memory_write(r10 - 0x80000000 + 4, &h3c, 4);
        cpu_physical_memory_write(0x1F00E600, mmcs_l54_stub,
                                  sizeof mmcs_l54_stub);
        cpu_physical_memory_write(0x1F00E600 + 0x88, &tva, 4);
        cpu_physical_memory_write(0x1F00E600 + 0x84,
                                  &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 }, 4);
        cpu_physical_memory_write(0x1F00E6F0,
                                  &(uint32_t){ MMCS_L54_STUB_VA + 0xf0 }, 4);
        if (slot_cur != MMCS_L54_STUB_VA) {
            cpu_physical_memory_write(MMCS_L54_SLOT_PA,
                                      &(uint32_t){ MMCS_L54_STUB_VA }, 4);
        }
        struct mmcs_l16_ent *e = &mmcs_l16_ents[7];
        e->evt_va = tva;
        e->stub_va = MMCS_L54_STUB_VA;
        e->evt_code = 0x320;
        e->slot_pa = MMCS_L54_SLOT_PA;
        e->daemon = 1;
        e->pending = 1;
        mmcs_l74cr_total++;
        fprintf(stderr, "MMCS-L74CR: t=%" PRId64 "ms reentrant API-lock "
                "deadlock broken %u/%u: waiter %08x takes the lock "
                "([%08x] := %08x, was the owner pcur %08x's %08x) + the "
                "v9 wake; the servant services the call -> the event SET "
                "path (markers at %08x)\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL), mmcs_l74cr_total,
                mmcs_l74cr_max_deliv, tva, r10 + 4, h3c, pcur, owner_h,
                MMCS_L54_STUB_VA + 0xf0);
        return;                     /* one delivery per cadence */
    }
}
