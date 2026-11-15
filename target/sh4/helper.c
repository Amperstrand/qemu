/*
 *  SH4 emulation
 *
 *  Copyright (c) 2005 Samuel Tardieu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "exec/cpu-common.h"

#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/log.h"

#if !defined(CONFIG_USER_ONLY)
#include "hw/sh4/sh_intc.h"
#include "sysemu/runstate.h"
#endif

#define MMU_OK                   0
#define MMU_ITLB_MISS            (-1)
#define MMU_ITLB_MULTIPLE        (-2)
#define MMU_ITLB_VIOLATION       (-3)
#define MMU_DTLB_MISS_READ       (-4)
#define MMU_DTLB_MISS_WRITE      (-5)
#define MMU_DTLB_INITIAL_WRITE   (-6)
#define MMU_DTLB_VIOLATION_READ  (-7)
#define MMU_DTLB_VIOLATION_WRITE (-8)
#define MMU_DTLB_MULTIPLE        (-9)
#define MMU_DTLB_MISS            (-10)
#define MMU_IADDR_ERROR          (-11)
#define MMU_DADDR_ERROR_READ     (-12)
#define MMU_DADDR_ERROR_WRITE    (-13)

#if defined(CONFIG_USER_ONLY)

int cpu_sh4_is_cached(CPUSH4State *env, target_ulong addr)
{
    /* For user mode, only U0 area is cacheable. */
    return !(addr & 0x80000000);
}

#else /* !CONFIG_USER_ONLY */

/* MMCS fork: file-scope prototype — the COWFIX hook in
 * superh_cpu_do_interrupt calls this before its definition. */
static int find_utlb_entry(CPUSH4State *env, target_ulong address,
                           int use_asid);
static void increment_urc(CPUSH4State *env);

void superh_cpu_do_interrupt(CPUState *cs)
{
    SuperHCPU *cpu = SUPERH_CPU(cs);
    CPUSH4State *env = &cpu->env;
    int do_irq = cs->interrupt_request & CPU_INTERRUPT_HARD;
    int do_exp, irq_vector = cs->exception_index;

    /* prioritize exceptions over interrupts */

    do_exp = cs->exception_index != -1;
    do_irq = do_irq && (cs->exception_index == -1);

    if (env->sr & (1u << SR_BL)) {
        if (do_exp && cs->exception_index != 0x1e0) {
            /* In theory a masked exception generates a reset exception,
               which in turn jumps to the reset vector. However this only
               works when using a bootloader. When using a kernel and an
               initrd, they need to be reloaded and the program counter
               should be loaded with the kernel entry point.
               qemu_system_reset_request takes care of that.  */
            qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
            return;
        }
        if (do_irq && !env->in_sleep) {
            return; /* masked */
        }
    }
    env->in_sleep = 0;

    /* MMCS fork: syscall tracer — log every trapa with args (flycast
     * wince.h pattern: decode API calls at the trap boundary; our CE5
     * calibration: TRA 0x71 = RegQueryValueExW per the REGFIX hook). */
    if (getenv("MMCS_SYSTRACE") && do_exp
        && (env->pc & 1 || env->pc >= 0xffff0000)) {
        /* flycast wince.h pattern: CE syscalls = odd/hi fetch exceptions */
        fprintf(stderr, "SYSCALL exp=%03x pc=%08x r4=%08x r5=%08x "
                "r6=%08x r7=%08x pr=%08x\n", cs->exception_index, env->pc,
                env->gregs[4], env->gregs[5], env->gregs[6], env->gregs[7],
                env->pr);
        /* MMCS_SYSTRACE_PR=<hex>[,<hex>...]: when pr matches, dump the
         * caller stack frame — decodes who calls through the coredll
         * wrapper identified by pr. MMCS_SYSTRACE_MEM=a,b,c: also dump
         * 12 words at each VA at the same hit. */
        const char *pw = getenv("MMCS_SYSTRACE_PR");
        if (pw) {
            char buf[256];
            snprintf(buf, sizeof buf, "%08x", env->pr);
            size_t hl = strlen(buf);
            for (const char *p = pw; p && *p; ) {
                if (strncmp(p, buf, hl) == 0
                    && (p[hl] == ',' || p[hl] == '\0')) {
                    fprintf(stderr, "PRWATCH pr=%08x r15=%08x frame:",
                            env->pr, env->gregs[15]);
                    for (int i = 0; i < 24; i++) {
                        uint32_t w = 0;
                        cpu_memory_rw_debug(cs, env->gregs[15] + 4 * i,
                                             (void *)&w, 4, 0);
                        fprintf(stderr, " %08x", w);
                    }
                    const char *mw = getenv("MMCS_SYSTRACE_MEM");
                    if (mw) {
                        char mb[512];
                        snprintf(mb, sizeof mb, "%s", mw);
                        for (char *tok = strtok(mb, ","); tok;
                             tok = strtok(NULL, ",")) {
                            uint32_t a = strtoul(tok, NULL, 16);
                            fprintf(stderr, "\nMEM %08x:", a);
                            for (int i = 0; i < 12; i++) {
                                uint32_t w = 0;
                                cpu_memory_rw_debug(cs, a + 4 * i,
                                                     (void *)&w, 4, 0);
                                fprintf(stderr, " %08x", w);
                            }
                        }
                    }
                    fprintf(stderr, "\n");
                    break;
                }
                p = strchr(p, ',');
                if (p) p++;
            }
        }
    }
    /* MMCS fork: MMCS_KAPIFIX — kernel-side API thunk faults. The OEM
     * thunk @0x908083f8 (callers 0x90807674 / 0x90807720, the per-IRQ
     * source init walkers) resolves its API set via *(0x88602bec); in
     * our boot the slot still holds the RAW handle 0x100 (the bind
     * stage never ran), so `mov.l @(40,r2),r3` faults (tea=0x128).
     * Late-binding the table is NOT safe (the kernel resets it and the
     * thunk then jmps to a stale/NULL method -> pc=0 storm, observed
     * 2026-11-15). The callers ignore the return value and proceed
     * with their per-source register writes, so synthesize a failed
     * API call: r0=0, resume at PR (the thunk jmps, so PR = the
     * caller's post-jsr site). Same treatment for kernel-mode fetch
     * faults at pc=0 (NULL method from a reset table). */
    if (env->mmcs_kapifix_active
        && (cs->exception_index == 0x040 || cs->exception_index == 0x060)
        && (env->pc == 0x908083fc || env->pc == 0x00000000)) {
        env->gregs[0] = 0;
        env->pc = env->pr;
        cs->exception_index = -1;
        return;
    }
    /* KAPIFIX part 3: the per-IRQ-source config fn (entry 0x9080765c,
     * 7-reg frame) faults reading its source's register block when
     * *(desc+84) is NULL (loader-data hole: the runtime descriptor
     * tables at 0x886028xx are incompletely populated in our boot).
     * Synthesize the full function return (r0=0 = source skipped) so
     * the walk advances — the same recovery the pre-ILKFIX boot got
     * for free when the CAS faults aborted the walk early. */
    if (env->mmcs_kapifix_active && cs->exception_index == 0x040
        && env->pc == 0x9080772c && env->tea == 0) {
        uint32_t w[7];
        cpu_memory_rw_debug(cs, env->gregs[15] + 20, (void *)w, 28, 0);
        env->pr = w[0];
        env->gregs[13] = w[1];
        env->gregs[12] = w[2];
        env->gregs[11] = w[3];
        env->gregs[10] = w[4];
        env->gregs[9] = w[5];
        env->gregs[8] = w[6];
        env->gregs[15] += 20 + 28;
        env->gregs[0] = 0;
        env->pc = env->pr;
        cs->exception_index = -1;
        return;
    }
    /* MMCS fork: MMCS_RINGFIX — the uHAL exception ring write
     * (kernel FUN_9080755c @0x9080755c, called by the exception
     * formatter FUN_90807364 via the handle slot @0x88602d30) faults
     * at its first deref `mov.l @(12,r2),r7` (pc 0x908075a2) because
     * the ring sub-state (*param_1) is NULL/garbage — the uHAL ring
     * second-stage init never ran in our boot (loader-data gated).
     * Every kernel exception then storms fault-logging itself
     * (5.2M faults/boot census 2026-11-15). Synthesize the function
     * return (r0=1 write-dropped): pop the r8/r9 pair pushed at entry
     * and return to PR, so the kernel exception handler completes. */
    if (env->mmcs_ringfix_active && cs->exception_index == 0x040
        && env->pc == 0x908075a2) {
        uint32_t rv[2];
        cpu_memory_rw_debug(cs, env->gregs[15], (void *)rv, 8, 0);
        env->gregs[9] = rv[0];
        env->gregs[8] = rv[1];
        env->gregs[15] += 8;
        env->gregs[0] = 1;              /* epilogue returns r8 -> 1 */
        env->pc = env->pr;
        cs->exception_index = -1;
        return;
    }
    /* MMCS fork: ILKFIX emulation half — interlocked ops whose KData
     * slots hold live vendor data (see tlb_fill MMCS_ILKFIX) execute as
     * exceptions instead (exp 0x180 illegal on the data bytes, or 0x040/
     * 0x0e0 if the page is otherwise unmapped). Emulate the stock
     * shexcept.src semantics and return to PR (the intrlock.src wrappers
     * jmp @r0 so PR = the original caller; the Decrement wrapper jsr's
     * and lands back in its own "jmp @r3; add #-1,r0" tail naturally).
     *
     * USER-mode: all blocks. KERNEL-mode: all blocks, but ARMED only
     * after the first user-mode interlocked fault (user_seen latch) —
     * that latch flips when the first launched user process runs its
     * coredll, i.e. strictly AFTER the kernel's early IRQ-init walk
     * (whose loader-data holes must stay hidden behind abort-early).
     * The kernel then needs the ops for the pager's COW copy of
     * compressed .data sections (coredll 0x40074000-page): without
     * them the copy aborts, the launched server maps the shared ROM
     * page read-only, and its first heap write takes a write violation
     * (excp 0x060 at 0x4002cdce -> 0x400746e8 x6066/boot = the
     * 0xC0000005 kill). The kernel DATA-page map stays user-only. */
    if (env->mmcs_ilkfix_active
        && (cs->exception_index == 0x180
            || cs->exception_index == 0x040
            || cs->exception_index == 0x0e0)
        && (env->pc & ~7u) >= 0x5B80 && (env->pc & ~7u) <= 0x5BF0) {
        static bool user_seen;
        bool kern = (env->sr & (1u << SR_MD)) != 0;
        if (!kern) {
            user_seen = true;
        } else if (!user_seen) {
            /* fall through to normal kernel exception handling */
            goto ilk_no_emu;
        }
        uint32_t blk = env->pc & ~7u, old = 0;
        switch (blk) {
        case 0x5B80: {                    /* ILMaskByte(r4, and, or) */
            uint8_t v;
            cpu_memory_rw_debug(cs, env->gregs[4], (void *)&v, 1, 0);
            old = (int8_t)v;
            v = (v & (uint8_t)env->gregs[5]) | (uint8_t)env->gregs[6];
            cpu_memory_rw_debug(cs, env->gregs[4], (void *)&v, 1, 1);
            break;
        }
        case 0x5B90:                      /* ILPopList(r4) */
            cpu_memory_rw_debug(cs, env->gregs[4], (void *)&old, 4, 0);
            if (old) {
                uint32_t next;
                cpu_memory_rw_debug(cs, old, (void *)&next, 4, 0);
                cpu_memory_rw_debug(cs, env->gregs[4], (void *)&next, 4, 1);
            }
            break;
        case 0x5BB0: {                    /* ILPushList(r4 list, r5 item) */
            uint32_t head;
            cpu_memory_rw_debug(cs, env->gregs[4], (void *)&head, 4, 0);
            cpu_memory_rw_debug(cs, env->gregs[5], (void *)&head, 4, 1);
            cpu_memory_rw_debug(cs, env->gregs[4],
                                (void *)&env->gregs[5], 4, 1);
            old = head;
            break;
        }
        case 0x5BC0:                      /* ILExchange(r4, r5) */
            cpu_memory_rw_debug(cs, env->gregs[4], (void *)&old, 4, 0);
            cpu_memory_rw_debug(cs, env->gregs[4],
                                (void *)&env->gregs[5], 4, 1);
            break;
        case 0x5BD0:                      /* ILCmpExchange(r4,r5,r6) */
            cpu_memory_rw_debug(cs, env->gregs[4], (void *)&old, 4, 0);
            if (old == env->gregs[6]) {
                cpu_memory_rw_debug(cs, env->gregs[4],
                                    (void *)&env->gregs[5], 4, 1);
            }
            break;
        case 0x5BE0:                      /* ILIncrement(r4) */
            cpu_memory_rw_debug(cs, env->gregs[4], (void *)&old, 4, 0);
            old = old + 1;
            cpu_memory_rw_debug(cs, env->gregs[4], (void *)&old, 4, 1);
            break;
        case 0x5BF0: {                    /* ILXAdd(r4, r5) */
            cpu_memory_rw_debug(cs, env->gregs[4], (void *)&old, 4, 0);
            uint32_t nv = old + env->gregs[5];
            cpu_memory_rw_debug(cs, env->gregs[4], (void *)&nv, 4, 1);
            break;
        }
        }
        env->gregs[0] = old;
        env->pc = env->pr;
        cs->exception_index = -1;
        return;
    }
ilk_no_emu:;
    /* MMCS fork: MMCS_COWFIX — fork-side copy-on-write for user .data.
     *
     * Decoded 2026-11-15 (driver-init lane): the launched PSL servers
     * die because their coredll .data page (VA 0x40074000-class) never
     * gets a demand page-in from the kernel pager (the compressed-
     * section private-copy path silently fails in our boot): kernel-
     * mode reads of 0x4007xxxx miss (excp 0x040, pc c0035c10) and the
     * user heap-arena write (0x4002cdce -> 0x400746e8) takes a write
     * MISS (excp 0x060, x6066/boot) which propagates as 0xC0000005 ->
     * TerminateProcess x3033 -> device.exe/BuiltIn/sdhi.dll never
     * load. On a user-mode write miss/violation inside
     * [0x40000000,0x80000000): map a private scratch RAM page (the 1MB
     * SDRAM margin above the ROMHDR top: phys 0x10710000..0x10800000),
     * best-effort copy the current page content (zero if unreadable —
     * the PSL bind retry loop re-creates its descriptors), rewire the
     * UTLB entry (pr=3, d=1) and re-execute the store. VA-deduped: a
     * re-fault re-points to the SAME scratch page (previous writes
     * preserved; NO re-copy). */
    /* Two gated shapes (env MMCS_COWFIX):
     *  (a) USER-mode write miss/violation, tea in [0x40000000,0x80000000)
     *      — the launched server's heap-arena writes;
     *  (b) KERNEL-mode read miss, tea in the coredll .data span
     *      [0x40074000,0x40078000) — the api0 servicing reads that
     *      would otherwise abort the PSL bind (x2/launch). */
    if (env->mmcs_cowfix_active
        && (((env->sr & (1u << SR_MD)) == 0
             && (cs->exception_index == 0x060
                 || cs->exception_index == 0x0c0)
             && env->tea >= 0x40000000 && env->tea < 0x80000000)
            || ((env->sr & (1u << SR_MD)) != 0
                && cs->exception_index == 0x040
                && env->tea >= 0x40074000 && env->tea < 0x40080000))) {
        uint32_t va = env->tea & ~0xFFFu;
        int n = find_utlb_entry(env, va,
                                !(env->mmucr & MMUCR_SV)
                                || !(env->sr & (1u << SR_MD)));
        tlb_t *e = (n >= 0) ? &env->utlb[n] : NULL;
        uint32_t mask = e ? (e->size - 1) : 0xFFF;
        uint32_t base = va & ~mask;
        /* dedup table + bump allocator over the scratch margin */
        static struct { uint32_t va, pa; } map[512];
        static int nmap;
        uint32_t pa = 0;
        bool reused = false;
        for (int i = 0; i < nmap; i++) {
            if (map[i].va == base) {
                pa = map[i].pa;
                reused = true;
                break;
            }
        }
        if (!reused) {
            static uint32_t next = 0x10710000;
            if (next + mask + 1 <= 0x10800000 && nmap < 512) {
                pa = next;
                next += mask + 1;
                map[nmap].va = base;
                map[nmap].pa = pa;
                nmap++;
            } else {
                fprintf(stderr, "MMCS: COWFIX scratch exhausted\n");
                goto cow_done;
            }
        }
        if (!reused) {
            static uint8_t pg[0x10000] __attribute__((aligned(8)));
            uint32_t sz = mask + 1;
            if (sz > sizeof pg) {
                sz = sizeof pg;
            }
            memset(pg, 0, sz);
            cpu_memory_rw_debug(cs, base, pg, sz, 0);  /* best-effort */
            cpu_physical_memory_write(pa, pg, sz);
        }
        if (e) {
            /* rewire the existing guest UTLB entry */
            e->ppn = (pa & ~mask) >> 10;
            e->pr = 3;              /* user+kernel RW */
            e->d = 1;
            e->v = 1;
            tlb_flush(env_cpu(env));
        } else {
            /* write MISS: no guest entry — install one via the ldtlb
             * path (PTEH/PTEL -> UTLB[urc]) so kernel-mode servicing
             * reads of the same VA also resolve; shared + RW. */
            env->pteh = (base & PTEH_VPN_MASK)
                        | (env->pteh & PTEH_ASID_MASK);
            env->ptel = ((pa >> 10) << 10)      /* PPN */
                        | (3 << 5)              /* PR = RW */
                        | PTEL_V | PTEL_SZ_LOW  /* 4K */
                        | PTEL_C | PTEL_D | PTEL_SH;
            cpu_load_tlb(env);
            increment_urc(env);
        }
        cs->exception_index = -1;
        return;                     /* re-execute the store */
    }
cow_done:;
    /* MMCS fork: APIFIX — calls to unmapped 0xFFFFxxxx API slots (the
     * 0xfffffbed class = syscall-to-unmapped-slot) crash forever on real
     * fetch faults. Synthesize r0=0 (success/NULL) and RET to the caller,
     * like the REGFIX pattern but at the syscall boundary. */
    if (getenv("MMCS_APIFIX") && do_exp
        && env->pc >= 0xffff0000 && env->pc < 0xffff8000
        && cs->exception_index == 0x0e0) {
        /* WinCE syscall convention: the caller did a `jsr @slot` — the
         * slot address IS the syscall entry. Returning = set r0 and
         * RET via the saved PR in the caller's stack frame. But the
         * SH4 exception already saved SPC/SSR; the simplest correct
         * "return" = restore SPC/SSR (undo the trap) and set r0. */
        env->gregs[0] = 0;              /* return value: success/NULL */
        env->pc = env->spc;             /* saved PC (post-jsr) */
        env->sr = env->ssr;             /* saved SR */
        cs->exception_index = -1;
        return;
    }
    /* MMCS fork: REGFIX trapa hook — synthesize RegQueryValueExW success
     * for the boot-registry bootstrap (the fdf circular-read break). */
    if (cs->exception_index == 0x160 &&
        env->mmcs_regfix_active && env->tra == 0x71) {
        /* RegQueryValueExW(hKey=r4, name=r5, res=r6, type=r7,
         *                  data=[r15+4], cbdata=[r15+8]).
         * Phase-0: answer known bootstrap names with real values from
         * default.reg ground truth; unknown names = ERROR_FILE_NOT_FOUND
         * (benign: the value simply doesn't exist yet). */
        static const struct { const char *name; uint32_t dword; } vals[] = {
            { "AutoMount", 1 },
            { "MountFlags", 0 },
            { "MountSystem", 1 },
            { "MountAsROM", 1 },
            { "MountAsBootable", 1 },
            { "AutoPart", 0 },
            { "AutoFormat", 0 },
            { "PnPWaitIoDelay", 0x1f4 },
            { "PNPUnloadDelay", 0x12c },
        };
        uint32_t r5 = env->gregs[5];
        uint32_t hit = 0;
        if (r5 > 0x10000) {
            char name[40]; int i;
            for (i = 0; i < 39; i++) {
                uint32_t ch;
                cpu_physical_memory_read(r5 + 2 * i, &ch, 1);
                cpu_physical_memory_read(r5 + 2 * i + 1, &hit, 1);
                if (!ch && !hit) break;
                if (ch < 0x80) name[i] = (char)ch; else break;
                name[i + 1] = 0;
            }
            for (unsigned k = 0; k < ARRAY_SIZE(vals); k++) {
                if (strcmp(name, vals[k].name) == 0) { hit = vals[k].dword; break; }
            }
        }
        if (hit) {
            /* type=REG_DWORD(4) if lpType; data if lpData/lpcbData */
            uint32_t type_ptr = env->gregs[7];
            uint32_t data_ptr = 0, cb_ptr = 0;
            /* stack args: [r15+4]=lpData [r15+8]=lpcbData (after the
             * trapa the stack still holds the caller's frame) */
            cpu_physical_memory_read(env->gregs[15] + 4, &data_ptr, 4);
            cpu_physical_memory_read(env->gregs[15] + 8, &cb_ptr, 4);
            if (type_ptr) {
                uint32_t t = 4;
                cpu_physical_memory_write(type_ptr, &t, 4);
            }
            if (cb_ptr) {
                uint32_t cb = 4;
                cpu_physical_memory_write(cb_ptr, &cb, 4);
            }
            if (data_ptr) {
                cpu_physical_memory_write(data_ptr, &hit, 4);
            }
            env->gregs[0] = 0;          /* ERROR_SUCCESS */
        } else {
            env->gregs[0] = 2;          /* ERROR_FILE_NOT_FOUND */
        }
        cs->exception_index = -1;
        return;
    }

    if (do_irq) {
        if (env->mmcs_evt_inject) {          /* MMCS fork: vendor-INTC event */
            irq_vector = env->intevt;
            env->mmcs_evt_inject = 0;
        } else {
            irq_vector = sh_intc_get_pending_vector(env->intc_handle,
                                                    (env->sr >> 4) & 0xf);
            if (irq_vector == -1) {
                /* MMCS fork: HARD asserted by our injector with the flag
                 * already consumed = stale line; drop it instead of the
                 * upstream g_assert_not_reached crash path. */
                cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
                return; /* masked */
            }
        }
    }

    if (qemu_loglevel_mask(CPU_LOG_INT)) {
        const char *expname;
        if (cs->exception_index == 0x040 || cs->exception_index == 0x060 ||
            cs->exception_index == 0x0a0) {
            fprintf(stderr, "SH4-MMU: excp=%03x pc=%08x tea=%08x pteh=%08x\n",
                    cs->exception_index, env->pc, env->tea, env->pteh);
            /* MMCS_FAULTPC=<hex>[,<hex>...]: at a fault whose PC matches,
             * dump the full register set + 16 stack words (the faulting
             * context BEFORE kernel dispatch — unlike a monitor 'stop'
             * which lands in the exception handler). */
            const char *fpw = getenv("MMCS_FAULTPC");
            if (fpw) {
                char buf[256];
                snprintf(buf, sizeof buf, "%08x", env->pc);
                size_t hl = strlen(buf);
                for (const char *p = fpw; p && *p; ) {
                    if (strncmp(p, buf, hl) == 0
                        && (p[hl] == ',' || p[hl] == '\0')) {
                        fprintf(stderr, "FAULTCTX pc=%08x tea=%08x pr=%08x "
                                "spc=%08x r0=%08x r1=%08x r2=%08x r3=%08x "
                                "r4=%08x r5=%08x r6=%08x r7=%08x r8=%08x "
                                "r9=%08x r10=%08x r11=%08x r12=%08x "
                                "r13=%08x r14=%08x r15=%08x\n",
                                env->pc, env->tea, env->pr, env->spc,
                                env->gregs[0], env->gregs[1], env->gregs[2],
                                env->gregs[3], env->gregs[4], env->gregs[5],
                                env->gregs[6], env->gregs[7], env->gregs[8],
                                env->gregs[9], env->gregs[10], env->gregs[11],
                                env->gregs[12], env->gregs[13], env->gregs[14],
                                env->gregs[15]);
                        fprintf(stderr, "STACK:");
                        for (int i = 0; i < 16; i++) {
                            uint32_t w = 0;
                            cpu_memory_rw_debug(cs, env->gregs[15] + 4 * i,
                                                 (void *)&w, 4, 0);
                            fprintf(stderr, " %08x", w);
                        }
                        fprintf(stderr, "\n");
                        break;
                    }
                    p = strchr(p, ',');
                    if (p) p++;
                }
            }
        }
        switch (cs->exception_index) {
        case 0x0e0:
            expname = "addr_error";
            break;
        case 0x040:
            expname = "tlb_miss";
            break;
        case 0x0a0:
            expname = "tlb_violation";
            break;
        case 0x180:
            expname = "illegal_instruction";
            break;
        case 0x1a0:
            expname = "slot_illegal_instruction";
            break;
        case 0x800:
            expname = "fpu_disable";
            break;
        case 0x820:
            expname = "slot_fpu";
            break;
        case 0x100:
            expname = "data_write";
            break;
        case 0x060:
            expname = "dtlb_miss_write";
            break;
        case 0x0c0:
            expname = "dtlb_violation_write";
            break;
        case 0x120:
            expname = "fpu_exception";
            break;
        case 0x080:
            expname = "initial_page_write";
            break;
        case 0x160:
            expname = "trapa";
            break;
        default:
            expname = do_irq ? "interrupt" : "???";
            break;
        }
        qemu_log("exception 0x%03x [%s] raised\n",
                  irq_vector, expname);
        log_cpu_state(cs, 0);
    }

    env->ssr = cpu_read_sr(env);
    env->spc = env->pc;
    env->sgr = env->gregs[15];
    env->sr |= (1u << SR_BL) | (1u << SR_MD) | (1u << SR_RB);
    env->lock_addr = -1;

    if (env->flags & TB_FLAG_DELAY_SLOT_MASK) {
        /* Branch instruction should be executed again before delay slot. */
        env->spc -= 2;
        /* Clear flags for exception/interrupt routine. */
        env->flags &= ~TB_FLAG_DELAY_SLOT_MASK;
    }

    if (do_exp) {
        env->expevt = cs->exception_index;
        switch (cs->exception_index) {
        case 0x000:
        case 0x020:
        case 0x140:
            env->sr &= ~(1u << SR_FD);
            env->sr |= 0xf << 4; /* IMASK */
            env->pc = 0xa0000000;
            break;
        case 0x040:
        case 0x060:
            env->pc = env->vbr + 0x400;
            break;
        case 0x160:
            env->spc += 2; /* special case for TRAPA */
            /* fall through */
        default:
            env->pc = env->vbr + 0x100;
            break;
        }
        return;
    }

    if (do_irq) {
        env->intevt = irq_vector;
        env->pc = env->vbr + 0x600;
        return;
    }
}

static void update_itlb_use(CPUSH4State * env, int itlbnb)
{
    uint8_t or_mask = 0, and_mask = (uint8_t) - 1;

    switch (itlbnb) {
    case 0:
        and_mask = 0x1f;
        break;
    case 1:
        and_mask = 0xe7;
        or_mask = 0x80;
        break;
    case 2:
        and_mask = 0xfb;
        or_mask = 0x50;
        break;
    case 3:
        or_mask = 0x2c;
        break;
    }

    env->mmucr &= (and_mask << 24) | 0x00ffffff;
    env->mmucr |= (or_mask << 24);
}

static int itlb_replacement(CPUSH4State * env)
{
    if ((env->mmucr & 0xe0000000) == 0xe0000000) {
        return 0;
    }
    if ((env->mmucr & 0x98000000) == 0x18000000) {
        return 1;
    }
    if ((env->mmucr & 0x54000000) == 0x04000000) {
        return 2;
    }
    if ((env->mmucr & 0x2c000000) == 0x00000000) {
        return 3;
    }
    cpu_abort(env_cpu(env), "Unhandled itlb_replacement");
}

/* Find the corresponding entry in the right TLB
   Return entry, MMU_DTLB_MISS or MMU_DTLB_MULTIPLE
*/
static int find_tlb_entry(CPUSH4State * env, target_ulong address,
                          tlb_t * entries, uint8_t nbtlb, int use_asid)
{
    int match = MMU_DTLB_MISS;
    uint32_t start, end;
    uint8_t asid;
    int i;

    asid = env->pteh & 0xff;

    for (i = 0; i < nbtlb; i++) {
        if (!entries[i].v)
            continue; /* Invalid entry */
        if (!entries[i].sh && use_asid && entries[i].asid != asid)
            continue; /* Bad ASID */
        start = (entries[i].vpn << 10) & ~(entries[i].size - 1);
        end = start + entries[i].size - 1;
        if (address >= start && address <= end) { /* Match */
            if (match != MMU_DTLB_MISS)
                return MMU_DTLB_MULTIPLE; /* Multiple match */
            match = i;
        }
    }
    return match;
}

static void increment_urc(CPUSH4State * env)
{
    uint8_t urb, urc;

    /* Increment URC */
    urb = ((env->mmucr) >> 18) & 0x3f;
    urc = ((env->mmucr) >> 10) & 0x3f;
    urc++;
    if ((urb > 0 && urc > urb) || urc > (UTLB_SIZE - 1))
        urc = 0;
    env->mmucr = (env->mmucr & 0xffff03ff) | (urc << 10);
}

/* Copy and utlb entry into itlb
   Return entry
*/
static int copy_utlb_entry_itlb(CPUSH4State *env, int utlb)
{
    int itlb;

    tlb_t * ientry;
    itlb = itlb_replacement(env);
    ientry = &env->itlb[itlb];
    if (ientry->v) {
        tlb_flush_page(env_cpu(env), ientry->vpn << 10);
    }
    *ientry = env->utlb[utlb];
    update_itlb_use(env, itlb);
    return itlb;
}

/* Find itlb entry
   Return entry, MMU_ITLB_MISS, MMU_ITLB_MULTIPLE or MMU_DTLB_MULTIPLE
*/
static int find_itlb_entry(CPUSH4State * env, target_ulong address,
                           int use_asid)
{
    int e;

    e = find_tlb_entry(env, address, env->itlb, ITLB_SIZE, use_asid);
    if (e == MMU_DTLB_MULTIPLE) {
        e = MMU_ITLB_MULTIPLE;
    } else if (e == MMU_DTLB_MISS) {
        e = MMU_ITLB_MISS;
    } else if (e >= 0) {
        update_itlb_use(env, e);
    }
    return e;
}

/* Find utlb entry
   Return entry, MMU_DTLB_MISS, MMU_DTLB_MULTIPLE */
static int find_utlb_entry(CPUSH4State * env, target_ulong address, int use_asid)
{
    /* per utlb access */
    increment_urc(env);

    /* Return entry */
    return find_tlb_entry(env, address, env->utlb, UTLB_SIZE, use_asid);
}

/* Match address against MMU
   Return MMU_OK, MMU_DTLB_MISS_READ, MMU_DTLB_MISS_WRITE,
   MMU_DTLB_INITIAL_WRITE, MMU_DTLB_VIOLATION_READ,
   MMU_DTLB_VIOLATION_WRITE, MMU_ITLB_MISS,
   MMU_ITLB_MULTIPLE, MMU_ITLB_VIOLATION,
   MMU_IADDR_ERROR, MMU_DADDR_ERROR_READ, MMU_DADDR_ERROR_WRITE.
*/
static int get_mmu_address(CPUSH4State * env, target_ulong * physical,
                           int *prot, target_ulong address,
                           MMUAccessType access_type)
{
    int use_asid, n;
    tlb_t *matching = NULL;

    use_asid = !(env->mmucr & MMUCR_SV) || !(env->sr & (1u << SR_MD));

    if (access_type == MMU_INST_FETCH) {
        n = find_itlb_entry(env, address, use_asid);
        if (n >= 0) {
            matching = &env->itlb[n];
            if (!(env->sr & (1u << SR_MD)) && !(matching->pr & 2)) {
                n = MMU_ITLB_VIOLATION;
            } else {
                *prot = PAGE_EXEC;
            }
        } else {
            n = find_utlb_entry(env, address, use_asid);
            if (n >= 0) {
                n = copy_utlb_entry_itlb(env, n);
                matching = &env->itlb[n];
                if (!(env->sr & (1u << SR_MD)) && !(matching->pr & 2)) {
                    n = MMU_ITLB_VIOLATION;
                } else {
                    *prot = PAGE_READ | PAGE_EXEC;
                    if ((matching->pr & 1) && matching->d) {
                        *prot |= PAGE_WRITE;
                    }
                }
            } else if (n == MMU_DTLB_MULTIPLE) {
                n = MMU_ITLB_MULTIPLE;
            } else if (n == MMU_DTLB_MISS) {
                n = MMU_ITLB_MISS;
            }
        }
    } else {
        n = find_utlb_entry(env, address, use_asid);
        if (n >= 0) {
            matching = &env->utlb[n];
            if (!(env->sr & (1u << SR_MD)) && !(matching->pr & 2)) {
                n = (access_type == MMU_DATA_STORE)
                    ? MMU_DTLB_VIOLATION_WRITE : MMU_DTLB_VIOLATION_READ;
            } else if ((access_type == MMU_DATA_STORE) && !(matching->pr & 1)) {
                n = MMU_DTLB_VIOLATION_WRITE;
            } else if ((access_type == MMU_DATA_STORE) && !matching->d) {
                n = MMU_DTLB_INITIAL_WRITE;
            } else {
                *prot = PAGE_READ;
                if ((matching->pr & 1) && matching->d) {
                    *prot |= PAGE_WRITE;
                }
            }
        } else if (n == MMU_DTLB_MISS) {
            n = (access_type == MMU_DATA_STORE)
                ? MMU_DTLB_MISS_WRITE : MMU_DTLB_MISS_READ;
        }
    }
    if (n >= 0) {
        n = MMU_OK;
        *physical = ((matching->ppn << 10) & ~(matching->size - 1))
                    | (address & (matching->size - 1));
    }
    return n;
}

static int get_physical_address(CPUSH4State * env, target_ulong * physical,
                                int *prot, target_ulong address,
                                MMUAccessType access_type)
{
    /* P1, P2 and P4 areas do not use translation */
    if ((address >= 0x80000000 && address < 0xc0000000) || address >= 0xe0000000) {
        if (!(env->sr & (1u << SR_MD))
                && (address < 0xe0000000 || address >= 0xe4000000)) {
            /* Unauthorized access in user mode (only store queues are available) */
            qemu_log_mask(LOG_GUEST_ERROR, "Unauthorized access\n");
            if (access_type == MMU_DATA_LOAD) {
                return MMU_DADDR_ERROR_READ;
            } else if (access_type == MMU_DATA_STORE) {
                return MMU_DADDR_ERROR_WRITE;
            } else {
                return MMU_IADDR_ERROR;
            }
        }
        if (address >= 0x80000000 && address < 0xc0000000) {
            /* Mask upper 3 bits for P1 and P2 areas */
            *physical = address & 0x1fffffff;
        } else {
            *physical = address;
        }
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return MMU_OK;
    }

    /* If MMU is disabled, return the corresponding physical page */
    if (!(env->mmucr & MMUCR_AT)) {
        *physical = address & 0x1FFFFFFF;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return MMU_OK;
    }

    /* We need to resort to the MMU */
    return get_mmu_address(env, physical, prot, address, access_type);
}

hwaddr superh_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    SuperHCPU *cpu = SUPERH_CPU(cs);
    target_ulong physical;
    int prot;

    if (get_physical_address(&cpu->env, &physical, &prot, addr, MMU_DATA_LOAD)
            == MMU_OK) {
        return physical;
    }

    return -1;
}

void cpu_load_tlb(CPUSH4State * env)
{
    CPUState *cs = env_cpu(env);
    int n = cpu_mmucr_urc(env->mmucr);
    tlb_t * entry = &env->utlb[n];

    if (entry->v) {
        /* Overwriting valid entry in utlb. */
        target_ulong address = entry->vpn << 10;
        tlb_flush_page(cs, address);
    }

    /* Take values into cpu status from registers. */
    entry->asid = (uint8_t)cpu_pteh_asid(env->pteh);
    entry->vpn  = cpu_pteh_vpn(env->pteh);
    entry->v    = (uint8_t)cpu_ptel_v(env->ptel);
    entry->ppn  = cpu_ptel_ppn(env->ptel);
    entry->sz   = (uint8_t)cpu_ptel_sz(env->ptel);
    switch (entry->sz) {
    case 0: /* 00 */
        entry->size = 1024; /* 1K */
        break;
    case 1: /* 01 */
        entry->size = 1024 * 4; /* 4K */
        break;
    case 2: /* 10 */
        entry->size = 1024 * 64; /* 64K */
        break;
    case 3: /* 11 */
        entry->size = 1024 * 1024; /* 1M */
        break;
    default:
        cpu_abort(cs, "Unhandled load_tlb");
        break;
    }
    entry->sh   = (uint8_t)cpu_ptel_sh(env->ptel);
    entry->c    = (uint8_t)cpu_ptel_c(env->ptel);
    entry->pr   = (uint8_t)cpu_ptel_pr(env->ptel);
    entry->d    = (uint8_t)cpu_ptel_d(env->ptel);
    entry->wt   = (uint8_t)cpu_ptel_wt(env->ptel);
    entry->sa   = (uint8_t)cpu_ptea_sa(env->ptea);
    entry->tc   = (uint8_t)cpu_ptea_tc(env->ptea);
}

 void cpu_sh4_invalidate_tlb(CPUSH4State *s)
{
    int i;

    /* UTLB */
    for (i = 0; i < UTLB_SIZE; i++) {
        tlb_t * entry = &s->utlb[i];
        entry->v = 0;
    }
    /* ITLB */
    for (i = 0; i < ITLB_SIZE; i++) {
        tlb_t * entry = &s->itlb[i];
        entry->v = 0;
    }

    tlb_flush(env_cpu(s));
}

uint32_t cpu_sh4_read_mmaped_itlb_addr(CPUSH4State *s,
                                       hwaddr addr)
{
    int index = (addr & 0x00000300) >> 8;
    tlb_t * entry = &s->itlb[index];

    return (entry->vpn  << 10) |
           (entry->v    <<  8) |
           (entry->asid);
}

void cpu_sh4_write_mmaped_itlb_addr(CPUSH4State *s, hwaddr addr,
                                    uint32_t mem_value)
{
    uint32_t vpn = (mem_value & 0xfffffc00) >> 10;
    uint8_t v = (uint8_t)((mem_value & 0x00000100) >> 8);
    uint8_t asid = (uint8_t)(mem_value & 0x000000ff);

    int index = (addr & 0x00000300) >> 8;
    tlb_t * entry = &s->itlb[index];
    if (entry->v) {
        /* Overwriting valid entry in itlb. */
        target_ulong address = entry->vpn << 10;
        tlb_flush_page(env_cpu(s), address);
    }
    entry->asid = asid;
    entry->vpn = vpn;
    entry->v = v;
}

uint32_t cpu_sh4_read_mmaped_itlb_data(CPUSH4State *s,
                                       hwaddr addr)
{
    int array = (addr & 0x00800000) >> 23;
    int index = (addr & 0x00000300) >> 8;
    tlb_t * entry = &s->itlb[index];

    if (array == 0) {
        /* ITLB Data Array 1 */
        return (entry->ppn << 10) |
               (entry->v   <<  8) |
               (entry->pr  <<  5) |
               ((entry->sz & 1) <<  6) |
               ((entry->sz & 2) <<  4) |
               (entry->c   <<  3) |
               (entry->sh  <<  1);
    } else {
        /* ITLB Data Array 2 */
        return (entry->tc << 1) |
               (entry->sa);
    }
}

void cpu_sh4_write_mmaped_itlb_data(CPUSH4State *s, hwaddr addr,
                                    uint32_t mem_value)
{
    int array = (addr & 0x00800000) >> 23;
    int index = (addr & 0x00000300) >> 8;
    tlb_t * entry = &s->itlb[index];

    if (array == 0) {
        /* ITLB Data Array 1 */
        if (entry->v) {
            /* Overwriting valid entry in utlb. */
            target_ulong address = entry->vpn << 10;
            tlb_flush_page(env_cpu(s), address);
        }
        entry->ppn = (mem_value & 0x1ffffc00) >> 10;
        entry->v   = (mem_value & 0x00000100) >> 8;
        entry->sz  = (mem_value & 0x00000080) >> 6 |
                     (mem_value & 0x00000010) >> 4;
        entry->pr  = (mem_value & 0x00000040) >> 5;
        entry->c   = (mem_value & 0x00000008) >> 3;
        entry->sh  = (mem_value & 0x00000002) >> 1;
    } else {
        /* ITLB Data Array 2 */
        entry->tc  = (mem_value & 0x00000008) >> 3;
        entry->sa  = (mem_value & 0x00000007);
    }
}

uint32_t cpu_sh4_read_mmaped_utlb_addr(CPUSH4State *s,
                                       hwaddr addr)
{
    int index = (addr & 0x00003f00) >> 8;
    tlb_t * entry = &s->utlb[index];

    increment_urc(s); /* per utlb access */

    return (entry->vpn  << 10) |
           (entry->v    <<  8) |
           (entry->asid);
}

void cpu_sh4_write_mmaped_utlb_addr(CPUSH4State *s, hwaddr addr,
                                    uint32_t mem_value)
{
    int associate = addr & 0x0000080;
    uint32_t vpn = (mem_value & 0xfffffc00) >> 10;
    uint8_t d = (uint8_t)((mem_value & 0x00000200) >> 9);
    uint8_t v = (uint8_t)((mem_value & 0x00000100) >> 8);
    uint8_t asid = (uint8_t)(mem_value & 0x000000ff);
    int use_asid = !(s->mmucr & MMUCR_SV) || !(s->sr & (1u << SR_MD));

    if (associate) {
        int i;
        tlb_t * utlb_match_entry = NULL;
        int needs_tlb_flush = 0;

        /* search UTLB */
        for (i = 0; i < UTLB_SIZE; i++) {
            tlb_t * entry = &s->utlb[i];
            if (!entry->v)
                continue;

            if (entry->vpn == vpn
                && (!use_asid || entry->asid == asid || entry->sh)) {
                if (utlb_match_entry) {
                    CPUState *cs = env_cpu(s);

                    /* Multiple TLB Exception */
                    cs->exception_index = 0x140;
                    s->tea = addr;
                    break;
                }
                if (entry->v && !v)
                    needs_tlb_flush = 1;
                entry->v = v;
                entry->d = d;
                utlb_match_entry = entry;
            }
            increment_urc(s); /* per utlb access */
        }

        /* search ITLB */
        for (i = 0; i < ITLB_SIZE; i++) {
            tlb_t * entry = &s->itlb[i];
            if (entry->vpn == vpn
                && (!use_asid || entry->asid == asid || entry->sh)) {
                if (entry->v && !v)
                    needs_tlb_flush = 1;
                if (utlb_match_entry)
                    *entry = *utlb_match_entry;
                else
                    entry->v = v;
                break;
            }
        }

        if (needs_tlb_flush) {
            tlb_flush_page(env_cpu(s), vpn << 10);
        }
    } else {
        int index = (addr & 0x00003f00) >> 8;
        tlb_t * entry = &s->utlb[index];
        if (entry->v) {
            CPUState *cs = env_cpu(s);

            /* Overwriting valid entry in utlb. */
            target_ulong address = entry->vpn << 10;
            tlb_flush_page(cs, address);
        }
        entry->asid = asid;
        entry->vpn = vpn;
        entry->d = d;
        entry->v = v;
        increment_urc(s);
    }
}

uint32_t cpu_sh4_read_mmaped_utlb_data(CPUSH4State *s,
                                       hwaddr addr)
{
    int array = (addr & 0x00800000) >> 23;
    int index = (addr & 0x00003f00) >> 8;
    tlb_t * entry = &s->utlb[index];

    increment_urc(s); /* per utlb access */

    if (array == 0) {
        /* ITLB Data Array 1 */
        return (entry->ppn << 10) |
               (entry->v   <<  8) |
               (entry->pr  <<  5) |
               ((entry->sz & 1) <<  6) |
               ((entry->sz & 2) <<  4) |
               (entry->c   <<  3) |
               (entry->d   <<  2) |
               (entry->sh  <<  1) |
               (entry->wt);
    } else {
        /* ITLB Data Array 2 */
        return (entry->tc << 1) |
               (entry->sa);
    }
}

void cpu_sh4_write_mmaped_utlb_data(CPUSH4State *s, hwaddr addr,
                                    uint32_t mem_value)
{
    int array = (addr & 0x00800000) >> 23;
    int index = (addr & 0x00003f00) >> 8;
    tlb_t * entry = &s->utlb[index];

    increment_urc(s); /* per utlb access */

    if (array == 0) {
        /* UTLB Data Array 1 */
        if (entry->v) {
            /* Overwriting valid entry in utlb. */
            target_ulong address = entry->vpn << 10;
            tlb_flush_page(env_cpu(s), address);
        }
        entry->ppn = (mem_value & 0x1ffffc00) >> 10;
        entry->v   = (mem_value & 0x00000100) >> 8;
        entry->sz  = (mem_value & 0x00000080) >> 6 |
                     (mem_value & 0x00000010) >> 4;
        entry->pr  = (mem_value & 0x00000060) >> 5;
        entry->c   = (mem_value & 0x00000008) >> 3;
        entry->d   = (mem_value & 0x00000004) >> 2;
        entry->sh  = (mem_value & 0x00000002) >> 1;
        entry->wt  = (mem_value & 0x00000001);
    } else {
        /* UTLB Data Array 2 */
        entry->tc = (mem_value & 0x00000008) >> 3;
        entry->sa = (mem_value & 0x00000007);
    }
}

int cpu_sh4_is_cached(CPUSH4State * env, target_ulong addr)
{
    int n;
    int use_asid = !(env->mmucr & MMUCR_SV) || !(env->sr & (1u << SR_MD));

    /* check area */
    if (env->sr & (1u << SR_MD)) {
        /* For privileged mode, P2 and P4 area is not cacheable. */
        if ((0xA0000000 <= addr && addr < 0xC0000000) || 0xE0000000 <= addr)
            return 0;
    } else {
        /* For user mode, only U0 area is cacheable. */
        if (0x80000000 <= addr)
            return 0;
    }

    /*
     * TODO : Evaluate CCR and check if the cache is on or off.
     *        Now CCR is not in CPUSH4State, but in SH7750State.
     *        When you move the ccr into CPUSH4State, the code will be
     *        as follows.
     */
#if 0
    /* check if operand cache is enabled or not. */
    if (!(env->ccr & 1))
        return 0;
#endif

    /* if MMU is off, no check for TLB. */
    if (env->mmucr & MMUCR_AT)
        return 1;

    /* check TLB */
    n = find_tlb_entry(env, addr, env->itlb, ITLB_SIZE, use_asid);
    if (n >= 0)
        return env->itlb[n].c;

    n = find_tlb_entry(env, addr, env->utlb, UTLB_SIZE, use_asid);
    if (n >= 0)
        return env->utlb[n].c;

    return 0;
}

bool superh_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    if (interrupt_request & CPU_INTERRUPT_HARD) {
        SuperHCPU *cpu = SUPERH_CPU(cs);
        CPUSH4State *env = &cpu->env;

        /* Delay slots are indivisible, ignore interrupts */
        if (env->flags & TB_FLAG_DELAY_SLOT_MASK) {
            return false;
        } else {
            superh_cpu_do_interrupt(cs);
            return true;
        }
    }
    return false;
}

bool superh_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                         MMUAccessType access_type, int mmu_idx,
                         bool probe, uintptr_t retaddr)
{
    SuperHCPU *cpu = SUPERH_CPU(cs);
    CPUSH4State *env = &cpu->env;
    int ret;

    target_ulong physical;
    int prot;

    ret = get_physical_address(env, &physical, &prot, address, access_type);

    /* MMCS fork: MMCS_ILKFIX — the WinCE5 SH4 KData user page (VA 0x5800).
     *
     * Decoded 2026-11-15 (driver-init lane): stock mdsh3.c MDInitialize
     * memcpy's the _InterlockedAPIs block (shexcept.src, 0x80 bytes at
     * KData+0x380) so user+kernel code can jsr into VA 0x5B80-0x5C00
     * (intrlock.src wrappers: InterlockedExchange 0x5BC0, CompareExchange
     * 0x5BD0, Increment 0x5BE0, ExchangeAdd/Decrement 0x5BF0, PopList
     * 0x5B90...). Our kernel never stocks that block and never ldtlb's
     * the page (S112/S117), so every interlocked call fetch-faults
     * (census 2026-11-15: pc=0x5bd0 x17.8K, 0x5b90 x5.8K, 0x5bf0 x2.9K,
     * KData hdr data faults at 0x5808/0x580c x7.9K), every PSL-server
     * launch dies 0xC0000005 in coredll heap init (TerminateProcess x3033
     * = the relaunch loop), device.exe/BuiltIn/sdhi.dll never load and
     * IISR chain[23]/[24] stay NULL.
     *
     * Fix: on first fault of VA page 0x5800, seed the stock-semantics
     * interlocked routines (assembled from shexcept.src with
     * sh4-linux-gnu-as, offsets cross-checked vs intrlock.src targets)
     * into the LIVE KData phys page 0x0C020800 (header verified live by
     * monitor dump: lpvTls/ahSys pointers), then map the surrounding 4K
     * guest page (qemu sh4 granularity) VA 0x5000 -> phys 0x0C020000 so
     * VA 0x5800..0x5BFF aliases the live KData page. Only provably-zero
     * blocks are seeded (read-before-write): live vendor runtime values
     * at phys +0x3b8..+0x3d4 are left alone and their slots handled by
     * the do_interrupt emulation half if ever fetched.
     *
     * Push vs pull (2026-11-15 A/B): kernel-mode interlocked
     * successes send the kernel's early IRQ-init walk deep into
     * loader-data holes (uHAL ring sub-state, kapi set slot,
     * per-source descriptors @0x886028xx +84, scheduler lists) — a
     * bottomless set this fork cannot fill. Pre-ILKFIX boots recovered
     * from kernel-mode CAS faults by aborting those walks early and
     * still reached the PSL launcher (the ~3033-relaunch loop). So the
     * map+seed applies to USER-MODE faults ONLY (mmu_idx == 1): user
     * processes (coredll DllMain PSL bind/heap init in the launched
     * servers) get working interlocked ops; the kernel keeps the
     * abort-early behavior.
     */
    if (ret != MMU_OK && ((uint32_t)address & 0xFFFFF000u) == 0x5000
        && mmu_idx == MMU_USER_IDX
        && getenv("MMCS_ILKFIX")) {
        static const uint8_t blk_poplist[16] = {   /* +0x390 */
            0x42, 0x60, 0x09, 0x00, 0x08, 0x20, 0x05, 0x8b,
            0x00, 0x0b, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00,
        };
        static const uint8_t blk_cas[16] = {       /* +0x3d0 */
            0x42, 0x60, 0x00, 0x36, 0x8b, 0x00, 0x52, 0x24,
            0x00, 0x0b, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00,
        };
        static const uint8_t blk_inc[16] = {       /* +0x3e0 */
            0x42, 0x60, 0x09, 0x00, 0x01, 0x70, 0x02, 0x24,
            0x00, 0x0b, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00,
        };
        static const uint8_t blk_xadd[16] = {      /* +0x3f0 */
            0x42, 0x60, 0x53, 0x61, 0x0c, 0x31, 0x12, 0x24,
            0x00, 0x0b, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00,
        };
        static const uint8_t blk_maskbyte[16] = {  /* +0x380 */
            0x40, 0x60, 0x59, 0x20, 0x6b, 0x20, 0x00, 0x24,
            0x00, 0x0b, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00,
        };
        static bool seeded;
        if (!seeded) {
            /* Read-before-write: only seed blocks that are still all
             * zero. The vendor kernel keeps live runtime values in some
             * of these slots (observed +0x3bc/+0x3c8/+0x3cc/+0x3d0 at
             * stall); those slots are NOT seeded — their fetches are
             * emulated in superh_cpu_do_interrupt instead. */
            struct { uint32_t off; const uint8_t *b; } sb[] = {
                { 0x00, blk_maskbyte }, { 0x10, blk_poplist },
                { 0x50, blk_cas },     { 0x60, blk_inc },
                { 0x70, blk_xadd },
            };
            for (unsigned i = 0; i < ARRAY_SIZE(sb); i++) {
                uint8_t cur[16];
                cpu_physical_memory_read(0x0C020B80 + sb[i].off, cur, 16);
                bool zero = true;
                for (int j = 0; j < 16; j++) {
                    if (cur[j]) { zero = false; break; }
                }
                if (zero) {
                    cpu_physical_memory_write(0x0C020B80 + sb[i].off,
                                              sb[i].b, 16);
                } else {
                    fprintf(stderr, "MMCS: ILKFIX slot +%03x busy "
                            "(live vendor data) - emulation only\n",
                            sb[i].off);
                }
            }
            seeded = true;
            fprintf(stderr, "MMCS: ILKFIX seeded interlocked blocks "
                    "@phys 0x0C020B80 (KData page)\n");
        }
        tlb_set_page(cs, 0x5000, 0x0C020000,
                     PAGE_READ | PAGE_WRITE | PAGE_EXEC, mmu_idx,
                     TARGET_PAGE_SIZE);
        return true;
    }

    /* MMCS fork: low-slot unbound-sentinel pages (VA 0x4000-0x7FFF, the
     * 0x5bd0-class init-stage targets, S82-S84). The kernel flushes
     * preloaded UTLB entries (MMUCR.TI) so ldtlb cannot survive; satisfy
     * these fetches here by mapping to the fork's rts-stub page at phys
     * 0x4000 (mapped under MMCS_LOWSLOT). Callers jsr into the sentinel,
     * hit rts, return harmlessly, retry loop advances. */
    if (ret != MMU_OK && address >= 0x4000 && address < 0x8000
        && getenv("MMCS_LOWSLOT")) {
        physical = address;               /* 1:1 to the rts page region */
        prot = PAGE_READ | PAGE_EXEC;
        tlb_set_page(cs, address & TARGET_PAGE_MASK,
                     address & TARGET_PAGE_MASK,
                     PAGE_READ | PAGE_EXEC, mmu_idx, TARGET_PAGE_SIZE);
        return true;
    }

    if (ret == MMU_OK) {
        address &= TARGET_PAGE_MASK;
        physical &= TARGET_PAGE_MASK;
        /* MMCS fork: MMCS_PSLFIX — force-complete coredll's PSL bind.
         *
         * Decoded 2026-11-15 (driver-init lane): each process's coredll
         * binds the running PSL servers' API sets via the bind fn at
         * coreddll VA 0x400181f0 (queries A/B/C/E = kernel api0-m17
         * lookups returning set handles 0x00400103..0x00430103, D = the
         * set-66 ready check via api2-m26). The E step (FUN_40024fc4 ->
         * FUN_40024cf4 -> coredll heap grow -> kernel api0-m29 call at
         * slot 0xfffffdc7, PR=0x40021336, hProc=0xc0000005) returns NULL
         * in our boot: the kernel services it in the target-process
         * context and that path takes an exception (k.coredll PDATA
         * cluster 0xc0035bd4+) every time. The bind therefore never
         * reaches its success tail, the "PSL APIs bound" latch
         * *(0x400746d8) stays 0, the server-launch loop retries ~3033x,
         * the launch thread dies -> device.exe/BuiltIn/sdhi.dll never
         * load -> IISR chain[23]/[24] stay NULL (the 0xAE0/0xB00
         * no-wake root cause).
         *
         * coredll is a compressed XIP module: each process's slot copy is
         * decompressed to RAM by the kernel pager, so the fix patches the
         * E-failure branch `bt 0x4001821c` (word 0x89e5 at page offset
         * 0x24e of the page mapped at VA 0x40018000, signature-verified)
         * to a NOP at TLB-fill time — before the page is ever translated,
         * per process instance. The bind tail then always runs and sets
         * the latch; the PSL heap is simply absent (driver init is local
         * and does not need it). */
        if (getenv("MMCS_PSLFIX") && address == 0x40018000) {
            static const uint8_t sig[6] = {
                0x0b, 0x43, 0x09, 0x00, 0x08, 0x20   /* jsr r3;nop;tst;bt.. */
            };
            uint8_t buf[8];
            cpu_physical_memory_read(physical + 0x248, buf, 8);
            if (buf[6] == 0xe5 && buf[7] == 0x89
                && memcmp(buf, sig, 6) == 0) {
                static uint8_t nop[2] = { 0x09, 0x00 };
                cpu_physical_memory_write(physical + 0x24e, nop, 2);
                fprintf(stderr, "MMCS: PSLFIX patched coredll bind gate "
                        "(phys %08x)\n", (unsigned)(physical + 0x24e));
            }
        }
        tlb_set_page(cs, address, physical, prot, mmu_idx, TARGET_PAGE_SIZE);
        return true;
    }
    if (probe) {
        return false;
    }

    if (ret != MMU_DTLB_MULTIPLE && ret != MMU_ITLB_MULTIPLE) {
        env->pteh = (env->pteh & PTEH_ASID_MASK) | (address & PTEH_VPN_MASK);
    }

    env->tea = address;
    switch (ret) {
    case MMU_ITLB_MISS:
    case MMU_DTLB_MISS_READ:
        cs->exception_index = 0x040;
        break;
    case MMU_DTLB_MULTIPLE:
    case MMU_ITLB_MULTIPLE:
        cs->exception_index = 0x140;
        break;
    case MMU_ITLB_VIOLATION:
        cs->exception_index = 0x0a0;
        break;
    case MMU_DTLB_MISS_WRITE:
        cs->exception_index = 0x060;
        break;
    case MMU_DTLB_INITIAL_WRITE:
        cs->exception_index = 0x080;
        break;
    case MMU_DTLB_VIOLATION_READ:
        cs->exception_index = 0x0a0;
        break;
    case MMU_DTLB_VIOLATION_WRITE:
        cs->exception_index = 0x0c0;
        break;
    case MMU_IADDR_ERROR:
    case MMU_DADDR_ERROR_READ:
        cs->exception_index = 0x0e0;
        break;
    case MMU_DADDR_ERROR_WRITE:
        cs->exception_index = 0x100;
        break;
    default:
        cpu_abort(cs, "Unhandled MMU fault");
    }
    cpu_loop_exit_restore(cs, retaddr);
}
#endif /* !CONFIG_USER_ONLY */
