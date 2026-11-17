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

/* MMCS fork (L12): hw/sh4/mmcs.c serves seeded scratch pages for the
 * servant .data window (FILES-decompressed init content). */
hwaddr mmcs_srvpg_data_pa(uint32_t va);

/* MMCS fork (L17): MMCS_IATFIX — the generalized C0-window (kernel-side
 * DLL) module service from hw/sh4/mmcs.c: XIP .text pages map the flash
 * ROM bytes, non-XIP pages seed the decompressed init content (the
 * lost-page-table class generalized beyond k.coredll: the L17 A/B found
 * the woken PNPThread dying on an fsdmgr .text page 0xc02d7000 miss
 * after the .data seeding fix). */
extern int mmcs_iatfix_on;
hwaddr mmcs_iatfix_page_pa(uint32_t va, bool *rw);

/* MMCS fork (L8): the MMCS_FILEVIEW scratch va->pa table, hoisted to
 * file scope so diagnostics (MMCS_NULLCALL) can read a frozen stack
 * physically — the guest UTLB entries get flushed per launch, but the
 * backing phys pages live on in the mmcs.fileview RAM region. */
static struct { uint32_t va, pa; } mmcs_fvmap[16384];
static int mmcs_nfvmap;
static uint32_t mmcs_fvmap_nxt = 0x20000000;

/* MMCS fork (L8): shared ILKFIX progress latch — set when the first
 * USER-mode KData-page fault maps VA 0x5000 (coredll PSL bind = the
 * launches are live, the early IRQ-init walk is past). Gates (a) the
 * kernel-mode interlocked fetch map below and (b) the exception-boundary
 * emulation's kernel-side arming (its old function-local latch never
 * fired: user fetches hit the mapped page and never fault). */
static bool mmcs_ilkfix_user_seen;

/* MMCS fork (L8): is this VA a plausible CODE address for this unit?
 * Windows: KData/LOWSLOT 0x4000-0x8000, coredll user window
 * 0x40000000-0x40100000, PSL servant module windows 0xC0000000-0xC8000000
 * (filesys 0xc00b / fsdmgr 0xc02c / gwes... observed live), kernel XIP
 * P1 0x90800000-0x97000000. Kernel RAM P1 0x88600000+ is DATA in this
 * boot (KData/structs/loader tables — no relocatable kernel code ever
 * loads), heap arenas / stack arena / MMIO / ASCII garbage = not code.
 * Used by the KAPIFIX garbage-dispatch synthesis. */
static bool mmcs_plausible_code(uint32_t va)
{
    return (va >= 0x00004000 && va < 0x00008000)
        || (va >= 0x40000000 && va < 0x40100000)
        || (va >= 0xC0000000 && va < 0xC8000000)
        || (va >= 0x90800000 && va < 0x97000000);
}

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

    /* MMCS fork: MMCS_APIRET (L10) — recover the kernel PSL direct-return
     * that lands in a USER thread. Decode (L10): WIN32 implicit-set
     * method 129 (slot pc 0xfffffdff) = the vendor kernel's
     * QueryPerformanceCounter (static table decode: CINFO "Wn32"
     * @0x90821848 -> methods @0x90821028, [129]=0x90842378; live bp:
     * PSL servant callers, pr=0xc0050d9e-class, pass r4=&stack-buffer
     * — the "r4=0" seen at the trap boundary is the USER's leftover
     * gregs, not the kernel's call args). While servicing the launch-1
     * servant's wait-family call chain (m19 slot 0xfffffddb from the
     * coredll wrapper at 0x4002cb02 -> kernel sub-calls m129 twice:
     * traps with pr=0xfffffdff [slot convention] and pr=0x908236a8
     * [trampoline continuation]), the kernel's dispatch returns through
     * the kernel-mode direct-return address (KData.pAPIReturn,
     * +0x98 = 0x9082369e/0x908236a8 in the PSL trampoline) but with
     * SSR still carrying the USER mode bits: the thread fetches the
     * trampoline at kernel P1 0x908236a8 IN USER MODE -> 0x0e0 ->
     * the kernel raises RaiseException(0xC0000005, NONCONTINUABLE)
     * into the servant (the L9 "#10 fault"). The servant dies mid-init
     * WHILE OWNING the coredll .data critical section at 0x40074648
     * (kernel sync-object arena at phys 0x1068xxxx, name=0x40074648,
     * handle family 0x004302xx); the filesys relaunch's first wait on
     * that dead-owned object (m17 = the WaitForMultiple-family
     * per-object wait, slot 0xfffffddf, r5=0xffffffff INFINITE) never
     * returns = THE L10 PARK. Fix: at the boundary, a USER-mode fetch
     * fault at the trampoline window [0x908236a8,0x908236b0) (P1 or
     * P2 alias) = the direct-return arriving with the wrong mode bit:
     * set SR.MD and resume — the trampoline's own epilogue (add #16,
     * mov r8,r0, restore regs, jmp @r3 = the saved user continuation)
     * then unwinds the thread correctly, the wait call completes, the
     * creator leaves the .data critsec normally, and the relaunched
     * servant's INFINITE wait is satisfied. */
    if (env->mmcs_apiret_active && do_exp
        && (cs->exception_index == 0x0e0 || cs->exception_index == 0x040
            || cs->exception_index == 0x060 || cs->exception_index == 0x0a0)
        && !(env->sr & (1u << SR_MD))
        && ((env->pc >= 0x908236a8 && env->pc < 0x908236b0)
            || (env->pc >= 0xb08236a8 && env->pc < 0xb08236b0))) {
        static int naret;
        if (naret++ < 16) {
            fprintf(stderr, "MMCS: APIRET user-mode direct-return recovered, "
                    "pc=%08x pr=%08x spc=%08x\n", env->pc, env->pr,
                    env->spc);
        }
        env->sr |= (1u << SR_MD);
        cs->exception_index = -1;
        return;
    }

    /* MMCS fork: MMCS_KILLSTK (L11) — give the kernel's KillThread
     * dispatch a stack when the dying thread's sp is dead. Decode
     * (L11, gdb bp at the kill-init block 0x90825c9c + thread-struct
     * walk): the post-APIRET endgame kills the broken servant by
     * writing its thread context [+0xb0 sp][+0xb4 pc = KillThread
     * 0x9083be50][+0xb8 sr] and making it runnable; the scheduler
     * resumes it THROUGH the PSL trampoline (pr=0x908236a8), so the
     * epilogue's `add #16,r15` turns the dead sp 0 into 0x10 and
     * KillThread's first `mov.l r8,@-r15` faults at VA 0xC (NULL
     * page) -> ExceptionDispatch -> stack-grow fails (0x10 is in
     * neither the kernel stack [0xd026ff00] nor the user stack
     * [0x0002ff00] range) -> "Secure stack overflow" -> kill-init
     * AGAIN -> the ~10 Hz forever loop that eats the CPU the
     * driver-init walk needs (the L11 spin; the in_asm "walk" pcs
     * 0x908083f8/0x90822990 = the exception-report formatter dumping
     * each cycle's register dump to the 0xa4500000 log ring, char by
     * char via the 0x90806958 writer). Fix: a kernel-mode fault at
     * the KillThread entry with a NULL-page-class sp = the kill
     * continuation arriving with no stack: re-point r15 at the top
     * of a dedicated kill-stack page (P1 alias of phys 0x25000000 —
     * kernel-mode P1/P2 bypass the UTLB, no translation needed) and
     * re-execute; KillThread then runs its shutdown list and the
     * kill COMPLETES, freeing the scheduler for the launch chain.
     * Stack = P2 0xBF00FF00 (uncached alias of phys 0x1F000000+64K;
     * P1/P2 only translate phys < 0x20000000). */
    if (env->mmcs_killstk_active && do_exp
        && (cs->exception_index == 0x060 || cs->exception_index == 0x040
            || cs->exception_index == 0x0e0)
        && (env->sr & (1u << SR_MD))
        && (env->pc == 0x9083be50 || (env->pc & ~1) == 0x9083be50)
        && env->gregs[15] < 0x1000) {
        static int nkill;
        if (nkill++ < 32) {
            fprintf(stderr, "MMCS: KILLSTK kill-dispatch stacked: pc=%08x "
                    "sp=%08x -> BF00FF00\n", env->pc, env->gregs[15]);
        }
        env->gregs[15] = 0xBF00FF00;    /* P2 alias of the kill-stack page */
        cs->exception_index = -1;
        return;                         /* re-execute the entry push */
    }

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
    /* MMCS_NULLCALL=1 (L8 diagnostic): the first kernel-mode fetch fault
     * at pc=0 (the NULL-fn-call freeze entry, silently absorbed by the
     * return-to-pr=0 loop below) dumps the full register set + stack
     * words BEFORE the black hole — the frames at r15 name the caller
     * chain that jumped/returned to NULL. Rate-limited: first 8 dumps,
     * then every 100000th (loop proof). */
    if (env->pc == 0x00000000 && getenv("MMCS_NULLCALL")
        && (env->sr & (1u << SR_MD))) {
        static unsigned long nseen;
        nseen++;
        if (nseen <= 8 || nseen % 100000 == 0) {
            fprintf(stderr, "NULLCALL #%lu exp=%03x pr=%08x spc=%08x "
                    "r0=%08x r1=%08x r2=%08x r3=%08x r4=%08x r5=%08x "
                    "r6=%08x r7=%08x r8=%08x r9=%08x r10=%08x r11=%08x "
                    "r12=%08x r13=%08x r14=%08x r15=%08x\n",
                    nseen, cs->exception_index, env->pr, env->spc,
                    env->gregs[0], env->gregs[1], env->gregs[2],
                    env->gregs[3], env->gregs[4], env->gregs[5],
                    env->gregs[6], env->gregs[7], env->gregs[8],
                    env->gregs[9], env->gregs[10], env->gregs[11],
                    env->gregs[12], env->gregs[13], env->gregs[14],
                    env->gregs[15]);
            fprintf(stderr, "NULLSTACK(virt):");
            for (int i = 0; i < 32; i++) {
                uint32_t w = 0;
                cpu_memory_rw_debug(cs, env->gregs[15] + 4 * i,
                                    (void *)&w, 4, 0);
                fprintf(stderr, " %08x", w);
            }
            fprintf(stderr, "\n");
            /* same words read PHYSICALLY through the FILEVIEW scratch
             * map (the guest UTLB entry may have been flushed since) */
            {
                uint32_t pg = env->gregs[15] & ~0xFFFu;
                uint32_t base_pa = 0;
                for (int j = 0; j < mmcs_nfvmap; j++) {
                    if (mmcs_fvmap[j].va == pg) {
                        base_pa = mmcs_fvmap[j].pa;
                        break;
                    }
                }
                if (base_pa) {
                    fprintf(stderr, "NULLSTACK(phys):");
                    for (int i = 0; i < 48; i++) {
                        uint32_t a = env->gregs[15] + 4 * i;
                        uint32_t pa = 0;
                        for (int j = 0; j < mmcs_nfvmap; j++) {
                            if (mmcs_fvmap[j].va == (a & ~0xFFFu)) {
                                pa = mmcs_fvmap[j].pa + (a & 0xFFFu);
                                break;
                            }
                        }
                        uint32_t w = 0;
                        if (pa) {
                            cpu_physical_memory_read(pa, &w, 4);
                        }
                        fprintf(stderr, " %08x", w);
                    }
                    fprintf(stderr, "\n");
                }
            }
        }
    }
    if (env->mmcs_kapifix_active
        && (cs->exception_index == 0x040 || cs->exception_index == 0x060)
        && (env->pc == 0x908083fc || env->pc == 0x00000000)) {
        env->gregs[0] = 0;
        env->pc = env->pr;
        cs->exception_index = -1;
        return;
    }
    /* KAPIFIX part 1b (L8, 2026-11-16): kernel-side garbage-dispatch
     * synthesis — the twin of the user-side MMCS_APIFIX 0xFFFFxxxx
     * class. With ILKFIX kernel-mode interlocked ops armed (L8), the
     * per-IRQ-source walk (callers 0x90807674/0x90807720-class) gets
     * past the old abort points and calls the kernel API thunk table
     * (@0x908083f8: r2=*(slot); jmp @*(r2+40)) with slots the loader
     * never bound: *(slot) points into loader data (observed method
     * 0x73617245 = ASCII "Ears", bytes from IPILib.dll's image) and
     * the tail-jmp fetch-faults at the garbage VA. Because the thunk
     * TAIL-JUMPS, pr = the original caller's post-jsr site, and those
     * callers ignore the return value (L3-proven) — so synthesize the
     * failed call: r0=0, resume at pr. Gated to KERNEL-mode fetch
     * faults whose pc is outside every real code window of this unit
     * AND whose pr is inside one (no synthesizing returns to garbage
     * callers). */
    if (env->mmcs_kapifix_active
        && (cs->exception_index == 0x040 || cs->exception_index == 0x0e0
            || cs->exception_index == 0x180
            || cs->exception_index == 0x1a0)
        && (env->sr & (1u << SR_MD))
        && env->pc != 0
        && env->pc < 0xffff0000     /* 0xFFFFxxxx = PSL syscall slots */
        && !mmcs_plausible_code(env->pc)
        && mmcs_plausible_code(env->pr)) {
        static int nkd;
        if (nkd++ < 32) {
            fprintf(stderr, "MMCS: KAPIFIX garbage dispatch pc=%08x "
                    "pr=%08x exp=%03x tea=%08x r4=%08x r15=%08x"
                    " -> failed-call return\n", env->pc,
                    env->pr, cs->exception_index, env->tea, env->gregs[4],
                    env->gregs[15]);
        }
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
    /* NOTE L15 (REVERTED EXPERIMENT): extending this guard to
     * pc=0x90807562 (the ring-handle read) was WRONG — that fault fires
     * in jmp-style call contexts where pr is stale/0, so the synthesis
     * jumped to 0 (a manufactured pc=0/pr=0 freeze). The real L15 fix is
     * the ring consumer (MMCS_RINGDRAIN): the producer's space check
     * `ring[12]-ring[8] < r6` blocks when nothing drains the ring. */
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
        && (env->pc & ~7u) >= 0x5B80 && (env->pc & ~7u) <= 0x5BF8) {
        bool kern = (env->sr & (1u << SR_MD)) != 0;
        if (!kern) {
            mmcs_ilkfix_user_seen = true;
        } else if (!(mmcs_ilkfix_user_seen && getenv("MMCS_KILK"))) {
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
        /* launched-server .data page-in misses = PSL launches live —
         * arm the kernel-mode ILKFIX fetch map (L8, MMCS_KILK) */
        if ((env->sr & (1u << SR_MD)) == 0 && getenv("MMCS_KILK")) {
            mmcs_ilkfix_user_seen = true;
        }
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

    /* MMCS fork: MMCS_FILEVIEW (L7) — back the launched servers' user
     * heap-arena write misses below 0x40000000.
     *
     * Decoded 2026-11-16 (launch lane, third pass): the per-launch
     * death sequence is NOT the 0xC8001000 reads (those are normal
     * kernel demand-paging — the kernel miss handler @0x90822de6
     * refills the SystemHeap window from real phys 0x08684000 /
     * 0x08a96000, proven by MMCS_UTLBLOG; do NOT intercept). The
     * actual killer, per -d int block-walk before every
     * RaiseException(0xC0000005) (x3025/boot): the coredll heap-grow
     * fn @0x40024d4c takes a USER write-MISS (excp 0x060) at
     * tea=0x18NN0036 — a user heap arena BELOW COWFIX's 0x40000000
     * floor (0x183f0000.. incrementing +0x20000 per relaunch =
     * 128KB leaked block per dead launch). Kernel servicing
     * (pc=0x90807382 x2) cannot page it in (the same broken pager
     * holes), so the write propagates as 0xC0000005 -> launch dies
     * -> relaunch. Fix: extend COWFIX shape (a) to tea >= 0x00800000
     * (above LOWSLOT, below 0x40000000), backed by the dedicated
     * "mmcs.fileview" RAM region at phys 0x20000000 (env MMCS_FILEVIEW
     * creates it in mmcs.c; 64MB = ~512 launches of leaked blocks —
     * enough for the driver-init phase to complete). VA-deduped like
     * the original COWFIX; exhaustion falls through to the old
     * behavior with a log line.
     *
     * Second shape (same pass): KERNEL-mode write-miss of the
     * 0xD0600000-0xDC000000 stack arena — the per-launch kernel-
     * thread stacks (tea=0xDBxxEF30-class descending 0x10000 per
     * relaunch, then 0xDAxx/0xD1xx after the first window was
     * covered, REPEATED faults at the same address = the kernel
     * retry-fails writing its own exception frame -> thread kill
     * 0xC0000005). The kernel never installs entries for these
     * (MMCS_UTLBLOG: no stack-arena installs); same scratch
     * treatment.
     *
     * L12 (2026-11-16): with the relaunch cycle surviving past the
     * servant page-ins (MMCS_SRVPG), the per-launch kernel stacks
     * march UP from 0xd006f000 (+0x10000/launch) and the newest
     * stack page is again missing from the guest page tables at the
     * thread's first write (pc=0xc003c9e0, tea=0xd007fe8c-class) —
     * the exception propagates and the launch parks. The L7-era
     * 0xD0600000 floor ("corrupts live kernel tables below") predates
     * KILK (its freeze = the L8 never-started-thread class, since
     * root-caused); MMCS_STKFLOOR=<hex> lowers the intercept floor
     * for the A/B (default unchanged). */
    static uint32_t mmcs_stkfloor;
    if (!mmcs_stkfloor) {
        const char *sf = getenv("MMCS_STKFLOOR");
        mmcs_stkfloor = sf ? strtoul(sf, NULL, 16) : 0xD0600000;
    }
    /* MMCS fork (L15d): MMCS_NULLTAG — a kernel-mode FETCH at pc=0
     * (the NULL-fn-call class; live caller spc=0x908381b8, args
     * r1=0xf4008000 vendor-INTC) loops forever on real-semantics
     * escalation: the ITLB miss handler can't resolve VA 0 AND the
     * vendor fault path never runs (the L2 walk dead-ends silently), so
     * the CPU refetches 0 (600k+ NULLCALL samples). Real HW escalates
     * the fetch to a fault the kernel understands -> the calling thread
     * dies via the marshalled 0xC0000005 path. Re-tag the exception as
     * 0x0e0 (data/address fault) with tea=pc so the vendor handler runs
     * its real TerminateProcess path — no synthesis, just escalation. */
    if (getenv("MMCS_NULLTAG")
        && cs->exception_index == 0x040
        && env->pc < 0x1000
        && (env->sr & (1u << SR_MD)) != 0) {
        env->tea = env->pc;
        cs->exception_index = 0x0e0;
        return;
    }

    /* MMCS fork (L15): MMCS_KPG — the kernel's low structure window
     * (VA 0x90600000-0x90800000 = P1 aliases of the ram3 backing at phys
     * 0x10000000-0x10800000) loses UTLB entries whose page-table refill
     * path died with the fault-aborted constructors (S130 class): the
     * live ring handle read at 0x90807562 (r4=0x9068fa88) faulted and
     * re-faulted forever — the L15 exception-entry park. FINDPAT proved
     * the backing page EXISTS (ring struct at phys 0x1068f784, identity
     * VA&0x1FFFFFFF). Fix: on kernel-mode DATA miss (0x0a0 read / 0x0c0
     * write) in that window, install the identity UTLB entry — no data
     * is invented, only the lost mapping restored. */
    if (env->mmcs_cowfix_active && getenv("MMCS_KPG")
        && (((cs->exception_index == 0x0a0 || cs->exception_index == 0x0c0)
            && (env->sr & (1u << SR_MD)) != 0
            && env->tea >= 0x90600000 && env->tea < 0x90800000)
            /* L15b: kernel .text fetch misses (excp 0x040, tea reads 0 —
             * use pc) — the code pages at 0x908xxxxx lose ITLB entries to
             * UTLB churn and the dead refill path can't restore them (the
             * L15 park looped refetching 0x90807562 forever). Identity
             * map (phys = VA & 0x1FFFFFFF = the XIP NOR window). */
            || ((cs->exception_index == 0x040)
                && ((env->sr & (1u << SR_MD)) != 0)
                && (env->pc >= 0x90800000 && env->pc < 0x91000000)))) {
        uint32_t kva = ((cs->exception_index == 0x040) ? env->pc : env->tea)
                       & ~0xFFFu;
        uint32_t kpa = kva & 0x1FFFFFFFu;   /* P1-alias identity */
        env->pteh = (kva & PTEH_VPN_MASK) | (env->pteh & PTEH_ASID_MASK);
        env->ptel = ((kpa >> 10) << 10)
                    | (3 << 5) | PTEL_V | PTEL_SZ_LOW
                    | PTEL_C | PTEL_D | PTEL_SH;
        cpu_load_tlb(env);
        increment_urc(env);
        cs->exception_index = -1;
        return;
    }

    /* MMCS_HBZERO (S131 repair #1): heap-window DATA-READ misses
     * (exception 0x0A0 — distinct from the 0x040 instruction-fetch miss)
     * get a demand-zero page. Rationale: the coredll list-walker (S129)
     * follows item pointers into never-written heap VAs; FILEVIEW only
     * backs writes. With a zero page the item key (+12) reads 0 — never
     * matches — and next (0) terminates the walk cleanly. Additive,
     * user-heap window only. */
    if (env->mmcs_cowfix_active && getenv("MMCS_HBZERO")
        && cs->exception_index == 0x0a0
        && (env->sr & (1u << SR_MD)) == 0
        && env->tea >= 0x00800000 && env->tea < 0x40000000) {
        uint32_t rva = env->tea & ~0xFFFu;
        uint32_t rpa = 0;
        for (int i = 0; i < mmcs_nfvmap; i++) {
            if (mmcs_fvmap[i].va == rva) {
                rpa = mmcs_fvmap[i].pa;
                break;
            }
        }
        if (!rpa
            && mmcs_fvmap_nxt + 0x1000 <= 0x24000000
            && mmcs_nfvmap < 16384) {
            rpa = mmcs_fvmap_nxt;
            mmcs_fvmap_nxt += 0x1000;
            mmcs_fvmap[mmcs_nfvmap].va = rva;
            mmcs_fvmap[mmcs_nfvmap].pa = rpa;
            mmcs_nfvmap++;
        }
        if (rpa) {
            env->pteh = (rva & PTEH_VPN_MASK) | (env->pteh & PTEH_ASID_MASK);
            env->ptel = ((rpa >> 10) << 10)
                        | (3 << 5) | PTEL_V | PTEL_SZ_LOW
                        | PTEL_C | PTEL_D | PTEL_SH;
            cpu_load_tlb(env);
            increment_urc(env);
            cs->exception_index = -1;
            return;
        }
    }

    /* L15c: movca.l emulation LOADS the destination before storing (the
     * cache-line-backup pattern in translate.c) — a READ miss (0x0a0) on
     * a not-yet-allocated arena page froze the kernel stack-fill loop
     * forever (pc=0x90838b8c, no fault census — the load re-faulted each
     * re-execution). Cover arena READ misses with the same demand
     * allocation as writes: the page is written immediately after. */
    if (env->mmcs_cowfix_active && getenv("MMCS_FILEVIEW")
        && (cs->exception_index == 0x060
            || cs->exception_index == 0x0c0
            || (cs->exception_index == 0x0a0
                && (env->sr & (1u << SR_MD)) != 0
                && env->tea >= mmcs_stkfloor
                && env->tea < 0xDC000000
                && (env->tea >= mmcs_stkfloor || mmcs_ilkfix_user_seen)))
        && (((env->sr & (1u << SR_MD)) == 0
             && env->tea >= 0x00800000 && env->tea < 0x40000000)
            || ((env->sr & (1u << SR_MD)) != 0
                && env->tea >= mmcs_stkfloor
                && env->tea < 0xDC000000
                /* below the L7 default floor = the L12 march frontier:
                 * only once the launches are live (the early IRQ-init
                 * walk's own low-arena writes must reach the guest) */
                && (env->tea >= mmcs_stkfloor || mmcs_ilkfix_user_seen)))) {
        /* user heap-arena write misses only happen once the PSL
         * launches are live — arm the kernel-mode ILKFIX fetch map
         * (L8, MMCS_KILK) */
        if ((env->sr & (1u << SR_MD)) == 0 && getenv("MMCS_KILK")) {
            mmcs_ilkfix_user_seen = true;
        }
        uint32_t va = env->tea & ~0xFFFu;
        uint32_t pa = 0;
        for (int i = 0; i < mmcs_nfvmap; i++) {
            if (mmcs_fvmap[i].va == va) {
                pa = mmcs_fvmap[i].pa;
                break;
            }
        }
        if (!pa) {
            if (mmcs_fvmap_nxt + 0x1000 <= 0x24000000 && mmcs_nfvmap < 16384) {
                pa = mmcs_fvmap_nxt;
                mmcs_fvmap_nxt += 0x1000;
                mmcs_fvmap[mmcs_nfvmap].va = va;
                mmcs_fvmap[mmcs_nfvmap].pa = pa;
                mmcs_nfvmap++;
                /* MMCS_FVLOG=1 (L8 diagnostic): every NEW scratch-page
                 * install (va, pa) — the stack-arena march + heap-arena
                 * leak census source, and the pa lookup for reading a
                 * frozen stack via physical memory. */
                if (getenv("MMCS_FVLOG")) {
                    static int nfvl;
                    if (nfvl++ < 4096) {
                        fprintf(stderr, "FVMAP new va=%08x -> pa=%08x "
                                "(n=%d)\n", va, pa, mmcs_nfvmap);
                    }
                }
            } else {
                fprintf(stderr, "MMCS: FILEVIEW scratch exhausted "
                        "(%d pages)\n", mmcs_nfvmap);
                goto fileview_done;
            }
        }
        /* install a guest UTLB entry via the ldtlb path (COWFIX miss
         * branch pattern) so kernel-mode servicing of the same VA
         * resolves too. */
        env->pteh = (va & PTEH_VPN_MASK) | (env->pteh & PTEH_ASID_MASK);
        env->ptel = ((pa >> 10) << 10)      /* PPN */
                    | (3 << 5)              /* PR = RW */
                    | PTEL_V | PTEL_SZ_LOW  /* 4K */
                    | PTEL_C | PTEL_D | PTEL_SH;
        cpu_load_tlb(env);
        increment_urc(env);
        cs->exception_index = -1;
        return;                     /* re-execute the store */
    }
fileview_done:;

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
            /* L20 (S140): the AutoLoad boot-FS phase value. Ground truth
             * = the real default.fdf hive (tree/Registry/default.reg):
             * [HKLM\System\StorageManager\AutoLoad\ObjectStore] carries
             * BootPhase=0 (Dll=filesys.dll, MountAsBootable=1) — the
             * object store IS the phase-0 boot filesystem on this unit,
             * mounted by StartBootPhase(0)'s AutoLoadFileSystems before
             * any block device exists (the documented CE boot order:
             * object store -> ROM files -> registry -> phase 1 FSDs
             * (Relfsd, BootPhase=1) -> LaunchXX/device.dll at phase 2).
             * Our synthetic registry only ever enumerates the compiled-in
             * 'Relfs' subkey (BootPhase-less), so every AutoLoad(0)
             * pass skips the mount and the filesys init sequence re-runs
             * StartBootPhase(0) forever (~7 Hz, the L20 gate). Answering
             * BootPhase=0 makes the enumerated entry mount at phase 0 =
             * the real ObjectStore mechanism. Gated: only while the
             * phase-0 loop is still spinning (first answers), so later
             * phases read their real values. */
            { "BootPhase", 0 },
        };
        /* L20: stop answering BootPhase after the phase-0 loop has had
         * 64 chances (a mounted boot FS stops the loop; a real phase-2
         * query later must see the live value, not our synthesis). */
        static int mmcs_l20_bootphase_n;
        uint32_t l20_bootphase = (mmcs_l20_bootphase_n++ < 64);
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
                if (strcmp(name, vals[k].name) == 0) {
                    if (strcmp(name, "BootPhase") == 0 && !l20_bootphase) {
                        break;  /* L20 gate: phase-0 window closed */
                    }
                    hit = vals[k].dword;
                    break;
                }
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

    /* MMCS fork: MMCS_KSLOT (L12) — raise the API-slot fetch fault for
     * KERNEL-mode slot calls. The vendor coredll re-raise wrapper
     * (0xc002f0a0-class: `mov.w #slot_lo16; jmp @r3`) jumps to the odd
     * 0xFFFFxxxx slot address expecting the instruction-fetch ADDRESS
     * ERROR (event 0x0e0) that the stock APICall entry (VBR+0x100,
     * shexcept.src) decodes as the syscall purely from (event==0x0e0 &&
     * SPC odd && SPC >= API_MAX) — mode-agnostic, with the previous
     * mode passed along via r2_user. QEMU's SH4 model raises that
     * address error for USER-mode P4 fetches only; a KERNEL-mode fetch
     * at the same VA is served from the unassigned system bus (the
     * page is softmmu-cached as MMIO by the marshaller's own data
     * loads at 0xfffffff8-class, so it never even reaches tlb_fill as
     * a fetch), reads 0x0000, and raises illegal_instruction 0x180
     * instead — so every kernel-side exception re-raise (the L12
     * forwarded-exception end game: no user handler installed ->
     * wrapper jmp @slot with the marshalled code) turns into
     * 0xC000001D, which is itself forwarded, re-raised, and recursed
     * ~55 deep down the kernel stack 0x450/iteration (the L12 march +
     * CPU burn that starves the relaunch chain). Fix: at the exception
     * boundary, a KERNEL-mode illegal-instruction raise (0x180/0x1a0)
     * whose pc is in the slot window [0xFFFF8000, 4GB) = the
     * kernel-mode API-slot call: re-tag it as the 0x0e0 address error
     * the vendor syscall entry decodes (SPC/SSR already saved by the
     * illegal raise; TEA := pc) and let the normal dispatch deliver
     * the vendor kernel its syscall. Gated on the launch-phase latch. */
    if (env->mmcs_kslot_active && do_exp
        && (cs->exception_index == 0x180 || cs->exception_index == 0x1a0)
        && (env->sr & (1u << SR_MD))
        && env->pc >= 0xFFFF8000u
        && mmcs_ilkfix_user_seen) {
        static int nks;
        if (nks++ < 32) {
            fprintf(stderr, "MMCS: KSLOT kernel-mode slot call pc=%08x "
                    "pr=%08x -> 0x0e0\n", env->pc, env->pr);
        }
        env->tea = env->pc;
        cs->exception_index = 0x0e0;
        /* fall through to the normal 0x0e0 dispatch */
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

    /* MMCS fork: MMCS_UTLBLOG — log guest UTLB installs in the
     * 0xC8000000 SystemHeap window (L7: which phys does the kernel
     * give the heap pages, and when). */
    if (getenv("MMCS_UTLBLOG")
        && (env->pteh & PTEH_VPN_MASK) >= 0xC8000000
        && (env->pteh & PTEH_VPN_MASK) < 0xC9000000
        && (env->ptel & PTEL_V)) {
        static int nlog;
        if (nlog++ < 100) {
            fprintf(stderr, "UTLBINSTALL va=%08x pa=%08x pr=%d sh=%d "
                    "sz=%d pc=%08x\n",
                    (env->pteh & PTEH_VPN_MASK) & ~0x3FF,
                    (env->ptel & 0x1FFFFC00) << 0,
                    (env->ptel >> 5) & 3, (env->ptel >> 1) & 1,
                    1 << (7 + 2 * ((env->ptel >> 7) & 3)),
                    env->pc);
        }
    }

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
     *
     * L8 correction (2026-11-16, launch lane): the abort-early policy
     * is right for the EARLY walk but wrong afterwards — kernel-mode
     * fetch faults at the interlocked block were censused at x223/boot
     * (0x5bd0 ILCmpExchange x93, 0x5bf0 ILXAdd/Decrement x127, 0x5b90
     * ILPopList x3) once launches run: the locked-inc helper
     * (0x908383c8, called from the thread/process-creation chain
     * 0x90835f10) aborts MID-CREATION, a half-built thread is queued,
     * and the scheduler later resumes its zeroed context (pc=0 pr=0 =
     * the L8 freeze); the never-executed InterlockedDecrement x127 =
     * the 64KB/launch stack-block leak marching the 0xD0 arena. Stock
     * intrlock.src runs these ops in "Kernel mode or User mode". Fix:
     * AFTER the first user-mode KData-page fault (mmcs_ilkfix_user_seen
     * = launches live, early walk past), kernel-mode FETCH faults into
     * [0x5B80,0x5C00) map the same seeded page. Data faults and the
     * whole page stay user-only (loader-data holes stay hidden).
     */
    if (ret != MMU_OK && ((uint32_t)address & 0xFFFFF000u) == 0x5000
        && ((mmu_idx == MMU_USER_IDX)
            || (getenv("MMCS_KILK")
                && mmcs_ilkfix_user_seen
                && access_type == MMU_INST_FETCH
                && (uint32_t)address >= 0x5B80
                && (uint32_t)address < 0x5C00))
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
        if (mmu_idx == MMU_USER_IDX) {
            mmcs_ilkfix_user_seen = true;
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

    /* MMCS fork: MMCS_SRVPG (L12) — page-in synthesis for the relaunched
     * servant's kernel-side k.coredll .text window.
     *
     * Decoded 2026-11-16 (L12, gdb bps at the servant entry 0xc004dba2 +
     * the re-raise jsr 0xc0036364 + the -d int walk): after KILLSTK the
     * relaunch cycle dies BEFORE its first syscall because the relaunched
     * servant's fresh thread (r16 cookie 0x108f115e-class) faults on its
     * FIRST kernel-side startup fetch (ITLB miss 0x040 at servant .text
     * e.g. 0xc003c3dc) — the guest's 2-level walk finds no page-table
     * entry for the new process's slot (the relaunch never rebuilds the
     * k.coredll module mapping; launch-1's directory is gone with the
     * dead process), so the vendor kernel's ExceptionDispatch classifies
     * the miss as a PSL-call access violation and FORWARDS it to user
     * mode: kernel 0x90823340 jsr's the marshal fn 0x90825694 which
     * forges the "user continuation" (RAM cells 0x8867f030 sp /
     * 0x8867f034 pc) and the rte at 0x908233d8 delivers the thread at
     * the k.coredll PSL-exception stub 0xc004dba2 with a 0xe4(228)-byte
     * marshalled param block (r4; the "ERROR 0xe4" of the L11 notes is
     * the BLOCK SIZE loaded by `mov.w #0xe4` at 0x90823334 — not an
     * error code; the block's first dword IS the error: 0xC0000005).
     * The stub -> 0xc00360f4 checks the per-process user exception
     * handler cell 0xc00836f0 (NULL — nobody ran SetExceptionHandler),
     * then tail-jumps 0xc004db6c which re-raises via the coredll API
     * wrapper at 0xc002f0a0 (`mov.w #0xfdc7; jmp @r3` — a USER-mode
     * syscall-slot call). But the whole forged chain carries SSR.MD=1
     * (the thread's own saved kernel mode — CE4 servants run kernel
     * side, so the vendor design is correct), and a KERNEL-mode fetch
     * at the 0xFFFFxxxx slot does not raise the slot-call fetch fault
     * in this SH4 model (P4 passthrough reads unassigned-bus zeros):
     * the fetched 0x0000 word raises illegal_instruction 0x180 ->
     * 0xC000001D (pr=0xc0036368) -> TerminateProcess -> relaunch ->
     * same missing page -> loop (94/320s in the L11 census, kernel
     * stack marching 0x450/launch).
     *
     * Fix (LOWSLOT/KILK shape): service the missing fetch directly —
     * a KERNEL-mode instruction miss in the k.coredll servant .text
     * window [0xC0021000, 0xC0082AD8) (the linear, unrelocated ROM
     * module section — byte-verified live: the stub page 0xc004dba2
     * and the wrapper 0xc002f0a0 match their ROM images exactly) maps
     * the 4K page at the flash ROM physical [0x108CC000 + (va -
     * 0xC0021000)] and re-executes. The fetch succeeds, the exception
     * is never raised, the forward/marshal/re-raise chain never runs,
     * and the relaunched servant proceeds into its normal startup.
     * Gated on the launch-phase latch (mmcs_ilkfix_user_seen) so the
     * early IRQ-init walk never touches the window. */
    if (ret != MMU_OK && mmu_idx != MMU_USER_IDX
        && mmcs_ilkfix_user_seen
        && env->mmcs_srvpg_active
        && (((uint32_t)address >= 0xC0021000
             && (uint32_t)address < 0xC0082B00
             && (access_type == MMU_INST_FETCH
                 || access_type == MMU_DATA_LOAD))
            || ((uint32_t)address >= 0xC0083000
                && (uint32_t)address < 0xC009D000))) {
        uint32_t page = (uint32_t)address & 0xFFFFF000u;
        if (page < 0xC0083000) {
            /* .text (and .text read as data): the linear unrelocated
             * ROM module image, mapped read-only straight at flash. */
            hwaddr pa = 0x108CC000 + (page - 0xC0021000);
            if (getenv("MMCS_SRVPGLOG")) {
                static int npg;
                if (npg++ < 64) {
                    fprintf(stderr, "MMCS: SRVPG servant page-in va=%08x "
                            "-> pa=%08" HWADDR_PRIx "\n", page, pa);
                }
            }
            tlb_set_page(cs, page, pa, PAGE_READ | PAGE_EXEC, mmu_idx,
                         TARGET_PAGE_SIZE);
        } else {
            /* .data sections: FILES-compressed init content — seeded
             * scratch page from hw/sh4/mmcs.c (deduped per VA). */
            hwaddr pa = mmcs_srvpg_data_pa(page);
            if (pa) {
                tlb_set_page(cs, page, pa, PAGE_READ | PAGE_WRITE, mmu_idx,
                             TARGET_PAGE_SIZE);
            } else {
                fprintf(stderr, "MMCS: SRVPG servant .data scratch "
                        "exhausted at va=%08x\n", page);
                return false;
            }
        }
        return true;
    }

    /* MMCS fork (L17): MMCS_IATFIX — the generalized kernel-side-DLL
     * window service (the SRVPG class beyond k.coredll; see the full
     * decode in hw/sh4/mmcs.c). A KERNEL-mode fetch/load miss anywhere
     * in the C0 window covered by the SRVPGTAB manifest: XIP .text
     * sections map the flash ROM bytes RO+X (the kernel-side mapping
     * the real pager installs — fsdmgr .text 0xc02c1000 <-> ROM
     * 0x90a82000, byte-identical), non-XIP sections map the seeded
     * decompressed-init scratch page (RW per the o32 write flag).
     * Gated on the launch-phase latch exactly like SRVPG. */
    if (ret != MMU_OK && mmu_idx != MMU_USER_IDX
        && mmcs_ilkfix_user_seen
        && mmcs_iatfix_on
        && (uint32_t)address >= 0xC0000000
        && (uint32_t)address < 0xC1000000
        && (access_type == MMU_INST_FETCH
            || access_type == MMU_DATA_LOAD
            || access_type == MMU_DATA_STORE)) {
        bool rw = false;
        hwaddr pa = mmcs_iatfix_page_pa((uint32_t)address, &rw);
        if (pa) {
            if (access_type == MMU_DATA_STORE && !rw) {
                /* store to a read-only section: let the normal write
                 * violation path run (fidelity: no silent writes) */
                return false;
            }
            int iprot = (rw ? (PAGE_READ | PAGE_WRITE) : PAGE_READ)
                        | PAGE_EXEC;
            tlb_set_page(cs, (uint32_t)address & 0xFFFFF000u, pa,
                         iprot, mmu_idx, TARGET_PAGE_SIZE);
            return true;
        }
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
