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
#include "hw/core/tcg-cpu-ops.h"
#include "exec/log.h"

#if !defined(CONFIG_USER_ONLY)
#include "hw/sh4/sh_intc.h"
#include "sysemu/runstate.h"
#include "migration/vmstate.h"
#include "migration/register.h"
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
hwaddr mmcs_iatfix_page_pa(uint32_t va, bool *rw, bool kernel_side);
/* MMCS fork (L28): MMCS_FSVT — the api-set cell binds (hw/sh4/mmcs.c).
 * mmcs_fsvt_bind_cells: one-shot physical write of the FILESYS/WIN32
 * method-table cells; returns the number written. mmcs_fsvt_p1: the
 * fallback table's P1 address (0 when not armed). */
int mmcs_fsvt_bind_cells(CPUState *cs);
uint32_t mmcs_fsvt_cell_debug(uint32_t cell);
uint32_t mmcs_fsvt_p1(void);
/* MMCS fork (L29): MMCS_REGVT — the FileSys api-set REGISTRY methods
 * service (hw/sh4/mmcs.c parses the real default.reg hive; the hook
 * below synthesizes the registered set's method answers at register
 * level when the [c00835c0] methods-cell derefs fault). */
int mmcs_regvt_is_armed(void);
uint32_t mmcs_regvt_open(uint32_t hkey, const char *subkey);
uint32_t mmcs_regvt_query(uint32_t hkey, const char *name,
                          uint32_t *type, uint32_t *len,
                          const uint8_t **data);
int mmcs_regvt_enum_key(uint32_t hkey, uint32_t idx, const char **name);
int mmcs_regvt_enum_value(uint32_t hkey, uint32_t idx,
                          const char **name, uint32_t *type,
                          uint32_t *len, const uint8_t **data);
int mmcs_regvt_query_info(uint32_t hkey, uint32_t *nsub,
                          uint32_t *maxsub, uint32_t *nvals,
                          uint32_t *maxvalname, uint32_t *maxval);
void mmcs_regvt_set(uint32_t hkey, const char *name, uint32_t type,
                    const uint8_t *data, uint32_t len);
int mmcs_regvt_bind(CPUState *cs);
uint32_t mmcs_regvt_method(uint32_t off);
uint32_t mmcs_regvt_stubs_p1(void);
int mmcs_regvt_read(CPUState *cs, uint32_t va, uint8_t *buf, int len);
/* MMCS fork (L22): MMCS_C0ARM — arm the C0-window module service in
 * the kernel-side servant lane (the launch latch never fires there;
 * see the full decode in hw/sh4/mmcs.c). */
extern int mmcs_c0arm;
/* MMCS fork (L23): MMCS_UWARM — kernel-mode user-window manifest
 * service (see hw/sh4/mmcs.c for the decode). */
extern int mmcs_uwarm;

/* MMCS fork (L21): MMCS_PGOWN — the write-sticky page-ownership table
 * (hw/sh4/mmcs.c). Consulted at every tlb_set_page site below: clean
 * writable pages install without PAGE_WRITE (the first store's
 * permission bounce re-enters tlb_fill — the guest translation grants
 * write, so no guest exception — and pins the page it lands on);
 * pinned pages override any later guest-authored remap of the VA with
 * their pinned backing. Passthrough when MMCS_PGOWN is unset. */
int mmcs_pgown_fill(CPUSH4State *env, uint32_t address, uint32_t *pa,
                    int prot, int is_store);

/* MMCS fork (L8): the MMCS_FILEVIEW scratch va->pa table, hoisted to
 * file scope so diagnostics (MMCS_NULLCALL) can read a frozen stack
 * physically — the guest UTLB entries get flushed per launch, but the
 * backing phys pages live on in the mmcs.fileview RAM region. */
static struct { uint32_t va, pa; } mmcs_fvmap[16384];
static int mmcs_nfvmap;
static uint32_t mmcs_fvmap_nxt = 0x20000000;

/* MMCS fork (savestate lane): the COWFIX dedup map + bump allocator
 * (was function-static inside superh_cpu_do_interrupt's COWFIX block;
 * hoisted so the "mmcs/helper" vmstate can stream it — the scratch
 * pages themselves live in migrated RAM, but a lost map would
 * allocate FRESH pages on the first post-restore fault and lose the
 * COW content). */
struct mmcs_cowfix_ent { uint32_t va, pa; };
static struct mmcs_cowfix_ent mmcs_cowfix_map[512];
static int mmcs_cowfix_nmap;
static uint32_t mmcs_cowfix_next = 0x10710000;

/* MMCS fork (L32): va->pa lookup over the FILEVIEW dedup table, for
 * the hw-side wake daemons that must read a parked thread's stack
 * wait-struct (the D0 stacks are P3/UTLB — no P1 identity). Returns
 * 0 when unknown. */

/* MMCS fork (S159): hw/sh4/mmcs.c clears this while the MLD FLROM owns
 * phys [0,16MB) (the L26 P1 servant-alias claim would hijack the
 * loader's own P1 NOR reads); restored at the handoff FLROM retirement */
extern int mmcs_p1_alias_enabled;

/* MMCS fork (L75/S226): a kernel-RAM VA (the 0x88600000-0x90800000 window:
 * KData, the heap, the thread arena — VA-0x80000000 == PA). */
static inline int kpa(uint32_t va)
{
    return va >= 0x88600000u && va < 0x90800000u;
}

uint32_t mmcs_fv_va2pa(uint32_t va)
{
    for (int i = 0; i < mmcs_nfvmap; i++) {
        if (mmcs_fvmap[i].va == (va & ~0xFFFu)) {
            return mmcs_fvmap[i].pa + (va & 0xFFF);
        }
    }
    return 0;
}

/* MMCS fork (L33): resolve a guest VA through the LIVE UTLB (get_mmu_
 * address's own hit formula; ASID-agnostic — kernel stack mappings are
 * SH or kernel-ASID). A freshly ldtlb'd kstack page may not yet be in
 * any host-side table (PGOWN/FILEVIEW), but the guest UTLB always
 * holds it. Returns 0 when no valid entry covers the VA. */
static uint32_t mmcs_utlb_va2pa(CPUSH4State *env, uint32_t va)
{
    for (int i = 0; i < UTLB_SIZE; i++) {
        const tlb_t *e = &env->utlb[i];
        if (!e->v) {
            continue;
        }
        uint32_t start = (e->vpn << 10) & ~(e->size - 1);
        if (va >= start && va < start + e->size) {
            return ((e->ppn << 10) & ~(e->size - 1))
                   | (va & (e->size - 1));
        }
    }
    return 0;
}

/* MMCS fork (L8): shared ILKFIX progress latch — set when the first
 * USER-mode KData-page fault maps VA 0x5000 (coredll PSL bind = the
 * launches are live, the early IRQ-init walk is past). Gates (a) the
 * kernel-mode interlocked fetch map below and (b) the exception-boundary
 * emulation's kernel-side arming (its old function-local latch never
 * fired: user fetches hit the mapped page and never fault).
 * L21: no longer static — hw/sh4/mmcs.c gates sub-floor stack-arena
 * page-ownership registration on the same latch. */
bool mmcs_ilkfix_user_seen;

/* MMCS fork (L68/S219): the live KData user page (MMCS_L68KD). */
int mmcs_l68_kd_on(void);

/* MMCS fork (L69/S220): the appverifier registry short-circuit. */
int mmcs_l69ap_on(void);
int mmcs_l70ks_on(void);
uint32_t mmcs_l68_kdata_page_pa(void);
/* MMCS fork (L66/S218): the low-arena stocker — hw/sh4/mmcs.c owns
 * the stock _InterlockedAPIs block + the per-granule zero/poison
 * policy; called at machine init, snapshot post-restore, and from
 * the lazy ILKFIX seed path when MMCS_L66STK is set. */
void mmcs_l66_stock_arena(const char *when);

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

    /* MMCS fork (L82/S234): MMCS_EXCTRACE — the exception census knob
     * (the workflow fix for the self-loop trap: the exception ENTRY is
     * the vector target, so any software breakpoint there re-vectors
     * into itself and pollutes the census with its own trap — the
     * 299-hit "storm" artifact, L82 probe3/4). This knob prints every
     * guest exception from the CPU side with ZERO guest interference:
     * {spc, expevt, pc, sr} + the mode decode. Default scope = the
     * FAULT classes only (expevt >= 0x040 AND != 0x160-trapa: address
     * errors, TLB violations, illegal instructions, the FPU class) —
     * the trapa/KCALL flood stays off; MMCS_EXCTRACE_ALL=1 adds it.
     * Env MMCS_EXCTRACE (default off). */
    if (do_exp && getenv("MMCS_EXCTRACE")) {
        static int mmcs_exctrace_n;
        uint32_t expevt_v = cs->exception_index & 0xfff;
        int is_trapa = (expevt_v == 0x180);
        int all = getenv("MMCS_EXCTRACE_ALL") != NULL;
        if (all || (expevt_v >= 0x040 && !is_trapa)) {
            if (mmcs_exctrace_n < 4000) {
                int real_fault = (expevt_v == 0x0e0 || expevt_v == 0x060
                                  || expevt_v == 0x0c0 || expevt_v == 0x100
                                  || expevt_v == 0x120);
                fprintf(stderr, "MMCS-EXCTRACE[%d] spc=%08x expevt=%03x pc=%08x tea=%08x sr=%08x%s\n",
                        mmcs_exctrace_n, env->spc, expevt_v, env->pc, env->tea, env->sr,
                        (env->sr & (1u << 30)) ? " MD" : " UM");
                if (real_fault && getenv("MMCS_EXCCTX")) {
                    /* the fault-context dump: the register file + pr (the
                     * caller) — decodes the failing API chain directly */
                    fprintf(stderr, "MMCS-EXCCTX spc=%08x tea=%08x pr=%08x "
                            "r0=%08x r1=%08x r2=%08x r3=%08x r4=%08x r5=%08x "
                            "r6=%08x r7=%08x r8=%08x r9=%08x r10=%08x r11=%08x "
                            "r14=%08x r15=%08x\n",
                            env->spc, env->tea, env->pr,
                            env->gregs[0], env->gregs[1], env->gregs[2], env->gregs[3],
                            env->gregs[4], env->gregs[5], env->gregs[6], env->gregs[7],
                            env->gregs[8], env->gregs[9], env->gregs[10], env->gregs[11],
                            env->gregs[14], env->gregs[15]);
                }
            }
            mmcs_exctrace_n++;
        }
    }

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

    /* MMCS fork: MMCS_CBRET (L33) — the first-user-process callback-return
     * completion. DECODE (L33, step-trails l33_probeB/C + the SLOTTRACE
     * census + the ROM disasm): the vendor services EVERY user API slot
     * through the PSL trampoline at 0x908235fa (exception entry
     * 0x90822a80 computes r0 = (SPC-0xfffffe01)>>1 = the method index and
     * jumps there with SSR in r2). The head special-cases index -1 (the
     * slot 0xfffffdff): with [pTh+0x1C] != 0 it takes the RESUME face
     * 0x908236f8 (r15 := [pTh+0x1C] = a kernel restart frame, then the
     * post-API 0x9082a6c0 chain-pop and the epilogue at 0x908236a8 which
     * jmps @[[frame+0x3C]] with r15=[frame+0x40] = the KERNEL
     * continuation); with [pTh+0x1C] == 0 it takes the plain-API face
     * (the marker method 0x908325b8 = "[pCurTh+0x38]=50", then the
     * user-return rte to SPC=[F+0x3C]=pr). The stock mirror = the
     * PerformCallBack protocol: the kernel launches a user callback with
     * pr pre-loaded 0xfffffdff (the vendor's 0x908238a4 driver does
     * exactly this: lds 0xfffffdff,pr; rte to user), the callback stub
     * ends with `rts` to the popped marker, and the -1 trap means "the
     * callback returned" — the kernel resumes its saved continuation.
     * The ThreadStart setup (0x90835bb0) launches the child's user phase
     * this way (jsr 0x90823778 @0x90835e74, pr=0x90835e78); its frame
     * ({r8..r13,pr} pushed at [kstack_top-0xE0..-0xC4]) sits untouched
     * below the trampoline's user-call frame slot (kstack_top-0x70-0x80:
     * the cells the trampoline writes at [F+0x3C..F+0x78] do not overlap
     * [launch_sp .. launch_sp+0x18] — bp-verified in the probeC trail).
     * BUG (the S153/S154 child death): in our emulation [pTh+0x1C] is 0
     * at the -1 trap, so the plain-API face runs: its rte goes to
     * SPC=[F+0x3C]=pr=0xfffffdff (the slot again — the cascade's second
     * -1 trap now carries pr=0x908236a8, the epilogue's own leftover),
     * whose frame {pc=0x908236a8, sp=user, flag=1} rtes to the kernel P1
     * trampoline IN USER MODE -> 0x0e0 -> the L10 APIRET MD-only fix
     * resumes the epilogue with the USER r15 -> it reads its frame off
     * the USER stack -> garbage-jump -> the kill machinery reaps the
     * child BEFORE EventModify SET (0x90835fd8) — the S152 park. (The two
     * reverted S154 APIRET2 attempts failed exactly here: the restart
     * record on the kstack {908236a8, user-sp, 1} re-executes the loop —
     * its pc cell IS the direct-return, so a frame re-drive cycles; only
     * the missing [pTh+0x1C] continuation breaks it; a synthesized
     * resume-record delivery was also tried and REJECTED: the natural
     * frame's chain cells ([+0x38]/[+0x48]/[+0x50]) are unknowable at
     * trap time, and the zeroed record drove the post-API validator
     * (0x9082a4f8) into an unbounded KCall-poll recursion, -0x2AC of
     * kstack per level). FIX (the direct completion): at the -1 marker
     * trap (pc=pr=0xfffffdff, USER mode) with [pTh+0x1C]==0, guarded by
     * the ThreadStart fingerprint (the setup's saved pr at
     * [kstack_top-0xE0+0x20] in [0x90835f14,0x90836000)), consume the
     * trap and jump STRAIGHT to the setup's post-launch continuation:
     * SR.MD on, r15 = kstack_top-0xE0 (the setup's launch sp), pc =
     * 0x90835e78 (ROM constant). The vendor's own exit sequence does the
     * rest — 0x90835e78 -> add#32 -> the pops restore r8-r13+pr from the
     * intact kstack frame -> rts into ThreadStart at 0x90835fb2 ->
     * EventModify SET 0x90835fd8 -> the create event satisfies and the
     * create-walker wakes NATURALLY (no daemon, no repair) -> the launch
     * cascade continues (the observed post-fix attractor: the kernel's
     * -30/0xE2 nested-slot class firing + a SECOND user thread running
     * its own startup through the USER coredll). Bounds:
     * MMCS_CBRET_MAX deliveries (default 64). The kstack is P3 (no P1
     * identity) — the fingerprint read resolves through the live guest
     * UTLB first (a fresh kstack page may be in no host-side table),
     * the PGOWN/FILEVIEW exports second (the L32 discipline). */
    /* MMCS fork (L34): the -1-trap census — every marker arrival with the
     * exact CBRET guard values (why a delivery did NOT fire: pend!=0 /
     * fingerprint miss / ktop resolution failure / pr shape). Env
     * MMCS_CBRET_DBG, default off. */
    if (env->mmcs_cbret_active && do_exp
        && cs->exception_index == 0x0e0
        && !(env->sr & (1u << SR_MD))
        && env->pc == 0xfffffdffu
        && getenv("MMCS_CBRET_DBG")) {
        static int ndbg;
        uint32_t pth = 0, ktop = 0, pendd = 0, sprd = 0, ktop_pa = 0;
        cpu_physical_memory_read(0x08679894, &pth, 4);
        if (pth >= 0x90600000u && pth < 0x90800000u) {
            cpu_physical_memory_read((pth & 0x1fffffffu) + 0x2c, &ktop, 4);
            cpu_physical_memory_read((pth & 0x1fffffffu) + 0x1c, &pendd, 4);
        }
        if (ktop >= 0xD0000000u && ktop < 0xE0000000u) {
            ktop_pa = mmcs_utlb_va2pa(env, ktop) ? : mmcs_stack_va2pa(ktop);
        }
        if (ktop_pa) {
            cpu_physical_memory_read(
                (ktop_pa & ~0xFFFu) + ((ktop - 0xE0) & 0xFFF) + 0x20,
                &sprd, 4);
        }
        if (ndbg++ < 96) {
            fprintf(stderr, "MMCS-CBRET-DBG -1trap th=%08x ktop=%08x "
                    "ktop_pa=%08x [1C]=%08x saved_pr=%08x pr=%08x "
                    "sp=%08x\n", pth, ktop, ktop_pa, pendd, sprd,
                    env->pr, env->gregs[15]);
        }
    }
    if (env->mmcs_cbret_active && do_exp
        && cs->exception_index == 0x0e0
        && !(env->sr & (1u << SR_MD))
        && env->pc == 0xfffffdffu
        && env->pr == 0xfffffdffu) {
        static uint32_t ncbret, maxcb;
        if (!maxcb) {
            maxcb = 64;
            const char *m = getenv("MMCS_CBRET_MAX");
            if (m) {
                maxcb = (uint32_t)atoi(m) ? : 1;
            }
        }
        uint32_t pth = 0, ktop = 0;
        cpu_physical_memory_read(0x08679894, &pth, 4);
        if (pth >= 0x90600000u && pth < 0x90800000u) {
            cpu_physical_memory_read((pth & 0x1fffffffu) + 0x2c, &ktop, 4);
        }
        uint32_t ktop_pa = (ktop >= 0xD0000000u && ktop < 0xE0000000u)
                           ? (mmcs_utlb_va2pa(env, ktop)
                              ? : mmcs_stack_va2pa(ktop)) : 0;
        uint32_t kpage_pa = ktop_pa & ~0xFFFu;
        if (ktop_pa && ncbret < maxcb) {
            uint32_t launch_sp = ktop - 0xE0;
            uint32_t saved_pr = 0;
            /* the setup prologue pushed {r8..r13,pr} then add#-32:
             * [launch_sp+0x20]=pr, [launch_sp+0x24]=r13 .. [+0x38]=r8
             * (the continuation's add#32 + pops expect exactly this) */
            cpu_physical_memory_read(kpage_pa + (launch_sp & 0xFFF) + 0x20,
                                     &saved_pr, 4);
            uint32_t pend = 1;
            cpu_physical_memory_read((pth & 0x1fffffffu) + 0x1c, &pend, 4);
            if (!pend
                && saved_pr >= 0x90835f14u && saved_pr < 0x90836000u) {
                /* DIRECT completion: jump straight to the setup's
                 * post-launch continuation in kernel mode with the
                 * setup's launch sp — the vendor's own epilogue
                 * (0x90835e78 -> add#32 -> pops -> rts) restores
                 * r8-r13+pr from the intact kstack frame and returns
                 * into ThreadStart, which proceeds to EventModify SET.
                 * No frame synthesis, no post-API chain walk (the
                 * synthesized-record drive recursed the KCall poll:
                 * the natural frame's chain cells are unknowable at
                 * trap time).
                 *
                 * L35 (S166): repair the frame's r9 slot before the
                 * pops. The setup saved r9=pTh (ThreadStart's arg2,
                 * stored at [launch_sp+0x34]); the user phase's own
                 * PSL syscall frames reuse the same shallow kstack
                 * (everything below ktop) and had clobbered it to 1 —
                 * the continuation's jsr@0x90835fbe then ran its
                 * delay slot `mov.l r12,@(12,r9)' with r9=1 -> the
                 * store hit 0xd -> the access-violation raise ->
                 * ThreadExceptionExit(STATUS_STACK_OVERFLOW) instead
                 * of the clean EventModify-SET exit (the S164/S165
                 * x276 exception-exit attractor; live-proven: the
                 * step-trail through 0x90835fb2 shows r9=1 at the
                 * jsr while every other popped reg was sane). On HW
                 * the register set comes from the kernel RESTART
                 * record ([pTh+0x1C], the resume face) which carries
                 * pCurTh; restoring pth to the slot gives the pops
                 * the same value. */
                cpu_physical_memory_write(
                    kpage_pa + (launch_sp & 0xFFF) + 0x34, &pth, 4);
                env->sr |= (1u << SR_MD);
                env->gregs[15] = launch_sp;
                env->pc = 0x90835e78;
                cs->exception_index = -1;
                ncbret++;
                fprintf(stderr, "MMCS: CBRET callback-return completed, "
                        "th=%08x kstack=%08x -> setup continuation "
                        "90835e78 (r9 slot repaired) (delivery %u/%u)\n",
                        pth, ktop, ncbret, maxcb);
                return;
            }
        }
        /* fall through: the guards failed (a pending continuation
         * exists, or the kstack frame is not a ThreadStart launch) —
         * the vendor dispatch proceeds untouched */
    }

    /* MMCS fork: MMCS_L69AP (L69/S220) — the appverifier registry
     * short-circuit (see hw/sh4/mmcs.c for the full decode). The
     * set-84 method-23 slot (0xffff55d3, the filesys registry API
     * set's RegOpenKeyExW) never completes through the vendor
     * dispatch in our world (the PerformCallBack/[pTh+0x1C] class)
     * and re-faults forever — the L68 shell-park spin that blocks
     * every user process's coredll init before main(). Deliver the
     * stock retail outcome at the trap boundary: consume the fetch
     * exception, r0 := ERROR_FILE_NOT_FOUND (2), resume the user
     * thread at pr (the jsr's own return site). Guards: USER mode,
     * the exact slot decode (set 84, method 23), the surgical arg
     * fingerprint (r4 = HKEY_LOCAL_MACHINE 0x80000002, r7 =
     * KEY_ALL_ACCESS 0x000f003f, pr in the user coredll window
     * 0x40011000..0x40080000). Cap: MMCS_L69AP_MAX (default 8). */
    if (mmcs_l69ap_on() && do_exp
        && cs->exception_index == 0x0e0
        && !(env->sr & (1u << SR_MD))
        && env->pc < 0xfffffe01u && env->pc >= 0xffff0001u
        && (env->pc & 1u)) {
        uint32_t idx = (0xfffffe01u - env->pc) >> 1;
        if (((idx >> 8) & 0x7f) == 84 && (idx & 0xff) == 23
            && env->gregs[4] == 0x80000002u
            && env->gregs[7] == 0x000f003fu
            && env->pr >= 0x40011000u && env->pr < 0x40080000u) {
            static uint32_t nap, maxap;
            if (!maxap) {
                maxap = 8;
                const char *m = getenv("MMCS_L69AP_MAX");
                if (m) {
                    maxap = (uint32_t)atoi(m) ? : 1;
                }
            }
            if (nap < maxap) {
                nap++;
                fprintf(stderr, "MMCS: L69AP appverifier RegOpenKeyExW "
                        "stock outcome (r0=2 ERROR_FILE_NOT_FOUND) th "
                        "pc=%08x -> pr=%08x (delivery %u/%u)\n",
                        env->pc, env->pr, nap, maxap);
                env->gregs[0] = 2;
                env->pc = env->pr;
                cs->exception_index = -1;
                return;
            }
        }
    }

    /* (MMCS_APIRET deleted 2026-11-19, retirement lane S173: the
     * compensator is inert in the successor world — fidelity scorecard
     * §1.9/§B3: exactly 1 window hit/boot in the pre-PGOWN plan world,
     * 0 hits in both L34-world runs; the L10 decode lives in git
     * history. Both APIRET+KILLSTK compensated the old shared-page
     * semantics that the PGOWN retirement (L34/S164) removed.) */
    /* (MMCS_KILLSTK L11 hook deleted 2026-11-19, retirement lane
     * S173: inert in the successor world — fidelity scorecard
     * §1.10/§B3: guard census 100% kill continuations with sp in
     * the LIVE D0 kstk arena (d00b…/d006…), zero foreign hits;
     * recovery fired 1x/boot in the pre-PGOWN plan world, 0x in
     * the L34 world. The kill-stack RAM page at phys 0x1F000000
     * (P2 0xBF00FF00) STAYS — it is the stub-page provider for
     * the HDEVT/L16EV/L26EV/L32EV daemons (mmcs.c). The L11
     * decode lives in git history.) */
    /* MMCS fork (L64): MMCS_S214DBG — THE RunApps DEATH SITE CATCH
     * (diagnostic, default off). The death under decode: the startup
     * thread dies at fsdmgr's FSD-interface forwarder thunk (runtime
     * c02cdbc0 = ROM 90a8ebc2): `mov.l @(12,r2),r4; add #72,r2;
     * mov.l @r2,r3; jsr @r3` — the [desc+0x48] method cell (FSD table
     * slot 18; the thunk forwards 4 reg + 5 stack args = the 9-arg
     * FsIoControlW shape) resolved to garbage. mmcs.c patches that jsr
     * (ROM 90a8ebee) into `trapa #0x72`; arm 1 here prints the live
     * register file + the full descriptor dump (desc = r2-0x48: the
     * FSD function table + the [desc+0xC] context arg the FSD receives)
     * + the method target's own first words (mapped? which module?),
     * then RECONSTRUCTS the stock jsr exactly (pr := 0xc02cdbf2 =
     * site+4, pc := r3) so the world runs on unperturbed — every pass
     * through the thunk is taped, the death pass included. Arm 2 tapes
     * the death-moment fault family: any kernel-mode fetch/prot-class
     * exception whose pc is not plausible code (the garbage-jump
     * class). Arm 3 tapes every kernel-mode exception taken by the
     * watched thread (MMCS_S214_TH, default 906dcacc = the RunApps
     * corpse) — catches a crash INSIDE a plausible-looking method. */
    if (do_exp && (env->sr & (1u << SR_MD)) && getenv("MMCS_S214DBG")) {
        static int ns214call, ns214flt, ns214th;
        if (cs->exception_index == 0x160 && env->tra == (0x72u << 2)
            && ns214call < 400) {
            uint32_t pth = 0;
            uint32_t r2 = env->gregs[2], r3 = env->gregs[3];
            uint32_t desc = r2 - 0x48;
            uint32_t pa, w;
            int i;
            cpu_physical_memory_read(0x08679894, &pth, 4);
            fprintf(stderr, "MMCS-S214 call %d: pth=%08x desc=%08x "
                    "r3(method)=%08x pr=%08x r4=%08x r5=%08x r6=%08x "
                    "r7=%08x\n", ns214call++, pth, desc, r3, env->pr,
                    env->gregs[4], env->gregs[5], env->gregs[6],
                    env->gregs[7]);
            pa = mmcs_utlb_va2pa(env, desc);
            if (!pa) {
                pa = mmcs_stack_va2pa(desc);
            }
            if (pa) {
                fprintf(stderr, "MMCS-S214 desc@pa=%08x:", pa);
                for (i = 0; i <= 0x50; i += 4) {
                    cpu_physical_memory_read(pa + i, &w, 4);
                    fprintf(stderr, " +%02x=%08x", i, w);
                }
                fprintf(stderr, "\n");
            } else {
                fprintf(stderr, "MMCS-S214 desc %08x UNRESOLVED\n", desc);
            }
            pa = mmcs_utlb_va2pa(env, r3);
            if (!pa) {
                pa = mmcs_stack_va2pa(r3);
            }
            if (pa) {
                fprintf(stderr, "MMCS-S214 method@pa=%08x:", pa);
                for (i = 0; i < 8; i += 4) {
                    cpu_physical_memory_read(pa + i, &w, 4);
                    fprintf(stderr, " +%x=%08x", i, w);
                }
                fprintf(stderr, "\n");
            } else {
                fprintf(stderr, "MMCS-S214 method %08x UNMAPPED\n", r3);
            }
            /* the stock jsr, reconstructed: pr = site+4, pc = r3 */
            env->pr = 0xc02cdbf2;
            env->pc = r3;
            cs->exception_index = -1;
            return;
        }
        if ((cs->exception_index == 0x040 || cs->exception_index == 0x060
             || cs->exception_index == 0x0a0 || cs->exception_index == 0x0c0
             || cs->exception_index == 0x0e0)
            && !mmcs_plausible_code(env->pc) && ns214flt < 64) {
            uint32_t pth = 0;
            int i;
            cpu_physical_memory_read(0x08679894, &pth, 4);
            fprintf(stderr, "MMCS-S214 FAULT evt=%03x pc=%08x tea=%08x "
                    "ssr=%08x spc=%08x pr=%08x pth=%08x regs:",
                    cs->exception_index, env->pc, env->tea, env->ssr,
                    env->spc, env->pr, pth);
            for (i = 0; i < 16; i++) {
                fprintf(stderr, " r%d=%08x", i, env->gregs[i]);
            }
            fprintf(stderr, "\n");
            ns214flt++;
        }
        {
            static uint32_t s214_th;
            static int s214_th_parsed;
            uint32_t pth = 0;
            if (!s214_th_parsed) {
                const char *t = getenv("MMCS_S214_TH");
                s214_th = t ? strtoul(t, NULL, 16) : 0x906dcaccu;
                s214_th_parsed = 1;
            }
            cpu_physical_memory_read(0x08679894, &pth, 4);
            if (pth == s214_th && ns214th < 300
                && cs->exception_index != 0x160) {
                fprintf(stderr, "MMCS-S214 TH-EXC evt=%03x pc=%08x "
                        "tea=%08x spc=%08x pr=%08x r2=%08x r3=%08x "
                        "r15=%08x\n", cs->exception_index, env->pc,
                        env->tea, env->spc, env->pr, env->gregs[2],
                        env->gregs[3], env->gregs[15]);
                ns214th++;
            }
        }
    }
    /* MMCS fork (L44): MMCS_L44DBG — the memset-guard death-class
     * diagnostic (default off). Static decode (L44, entry-anchored
     * disasm): 0xc005fb6c is memset's OWN 4-byte fill store
     * `mov.l r9,@r4` (memset 0xc005fa94..0xc005fba4 has NO argument
     * validation; its tail call through pool [0xc005fba0] is the SH4
     * CRT braf jump-table fill dispatcher 0xc0071764 — the S189
     * "CRT argument-validation fallback" reading was a PTR_FUN label
     * misread). The class = a kernel-mode WRITE fault at the store:
     * TEA is the faulting destination (the dead-process buffer), and
     * the raise forwards through the c0036xxx wrapper (pr=c0036368 =
     * its fallback-call return) -> c004db6c -> jmp c002f0a0 ->
     * 0xfffffdc7 (the KSLOT RaiseException, pr preserved by both
     * jmps). Hook (1): any kernel-mode fault inside the memset window
     * prints TEA + the live memset regs (r4 cursor / r5 val / r6
     * remaining = the bound) + pr + kstack + pCurTh. Hook (2): the
     * KSLOT raise (evt 0x180 at pc 0xfffffdc7 with r4=0xc0000005)
     * dumps the marshalled record at r7 — the +0x90/+0x94 planted
     * user-forward cells and the +0xb0/+0xb4 real-ctx save point (the
     * S131 layout) carry the ORIGINAL fault context. */
    if (do_exp && (env->sr & (1u << SR_MD)) && getenv("MMCS_L44DBG")) {
        static int nl44a, nl44b;
        if (env->pc >= 0xc005fa94u && env->pc < 0xc005fba4u
            && nl44a++ < 64) {
            uint32_t pth = 0;
            cpu_physical_memory_read(0x08679894, &pth, 4);
            fprintf(stderr, "MMCS-L44DBG memset-fault evt=%03x pc=%08x "
                    "tea=%08x(dst) r4=%08x(cursor) r5=%08x(val) "
                    "r6=%08x(remaining) pr=%08x r15=%08x(kstk) "
                    "pCurTh=%08x\n", cs->exception_index, env->pc,
                    env->tea, env->gregs[4], env->gregs[5], env->gregs[6],
                    env->pr, env->gregs[15], pth);
        }
        /* (1b) every kernel-mode PROTECTION violation (evt 0x060 /
         * 0x0a0 write-protect / init-page-write class) at ANY pc —
         * the fatal c0000005 faults are here, wherever the CRT store
         * lives (memset/memcpy/copy loops). */
        if ((cs->exception_index == 0x060
             || cs->exception_index == 0x0a0) && nl44a++ < 64) {
            uint32_t pth = 0;
            cpu_physical_memory_read(0x08679894, &pth, 4);
            fprintf(stderr, "MMCS-L44DBG prot-fault evt=%03x pc=%08x "
                    "tea=%08x(dst) r4=%08x r5=%08x r6=%08x r7=%08x "
                    "pr=%08x r15=%08x(kstk) pCurTh=%08x\n",
                    cs->exception_index, env->pc, env->tea,
                    env->gregs[4], env->gregs[5], env->gregs[6],
                    env->gregs[7], env->pr, env->gregs[15], pth);
        }
        if (cs->exception_index == 0x180 && env->pc == 0xfffffdc7u
            && env->gregs[4] == 0xc0000005u && nl44b++ < 16) {
            uint32_t rp = mmcs_utlb_va2pa(env, env->gregs[7]);
            if (!rp) {
                rp = mmcs_stack_va2pa(env->gregs[7]);
            }
            fprintf(stderr, "MMCS-L44DBG kslot-raise r15=%08x r7=%08x(rec) "
                    "rec_pa=%08x rec:", env->gregs[15], env->gregs[7], rp);
            if (rp) {
                for (int i = 0x00; i <= 0xe0; i += 4) {
                    uint32_t w = 0;
                    cpu_physical_memory_read(rp + i, (void *)&w, 4);
                    fprintf(stderr, " +%02x=%08x", i, w);
                }
            }
            fprintf(stderr, "\n");
        }
    }
    /* MMCS fork: syscall tracer — log every trapa with args (flycast
     * wince.h pattern: decode API calls at the trap boundary; our CE5
     * calibration: TRA 0x71 = RegQueryValueExW per the REGFIX hook). */
    if (getenv("MMCS_SYSTRACE") && do_exp
        && (env->pc & 1 || env->pc >= 0xffff0000)) {
        /* flycast wince.h pattern: CE syscalls = odd/hi fetch exceptions.
         * L33: sr/ssr/spc/r15 added — the nested-slot decode needs the
         * MODE at the trap boundary (user P4 fetch = 0x0e0 native;
         * kernel slot calls arrive 0x180->KSLOT or via rte re-entry). */
        fprintf(stderr, "SYSCALL exp=%03x pc=%08x sr=%08x ssr=%08x "
                "spc=%08x r15=%08x r4=%08x r5=%08x "
                "r6=%08x r7=%08x pr=%08x\n", cs->exception_index, env->pc,
                env->sr, env->ssr, env->spc, env->gregs[15],
                env->gregs[4], env->gregs[5], env->gregs[6], env->gregs[7],
                env->pr);
        /* MMCS_SLOTTRACE (L33): for slot-class traps, decode the vendor
         * method index (idx = (pc - 0xfffffe01) >> 1; the exception entry
         * 0x90822a98 computes exactly this) and the trampoline head's
         * branch selector [pCurTh+0x1C] (nonzero at a -1-slot trap = the
         * kernel-continuation resume path 0x908236f8; zero = the plain
         * API face — the L33 death-class discriminator). */
        if (getenv("MMCS_SLOTTRACE") && env->pc >= 0xfffefe03u) {
            uint32_t pth = 0, c1c = 0, c38 = 0;
            cpu_physical_memory_read(0x08679894, &pth, 4);
            if (pth >= 0x90600000u && pth < 0x90800000u) {
                cpu_physical_memory_read((pth & 0x1fffffffu) + 0x1c,
                                         &c1c, 4);
                cpu_physical_memory_read((pth & 0x1fffffffu) + 0x38,
                                         &c38, 4);
            }
            fprintf(stderr, "SLOT idx=%d pth=%08x [1C]=%08x [38]=%08x\n",
                    (int32_t)(env->pc - 0xfffffe01u) >> 1, pth, c1c, c38);
        }
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
    /* MMCS fork (L28): MMCS_FSVT — the k.coredll api-set CELL rescue.
     * The kernel-side coredll loads api-set method-table bases from
     * runtime-bound .data cells ([c00835c0] FILESYS, [c0083600] WIN32)
     * that ship 0 and never get bound in emulation (the loader's
     * CopyRegions also re-zeroes any seed-time patch), so the thunk
     * derefs fault at NULL+0xXX. Rescue (register-level, immune to the
     * backing-flipflop): point the deref base at the REAL table — the
     * FS thunks jump straight to fsdmgr's FSINT_* kernel-direct
     * implementations (same ABI; the tea names the method offset) —
     * or, for the WIN32 cell, the ROM methods table at 0x90821028
     * (CINFO 'Wn32' @90821848: CreateAPISet +0x08, GetLastError
     * +0x178). Unmapped FS offsets fall to the all-stub FSVT table
     * (mov #-1,r0; rts — the guarded failure path). */
    if ((cs->exception_index == 0x040 || cs->exception_index == 0x0a0)
        && (env->sr & (1u << SR_MD))
        && env->tea < 0x1000
        && env->pc >= 0xc0020000 && env->pc < 0xc0082b00) {
        bool hit = false;
        bool adv = true;
        if (env->pc >= 0xc0030988 && env->pc <= 0xc0030da0
            && !(env->pc & 3)) {
            /* FS thunk cluster: `mov.l @(r0,r3),r3` with r0=NULL and
             * r3=extu.b(-imm)=method offset => tea = the offset. Jump
             * straight to fsdmgr's FSINT_* kernel-direct
             * implementations (same ABI); unmapped offsets fall to
             * the all-stub FSVT table (returns -1, the guarded
             * failure path). Skip the deref (pc+2 = the jmp). */
            static const struct { uint16_t off; uint32_t fn; } fsint[] = {
                { 0xb4, 0xc02c8ca4 },   /* RegisterAFSEx  */
                { 0xb8, 0xc02c8db0 },   /* DeregisterAFS  */
                { 0xd0, 0xc02c8c60 },   /* RegisterAFSName */
                { 0xd4, 0xc02c8e50 },   /* DeregisterAFSName */
            };
            uint32_t tgt = 0;
            for (unsigned i = 0; i < ARRAY_SIZE(fsint); i++) {
                if (fsint[i].off == env->tea) {
                    tgt = fsint[i].fn;
                    break;
                }
            }
            if (!tgt && mmcs_regvt_is_armed()) {
                /* L30: the REGVT table (registry stubs + the REAL
                 * vendor methods routed from filesys .text c00b1358)
                 * owns every offset it knows — e.g. SignalStarted
                 * +0x108 = c00badf0 (the kernel's pSignalStarted =
                 * coredll ord 639 -> this cluster's c00309a0 thunk)
                 * must reach the REAL implementation, not the -1
                 * stub (the stub answer killed the signaler's
                 * internal wait and parked the boot). */
                tgt = mmcs_regvt_method(env->tea);
                if (tgt) {
                    mmcs_regvt_bind(cs);
                }
            }
            if (!tgt) {
                /* L30: unknown offsets land on the all-stub CODE slot
                 * (mov #-1,r0; rts at +0xF00). The v1 target
                 * `table_base + tea` only worked for tea < 0xE0 (the
                 * pointer-filled slots); larger offsets (e.g. the
                 * launcher's post-FSReady FS method 66 at +0x108)
                 * landed in the empty tail of the 4K page and raised
                 * illegal 0x180. */
                tgt = mmcs_fsvt_p1() + 0xF00;
            }
            env->gregs[3] = tgt;
            hit = true;
        } else if (env->pc == 0xc0030b92) {
            /* RegisterAFSEx (jsr variant): the fault surfaces AT the
             * jsr (delay-slot reporting); re-drive the jsr itself with
             * r3 preloaded — do NOT advance past it (the L28 lesson:
             * advancing skipped the call and the epilogue unwound a
             * live frame with r15 += 20 -> the c0032b86 r15=0x10
             * garbage read). */
            env->gregs[3] = 0xc02c8ca4;   /* FSINT_RegisterAFSEx */
            adv = false;
            hit = true;
        } else if (env->pc == 0xc002f5d8) {
            /* CreateAPISet: `mov.l @(8,r2),r3` — base r2, offset
             * re-applied by the instruction */
            env->gregs[2] = 0x90821028;
            hit = true;
         } else if (env->pc == 0xc002ec04) {
             /* GetLastError: `add #80,r2; mov.l @r2,r3` — the offset is
              * already folded into r2 (=tea); the table base must be
              * added back */
             env->gregs[2] = 0x90821028 + env->tea;
             hit = true;
         }
         if (hit) {
             static int nfs;
            if (nfs++ < 24) {
                fprintf(stderr, "MMCS: FSVT api-set rescue pc=%08x "
                        "tea=%08x pr=%08x -> %08x\n", env->pc, env->tea,
                        env->pr, env->gregs[3]);
            }
            if (adv) {
                env->pc += 2;      /* execute the jmp @r3 */
            }
            cs->exception_index = -1;
            return;             /* re-execute with the table */
        }
    }
    /* MMCS fork (L29): MMCS_REGVT v2 — synthesize the REGISTERED
     * FileSys api set at first FS-cell fault. DECODE: the k.coredll
     * registry thunks (EAT RegCloseKey c0032a0c, RegCreateKeyExW
     * c0032a30, RegEnumValueW c0032a88, RegEnumKeyExW c0032afc,
     * RegQueryInfoKeyW c0032b98, RegOpenKeyExW c0032b78,
     * RegQueryValueExW c0032c0c, RegSetValueExW c0032c3c — and the
     * wider cell-thunk family, e.g. method-7 site c0032750) all
     * dispatch `jsr/jmp [[[c00835c0]] + method*4]` with the STOCK
     * kmisc.c numbering (17/18/21/22/23/24/25/26); the cell ships 0
     * because the HW filesys CreateAPISet("FileSys")+RegisterAPISet
     * bind (which needs the registry — circular) never ran in
     * emulation. On the deref fault (tea = the method byte offset),
     * build the methods table + `trapa #0x73` stubs in the FSVT page,
     * bind the cell (fault-time writes survive — the loader's
     * CopyRegions re-zero only killed the L28 seed-time binds), load
     * r3 with the method target and execute the jsr/jmp. Registry
     * stubs trap into the handler below with the FULL ABI intact
     * (args r4-r7 + [r15+16..] — the out-param pointers the v1
     * fault-site synthesis could not recover, e.g. RegEnumKeyExW's
     * lpcbName, whose stale value made the vendor hive-copy tree
     * self-link and loop the flush walk 1.17M times). FS methods
     * (0xb4/0xb8/0xd0/0xd4) route straight to fsdmgr's FSINT_*
     * implementations; unknown offsets to the all-stub (-1). */
    if (mmcs_regvt_is_armed()
        && (cs->exception_index == 0x040 || cs->exception_index == 0x0a0)
        && (env->sr & (1u << SR_MD))
        && env->tea < 0x1000
        && !(env->tea & 3)
        && env->pc >= 0xc0020000 && env->pc < 0xc0082b00) {
        uint32_t tgt = mmcs_regvt_method(env->tea);
        if (tgt || mmcs_fsvt_p1()) {
            mmcs_regvt_bind(cs);
            if (!tgt) {
                /* MMCS fork (L30): unknown method offset -> the
                 * all-stub -1 (the guarded failure of an unregistered
                 * optional method). The L29 design promised this but
                 * only wired the KNOWN offsets, so the method-7 site
                 * (c0032750, GetFileAttributesW at +0x1c) fell to the
                 * vendor exception handler and killed the servant
                 * thread on prgInit's post-boot-phase
                 * \Windows\Restore.fdf probe (NULL-cell deref at
                 * 0x1c — the cell bind does not survive the page
                 * flip-flop, the register-level re-drive does). */
                tgt = mmcs_fsvt_p1() + 0xF00;
            }
            env->gregs[3] = tgt;
            static int nrb;
            if (nrb++ < 12) {
                fprintf(stderr, "MMCS: REGVT cell bind + dispatch pc=%08x "
                        "tea=%08x -> %08x\n", env->pc, env->tea, tgt);
            }
            env->pc += 2;      /* skip the deref; execute the jsr/jmp @r3 */
            cs->exception_index = -1;
            return;
        }
    }
    /* MMCS fork (L29): the REGVT registry-method stubs (trapa #0x73,
     * TRA=0x1CC). The stub is the api-set METHOD: it receives the full
     * WinCE SH4 ABI (r4-r7 + stack args at [r15+16], [r15+20], ... in
     * the CALLING thunk's frame — verified against the thunks' own
     * arg-staging code) and returns to the thunk's epilogue via pr.
     * Answer from the real default.reg hive; all out-params written
     * through the softmmu. */
    if (cs->exception_index == 0x160
        && env->tra == (0x73u << 2)
        && mmcs_regvt_is_armed()
        && (env->sr & (1u << SR_MD))
        && env->pc >= mmcs_regvt_stubs_p1()
        && env->pc < mmcs_regvt_stubs_p1() + 8 * 8) {
        /* env->pc at the trapa exception = the trapa insn address =
         * the 8-aligned stub base (verified live) */
        uint32_t api = (env->pc - mmcs_regvt_stubs_p1()) >> 3;
        uint32_t r4 = env->gregs[4], r5 = env->gregs[5];
        uint32_t r6 = env->gregs[6], r7 = env->gregs[7];
        uint32_t rc = 2;
        char name[280];
        uint32_t a[8] = { 0 };
        for (int i = 0; i < 8; i++) {
            cpu_memory_rw_debug(cs, env->gregs[15] + 16 + 4 * i,
                                (uint8_t *)&a[i], 4, 0);
        }
        if (r5 > 0x10000 && r5 < 0xFFFF0000u) {
            uint8_t w[560];
            if (mmcs_regvt_read(cs, r5, w, sizeof w) == 0) {
                int i;
                for (i = 0; i < 279; i++) {
                    if (!w[2 * i] && !w[2 * i + 1]) {
                        break;
                    }
                    name[i] = (w[2 * i] < 0x80 && w[2 * i + 1] == 0)
                                  ? (char)w[2 * i] : '?';
                }
                name[i] = 0;
            } else {
                name[0] = 0;
            }
        } else {
            name[0] = 0;
        }
        switch (api) {
        case 4: {   /* RegOpenKeyExW(hk, sub, opt, sam, phk=a[0]) */
            uint32_t hk = mmcs_regvt_open(r4, name);
            if (hk) {
                if (a[0]) {
                    cpu_memory_rw_debug(cs, a[0], (uint8_t *)&hk, 4, 1);
                }
                rc = 0;
            } else {
                rc = 2;
            }
            break;
        }
        case 6: {   /* RegQueryValueExW(hk, name, resv, lpType=r7,
                     * lpData=a[0], lpcbData: the RegQueryValueExW thunk
                     * (c0032c0c: `sts pr; add #-28,r15`) re-stages the
                     * method's stack args as 5th=[r15+16] (lpData) and
                     * 6th=[r15+24] (the lpcbData POINTER), with its own
                     * deref *lpcbData at [r15+20] — the v1 code read
                     * [r15+20] as the pointer and got the raw cb VALUE,
                     * so every data-read call answered ERROR_MORE_DATA,
                     * FsdGetRegistryValue failed, LoadFlags defaulted
                     * to ASYNC and the ObjectStore never entered the
                     * SYNC load list (no file system ever mounted). */
            uint32_t type = 0, len = 0;
            const uint8_t *data = NULL;
            uint32_t a1 = 0;
            cpu_memory_rw_debug(cs, env->gregs[15] + 24,
                                (uint8_t *)&a1, 4, 0);
            rc = mmcs_regvt_query(r4, name, &type, &len, &data);
            if (rc == 0) {
                uint32_t cb = 0;
                int cb_rd = -1, cb_wr = 0, d_wr = 0;
                if (a1) {
                    cb_rd = cpu_memory_rw_debug(cs, a1,
                                                (uint8_t *)&cb, 4, 0);
                }
                if (r7) {
                    cpu_memory_rw_debug(cs, r7, (uint8_t *)&type, 4, 1);
                }
                if (!a[0] || cb < len) {
                    rc = a[0] ? 234 : 0;   /* size query vs short buf */
                } else {
                    d_wr = cpu_memory_rw_debug(cs, a[0], (void *)data,
                                               len, 1);
                    if (d_wr) {
                        rc = 234;
                    }
                }
                if (a1) {
                    cb_wr = cpu_memory_rw_debug(cs, a1,
                                                (uint8_t *)&len, 4, 1);
                }
                if (getenv("MMCS_REGVT_QDBG")) {
                    fprintf(stderr, "MMCS: REGVT q6 '%s' a0=%08x a1=%08x "
                            "cb=%d(len=%d type=%u) rd=%d d_wr=%d cb_wr=%d "
                            "rc=%d\n", name, a[0], a1, cb, len, type,
                            cb_rd, d_wr, cb_wr, rc);
                }
                break;
            }
            break;
        }
        case 1: {   /* RegCreateKeyExW(..., phk=a[4], pdisp=a[5]) */
            uint32_t hk = mmcs_regvt_open(r4, name);
            if (hk) {
                if (a[4]) {
                    cpu_memory_rw_debug(cs, a[4], (uint8_t *)&hk, 4, 1);
                }
                if (a[5]) {
                    uint32_t disp = 2;   /* REG_OPENED_EXISTING_KEY */
                    cpu_memory_rw_debug(cs, a[5], (uint8_t *)&disp, 4, 1);
                }
                rc = 0;
            } else {
                rc = 2;
            }
            break;
        }
        case 7: {   /* RegSetValueExW(hk, name, resv, type=r7,
                     * lpData=a[0] ptr, cbData=a[1] VALUE) */
            uint8_t data[512];
            uint32_t cb = a[1];
            if (a[0] && cb && cb <= sizeof data
                && cpu_memory_rw_debug(cs, a[0], data, cb, 0) == 0) {
                mmcs_regvt_set(r4, name, r7, data, cb);
            }
            rc = 0;
            break;
        }
        case 0: {   /* RegCloseKey(hk) */
            rc = 0;
            break;
        }
        case 3: {   /* RegEnumKeyExW(hk, idx=r5, lpName=r6,
                     * lpcbName=a[0] PTR, lpClass=a[2], lpcbClass=a[3]) */
            const char *kn = NULL;
            rc = mmcs_regvt_enum_key(r4, r5, &kn);
            if (rc == 0 && kn) {
                uint32_t chars = strlen(kn);
                uint32_t cb = 0;
                if (a[0]) {
                    cpu_memory_rw_debug(cs, a[0], (uint8_t *)&cb, 4, 0);
                }
                if (r6 && (cb ? cb : chars + 1) >= chars + 1) {
                    uint8_t w[560];
                    for (uint32_t i = 0; i < chars; i++) {
                        w[2 * i] = (uint8_t)kn[i];
                        w[2 * i + 1] = 0;
                    }
                    w[2 * chars] = w[2 * chars + 1] = 0;
                    cpu_memory_rw_debug(cs, r6, w, (chars + 1) * 2, 1);
                    if (a[3]) {
                        uint32_t cz = 0;
                        cpu_memory_rw_debug(cs, a[3], (uint8_t *)&cz, 4, 1);
                    }
                } else {
                    rc = 234;
                }
                if (a[0]) {
                    cpu_memory_rw_debug(cs, a[0], (uint8_t *)&chars, 4, 1);
                }
            }
            break;
        }
        case 2: {   /* RegEnumValueW(hk, idx=r5, lpName=r6,
                     * lpcbName=a[0] PTR, lpResv=a[1], lpType=a[2],
                     * lpData=a[3], lpcbData=a[4] PTR) */
            const char *vn = NULL;
            uint32_t type = 0, len = 0;
            const uint8_t *data = NULL;
            rc = mmcs_regvt_enum_value(r4, r5, &vn, &type, &len, &data);
            if (rc == 0 && vn) {
                uint32_t chars = strlen(vn);
                if (r6) {
                    uint8_t w[560];
                    for (uint32_t i = 0; i < chars; i++) {
                        w[2 * i] = (uint8_t)vn[i];
                        w[2 * i + 1] = 0;
                    }
                    w[2 * chars] = w[2 * chars + 1] = 0;
                    cpu_memory_rw_debug(cs, r6, w, (chars + 1) * 2, 1);
                }
                if (a[0]) {
                    cpu_memory_rw_debug(cs, a[0], (uint8_t *)&chars, 4, 1);
                }
                if (a[2]) {
                    cpu_memory_rw_debug(cs, a[2], (uint8_t *)&type, 4, 1);
                }
                uint32_t cb = 0;
                if (a[4]) {
                    cpu_memory_rw_debug(cs, a[4], (uint8_t *)&cb, 4, 0);
                }
                if (a[3] && data && cb >= len) {
                    cpu_memory_rw_debug(cs, a[3], (void *)data, len, 1);
                }
                if (a[4]) {
                    cpu_memory_rw_debug(cs, a[4], (uint8_t *)&len, 4, 1);
                }
            }
            break;
        }
        case 5: {   /* RegQueryInfoKeyW(hk, lpClass=r5, lpcbClass=r6,
                     * lpResv=r7, lpcSubKeys=a[0], lpcbMaxSubKeyLen=a[1],
                     * lpcbMaxClassLen=a[2], lpcValues=a[3],
                     * lpcbMaxValueNameLen=a[4], lpcbMaxValueLen=a[5],
                     * lpcbSD=a[6], lpft=a[7]) */
            uint32_t nsub = 0, ms = 0, nv = 0, mvn = 0, mvl = 0;
            rc = mmcs_regvt_query_info(r4, &nsub, &ms, &nv, &mvn, &mvl);
            if (rc == 0) {
                uint32_t zero = 0;
                if (a[0]) {
                    cpu_memory_rw_debug(cs, a[0], (uint8_t *)&nsub, 4, 1);
                }
                if (a[1]) {
                    cpu_memory_rw_debug(cs, a[1], (uint8_t *)&ms, 4, 1);
                }
                if (a[2]) {
                    cpu_memory_rw_debug(cs, a[2], &zero, 4, 1);
                }
                if (a[3]) {
                    cpu_memory_rw_debug(cs, a[3], (uint8_t *)&nv, 4, 1);
                }
                if (a[4]) {
                    cpu_memory_rw_debug(cs, a[4], (uint8_t *)&mvn, 4, 1);
                }
                if (a[5]) {
                    cpu_memory_rw_debug(cs, a[5], (uint8_t *)&mvl, 4, 1);
                }
                if (a[6]) {
                    cpu_memory_rw_debug(cs, a[6], &zero, 4, 1);
                }
                if (a[7]) {
                    cpu_memory_rw_debug(cs, a[7], &zero, 4, 1);
                    cpu_memory_rw_debug(cs, a[7] + 4, &zero, 4, 1);
                }
            }
            break;
        }
        default:
            rc = 87;    /* ERROR_INVALID_PARAMETER */
            break;
        }
        static int nrt;
        static int rtcap = -1;
        if (rtcap < 0) {
            const char *c = getenv("MMCS_REGVT_LOG");
            rtcap = c ? atoi(c) : 40;
        }
        if (nrt++ < rtcap) {
            fprintf(stderr, "MMCS: REGVT api=%u pc=%08x hk=%08x '%s' "
                    "idx=%08x -> rc=%d\n", api, env->pc, r4, name, r5, rc);
        }
        env->gregs[0] = rc;
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
    /* MMCS fork (L61/S211): MMCS_L61EV — THE RING DATA-PAGE
     * STORE-DROP. The post-launch-loop world (the L60 exit): the uHAL
     * ring's second-stage init HAS run (the handle resolves, the ring
     * struct at the 0x8862ada0-class cell is mapped) — the RINGFIX
     * NULL-sub-state fault never fires. But the ring DATA buffer sits
     * at VA 0x18e7c000 (buffer base + wptr, e.g. tea 0x18e7c2d0) on a
     * page NO context ever maps: every exception report's copy store
     * `mov.b r1,@(r0,r3)` (path A 0x9080757e, path B 0x908075b6)
     * write-misses and the dispatch re-executes the SAME store forever
     * — 422,490 identical excp=060 faults in one 7s window (the
     * S122-L2 fault-logging storm class redux, now at the DATA page).
     * The RINGFIX precedent (write-dropped): retire the store without
     * effect — the ring bookkeeping stores that follow (ring[4]/[8]
     * wrap+advance, all in the MAPPED ring struct) complete, the
     * report fn returns, the exception handler finishes. The dropped
     * bytes are the debug print only (the ring is never control
     * flow). Guards: excp 0x60 (write miss) + the two exact store
     * pcs of the ring-writer fn_9080755c — no other write path.
     * NOTE: a file-static (NOT a CPU vmstate field) — snapshot
     * compatibility with the pre-L61 chain is the law (a vmstate
     * field addition rejects every older .vmstate: "Missing section
     * footer for cpu"). */
    static int mmcs_l61ev_armed = -1;
    if (mmcs_l61ev_armed < 0) {
        mmcs_l61ev_armed = getenv("MMCS_L61EV") != NULL;
    }
    if (mmcs_l61ev_armed && cs->exception_index == 0x060
        && (env->pc == 0x908075b6 || env->pc == 0x9080757e)) {
        env->pc += 2;                   /* retire the store: dropped */
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
        bool kern_arms = getenv("MMCS_KILK") || getenv("MMCS_L66STK");
        if (getenv("MMCS_L66DBG")) {
            static int nl66dbg;
            if (nl66dbg++ < 32) {
                fprintf(stderr, "MMCS-L66DBG emu-gate: pc=%08x kern=%d "
                        "user_seen=%d kilk=%d lkstk=%d sr=%08x\n",
                        env->pc, kern, (int)mmcs_ilkfix_user_seen,
                        getenv("MMCS_KILK") != NULL,
                        getenv("MMCS_L66STK") != NULL, env->sr);
            }
        }
        if (!kern) {
            mmcs_ilkfix_user_seen = true;
        } else if (!(mmcs_ilkfix_user_seen && kern_arms)) {
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
        /* dedup table + bump allocator over the scratch margin
         * (savestate lane: hoisted to file scope — the snapshot
         * streams it as part of "mmcs/helper") */
        struct mmcs_cowfix_ent *map = mmcs_cowfix_map;
        int nmap = mmcs_cowfix_nmap;
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
            uint32_t next = mmcs_cowfix_next;
            if (next + mask + 1 <= 0x10800000 && nmap < 512) {
                pa = next;
                next += mask + 1;
                map[nmap].va = base;
                map[nmap].pa = pa;
                nmap++;
                mmcs_cowfix_next = next;
                mmcs_cowfix_nmap = nmap;
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
    /* MMCS fork (L39/S181): the kstack-execution kill-continuation
     * repair. DECODE (live, int+exec windows, this lane): the woken
     * DoWait-orphan's exception-forward cascade (the per-wake
     * c004dba2 entries) DEGRADES — the thread's saved kernel context
     * acquires an SPC pointing INTO ITS OWN D0-window kstack (first
     * stack-landing during the c0000005 forwards; then every wake
     * rte-delivers it there via the KCall-exit restore 0x90823344-8c
     * reading [frame+16]), the fetch executes stack words as code until
     * an illegal 0x180 lands (e.g. pc=0xd01cf900 pr=0xd01cf8fc on the
     * PNP waiter), the vendor forward machinery re-forwards it as
     * 0xC000001D to the k.coredll stub ([0x8867f030]=0xc004dba2), the
     * stub re-raises through the KSLOT slot call, and the thread
     * re-parks at the DoWait face — one cycle per L26 wake, forever,
     * at a FIXED frame (the vendor endgame — the told waiter's death —
     * never completes). On HW the vendor NEVER executes a kernel
     * stack: a KERNEL-mode illegal whose fault pc is inside the D0
     * kstack window [0xD0000000,0xDC000000) is unreachable vendor
     * state, and the vendor's own response to a dead corrupted thread
     * is the kill continuation (the S131-decoded dispatch: the thread
     * ctx pc=KillThread 0x9083be50 + a valid kill stack). Fix: at the
     * exception boundary, route the thread into THAT vendor kill
     * continuation — pc=0x9083be50, r15=P2 0xBF00FF00 (the dedicated
     * kill-stack RAM page at phys 0x1F000000, mapped every boot; the
     * L11-era discipline) — so the vendor's own KillThread shutdown
     * (owner-wait, handle close, DeCommitStack) completes the death
     * natively instead of cycling. The death is COMPLETED, not
     * suppressed: the told waiter exits through the same vendor path
     * L36/L37 watched run to KillThread when the cascade got enough
     * slices. Env-gated MMCS_L39KILL, default off. */
    if (env->mmcs_l39kill_active && do_exp
        && (cs->exception_index == 0x180 || cs->exception_index == 0x1a0)
        && (env->sr & (1u << SR_MD))
        && env->pc >= 0xD0000000u && env->pc < 0xDC000000u) {
        static int nl39;
        if (nl39++ < 32) {
            fprintf(stderr, "MMCS-L39KILL: t-kstack-exec pc=%08x pr=%08x "
                    "spc=%08x -> vendor kill continuation 9083be50 "
                    "(%d)\n", env->pc, env->pr, env->spc, nl39);
        }
        env->gregs[15] = 0xBF00FF00u;
        env->pc = 0x9083BE50u;
        cs->exception_index = -1;
        return;
    }

    /* MMCS fork (L75/S226): MMCS_L75TX — THE DYING-THREAD FORWARD'S DEAD
     * ADDRESS-SPACE EXIT. DECODE (live, the l75 census + -d int tape +
     * the l75_bp SwitchProc probe + the l75_kill manual delivery, all on
     * the l74-chain restore): the chain world's '['-marker loop is an
     * exception-forward that cannot land. The servant 0x906a3c38 (the
     * primary thread of process P = 0x90699d8c, hProc 0x00df0002) took the
     * set-84 NULL-object fault at 0x90843258 (address 0x234); the kernel
     * classified it a stack overflow (0x234 within 4K above the record's
     * zero limit -> STATUS_STACK_OVERFLOW), found no handler and ran the
     * vendor forward FUN_9082546c: mark DYING (state16 |= 8), switch to
     * the OWNER ([th+0x10] := [th+0x14]), ctx.pc := the USER twin
     * [0x8867ebb8] = 0x4002cb50 (ThreadExceptionExit), SR.MD := 0. P's
     * directory (0x90552000) carries only an EMPTY coredll-window L2 table
     * (0x90555000: zero valid PTEs — the process's address space is gone)
     * -> the fetch at the twin is an unresolvable ITLB miss -> the same
     * forward again, ~945x/s, each pass re-printing the exception report
     * through g_pOemGlobal->WriteDebugString until the SRD ring
     * overflows ("\r\n[...*ALERT* buffer overflowed"). The KERNEL twin is
     * no exit either: [0x8867e75c] (its call gateway) reads 0.
     *
     * On HW the vendor NEVER runs a forward whose target page is absent
     * from the owner's directory (every live process maps the coredll
     * window); the vendor's own response to a dead thread is the kill
     * continuation (the S131 decode, the L39/L42 precedent): pc =
     * KillThread 0x9083be50 on the KILLSTK page. DELIVERED HERE, at the
     * exception boundary of that very fetch miss, when: the thread is a
     * DYING arena thread switched to a NON-kernel owner, and the twin's
     * page has no valid PTE in the owner's directory. The death is
     * COMPLETED, not suppressed.
     *
     * (b) The kill path's BROKEN WAIT CHAIN: the next dying thread's
     * KillThread walks its wait-block list (fn_90827bfc); a block whose
     * next pointer is NULL (impossible-stock: the lists are circular)
     * stores through it at 0x90827c12 (a write miss at address 8 -> the
     * kernel forward cascade 0xc004dba2 -> the pc=0 park). Fix-up: take
     * the vendor's OWN single-block branch ([th+8] := 0, resume at
     * 0x90827c1c; r7 is already 0 from the shared delay slot).
     *
     * Env MMCS_L75TX (default off); MMCS_L75TX_MAX = per-class delivery
     * cap (default 8). */
    if (do_exp && getenv("MMCS_L75TX")) {
        static uint32_t nl75tx, nl75wc;
        uint32_t nmax = 8;
        const char *mv = getenv("MMCS_L75TX_MAX");

        if (mv && *mv) {
            nmax = strtoul(mv, NULL, 0);
        }
        if (cs->exception_index == 0x040
            && !(env->sr & (1u << SR_MD)) && nl75tx < nmax) {
            uint32_t twin = 0, pth = 0, kproc = 0, t[3] = {0};
            int unmappable = 0;

            cpu_physical_memory_read(0x0867ebb8, &twin, 4);
            cpu_physical_memory_read(0x08679894, &pth, 4);
            cpu_physical_memory_read(0x0867aa00, &kproc, 4);
            if (twin >= 0x40000000u && twin < 0x48000000u
                && (env->pc ^ twin) < 0x1000u
                && pth >= 0x90680000u && pth < 0x90780000u) {
                cpu_physical_memory_read(pth - 0x80000000u + 0x0C, &t[0], 4);
                cpu_physical_memory_read(pth - 0x80000000u + 0x10, &t[1], 4);
                cpu_physical_memory_read(pth - 0x80000000u + 0x14, &t[2], 4);
                unmappable = 1;
                if ((t[0] & 8u) && t[1] == t[2] && t[2] != kproc && kpa(t[2])) {
                    uint32_t dir = 0, l1 = 0, pte = 0;

                    cpu_physical_memory_read(t[2] - 0x80000000u + 0x2C, &dir, 4);
                    if (kpa(dir)) {
                        cpu_physical_memory_read(dir - 0x80000000u
                                                 + ((twin >> 22) & 0x3FF) * 4, &l1, 4);
                        if (kpa(l1)) {
                            cpu_physical_memory_read(l1 - 0x80000000u
                                                     + ((twin >> 12) & 0x3FF) * 4, &pte, 4);
                            unmappable = !(pte & 0x100u);
                        }
                    }
                    if (unmappable) {
                        nl75tx++;
                        fprintf(stderr, "MMCS-L75TX: dying-thread "
                                "forward cannot land: th %08x st16 %08x owner %08x "
                                "twin %08x (dir %08x l1 %08x pte %08x) -> vendor "
                                "kill continuation 9083be50 (%u/%u)\n",
                                pth, t[0], t[2], twin, dir, l1, pte, nl75tx, nmax);
                        env->sr |= (1u << SR_MD) | 0xF0u;
                        env->sr &= ~((1u << SR_BL) | (1u << SR_RB));
                        env->gregs[4] = 1;      /* the exit code (the kernel twin's) */
                        env->gregs[15] = 0xBF00FF00u;
                        env->pc = 0x9083BE50u;
                        cs->exception_index = -1;
                        return;
                    }
                }
            }
        }
        if (cs->exception_index == 0x060 && (env->sr & (1u << SR_MD))
            && env->pc == 0x90827C12u && env->gregs[2] == 0
            && env->gregs[3] != 0 && nl75wc < nmax
            && env->gregs[4] >= 0x90680000u && env->gregs[4] < 0x90780000u) {
            uint32_t zero = 0;

            cpu_physical_memory_write(env->gregs[4] - 0x80000000u + 8, &zero, 4);
            nl75wc++;
            fprintf(stderr, "MMCS-L75TX: broken wait chain in the "
                    "kill path: th %08x blk %08x next NULL -> the vendor single-"
                    "block branch 90827c1c (%u/%u)\n",
                    env->gregs[4], env->gregs[3], nl75wc, nmax);
            env->pc = 0x90827C1Cu;
            cs->exception_index = -1;
            return;
        }
    }

    /* MMCS fork (L78/S229): MMCS_L78TX — THE DYING THREAD'S UNLANDABLE
     * KSLOT-RAISE DEATH-CASCADE COMPLETION (the debugger-thread death
     * quietus; decoded 2026-11-25, the post-dead-world lane).
     *
     * THE DECODE (Observed: l78_probe4/5/6 — the gate-(ii) MakeRun-shape
     * resume of the debugger thread 0x906a3c38 on the l77-postdeath
     * restore, + the -d int tape; the pc=0xfffffdc7 identity per the
     * fork's own L44 static decode): the thread parked at the
     * exception-entry prologue 0x908232f0 is an impossible-stock
     * artifact (a thread preempted BEFORE its exception entry could
     * save EXPEVT — stock masks interrupts through the entry; the
     * recycled-TCB world broke that law). Resuming it there (the stock
     * preempt-path shape: MakeRun + pick + the switcher resume)
     * executes the entry with a STALE EXPEVT: the dispatch classifies
     * 0xC000001D, the no-handler death path runs, the vendor forward
     * FUN_9082546c targets the USER twin 0x4002cb50 whose page is
     * absent from Q's directory — the L75TX router lands the kill
     * continuation and Q's exit code is written (0x103 -> 1) — and
     * then the death's user-teardown leg CASCADES through the recycled
     * kstack's corrupted frames: the frame chain keeps invoking the
     * KSLOT RaiseException trampoline (evt 0x180 at pc 0xfffffdc7,
     * r4 = 0xC00000FD — the old servant's parked death code read back
     * from the recycled frame residue) — each raise runs the full
     * kernel dispatch and re-prints the exception report through the
     * OAL writer until a self-faulting TLB miss in the writer parks
     * the whole world at pc 0 WITH THE TICK DEAD (CurMSec frozen).
     *
     * On HW the recycled-frame cascade cannot occur (the teardown's
     * frame chain is intact and a dying thread's user leg runs the
     * twin, not a stale KSLOT raise); the vendor's own response to a
     * dead thread is the kill continuation (the L39/L42/L75
     * precedent). DELIVERED HERE, at the kslot-raise boundary, when:
     * the fetch is in the P4 slot window (pc >= 0xFFFF0000) with r4 =
     * a 0xC000xxxx NTSTATUS, the current thread is a DYING (st16 bit
     * 0x08) arena thread with a death/exit code present ([th+0x38] !=
     * 0), and its process exit cell ([[proc+8]+0x14]) is already
     * written (!= 0x103 STILL_ACTIVE — the termination has landed;
     * this only completes the thread's own quietus). The delivery is
     * the L75TX shape: kernel SR + IMASK 0xF, r4 := the exit code,
     * r15 := the KILLSTK page, pc := 0x9083BE50.
     *
     * Env MMCS_L78TX (default off); MMCS_L78TX_MAX cap default 4. */
    if (do_exp && getenv("MMCS_L78TX")) {
        static uint32_t nl78tx;
        uint32_t n78max = 4;
        const char *mv78 = getenv("MMCS_L78TX_MAX");

        if (mv78 && *mv78) {
            n78max = strtoul(mv78, NULL, 0);
        }
        if (cs->exception_index == 0x180
            && env->pc >= 0xFFFF0000u && nl78tx < n78max
            && (env->gregs[4] & 0xF0000000u) == 0xC0000000u) {
            uint32_t pth = 0, st16 = 0, code = 0, exitc = 0;

            cpu_physical_memory_read(0x08679894, &pth, 4);
            if (pth >= 0x90680000u && pth < 0x90780000u) {
                cpu_physical_memory_read(pth - 0x80000000u + 0x0C, &st16, 4);
                cpu_physical_memory_read(pth - 0x80000000u + 0x38, &code, 4);
                uint32_t proc = 0, exitblk = 0;

                cpu_physical_memory_read(pth - 0x80000000u + 0x10, &proc, 4);
                if (proc >= 0x90680000u && proc < 0x90780000u) {
                    cpu_physical_memory_read(proc - 0x80000000u + 8,
                                             &exitblk, 4);
                }
                if ((st16 & 8u) && code != 0
                    && exitblk >= 0x90680000u && exitblk < 0x90780000u) {
                    cpu_physical_memory_read(exitblk - 0x80000000u + 0x14,
                                             &exitc, 4);
                }
                if ((st16 & 8u) && code != 0 && exitc != 0
                    && exitc != 0x103u) {
                    nl78tx++;
                    fprintf(stderr, "MMCS-L78TX: dying thread's unlandable "
                            "kslot-raise cascade: th %08x (st16 %08x, code "
                            "%08x, exit cell %08x, raise %08x) pc=%08x -> "
                            "vendor kill continuation 9083be50 (%u/%u)\n",
                            pth, st16, code, exitc, env->gregs[4], env->pc,
                            nl78tx, n78max);
                    env->sr |= (1u << SR_MD) | 0xF0u;
                    env->sr &= ~((1u << SR_BL) | (1u << SR_RB));
                    env->gregs[4] = exitc & 0xFFFFFFFFu;
                    env->gregs[15] = 0xBF00FF00u;
                    env->pc = 0x9083BE50u;
                    cs->exception_index = -1;
                    return;
                }
            }
        }
    }

    /* MMCS fork (L80/S232): MMCS_L80TX — THE DYING THREAD'S
     * KSLOT-RAISE SKIP (the failed-call synthesis; the cold-boot
     * crash fix; decoded 2026-11-25, the era-replay lane).
     *
     * THE DECODE (Observed: the l80_probe5..7 spiral tapes on
     * l79-grave + the l81-era cold boots under the full accumulated
     * stack): the recycled-frame KSLOT RaiseException legs
     * (evt 0x180 at pc 0xfffffdc7, r4 = 0xC000xxxx — the old
     * servant's parked death codes read back from the recycled
     * stack residue) fire whenever a death path walks the corrupted
     * frames. TWO world classes hit it:
     * (a) the l79-grave parked pair: the L78TX route restarts the
     *     kill continuation at its top, which re-enters the wait =
     *     THE CLOSED-LOOP SPIRAL (the l80_probe7 full-budget tape:
     *     156 routes, the death never completes);
     * (b) THE COLD BOOT under the full accumulated stack (the
     *     era-replay experiment): the early-world death chains run
     *     the SAME cascade class with the process exit cell NOT yet
     *     written (the L78TX gate does not match) — the cascade
     *     marches the exception stack down (r15 0x8862f5dc ->
     *     0x8862ac04 at ~0x4B0/raise) until QEMU ITSELF ABORTS
     *     (SIGABRT, exit -6, silent; serial frozen at 723 B = the
     *     wfc-era boundary).
     * THE STOCK SHAPE for both: the raise is a CALL (the
     * c0036xxx-wrapper family's call into RaiseException whose pr =
     * the wrapper's own return point — the L44 static decode); the
     * KAPIFIX-1b philosophy applies: synthesize the FAILED CALL —
     * r0 := 0 (the callers ignore the return; L3-proven), resume at
     * pr — the death path CONTINUES PAST the raise instead of
     * looping/restarting.
     *
     * GATE: evt 0x180, pc in the P4 slot window (>= 0xFFFF0000),
     * r4 a 0xC000xxxx NTSTATUS, pCurTh a DYING (st16 bit 0x08)
     * arena thread with a death/exit code present ([th+0x38] != 0),
     * AND pr plausible guest code (mmcs_plausible_code — never
     * synthesize a return to garbage callers). Sits AFTER the
     * L78TX block: the L78TX gate (exit-cell-written) keeps the
     * parked-pair route; this covers the legs L78TX cannot match
     * (the cold-boot class, the exit-cell-not-yet-written deaths)
     * — a probe isolates them by env.
     *
     * Env MMCS_L80TX (default off); MMCS_L80TX_MAX cap default 8. */
    if (do_exp && getenv("MMCS_L80TX")) {
        static uint32_t nl80tx;
        uint32_t n80max = 8;
        const char *mv80 = getenv("MMCS_L80TX_MAX");

        if (mv80 && *mv80) {
            n80max = strtoul(mv80, NULL, 0);
        }
        if (cs->exception_index == 0x180
            && env->pc >= 0xFFFF0000u && nl80tx < n80max
            && (env->gregs[4] & 0xF0000000u) == 0xC0000000u
            && mmcs_plausible_code(env->pr)) {
            uint32_t pth = 0, st16 = 0, code = 0;

            cpu_physical_memory_read(0x08679894, &pth, 4);
            if (pth >= 0x90680000u && pth < 0x90780000u) {
                cpu_physical_memory_read(pth - 0x80000000u + 0x0C, &st16, 4);
                cpu_physical_memory_read(pth - 0x80000000u + 0x38, &code, 4);
                if ((st16 & 8u) && code != 0) {
                    nl80tx++;
                    fprintf(stderr, "MMCS-L80TX: dying thread's kslot-raise "
                            "SKIP: th %08x (st16 %08x, code %08x, raise %08x) "
                            "pc=%08x pr=%08x -> r0 := 0, resume at pr (the "
                            "failed-call synthesis, %u/%u)\n",
                            pth, st16, code, env->gregs[4], env->pc, env->pr,
                            nl80tx, n80max);
                    env->gregs[0] = 0;
                    env->pc = env->pr;
                    cs->exception_index = -1;
                    return;
                }
            }
        }
    }

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
            if (getenv("MMCS_EVTDBG")) {
                uint32_t br7 = env->gregs[7 ^ 0x10];
                uint32_t c7 = 0;
                cpu_memory_rw_debug(cs, br7 + 40, (void *)&c7, 4, 0);
                fprintf(stderr, "EVTDBG: inject vec=%03x br7=%08x [br7+28]=%08x\n",
                        irq_vector, br7, c7);
            }
        } else {
            irq_vector = sh_intc_get_pending_vector(env->intc_handle,
                                                    (env->sr >> 4) & 0xf);
            if (irq_vector == -1) {
                /* MMCS fork: HARD asserted by our injector with the flag
                 * already consumed = stale line; drop it instead of the
                 * upstream g_assert_not_reached crash path. */
                /* MMCS fork (L35/Linux lane): a REAL pending request that
                 * is masked right now (imask 0xF) must keep the HARD
                 * line armed — sh_intc only re-asserts on the pending
                 * 0->1 edge, so clearing here would lose the wake for a
                 * later assert; a guest SLEEP with the line dropped
                 * never wakes (observed: Linux parked in default_idle
                 * with TMU0+SCIF TXI pending — see sh_intc_has_pending).
                 * No effect on boots that never arm an INTC source. */
                if (env->intc_handle &&
                    sh_intc_has_pending(env->intc_handle)) {
                    return; /* masked but armed — line stays high */
                }
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

    /* MMCS fork (L25 diag): illegal_instruction raised while fetching
     * in the kernel-side-DLL C0 window — dump the UTLB entry that
     * covered the fetch page and the physical bytes it backed, so a
     * garbage-content fetch (wrong PPN / shadowed page) is provable
     * from the -d int stream alone. */
    if (irq_vector == 0x180 && env->pc >= 0xC0000000 && env->pc < 0xC1000000
        && getenv("MMCS_L25DBG")) {
        int li;
        for (li = 0; li < UTLB_SIZE; li++) {
            tlb_t *e = &env->utlb[li];
            uint32_t mask = e->size - 1;
            if (!e->v || (env->pc & ~mask) != (e->vpn << 12)) {
                continue;
            }
            hwaddr pa = ((hwaddr)e->ppn << 10) + (env->pc & mask);
            uint8_t b[8] = { 0 };
            cpu_physical_memory_read(pa, b, 8);
            qemu_log("L25DBG: illegal fetch pc=%08x utlb[%d] vpn=%08x "
                     "ppn=%08x(%08x) sz=%u pr=%u sh=%u asid=%u -> "
                     "pa=%08x bytes=%02x%02x%02x%02x %02x%02x%02x%02x\n",
                     env->pc, li, e->vpn << 12, e->ppn,
                     (uint32_t)e->ppn << 10, e->size, e->pr, e->sh,
                     e->asid, (uint32_t)pa,
                     b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
        }
        qemu_log("L25DBG: (no covering utlb entry listed above = the "
                 "fetch missed; bytes come from elsewhere)\n");
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
        /* MMCS fork (L82/S236): MMCS_L82ZOM — the repeated-fault reaper
         * (the TAIL form: the head-block TCB surgery was overwritten by
         * the live handler's retry decision every cycle — the L78 law
         * only held from the PARKED state). At the Nth identical 0x0e0
         * user-fetch fault (the zombie whose marshalled death never
         * completes), redirect the CPU itself: pc := the vendor's kill
         * continuation 0x9083BE50, BL cleared, sp := the thread's own
         * kstack ([TCB+0xB0]) — the vendor's own kill machinery then
         * processes the thread from its own entry. */
        if (getenv("MMCS_L82ZOM") && cs->exception_index == 0x0e0) {
            /* L82/S254: THE PER-KEY TALLY TABLE (the v2 bug: the single
             * (key,key2) pair reset on every interleaved 0x0e0 class —
             * the zombie's 3866x never accumulated 32 consecutive; now
             * 8 per-key slots accumulate independently) */
            static uint32_t zom_keys[8][2];
            static int zom_counts[8];
            static int zom_kills, zom_next;
            uint32_t k1 = env->spc, k2 = env->pc;
            int slot = -1;
            for (int i = 0; i < 8; i++) {
                if (zom_keys[i][0] == k1 && zom_keys[i][1] == k2) {
                    slot = i;
                    break;
                }
            }
            if (slot < 0) {
                slot = zom_next++ & 7;
                zom_keys[slot][0] = k1;
                zom_keys[slot][1] = k2;
                zom_counts[slot] = 0;
            }
            zom_counts[slot]++;
            int zom_count = zom_counts[slot];
            int n_kill = 32;
            const char *zk = getenv("MMCS_L82ZOM_N");
            if (zk && *zk) {
                n_kill = atoi(zk);
            }
            if (zom_count >= n_kill && zom_kills < 16) {
                uint32_t pth = 0, ksp = 0;
                cpu_physical_memory_read(0x08679894, &pth, 4);
                if (pth >= 0x90680000u && pth < 0x90700000u) {
                    cpu_physical_memory_read(
                        0x10000000u + (pth - 0x90680000u) + 0xB0,
                        (uint8_t *)&ksp, 4);
                }
                if (ksp >= 0xd0000000u && ksp < 0xd0800000u) {
                    env->gregs[15] = ksp;
                }
                env->pc = 0x9083BE50;
                env->sr &= ~(1u << SR_BL);
                zom_kills++;
                zom_count = 0;
                fprintf(stderr, "MMCS-L82ZOM: TAIL redirect TCB %08x "
                        "(spc=%08x pc=%08x) -> kill continuation "
                        "0x9083BE50, sp=%08x (kill %d)\n",
                        pth, k1, k2, env->gregs[15], zom_kills);
            }
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

    int rdbg = get_physical_address(&cpu->env, &physical, &prot, addr,
                                    MMU_DATA_LOAD);
    if (getenv("MMCS_DBGVA")) {
        static int ndbg;
        if (ndbg++ < 32) {
            fprintf(stderr, "GETPHYSDBG va=%08" VADDR_PRIx " ret=%d pa=%08x "
                    "sr=%08x mmucr=%08x pc=%08x\n", addr, rdbg, physical,
                    cpu->env.sr, cpu->env.mmucr, cpu->env.pc);
        }
    }
    if (rdbg == MMU_OK) {
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

    /* MMCS fork (L82): MMCS_TLBTRACE — the fill-flow visibility knob
     * (the L82UM non-firing debug): every tlb_fill with {va, acc, idx,
     * ret} so the refill-block reachability is observable. */
    if (getenv("MMCS_TLBTRACE")) {
        static int nfill;
        static int ndwin;
        if ((uint32_t)address >= 0xD0000000u) {
            /* d-window fills: UNCAPPED (the L82UM debug) + the knob state */
            static int l82um_dbg;
            if (!l82um_dbg) {
                l82um_dbg = 1;
                fprintf(stderr, "MMCS-L82UM-DBG knob=%d\n",
                        !!getenv("MMCS_L82UM"));
            }
            if (ndwin++ < 200) {
                fprintf(stderr, "MMCS-TLBFILL-DWIN[%d] va=%08x acc=%d "
                        "idx=%d ret=%d\n", ndwin, (uint32_t)address,
                        (int)access_type, mmu_idx, ret);
            }
        } else if (nfill++ < 3000 && getenv("MMCS_TLBTRACE_ALL")) {
            fprintf(stderr, "MMCS-TLBFILL[%d] va=%08x acc=%d idx=%d "
                    "ret=%d\n", nfill, (uint32_t)address,
                    (int)access_type, mmu_idx, ret);
        }
    }

    /* MMCS fork (L26): P1 KERNEL-ALIAS of the C0 servant window.
     *
     * Decoded 2026-11-17 (L26 park walk): this image's own pre-bound
     * dispatch tables call kernel-side servants through their P1
     * aliases — filesys.dll's FS_* dispatch block (decompressed .data
     * at c00ce2bc-c00ce2e4, 54 words) ships LITERAL 0x802cxxxx
     * targets (fsdmgr!FS_MoveFileW = 0x802c7668 = the servant
     * c02c7668 with the P1-window base), and six more modules carry
     * the same class (c0243000/c0253000/c0276000/c029b000/c02a5000/
     * c02b4000/c00e3000 rows). On HW the vendor loader places the
     * servant's pages at phys 0x02c1000-class and maps BOTH views
     * (UTLB P3 c02c1000 + the always-valid P1 0x802c1000 direct
     * alias) — the pre-bound tables call through P1 precisely
     * because it needs no UTLB entry. The emulated crash: the filesys
     * FUN_c00cb96c dispatch jsr'd 0x802c7668, P1 identity-resolved
     * to phys 0x02c7668 (free RAM = garbage bytes), the fetch raised
     * illegal 0x180 and the KAPIFIX failed-call synthesis retired
     * the whole filesys init lane -> the park (empty run queue,
     * arena recycled, chain[23]/[24] NULL).
     *
     * Fix: a KERNEL-mode fetch/load/store miss in [0x80000000,
     * 0x81000000) whose +0x40000000 alias falls in the manifest's C0
     * window maps THE SAME backing the C0 service serves (XIP .text
     * = flash bytes RO+X, non-XIP = the SAME deduped instance
     * scratch page, RW per the L22 decode) — one shared instance
     * across both views, exactly the HW dual mapping. The manifest
     * gate keeps the claim narrow: only the phys range the servant
     * itself occupies on HW (the heap can never hold objects there),
     * everything else in P1 keeps the identity path. PGOWN keys the
     * normalized C0 VA so P1/P3 views share one ownership entry. */
    if (mmu_idx != MMU_USER_IDX
        && (mmcs_ilkfix_user_seen || mmcs_c0arm)
        && mmcs_iatfix_on
        && mmcs_p1_alias_enabled      /* S159: off while the MLD FLROM
                                       * owns phys [0,16MB) — the loader's
                                       * P1 NOR reads (the Opening BMP at
                                       * 0x80100000) must not be claimed
                                       * as servant aliases; restored at
                                       * the handoff FLROM retirement */
        && (uint32_t)address >= 0x80000000
        && (uint32_t)address < 0x81000000
        && (access_type == MMU_INST_FETCH
            || access_type == MMU_DATA_LOAD
            || access_type == MMU_DATA_STORE)) {
        bool arw = false;
        hwaddr apa = mmcs_iatfix_page_pa(
            (uint32_t)address + 0x40000000u, &arw, true);
        if (apa) {
            static int nal;
            if (nal++ < 24) {
                fprintf(stderr, "MMCS-L26: P1 servant alias va=%08x "
                        "-> c0 va=%08x pa=%08" HWADDR_PRIx " acc=%d "
                        "rw=%d\n", (uint32_t)address,
                        (uint32_t)address + 0x40000000u, apa,
                        (int)access_type, (int)arw);
            }
            if (access_type == MMU_DATA_STORE && !arw) {
                /* store to a read-only section through the alias:
                 * raise the guest write violation at the faulting
                 * (alias) VA — same fidelity as the C0/IATFIX path. */
                static int naro;
                if (naro++ < 8) {
                    fprintf(stderr, "MMCS-L26: RO-section store refused "
                            "va=%08x (p1 alias)\n", (uint32_t)address);
                }
                env->pteh = (env->pteh & PTEH_ASID_MASK)
                            | ((uint32_t)address & PTEH_VPN_MASK);
                env->tea = (uint32_t)address;
                cs->exception_index = 0x0c0;
                cpu_loop_exit_restore(cs, retaddr);
            }
            int ap = ((arw ? (PAGE_READ | PAGE_WRITE) : PAGE_READ)
                      | PAGE_EXEC);
            uint32_t apa32 = (uint32_t)apa;
            ap = mmcs_pgown_fill(env, (uint32_t)address + 0x40000000u,
                                 &apa32, ap,
                                 access_type == MMU_DATA_STORE);
            tlb_set_page(cs, (uint32_t)address & 0xFFFFF000u, apa32,
                         ap, mmu_idx, TARGET_PAGE_SIZE);
            return true;
        }
    }

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
            || ((getenv("MMCS_KILK") || getenv("MMCS_L66STK"))
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
            if (mmcs_l68_kd_on()) {
                /* L68/S219: the backing is the LIVE KData page — the
                 * vendor's own MDInitialize block at KData+0x380 is the
                 * stock; nothing is seeded. */
                fprintf(stderr, "MMCS-L68: KData user page -> the LIVE "
                        "KData page %08x (no seed; the vendor's own "
                        "_InterlockedAPIs block is the stock)\n",
                        mmcs_l68_kdata_page_pa());
            } else if (getenv("MMCS_L66STK")) {
                /* L66/S218: seed the CORRECT stock block (all eight
                 * granules, poison-repair policy) — see
                 * hw/sh4/mmcs.c mmcs_l66_stock_arena. */
                mmcs_l66_stock_arena("lazy-fault");
            } else {
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
            }
            seeded = true;
            fprintf(stderr, "MMCS: ILKFIX seeded interlocked blocks "
                    "@phys 0x0C020B80 (KData page)\n");
        }
        if (mmu_idx == MMU_USER_IDX) {
            mmcs_ilkfix_user_seen = true;
        }
        uint32_t kdpa = 0x0C020000;
        uint32_t l68pa = mmcs_l68_kd_on() ? mmcs_l68_kdata_page_pa() : 0;
        if (l68pa) {
            kdpa = l68pa;             /* L68/S219: the live KData page */
        }
        int kdprot = mmcs_pgown_fill(env, 0x5000, &kdpa,
                                     PAGE_READ | PAGE_WRITE | PAGE_EXEC, 0);
        /* L82/S252: THE 2-ENTRY SPLIT — the pgown's clean-pin strips
         * the write for BOTH modes; the stock serves the KERNEL an RW
         * view (the vendor's 0x5bd0-class per-thread context writes
         * run kernel-mode; the entry-print census: ret=-1 write
         * violations at 0x5bd0, 2700x at the ring-writer spc). */
        if (mmu_idx == MMU_USER_IDX) {
            tlb_set_page(cs, 0x5000, kdpa, kdprot, mmu_idx,
                         TARGET_PAGE_SIZE);
        } else {
            tlb_set_page(cs, 0x5000, kdpa, kdprot | PAGE_WRITE, mmu_idx,
                         TARGET_PAGE_SIZE);
        }
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
        /* L82/S251: THE WRITABLE SENTINEL — the entry-print census
         * (2700x write violations at the 0x5bd0-class): the stock's
         * low-slot page carries the vendor's per-thread context
         * structures (the ring-writer's [r2+4] stores); serving it
         * RO makes every context write a ret=-1 violation loop. The
         * stock page is RW (the rts stub sits at the page HEAD; the
         * 0x5bd0-class tails are scratch). */
        tlb_set_page(cs, address & TARGET_PAGE_MASK,
                     address & TARGET_PAGE_MASK,
                     PAGE_READ | PAGE_WRITE | PAGE_EXEC, mmu_idx,
                     TARGET_PAGE_SIZE);
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
     * early IRQ-init walk never touches the window — OR on MMCS_C0ARM
     * (L22): the kernel-side servant lane, where no user-mode event
     * ever fires the latch and the loader walks need the window from
     * the kernel's own KernelInit2 module load on (the L22 decode). */
    if (ret != MMU_OK && mmu_idx != MMU_USER_IDX
        && (mmcs_ilkfix_user_seen || mmcs_c0arm)
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
                uint32_t pa32 = (uint32_t)pa;
                int pprot = mmcs_pgown_fill(env, page, &pa32,
                                            PAGE_READ | PAGE_WRITE,
                                            access_type == MMU_DATA_STORE);
                tlb_set_page(cs, page, pa32, pprot, mmu_idx,
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
     * Gated on the launch-phase latch exactly like SRVPG — or on
     * MMCS_C0ARM (L22, the kernel-side servant lane). */
    if (ret != MMU_OK && mmu_idx != MMU_USER_IDX
        && (mmcs_ilkfix_user_seen || mmcs_c0arm)
        && mmcs_iatfix_on
        && (uint32_t)address >= 0xC0000000
        && (uint32_t)address < 0xC1000000
        && (access_type == MMU_INST_FETCH
            || access_type == MMU_DATA_LOAD
            || access_type == MMU_DATA_STORE)) {
        bool rw = false;
        hwaddr pa = mmcs_iatfix_page_pa((uint32_t)address, &rw, true);
        if (pa) {
            if (access_type == MMU_DATA_STORE && !rw) {
                /* store to a read-only section: raise the guest write
                 * violation (fidelity: no silent writes) — the vendor
                 * handler sees exactly the HW protection fault. */
                static int noro;
                if (noro++ < 8) {
                    fprintf(stderr, "MMCS-L25: RO-section store refused "
                            "va=%08x (iatfix)\n", (uint32_t)address);
                }
                env->pteh = (env->pteh & PTEH_ASID_MASK)
                            | ((uint32_t)address & PTEH_VPN_MASK);
                env->tea = (uint32_t)address;
                cs->exception_index = 0x0c0;   /* dtlb_violation_write */
                cpu_loop_exit_restore(cs, retaddr);
            }
            int iprot = (rw ? (PAGE_READ | PAGE_WRITE) : PAGE_READ)
                        | PAGE_EXEC;
            uint32_t pa32 = (uint32_t)pa;
            iprot = mmcs_pgown_fill(env, (uint32_t)address, &pa32, iprot,
                                    access_type == MMU_DATA_STORE);
            if (getenv("MMCS_L25DBG")
                && (uint32_t)address < 0xC0020000) {
                uint8_t b[8] = { 0 };
                cpu_physical_memory_read(pa32, b, 8);
                fprintf(stderr, "MMCS-L25DBG iatfix va=%08x acc=%d "
                        "pa=%08x->%08x rw=%d bytes=%02x%02x%02x%02x "
                        "%02x%02x%02x%02x\n", (uint32_t)address,
                        (int)access_type, (uint32_t)pa, pa32, (int)rw,
                        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
            }
            tlb_set_page(cs, (uint32_t)address & 0xFFFFF000u, pa32,
                         iprot, mmu_idx, TARGET_PAGE_SIZE);
            return true;
        }
    }

    /* MMCS fork (L23): MMCS_UWARM — the CURRENT-PROCESS USER-window
     * module service (the full decode in hw/sh4/mmcs.c). A KERNEL-mode
     * fetch/load/store miss in [0x40000000,0x80000000) covered by the
     * SRP2 manifest's user rows (this fixed-slot image bakes absolute
     * 0x4xxxxxxx realaddrs into the ROM TOC: coredll .text XIP at
     * 0x40011000<->ROM 0x90853000, RW at 0x40074000+): XIP .text maps
     * the flash ROM bytes RO+X, non-XIP maps the decompressed-init
     * scratch page (RW per the o32 write flag) — exactly the mapping
     * the real pager installs for the current process (kernel access
     * to the user window is legal on HW; the oalioctl import walk and
     * its pre-bound 0x4001xxxx IAT targets depend on it). */
    if (ret != MMU_OK && mmu_idx != MMU_USER_IDX
        && mmcs_uwarm
        && mmcs_iatfix_on
        && (uint32_t)address >= 0x40000000
        && (uint32_t)address < 0x80000000
        && (access_type == MMU_INST_FETCH
            || access_type == MMU_DATA_LOAD
            || access_type == MMU_DATA_STORE)) {
        bool rw = false;
        hwaddr pa = mmcs_iatfix_page_pa((uint32_t)address, &rw, false);
        if (pa) {
            if (access_type == MMU_DATA_STORE && !rw) {
                /* store to a read-only section: raise the guest write
                 * violation (fidelity: no silent writes) — the vendor
                 * handler sees exactly the HW protection fault. */
                static int nuro;
                if (nuro++ < 8) {
                    fprintf(stderr, "MMCS-L25: RO-section store refused "
                            "va=%08x (uwarm)\n", (uint32_t)address);
                }
                env->pteh = (env->pteh & PTEH_ASID_MASK)
                            | ((uint32_t)address & PTEH_VPN_MASK);
                env->tea = (uint32_t)address;
                cs->exception_index = 0x0c0;   /* dtlb_violation_write */
                cpu_loop_exit_restore(cs, retaddr);
            }
            int uprot = (rw ? (PAGE_READ | PAGE_WRITE) : PAGE_READ)
                        | PAGE_EXEC;
            uint32_t pa32 = (uint32_t)pa;
            uprot = mmcs_pgown_fill(env, (uint32_t)address, &pa32, uprot,
                                    access_type == MMU_DATA_STORE);
            tlb_set_page(cs, (uint32_t)address & 0xFFFFF000u, pa32,
                         uprot, mmu_idx, TARGET_PAGE_SIZE);
            return true;
        }
        /* MMCS fork (L28): MMCS_UWHEAP — the CURRENT-PROCESS-SLOT demand
         * pages. The manifest rows cover only the ROM TOC's fixed-slot
         * modules; everything the running servants allocate DYNAMICALLY
         * in the process slots (the L28 decode: filesys's HeapCreate ->
         * the kernel-side constructor c0034840 building the 'HeaP'-signed
         * object -> the kernel heap allocator c00343fc returns 0x70010000
         * = the filesys process-slot heap; the constructor's stores at
         * +0x34 faulted, the vendor exception march killed every servant
         * relaunch at 5-10Hz) has no manifest row and no guest page
         * table entry (the synthetic launch never built the process).
         * On HW the kernel maps those pages itself when it services its
         * own allocation; serve the same semantics host-side: a
         * demand-zero RW page from the FILEVIEW pool, VA-deduped per
         * boot, PGOWN-integrated (write-pins, remap-sticky). */
        static int uwheap = -1;
        if (uwheap < 0) {
            uwheap = getenv("MMCS_UWHEAP") && getenv("MMCS_FILEVIEW");
        }
        if (uwheap) {
            uint32_t va = (uint32_t)address & ~0xFFFu;
            uint32_t npa = 0;
            for (int i = 0; i < mmcs_nfvmap; i++) {
                if (mmcs_fvmap[i].va == va) {
                    npa = mmcs_fvmap[i].pa;
                    break;
                }
            }
            if (!npa && mmcs_fvmap_nxt + 0x1000 <= 0x24000000
                && mmcs_nfvmap < 16384) {
                npa = mmcs_fvmap_nxt;
                mmcs_fvmap_nxt += 0x1000;
                mmcs_fvmap[mmcs_nfvmap].va = va;
                mmcs_fvmap[mmcs_nfvmap].pa = npa;
                mmcs_nfvmap++;
                static int nuw;
                if (nuw++ < 32) {
                    fprintf(stderr, "MMCS: UWHEAP demand-zero slot page "
                            "va=%08x -> pa=%08x\n", va, npa);
                }
            }
            if (npa) {
                int hprot = mmcs_pgown_fill(env, va, &npa,
                                            PAGE_READ | PAGE_WRITE | PAGE_EXEC,
                                            access_type == MMU_DATA_STORE);
                tlb_set_page(cs, va, npa, hprot, mmu_idx,
                             TARGET_PAGE_SIZE);
                return true;
            }
        }
    }

    /* MMCS fork (L22 diagnostic): MMCS_L22DBG=1 — log every UNserviced
     * C0-window miss with the gate state (which condition refused the
     * SRVPG/IATFIX service). Env-gated diagnostic only, no behavior
     * change. */
    if (ret != MMU_OK && getenv("MMCS_L22DBG")
        && (uint32_t)address >= 0xC0000000
        && (uint32_t)address < 0xC1000000) {
        static int nl;
        if (nl++ < 400) {
            fprintf(stderr, "MMCS-L22DBG miss va=%08x acc=%d mmu_idx=%d "
                    "sr=%03x ilk=%d srvpg=%d iatfix=%d c0arm=%d pr=%08x\n",
                    (uint32_t)address, (int)access_type, mmu_idx,
                    (uint32_t)env->sr, (int)mmcs_ilkfix_user_seen,
                    (int)env->mmcs_srvpg_active, (int)mmcs_iatfix_on,
                    (int)mmcs_c0arm, env->pr);
        }
    }

    /* MMCS fork (L70/S221): MMCS_L70KS — the kernel kstack-arena P3
     * window refill (the full decode in hw/sh4/mmcs.c). A KERNEL-mode
     * data load/store miss in the D0 window [0xd0000000, top) — the
     * vendor's own top-of-RAM kstack/block arena (VA = PA + 0xC0000000
     * over the RAM top; window top derived from the vendor's own
     * OEMGLOBAL dwMainMemoryEndAddress cell at run time) = a straggler
     * walk over a FREED kstack window whose backing RAM still holds
     * the vendor's stale data. Refill the identity PA and let the
     * vendor code read its own arena. Fetches are NOT served. */
    if (ret != MMU_OK && mmcs_l70ks_on()
        && mmu_idx != MMU_USER_IDX
        && (uint32_t)address >= 0xD0000000u
        && (access_type == MMU_DATA_LOAD
            || access_type == MMU_DATA_STORE)) {
        static uint32_t ks_top;
        if (!ks_top) {
            uint32_t mea = 0;
            cpu_physical_memory_read(0x086025e4, &mea, 4);   /* OEMGLOBAL
                                             * +0x64 dwMainMemoryEnd */
            if (mea < 0x90600000u || mea >= 0x92000000u) {
                mea = 0x90700000u;   /* the observed live value */
            }
            ks_top = 0xC0000000u + (mea - 0x80000000u);
        }
        if ((uint32_t)address < ks_top) {
            uint32_t pa = (uint32_t)address - 0xC0000000u;
            static int nks;
            if (nks++ < 24) {
                fprintf(stderr, "MMCS-L70KS: kstack-arena window refill "
                        "va=%08x -> pa=%08x acc=%d (%d)\n",
                        (uint32_t)address, pa, (int)access_type, nks);
            }
            int kprot = mmcs_pgown_fill(env, (uint32_t)address, &pa,
                                        PAGE_READ | PAGE_WRITE,
                                        access_type == MMU_DATA_STORE);
            tlb_set_page(cs, (uint32_t)address & 0xFFFFF000u, pa,
                         kprot, mmu_idx, TARGET_PAGE_SIZE);
            return true;
        }
    }

    /* MMCS fork (L82/S235): MMCS_L82UM — the USER-mode d-window data
     * refill (the S234 census root). THE DECODE (L82 probe5/6, the
     * EXCTRACE/EXCCTX census): the fresh full-family boot's REAL fault
     * classes are USER-mode (UM, sr=00008000) d-window data misses:
     * the filesys region walk (c0034854: the 64KB-region header read
     * [base+0x34], r1=0x10000, pr=c0034914 — walking the arena the
     * stock VirtualAlloc would have mapped) and the kernel-stack
     * allocator's user-side commits (9083197a/908318c0: r4=region,
     * r1=0x20000000 RESERVE, r5=0x10000 COMMIT, the first touch at
     * [page+...]). The stock: the kernel's VirtualAlloc populates the
     * per-process UTLB; in emulation the commit's UTLB update doesn't
     * happen (the page-table path is incomplete), so every walk/commit
     * first-touch takes 0x040/0x0e0 and the child dies. FIX: the same
     * stock-faithful identity refill as L70KS (PA = VA - 0xC0000000 —
     * the page IS the real RAM arena backing; the vendor's own data),
     * served for the USER-mode data miss. Gated on MMCS_L82UM (default
     * off) AND the L70KS window logic (the shared top derivation).
     * Fetches are NOT served (executing stack data stays a real bug). */
    /* L82/S252: THE P0 RING-BANK WINDOW — the ring-writer's stores at
     * VA 0x010f3471 (P0 = TLB-mapped, NOT the P1 identity!) fault as
     * DTLB write misses (2044x+3360x): the guest's own page-table
     * entry for the vendor's ring bank is absent in the fresh world.
     * Serve the fill directly: 1:1 to the ram4 bank (16MB @ phys
     * 0x01000000), RW — the vendor's ring/context bank. */
    if (ret != MMU_OK && (uint32_t)address >= 0x01000000u
        && (uint32_t)address < 0x02000000u
        && getenv("MMCS_P0RING")
        && (access_type == MMU_DATA_LOAD
            || access_type == MMU_DATA_STORE)) {
        tlb_set_page(cs, address & TARGET_PAGE_MASK,
                     address & TARGET_PAGE_MASK,
                     PAGE_READ | PAGE_WRITE, mmu_idx, TARGET_PAGE_SIZE);
        return true;
    }

    /* L82/S257: THE P3 WINDOW (the filesys/swapserver .text fetch
     * misses) — the everything.env world's user phase: the low-count
     * c00xxxxx classes (the P3 = TLB-mapped; the guest's own entries
     * absent for the loaded server .text). The guest's intent: the
     * P3 va c00xxxxx maps the SDRAM copy (1:1 va-0x40000000). The
     * same fill-service class as P0RING, default-off knob. */
    if (ret != MMU_OK && (uint32_t)address >= 0xC0000000u
        && (uint32_t)address < 0xC0200000u
        && getenv("MMCS_P3WIN")) {
        tlb_set_page(cs, address & TARGET_PAGE_MASK,
                     (address & TARGET_PAGE_MASK) - 0x40000000u,
                     PAGE_READ | PAGE_EXEC, mmu_idx, TARGET_PAGE_SIZE);
        return true;
    }

    /* L82/S250: THE ENTRY-PRINT — every FAILING fill's {addr, ret,
     * acc, idx} (the L82UM zero-fire mystery) */
    if (ret != MMU_OK && getenv("MMCS_L82UM")) {
        static int nent;
        if (nent++ < 40) {
            fprintf(stderr, "MMCS-L82ENT[%d] addr=%08x ret=%d acc=%d "
                    "idx=%d\n", nent, (uint32_t)address, ret,
                    (int)access_type, mmu_idx);
        }
    }
    if (ret != MMU_OK && getenv("MMCS_L82UM")
        && (uint32_t)address >= 0xD0000000u
        && (access_type == MMU_DATA_LOAD
            || access_type == MMU_DATA_STORE)) {
        static uint32_t um_top;
        if (!um_top) {
            uint32_t mea = 0;
            cpu_physical_memory_read(0x086025e4, &mea, 4);
            if (mea < 0x90600000u || mea >= 0x92000000u) {
                mea = 0x90700000u;
            }
            um_top = 0xC0000000u + (mea - 0x80000000u);
        }
        if ((uint32_t)address < um_top) {
            uint32_t pa = (uint32_t)address - 0xC0000000u;
            static int num;
            if (num++ < 24) {
                fprintf(stderr, "MMCS-L82UM: user d-window refill "
                        "va=%08x -> pa=%08x acc=%d (%d)\n",
                        (uint32_t)address, pa, (int)access_type, num);
            }
            int uprot = mmcs_pgown_fill(env, (uint32_t)address, &pa,
                                        PAGE_READ | PAGE_WRITE,
                                        access_type == MMU_DATA_STORE);
            tlb_set_page(cs, (uint32_t)address & 0xFFFFF000u, pa,
                         uprot, mmu_idx, TARGET_PAGE_SIZE);
            return true;
        }
    }

    /* MMCS fork (L71/S222): MMCS_L71IT — the stale-ITLB kernel-data
     * refill (the L70KS live-page family). THE DECODE (this lane,
     * register-level): the L70KS world's standing death is NOT the
     * ring-writer unbound-cell call (the null rung killed that
     * premise: [0x88602d30] IS stocked = 0x8862ada0 by
     * OEMInitDebugSerial's tail, the ring indices advance live) but
     * the kernel MODULE-WINDOW data miss: the 64-entry guest UTLB
     * churns (the healthy/death dumps show the C0-window entries
     * cycling v=0/gone), while the ITLB keeps its stale-but-valid
     * copy of the same guest-installed mapping (SH4 never invalidates
     * ITLB copies on UTLB replacement) — so the code keeps EXECUTING
     * (fetch path: ITLB hit / cached TBs) while a literal-pool DATA
     * read of the same page (the SHC `mov.l Lpool,r3; mov.l @r3`
     * idiom — observed live: evt=040 pc=c00cbe44 tea=c00cbe44
     * r3=c00cbe44, the launcher's post-hand-off filesys continuation)
     * misses the UTLB. On HW the kernel-mode TLB-miss vector refills
     * from the page tables (the mapping is live — the entry was
     * installed by the vendor loader); in our world the vendor
     * exception path declares the kernel data miss FATAL (the stock
     * CE6 kernel-pages-resident contract) -> the report -> the
     * nested cascade -> the scheduler parks in OEMIdle with SR.BL=1
     * (the permanent freeze; pc 0x908089fe = OEMIdle's post-sleep
     * reload loop, sp = the KData exception stack 0x886797b4).
     * FIX: a KERNEL-mode DTLB read miss whose page holds a VALID
     * stale ITLB entry = the last-known-good GUEST-installed mapping:
     * serve the access (and the page's exec) from the ITLB entry's
     * own ppn — exactly the refill the stock handler would perform,
     * delivered host-side through the L70KS discipline. Stores and
     * fetches are NOT served (the decoded domino is a read; fetch
     * misses imply no ITLB copy exists). Env MMCS_L71IT (default
     * off). A file-static arm only (the L61 vmstate law). */
    static int mmcs_l71it_armed = -1;
    if (mmcs_l71it_armed < 0) {
        mmcs_l71it_armed = getenv("MMCS_L71IT") != NULL;
    }
    if (mmcs_l71it_armed && ret == MMU_DTLB_MISS_READ
        && mmu_idx != MMU_USER_IDX) {
        int hit = -1;
        for (int i = 0; i < ITLB_SIZE; i++) {
            const tlb_t *e = &env->itlb[i];
            if (!e->v) {
                continue;
            }
            uint32_t start = (e->vpn << 10) & ~(e->size - 1);
            if ((uint32_t)address >= start
                && (uint32_t)address < start + e->size) {
                hit = i;
                break;
            }
        }
        static int n71hit, n71miss;
        if (hit >= 0) {
            const tlb_t *e = &env->itlb[hit];
            uint32_t pa = (((e->ppn << 10) & ~(e->size - 1))
                           | ((uint32_t)address & (e->size - 1)));
            int p71 = PAGE_READ | PAGE_EXEC;
            if ((e->pr & 1) && e->d) {
                p71 |= PAGE_WRITE;
            }
            uint32_t pa32 = pa & TARGET_PAGE_MASK;
            p71 = mmcs_pgown_fill(env, (uint32_t)address & TARGET_PAGE_MASK,
                                  &pa32, p71, false);
            if (n71hit++ < 24) {
                fprintf(stderr, "MMCS-L71IT: stale-ITLB kernel-data refill "
                        "va=%08x -> pa=%08x (itlb %d pr=%u d=%u) (%d)\n",
                        (uint32_t)address, pa32, hit, e->pr, e->d, n71hit);
            }
            tlb_set_page(cs, (uint32_t)address & TARGET_PAGE_MASK, pa32,
                         p71, mmu_idx, TARGET_PAGE_SIZE);
            return true;
        } else if (n71miss++ < 24) {
            fprintf(stderr, "MMCS-L71IT: kernel data miss, no ITLB copy "
                    "(va=%08x pr=%08x) (%d)\n",
                    (uint32_t)address, env->pr, n71miss);
        }
    }

    if (ret == MMU_OK) {
        address &= TARGET_PAGE_MASK;
        physical &= TARGET_PAGE_MASK;
        /* (MMCS_PSLFIX deleted 2026-11-19, retirement lane S173: armed-
         * but-inert requalification archived by the fidelity scorecard
         * §1.14/§E — patch applied, serial+census identical; the parked
         * guest-code patch never mattered to any working combo.) */
        /* L21: the ownership choke point — clean writable pages install
         * write-stripped (first store bounces back and pins); pinned
         * pages override the guest translation's pa with their sticky
         * backing (the S140 vanishing-write fix: the kernel's remap of
         * a written VA serves the pinned copy, not a fresh zero page). */
        prot = mmcs_pgown_fill(env, (uint32_t)address,
                               (uint32_t *)&physical, prot,
                               access_type == MMU_DATA_STORE);
        tlb_set_page(cs, address, physical, prot, mmu_idx, TARGET_PAGE_SIZE);
        return true;
    }
    if (probe) {
        return false;
    }

    /* MMCS fork (L82): the RAISING-fill trace — every fill that FAILS
     * through to the exception tail (no block claimed it): the exact
     * {va, acc, idx, ret} at the raise. The L82UM non-firing debug. */
    if (getenv("MMCS_TLBTRACE")) {
        static int nraise;
        if (nraise++ < 400) {
            fprintf(stderr, "MMCS-TLBRAISE[%d] va=%08x acc=%d idx=%d "
                    "ret=%d\n", nraise, (uint32_t)address,
                    (int)access_type, mmu_idx, ret);
        }
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

/* ===================== savestate (snapshot lane) =====================
 * MMCS fork: "mmcs/helper" — the helper-side host tables that gate
 * execution MUST survive a snapshot: the FILEVIEW va->pa dedup table
 * (+ allocator cursor — a lost cursor would hand out FRESH pages over
 * the migrated ones' addresses), the COWFIX map (same discipline, its
 * scratch is the SDRAM top margin), and the ILKFIX launch latch
 * (gates sub-floor PGOWN registration; a lost latch changes post-
 * restore page-ownership behavior). Env-derived lazy caches
 * (MMCS_STKFLOOR floor, UWHEAP latch, one-shot seed guards) are
 * deliberately NOT streamed: they re-derive from the same env, and
 * the ILKFIX seed is read-before-write (never stomps migrated RAM).
 */
#if !defined(CONFIG_USER_ONLY)
struct MmcsHelperSnap {
    uint32_t fvmap[16384][2];
    int32_t nfvmap;
    uint32_t fvmap_nxt;
    uint32_t cowmap[512][2];
    int32_t cown;
    uint32_t cownext;
    int32_t user_seen;
};
static struct MmcsHelperSnap mmcs_helper_snap;

static int mmcs_helper_pre_save(void *opaque)
{
    struct MmcsHelperSnap *s = opaque;
    memcpy(s->fvmap, mmcs_fvmap, sizeof s->fvmap);
    s->nfvmap = mmcs_nfvmap;
    s->fvmap_nxt = mmcs_fvmap_nxt;
    memcpy(s->cowmap, mmcs_cowfix_map, sizeof s->cowmap);
    s->cown = mmcs_cowfix_nmap;
    s->cownext = mmcs_cowfix_next;
    s->user_seen = mmcs_ilkfix_user_seen;
    return 0;
}

static int mmcs_helper_post_load(void *opaque, int version_id)
{
    struct MmcsHelperSnap *s = opaque;
    memcpy(mmcs_fvmap, s->fvmap, sizeof s->fvmap);
    mmcs_nfvmap = s->nfvmap;
    mmcs_fvmap_nxt = s->fvmap_nxt;
    memcpy(mmcs_cowfix_map, s->cowmap, sizeof s->cowmap);
    mmcs_cowfix_nmap = s->cown;
    mmcs_cowfix_next = s->cownext;
    mmcs_ilkfix_user_seen = s->user_seen;
    fprintf(stderr, "MMCS-SNAP: helper tables restored (fvmap=%d "
            "cowmap=%d launch-latch=%d)\n",
            mmcs_nfvmap, mmcs_cowfix_nmap, (int)mmcs_ilkfix_user_seen);
    return 0;
}

static const VMStateDescription vmstate_mmcs_helper = {
    .name = "mmcs/helper",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = mmcs_helper_pre_save,
    .post_load = mmcs_helper_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32_2DARRAY(fvmap, struct MmcsHelperSnap, 16384, 2),
        VMSTATE_INT32(nfvmap, struct MmcsHelperSnap),
        VMSTATE_UINT32(fvmap_nxt, struct MmcsHelperSnap),
        VMSTATE_UINT32_2DARRAY(cowmap, struct MmcsHelperSnap, 512, 2),
        VMSTATE_INT32(cown, struct MmcsHelperSnap),
        VMSTATE_UINT32(cownext, struct MmcsHelperSnap),
        VMSTATE_INT32(user_seen, struct MmcsHelperSnap),
        VMSTATE_END_OF_LIST()
    }
};

void mmcs_helper_vmstate_register(void)
{
    vmstate_register(NULL, 0, &vmstate_mmcs_helper, &mmcs_helper_snap);
}
#endif /* !CONFIG_USER_ONLY */

#endif /* !CONFIG_USER_ONLY */
