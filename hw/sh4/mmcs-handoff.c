/*
 * MMCS fork (device split lane, 2026-11-26 — peer review M2c, split #7b):
 * the S159 MLD-HANDOFF — the loader no-update path -> the OS launch, one
 * continuous boot — extracted VERBATIM from hw/sh4/mmcs.c (pure code
 * motion; the decode comment moves with the family). The stub IS the
 * resident-stage stand-in: once the loader concludes its scan (the park
 * windows, debounced), regain control and drive the loader's OWN
 * launcher (pc := 0x88935590, r4 := MMCS_ENTRY). Validated by the
 * byte-stability gates (the standing-combo tape record rides this path).
 */
#include "qemu/osdep.h"
#include "hw/sh4/mmcs-handoff.h"
#include "cpu.h"
#include "exec/address-spaces.h"
#include "qemu/timer.h"

static QEMUTimer *mmcs_handoff_timer;
static QEMUTimer *mmcs_handoff_retire_timer;
static MemoryRegion *mmcs_handoff_flrom_mr;
static MemoryRegion *mmcs_handoff_sysmem;

/* ---- the arm + capture setters (called from mmcs.c's MLD branch;
 * the env knobs stay at the mmcs.c call sites via getenv here) ------- */

void mmcs_handoff_set_flrom(MemoryRegion *fr)
{
    mmcs_handoff_flrom_mr = fr;
    mmcs_handoff_sysmem = get_system_memory();
}

void mmcs_handoff_arm(SuperHCPU *cpu)
{
    mmcs_handoff_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                      mmcs_handoff_poll, NULL);
    timer_mod(mmcs_handoff_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
              + atoi(getenv("MMCS_HANDOFF_MIN") ? : "3000"));
    mmcs_handoff_retire_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                             mmcs_handoff_retire_flrom,
                                             NULL);
}

/*
 * — once the loader has CONCLUDED its scan (the park windows below,
 * debounced), regain control and drive the loader's OWN launcher
 * (pc := 0x88935590, r4 := MMCS_ENTRY): the serial seam is the real
 * ' <Launch> 0x908066b0' print and the jump runs the loader's own
 * trampoline. The trampoline's CFI reset polls for 9/9 at NOR+0x1C000
 * (RAM read-back never leaves status mode) — pre-seed the two words so it
 * takes its skip branch (the real flash sits in the array state). SDRAM
 * residue: the loader image at 0x08900000 etc is LEFT IN PLACE (on HW the
 * kernel boots FROM the loader's jump with the loader resident inside the
 * kernel pool 0x08600000-0x10700000) — jump for real; the one NOT
 * tolerated shape is retired at the seam (the FLROM window, see the
 * launch fn). Env MMCS_HANDOFF=1 (needs MMCS_MLD + MMCS_FLROM + -bios),
 * default off. */
SuperHCPU *mmcs_handoff_cpu;
int mmcs_handoff_hits;
int mmcs_handoff_fired;

/* S159: the L26 P1 servant-alias hook (target/sh4/helper.c) claims
 * kernel-mode P1 [0x80000000,0x81000000) = phys [0,16MB) — exactly the
 * NOR FLROM window in MLD mode. In the default boot that phys space is
 * unassigned so the hook only ever served the C0 servants; with the
 * FLROM mapped the loader's own P1 NOR reads (the Opening BMP at
 * 0x80100000) get hijacked to manifest scratch (live: DispLoadBitmap
 * 'bfType = 0' with SRVPGTAB+IATFIX+C0ARM armed). Cleared while the
 * FLROM is mapped (MLD modes), restored at the seam-time FLROM
 * retirement. */
int mmcs_p1_alias_enabled = 1;

void mmcs_handoff_retire_flrom(void *opaque)
{
    if (mmcs_handoff_flrom_mr && mmcs_handoff_sysmem) {
        memory_region_del_subregion(mmcs_handoff_sysmem,
                                    mmcs_handoff_flrom_mr);
        mmcs_p1_alias_enabled = 1;
        fprintf(stderr, "MMCS: HANDOFF FLROM window retired — phys "
                "[0,16MB) back to the WinCE-mode (unassigned) shape; "
                "SDRAM loader residue left in place\n");
    }
}

static bool mmcs_handoff_park_pc(uint32_t pc)
{
    /* the no-update terminal park: the subcpu receive-error loop (live
     * samples; the cycle alternates between the SCIF wait at 0x8893bd1a
     * and the HALFCHECK driver at 0x88935f88-0x88936020) */
    return (pc >= 0x88935f80u && pc < 0x88936030u) ||
           (pc >= 0x8893bd00u && pc < 0x8893bd30u);
}

static void mmcs_handoff_launch(CPUState *cs, run_on_cpu_data data)
{
    SuperHCPU *cpu = SUPERH_CPU(cs);
    CPUSH4State *env = &cpu->env;

    if (mmcs_handoff_fired) {
        return;
    }
    mmcs_handoff_fired = 1;
    /* THE RESIDUE RECONCILIATION (verified by A/B this lane): the kernel's
     * FIRST USER PROCESS runs its initial thread with the user stack in
     * the LOW identity window (live evidence: child sp r15=0x0002fd90,
     * spc=0x40021784) — under the default WinCE boot phys 0x2fd90 is
     * UNASSIGNED (reads 0, writes dropped) and the child completes its
     * startup; with the 16 MB FLROM MR present the stack reads the NOR
     * seed bytes (LOADING.KWI garbage) and the child dies before its
     * first callback return — the create-completion interlock breaks and
     * the launch loop degenerates into a user slot-call retry storm
     * (pc=ffff55d3 x5.1M/110s). On real HW phys [0,16MB) is the NOR the
     * kernel never stacks into; the default-mode unassigned window is
     * the kernel-tolerated shape, so at the seam we retire the FLROM
     * window (the loader is done with the NOR; its post-boot reader, the
     * DRF flash driver, is fail-soft on reads-0 exactly as the default
     * boot). Retired 100 ms after the poke (the trampoline's CFI reset
     * runs in that window against the still-mapped NOR). The L26 P1
     * servant-alias hook re-arms with it. MMCS_HANDOFF_KEEPFLROM=1
     * disables the retirement for A/B. */
    if (mmcs_handoff_flrom_mr && !getenv("MMCS_HANDOFF_KEEPFLROM")) {
        timer_mod(mmcs_handoff_retire_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 100);
    }
    /* the CFI skip-branch pre-seed (see the block comment) — MUST precede
     * the FLROM retirement (the trampoline's CFI window leaves with it) */
    uint16_t nine = 9;
    cpu_physical_memory_write(0x001C000, &nine, 2);
    cpu_physical_memory_write(0x001C002, &nine, 2);
    fprintf(stderr, "MMCS: HANDOFF seam — loader scan concluded (park pc "
            "%08x, %d poll hits); driving the loader's own launcher "
            "0x88935590(r4=%08x): serial ' <Launch> 0x%x' + trampoline "
            "0x88935be8 jmp; SDRAM residue left in place\n",
            env->pc, mmcs_handoff_hits, MMCS_ENTRY, MMCS_ENTRY);
    /* r4 is a BANKED register (r0-r7, SR.RB=1 in the loader: gregs index
     * XOR 0x10 per target/sh4/translate.c REG(x); the bank bit comes from
     * env->sr, not env->flags) — the launcher moves it to r8 (unbanked)
     * and back before the trampoline jmp @r4 */
    unsigned bank = (env->sr & (1u << SR_RB)) ? 0x10u : 0u;
    env->gregs[4 ^ bank] = MMCS_ENTRY;
    env->pc = 0x88935590u;      /* the loader's launcher (own print) */
    env->pr = 0;
    env->in_sleep = 0;
    env->flags &= ~TB_FLAG_DELAY_SLOT_MASK;
}

void mmcs_handoff_poll(void *opaque)
{
    if (mmcs_handoff_fired || !mmcs_handoff_cpu) {
        return;
    }
    /* benign u32 sample of the live pc (the established daemon pattern);
     * the mutation itself runs in vCPU context via run_on_cpu */
    uint32_t pc = mmcs_handoff_cpu->env.pc;
    if (mmcs_handoff_park_pc(pc)) {
        if (++mmcs_handoff_hits >= 8) {
            run_on_cpu(CPU(mmcs_handoff_cpu), mmcs_handoff_launch,
                       RUN_ON_CPU_NULL);
            return;             /* one-shot; timer not rearmed */
        }
    } else {
        mmcs_handoff_hits = 0;
    }
    timer_mod(mmcs_handoff_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 250);
}
