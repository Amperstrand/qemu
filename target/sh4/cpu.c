/*
 * QEMU SuperH CPU
 *
 * Copyright (c) 2005 Samuel Tardieu
 * Copyright (c) 2012 SUSE LINUX Products GmbH
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
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/qemu-print.h"
#include "cpu.h"
#include "migration/vmstate.h"
#include "migration/qemu-file.h"
#include "qapi/qmp/json-writer.h"
#include "exec/exec-all.h"
#include "exec/tb-flush.h"
#include "fpu/softfloat-helpers.h"
#include "tcg/tcg.h"

/* target/sh4/op_helper.c (helper.h cannot be included here — its TCG
 * generator context conflicts with the cpu.h includes) */
void helper_ld_fpscr(CPUSH4State *env, uint32_t val);

static void superh_cpu_set_pc(CPUState *cs, vaddr value)
{
    SuperHCPU *cpu = SUPERH_CPU(cs);

    cpu->env.pc = value;
}

static vaddr superh_cpu_get_pc(CPUState *cs)
{
    SuperHCPU *cpu = SUPERH_CPU(cs);

    return cpu->env.pc;
}

static void superh_cpu_synchronize_from_tb(CPUState *cs,
                                           const TranslationBlock *tb)
{
    SuperHCPU *cpu = SUPERH_CPU(cs);

    tcg_debug_assert(!(cs->tcg_cflags & CF_PCREL));
    cpu->env.pc = tb->pc;
    cpu->env.flags = tb->flags & TB_FLAG_ENVFLAGS_MASK;
}

static void superh_restore_state_to_opc(CPUState *cs,
                                        const TranslationBlock *tb,
                                        const uint64_t *data)
{
    SuperHCPU *cpu = SUPERH_CPU(cs);

    cpu->env.pc = data[0];
    cpu->env.flags = data[1];
    /*
     * Theoretically delayed_pc should also be restored. In practice the
     * branch instruction is re-executed after exception, so the delayed
     * branch target will be recomputed.
     */
}

#ifndef CONFIG_USER_ONLY
static bool superh_io_recompile_replay_branch(CPUState *cs,
                                              const TranslationBlock *tb)
{
    SuperHCPU *cpu = SUPERH_CPU(cs);
    CPUSH4State *env = &cpu->env;

    if ((env->flags & (TB_FLAG_DELAY_SLOT | TB_FLAG_DELAY_SLOT_COND))
        && !(cs->tcg_cflags & CF_PCREL) && env->pc != tb->pc) {
        env->pc -= 2;
        env->flags &= ~(TB_FLAG_DELAY_SLOT | TB_FLAG_DELAY_SLOT_COND);
        return true;
    }
    return false;
}
#endif

static bool superh_cpu_has_work(CPUState *cs)
{
    return cs->interrupt_request & CPU_INTERRUPT_HARD;
}

static void superh_cpu_reset_hold(Object *obj)
{
    CPUState *s = CPU(obj);
    SuperHCPU *cpu = SUPERH_CPU(s);
    SuperHCPUClass *scc = SUPERH_CPU_GET_CLASS(cpu);
    CPUSH4State *env = &cpu->env;

    if (scc->parent_phases.hold) {
        scc->parent_phases.hold(obj);
    }

    memset(env, 0, offsetof(CPUSH4State, end_reset_fields));

    env->pc = 0xA0000000;
#if defined(CONFIG_USER_ONLY)
    env->fpscr = FPSCR_PR; /* value for userspace according to the kernel */
    set_float_rounding_mode(float_round_nearest_even, &env->fp_status); /* ?! */
#else
    env->sr = (1u << SR_MD) | (1u << SR_RB) | (1u << SR_BL) |
              (1u << SR_I3) | (1u << SR_I2) | (1u << SR_I1) | (1u << SR_I0);
    env->fpscr = FPSCR_DN | FPSCR_RM_ZERO; /* CPU reset value according to SH4 manual */
    set_float_rounding_mode(float_round_to_zero, &env->fp_status);
    set_flush_to_zero(1, &env->fp_status);
#endif
    set_default_nan_mode(1, &env->fp_status);
}

static void superh_cpu_disas_set_info(CPUState *cpu, disassemble_info *info)
{
    info->mach = bfd_mach_sh4;
    info->print_insn = print_insn_sh;
}

static void superh_cpu_list_entry(gpointer data, gpointer user_data)
{
    const char *typename = object_class_get_name(OBJECT_CLASS(data));
    int len = strlen(typename) - strlen(SUPERH_CPU_TYPE_SUFFIX);

    qemu_printf("%.*s\n", len, typename);
}

void sh4_cpu_list(void)
{
    GSList *list;

    list = object_class_get_list_sorted(TYPE_SUPERH_CPU, false);
    g_slist_foreach(list, superh_cpu_list_entry, NULL);
    g_slist_free(list);
}

static ObjectClass *superh_cpu_class_by_name(const char *cpu_model)
{
    ObjectClass *oc;
    char *s, *typename = NULL;

    s = g_ascii_strdown(cpu_model, -1);
    if (strcmp(s, "any") == 0) {
        oc = object_class_by_name(TYPE_SH7750R_CPU);
        goto out;
    }

    typename = g_strdup_printf(SUPERH_CPU_TYPE_NAME("%s"), s);
    oc = object_class_by_name(typename);

out:
    g_free(s);
    g_free(typename);
    return oc;
}

static void sh7750r_cpu_initfn(Object *obj)
{
    SuperHCPU *cpu = SUPERH_CPU(obj);
    CPUSH4State *env = &cpu->env;

    env->id = SH_CPU_SH7750R;
    env->features = SH_FEATURE_BCR3_AND_BCR4;
}

static void sh7750r_class_init(ObjectClass *oc, void *data)
{
    SuperHCPUClass *scc = SUPERH_CPU_CLASS(oc);

    scc->pvr = 0x00050000;
    scc->prr = 0x00000100;
    scc->cvr = 0x00110000;
}

static void sh7751r_cpu_initfn(Object *obj)
{
    SuperHCPU *cpu = SUPERH_CPU(obj);
    CPUSH4State *env = &cpu->env;

    env->id = SH_CPU_SH7751R;
    env->features = SH_FEATURE_BCR3_AND_BCR4;
}

static void sh7751r_class_init(ObjectClass *oc, void *data)
{
    SuperHCPUClass *scc = SUPERH_CPU_CLASS(oc);

    scc->pvr = 0x04050005;
    scc->prr = 0x00000113;
    scc->cvr = 0x00110000; /* Neutered caches, should be 0x20480000 */
}

static void sh7785_cpu_initfn(Object *obj)
{
    SuperHCPU *cpu = SUPERH_CPU(obj);
    CPUSH4State *env = &cpu->env;

    env->id = SH_CPU_SH7785;
    env->features = SH_FEATURE_SH4A;
}

static void sh7785_class_init(ObjectClass *oc, void *data)
{
    SuperHCPUClass *scc = SUPERH_CPU_CLASS(oc);

    scc->pvr = 0x10300700;
    scc->prr = 0x00000200;
    scc->cvr = 0x71440211;
}

static void superh_cpu_realizefn(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    SuperHCPUClass *scc = SUPERH_CPU_GET_CLASS(dev);
    Error *local_err = NULL;

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

    cpu_reset(cs);
    qemu_init_vcpu(cs);

    scc->parent_realize(dev, errp);
}

static void superh_cpu_initfn(Object *obj)
{
    SuperHCPU *cpu = SUPERH_CPU(obj);
    CPUSH4State *env = &cpu->env;

    env->movcal_backup_tail = &(env->movcal_backup);
}

#ifndef CONFIG_USER_ONLY
/* MMCS fork (savestate lane): the SH4 CPU was shipped upstream as
 * {.unmigratable = 1}, which hard-blocks savevm/migrate for every
 * machine built on this target (qemu_savevm_state_blocked fails on
 * any registered vmsd with the flag). This is a full field-faithful
 * VMStateDescription for CPUSH4State so the fork's snapshot harness
 * (corpus scripts/emul/snapshot.sh, migrate exec: + -incoming) works.
 *
 * Field notes:
 *  - tlb_t packs its per-entry attributes into compiler-laid-out
 *    bitfields; a custom VMStateInfo serializes them explicitly
 *    (host-layout independent).
 *  - env.fp_status is DERIVED state (helper_ld_fpscr recomputes it
 *    from fpscr) — rebuilt in post_load instead of streamed.
 *  - env.intc_handle / movcal_backup_tail are host pointers — the
 *    former is re-wired by machine init (sh7750_init) before load,
 *    the latter is rebuilt by the movcal deserializer.
 *  - the env.mmcs_*_active latches are env-knob mirrors set at
 *    machine init; they are streamed anyway (cheap, and keeps the
 *    snapshot self-consistent if a knob was armed mid-boot).
 */
static int sh4_tlb_put(QEMUFile *f, void *pv, size_t size,
                       const VMStateField *field, JSONWriter *vmdesc)
{
    const tlb_t *t = pv;
    uint16_t bits = (t->v & 1u) | ((t->sz & 3u) << 1) |
                    ((t->sh & 1u) << 3) | ((t->c & 1u) << 4) |
                    ((t->pr & 3u) << 5) | ((t->d & 1u) << 7) |
                    ((t->wt & 1u) << 8) | ((t->sa & 7u) << 9) |
                    ((t->tc & 1u) << 12);
    qemu_put_be32(f, t->vpn);
    qemu_put_be32(f, t->ppn);
    qemu_put_be32(f, t->size);
    qemu_put_byte(f, t->asid);
    qemu_put_be16(f, bits);
    return 0;
}

static int sh4_tlb_get(QEMUFile *f, void *pv, size_t size,
                       const VMStateField *field)
{
    tlb_t *t = pv;
    uint16_t bits;
    t->vpn = qemu_get_be32(f);
    t->ppn = qemu_get_be32(f);
    t->size = qemu_get_be32(f);
    t->asid = qemu_get_byte(f);
    bits = qemu_get_be16(f);
    t->v = bits & 1u;
    t->sz = (bits >> 1) & 3u;
    t->sh = (bits >> 3) & 1u;
    t->c = (bits >> 4) & 1u;
    t->pr = (bits >> 5) & 3u;
    t->d = (bits >> 7) & 1u;
    t->wt = (bits >> 8) & 1u;
    t->sa = (bits >> 9) & 7u;
    t->tc = (bits >> 12) & 1u;
    return 0;
}

static const VMStateInfo vmstate_info_sh4_tlb = {
    .name = "tlb_t",
    .get = sh4_tlb_get,
    .put = sh4_tlb_put,
};

static int sh4_movcal_put(QEMUFile *f, void *pv, size_t size,
                          const VMStateField *field, JSONWriter *vmdesc)
{
    CPUSH4State *env = container_of(pv, CPUSH4State, movcal_backup);
    memory_content *n;
    unsigned cnt = 0;
    for (n = env->movcal_backup; n; n = n->next) {
        cnt++;
    }
    qemu_put_be32(f, cnt);
    for (n = env->movcal_backup; n; n = n->next) {
        qemu_put_be32(f, n->address);
        qemu_put_be32(f, n->value);
    }
    return 0;
}

static int sh4_movcal_get(QEMUFile *f, void *pv, size_t size,
                          const VMStateField *field)
{
    CPUSH4State *env = container_of(pv, CPUSH4State, movcal_backup);
    memory_content *list = NULL;
    memory_content **tail = &list;
    unsigned cnt = qemu_get_be32(f);
    while (cnt--) {
        memory_content *n = g_new(memory_content, 1);
        n->address = qemu_get_be32(f);
        n->value = qemu_get_be32(f);
        *tail = n;
        tail = &n->next;
    }
    *tail = NULL;
    env->movcal_backup = list;
    env->movcal_backup_tail = list ? tail : &env->movcal_backup;
    return 0;
}

static const VMStateInfo vmstate_info_sh4_movcal = {
    .name = "movcal_backup",
    .get = sh4_movcal_get,
    .put = sh4_movcal_put,
};

static int superh_cpu_post_load(void *opaque, int version_id)
{
    SuperHCPU *cpu = opaque;
    CPUSH4State *env = &cpu->env;

    /* fp_status is derived from fpscr (see helper_ld_fpscr) */
    helper_ld_fpscr(env, env->fpscr);
    /* TCG may hold translations keyed on the pre-load CPU state */
    tb_flush(env_cpu(env));
    return 0;
}

static bool sh4_movcal_needed(void *opaque, int version_id)
{
    SuperHCPU *cpu = opaque;
    return cpu->env.movcal_backup != NULL;
}

static const VMStateDescription vmstate_sh_cpu = {
    .name = "cpu",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = superh_cpu_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_CPU(),
        VMSTATE_UINT32(env.flags, SuperHCPU),
        VMSTATE_UINT32_ARRAY(env.gregs, SuperHCPU, 24),
        VMSTATE_UINT32_ARRAY(env.fregs, SuperHCPU, 32),
        VMSTATE_UINT32(env.sr, SuperHCPU),
        VMSTATE_UINT32(env.sr_m, SuperHCPU),
        VMSTATE_UINT32(env.sr_q, SuperHCPU),
        VMSTATE_UINT32(env.sr_t, SuperHCPU),
        VMSTATE_UINT32(env.ssr, SuperHCPU),
        VMSTATE_UINT32(env.spc, SuperHCPU),
        VMSTATE_UINT32(env.gbr, SuperHCPU),
        VMSTATE_UINT32(env.vbr, SuperHCPU),
        VMSTATE_UINT32(env.sgr, SuperHCPU),
        VMSTATE_UINT32(env.dbr, SuperHCPU),
        VMSTATE_UINT32(env.pc, SuperHCPU),
        VMSTATE_UINT32(env.delayed_pc, SuperHCPU),
        VMSTATE_UINT32(env.delayed_cond, SuperHCPU),
        VMSTATE_UINT32(env.mach, SuperHCPU),
        VMSTATE_UINT32(env.macl, SuperHCPU),
        VMSTATE_UINT32(env.pr, SuperHCPU),
        VMSTATE_UINT32(env.fpscr, SuperHCPU),
        VMSTATE_UINT32(env.fpul, SuperHCPU),
        VMSTATE_UINT32(env.mmucr, SuperHCPU),
        VMSTATE_UINT32(env.pteh, SuperHCPU),
        VMSTATE_UINT32(env.ptel, SuperHCPU),
        VMSTATE_UINT32(env.ptea, SuperHCPU),
        VMSTATE_UINT32(env.ttb, SuperHCPU),
        VMSTATE_UINT32(env.tea, SuperHCPU),
        VMSTATE_UINT32(env.tra, SuperHCPU),
        VMSTATE_UINT32(env.expevt, SuperHCPU),
        VMSTATE_UINT32(env.intevt, SuperHCPU),
        VMSTATE_UINT32(env.mmcs_evt_inject, SuperHCPU),
        VMSTATE_UINT32(env.mmcs_regfix_active, SuperHCPU),
        VMSTATE_UINT32(env.mmcs_ilkfix_active, SuperHCPU),
        VMSTATE_UINT32(env.mmcs_ringfix_active, SuperHCPU),
        VMSTATE_UINT32(env.mmcs_kapifix_active, SuperHCPU),
        VMSTATE_UINT32(env.mmcs_cbret_active, SuperHCPU),
        VMSTATE_UINT32(env.mmcs_srvpg_active, SuperHCPU),
        VMSTATE_UINT32(env.mmcs_kslot_active, SuperHCPU),
        VMSTATE_UINT32(env.mmcs_cowfix_active, SuperHCPU),
        /* tlb_t entries: custom info (bitfield layout is host-specific) */
        {
            .name         = "itlb",
            .info         = &vmstate_info_sh4_tlb,
            .size         = sizeof(tlb_t),
            .num          = ITLB_SIZE,
            .flags        = VMS_ARRAY,
            .offset       = offsetof(SuperHCPU, env.itlb),
        },
        {
            .name         = "utlb",
            .info         = &vmstate_info_sh4_tlb,
            .size         = sizeof(tlb_t),
            .num          = UTLB_SIZE,
            .flags        = VMS_ARRAY,
            .offset       = offsetof(SuperHCPU, env.utlb),
        },
        VMSTATE_UINT32(env.lock_addr, SuperHCPU),
        VMSTATE_UINT32(env.lock_value, SuperHCPU),
        VMSTATE_INT32(env.id, SuperHCPU),
        VMSTATE_UINT32(env.features, SuperHCPU),
        VMSTATE_INT32(env.in_sleep, SuperHCPU),
        VMSTATE_POINTER_TEST(env.movcal_backup, SuperHCPU,
                             sh4_movcal_needed,
                             vmstate_info_sh4_movcal, memory_content *),
        VMSTATE_END_OF_LIST()
    },
};

#include "hw/core/sysemu-cpu-ops.h"

static const struct SysemuCPUOps sh4_sysemu_ops = {
    .get_phys_page_debug = superh_cpu_get_phys_page_debug,
};
#endif

#include "hw/core/tcg-cpu-ops.h"

/* L82/S290: the fork's debug handler — the BP observation route
 * (cpu-exec.c's cpu_handle_debug_exception calls this for EVERY
 * EXCP_DEBUG: the breakpoints route HERE, not through
 * superh_cpu_do_interrupt — the S290 validator proved it). */
void mmcs_l86sr_repair(CPUSH4State *env);

static void mmcs_debug_excp_handler(CPUState *cs)
{
    SuperHCPU *cpu = SUPERH_CPU(cs);
    CPUSH4State *env = &cpu->env;
    if (getenv("MMCS_L86SR") && env->pc == 0x90835fc2u) {
        mmcs_l86sr_repair(env);
    }
    if (getenv("MMCS_FSREADBACK")) {
        static const struct { uint32_t pc; const char *nm; } fss[] = {
            { 0x908066b0, "BootLoader_Launch" },
            { 0x90835f14, "ThreadStart" },
            { 0x9082cbf4, "SC_CreateProc" },
            { 0xc00bb4e0, "FileSysMain" },
            { 0x9083e220, "RunApps:CreateEvent" },
            { 0x9083e248, "RunApps:park" },
            { 0x9083e24e, "RunApps:resume" },
            { 0xc00bb514, "FileSysMain:engine" },
            { 0xc00bb5ee, "FileSysMain:signaler" },
            { 0xc00baffe, "OpenEventW(FSReady)" },
            { 0xc00bb00c, "THE SET" },
            { 0x9094c016, "boot-sync wait" },
        };
        for (unsigned i = 0; i < sizeof fss / sizeof fss[0]; i++) {
            if (env->pc == fss[i].pc) {
                fprintf(stderr, "MMCS-FSR: %s REACHED (pc=%08x)\n",
                        fss[i].nm, env->pc);
                break;
            }
        }
    }
}

static const struct TCGCPUOps superh_tcg_ops = {
    .debug_excp_handler = mmcs_debug_excp_handler,
    .initialize = sh4_translate_init,
    .synchronize_from_tb = superh_cpu_synchronize_from_tb,
    .restore_state_to_opc = superh_restore_state_to_opc,

#ifndef CONFIG_USER_ONLY
    .tlb_fill = superh_cpu_tlb_fill,
    .cpu_exec_interrupt = superh_cpu_exec_interrupt,
    .do_interrupt = superh_cpu_do_interrupt,
    .do_unaligned_access = superh_cpu_do_unaligned_access,
    .io_recompile_replay_branch = superh_io_recompile_replay_branch,
#endif /* !CONFIG_USER_ONLY */
};

static void superh_cpu_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);
    SuperHCPUClass *scc = SUPERH_CPU_CLASS(oc);
    ResettableClass *rc = RESETTABLE_CLASS(oc);

    device_class_set_parent_realize(dc, superh_cpu_realizefn,
                                    &scc->parent_realize);

    resettable_class_set_parent_phases(rc, NULL, superh_cpu_reset_hold, NULL,
                                       &scc->parent_phases);

    cc->class_by_name = superh_cpu_class_by_name;
    cc->has_work = superh_cpu_has_work;
    cc->dump_state = superh_cpu_dump_state;
    cc->set_pc = superh_cpu_set_pc;
    cc->get_pc = superh_cpu_get_pc;
    cc->gdb_read_register = superh_cpu_gdb_read_register;
    cc->gdb_write_register = superh_cpu_gdb_write_register;
#ifndef CONFIG_USER_ONLY
    cc->sysemu_ops = &sh4_sysemu_ops;
    dc->vmsd = &vmstate_sh_cpu;
#endif
    cc->disas_set_info = superh_cpu_disas_set_info;

    cc->gdb_num_core_regs = 59;
    cc->tcg_ops = &superh_tcg_ops;
}

#define DEFINE_SUPERH_CPU_TYPE(type_name, cinit, initfn) \
    {                                                    \
        .name = type_name,                               \
        .parent = TYPE_SUPERH_CPU,                       \
        .class_init = cinit,                             \
        .instance_init = initfn,                         \
    }
static const TypeInfo superh_cpu_type_infos[] = {
    {
        .name = TYPE_SUPERH_CPU,
        .parent = TYPE_CPU,
        .instance_size = sizeof(SuperHCPU),
        .instance_align = __alignof(SuperHCPU),
        .instance_init = superh_cpu_initfn,
        .abstract = true,
        .class_size = sizeof(SuperHCPUClass),
        .class_init = superh_cpu_class_init,
    },
    DEFINE_SUPERH_CPU_TYPE(TYPE_SH7750R_CPU, sh7750r_class_init,
                           sh7750r_cpu_initfn),
    DEFINE_SUPERH_CPU_TYPE(TYPE_SH7751R_CPU, sh7751r_class_init,
                           sh7751r_cpu_initfn),
    DEFINE_SUPERH_CPU_TYPE(TYPE_SH7785_CPU, sh7785_class_init,
                           sh7785_cpu_initfn),

};

DEFINE_TYPES(superh_cpu_type_infos)
