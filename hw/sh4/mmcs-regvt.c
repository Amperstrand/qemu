/*
 * MMCS fork (device split lane, 2026-11-25 — peer review M2c, split #2):
 * the REGVT registry virtualization — the L29/L30 hive + API-set surface
 * + the "mmcs/regvt" vmstate, extracted VERBATIM from hw/sh4/mmcs.c
 * (pure code motion, zero behavior change; validated by the
 * byte-stability gates — golden / fidelity-quick / standing-combo —
 * and the restored-snapshot chain). Decode history: S103/S149/S159.
 */
#include "qemu/osdep.h"
#include "hw/sh4/mmcs-regvt.h"
#include "cpu.h"
#include "exec/address-spaces.h"
#include "migration/vmstate.h"
#include "migration/register.h"

/* MMCS fork (L29): MMCS_REGVT — the FileSys api-set REGISTRY methods
 * service. DECODE: fsdmgr's AutoLoadFileSystems mount lane calls its
 * local RegOpenKeyExW wrapper (c02c917c: HKLM=80000002 pool + subkey)
 * through the loader-rebound IAT to k.coredll's RegOpenKeyExW export
 * c0032b78, which dispatches through the FILESYS api-set methods cell
 * [c00835c0]+0x5C (method 23 — the stock kmisc.c NKRegOpenKeyExW index,
 * verbatim on this vendor: 17=RegCloseKey 18=RegCreateKeyExW
 * 21=RegEnumValueW 22=RegEnumKeyExW 23=RegOpenKeyExW 24=RegQueryInfoKeyW
 * 25=RegQueryValueExW 26=RegSetValueExW). The cell ships 0 (the HW bind
 * = filesys's CreateAPISet("FileSys")+RegisterAPISet lane, which needs
 * the registry to finish first — circular in emulation), so the deref
 * faulted at c0032b86 (tea=0x5c) and the vendor exception march killed
 * every relaunch. The service synthesizes the REGISTERED set's registry
 * methods at REGISTER level in helper.c (the FSVT class): the call is
 * answered from a fork-side hive parsed from the REAL default.reg (the
 * default.fdf ground-truth tree: AutoLoad\ObjectStore BootPhase=0
 * Dll=filesys.dll MountAsBootable=1, AutoLoad\Relfsd Dll=relfsd.dll),
 * with HKEY handles 0x8100xxxx indexed into the parsed tree. All
 * accessors return -1 (not found) when REGVT is not armed. */
#define MMCS_REGVT_HKLM 0x80000002u
struct mmcs_regval {
    char *name;
    uint8_t *data;
    uint32_t len;
    uint32_t type;
};
struct mmcs_regkey {
    char *name;                 /* ASCII path component */
    struct mmcs_regkey **sub;
    unsigned nsub, subcap;
    struct mmcs_regval *vals;
    unsigned nvals, valcap;
};
static struct mmcs_regkey *mmcs_regvt_root;   /* HKLM */
static struct mmcs_regkey **mmcs_regvt_handles;
static unsigned mmcs_regvt_nhandles;
static int mmcs_regvt_armed;
static unsigned mmcs_regvt_real_methods;
static uint32_t mmcs_regvt_real[149];
static unsigned mmcs_regvt_real_n;

static struct mmcs_regkey *mmcs_regkey_new(const char *name)
{
    struct mmcs_regkey *k = g_new0(struct mmcs_regkey, 1);
    k->name = g_strdup(name);
    return k;
}

static struct mmcs_regkey *mmcs_regkey_find(struct mmcs_regkey *parent,
                                             const char *name)
{
    for (unsigned i = 0; i < parent->nsub; i++) {
        if (g_ascii_strcasecmp(parent->sub[i]->name, name) == 0) {
            return parent->sub[i];
        }
    }
    return NULL;
}

static struct mmcs_regkey *mmcs_regkey_open1(struct mmcs_regkey *parent,
                                             const char *name)
{
    struct mmcs_regkey *k = mmcs_regkey_find(parent, name);
    if (k) {
        return k;
    }
    if (parent->nsub == parent->subcap) {
        parent->subcap = parent->subcap ? parent->subcap * 2 : 8;
        parent->sub = g_renew(struct mmcs_regkey *, parent->sub,
                              parent->subcap);
    }
    k = mmcs_regkey_new(name);
    parent->sub[parent->nsub++] = k;
    return k;
}

static void mmcs_regkey_setval(struct mmcs_regkey *k, const char *name,
                               uint32_t type, const uint8_t *data,
                               uint32_t len)
{
    struct mmcs_regval *v = NULL;
    for (unsigned i = 0; i < k->nvals; i++) {
        if (g_ascii_strcasecmp(k->vals[i].name, name) == 0) {
            v = &k->vals[i];
            g_free(v->data);
            break;
        }
    }
    if (!v) {
        if (k->nvals == k->valcap) {
            k->valcap = k->valcap ? k->valcap * 2 : 8;
            k->vals = g_renew(struct mmcs_regval, k->vals, k->valcap);
        }
        v = &k->vals[k->nvals++];
        memset(v, 0, sizeof *v);
        v->name = g_strdup(name);
    }
    v->type = type;
    v->data = g_memdup2(data, len ? len : 1);
    v->len = len;
}

/* Parse the .reg (REGEDIT4) ground-truth hive: [HKEY_LOCAL_MACHINE\a\b]
 * sections with "name"="str", "name"=dword:XX, "name"=hex:xx,.. values.
 * The tree IS the real default.fdf content (the hive the object-store
 * registry would serve). */
void mmcs_regvt_load(const char *path)
{
    gchar *txt;
    if (!g_file_get_contents(path, &txt, NULL, NULL)) {
        fprintf(stderr, "MMCS: REGVT %s: cannot read - IGNORED\n", path);
        return;
    }
    mmcs_regvt_root = mmcs_regkey_new("HKLM");
    gchar **lines = g_strsplit(txt, "\n", 0);
    struct mmcs_regkey *cur = NULL;
    for (unsigned i = 0; lines[i]; i++) {
        gchar *ln = lines[i];
        g_strstrip(ln);
        if (!*ln || *ln == ';') {
            continue;
        }
        if (g_str_has_prefix(ln, "[")) {
            gchar *end = strchr(ln, ']');
            if (!end) {
                continue;
            }
            *end = 0;
            const char *pathpart = ln + 1;
            if (g_ascii_strncasecmp(pathpart, "HKEY_LOCAL_MACHINE", 18) == 0) {
                pathpart += 18;
            } else {
                cur = NULL;     /* only the HKLM tree */
                continue;
            }
            cur = mmcs_regvt_root;
            while (*pathpart == '\\') {
                pathpart++;
            }
            while (*pathpart) {
                const char *sep = strchr(pathpart, '\\');
                size_t n = sep ? (size_t)(sep - pathpart) : strlen(pathpart);
                gchar *comp = g_strndup(pathpart, n);
                cur = mmcs_regkey_open1(cur, comp);
                g_free(comp);
                pathpart += n;
                while (*pathpart == '\\') {
                    pathpart++;
                }
            }
            continue;
        }
        if (!cur) {
            continue;
        }
        /* value line: "name"=<data> or @=<data> */
        const char *vp = NULL;
        char name[256];
        if (ln[0] == '@' && (ln[1] == '=' )) {
            name[0] = 0;
            vp = ln + 2;
        } else if (ln[0] == '"') {
            const char *e = ln + 1;
            char *o = name;
            while (*e && *e != '"' && o < name + sizeof name - 1) {
                if (*e == '\\' && e[1]) {
                    e++;
                }
                *o++ = *e++;
            }
            *o = 0;
            if (*e != '"') {
                continue;
            }
            vp = e + 1;
            while (*vp == ' ') {
                vp++;
            }
            if (*vp != '=') {
                continue;
            }
            vp++;
        }
        if (!vp) {
            continue;
        }
        if (g_str_has_prefix(vp, "dword:")) {
            uint32_t d = (uint32_t)strtoul(vp + 6, NULL, 16);
            mmcs_regkey_setval(cur, name, 4, (uint8_t *)&d, 4);
        } else if (g_str_has_prefix(vp, "hex:")) {
            GString *h = g_string_new(NULL);
            for (const char *p = vp + 4; *p; ) {
                if (!g_ascii_isxdigit(*p)) {
                    p++;
                    continue;
                }
                int hi = g_ascii_xdigit_value(*p++);
                int lo = g_ascii_isxdigit(*p) ? g_ascii_xdigit_value(*p++) : 0;
                g_string_append_c(h, (hi << 4) | lo);
            }
            mmcs_regkey_setval(cur, name, 3, (uint8_t *)h->str, h->len);
            g_string_free(h, TRUE);
        } else if (vp[0] == '"') {
            const char *e = vp + 1;
            GString *w = g_string_new(NULL);
            while (*e && *e != '"') {
                if (*e == '\\' && e[1]) {
                    e++;
                }
                gunichar2 u = (gunichar2)(unsigned char)*e++;
                g_string_append_len(w, (const char *)&u, 2);
            }
            gunichar2 z = 0;
            g_string_append_len(w, (const char *)&z, 2);
            mmcs_regkey_setval(cur, name, 1, (uint8_t *)w->str, w->len);
            g_string_free(w, TRUE);
        } else if (g_str_has_prefix(vp, "hex(7):")) {
            /* REG_MULTI_SZ: kept raw */
            GString *h = g_string_new(NULL);
            for (const char *p = vp + 7; *p; ) {
                if (!g_ascii_isxdigit(*p)) {
                    p++;
                    continue;
                }
                int hi = g_ascii_xdigit_value(*p++);
                int lo = g_ascii_isxdigit(*p) ? g_ascii_xdigit_value(*p++) : 0;
                g_string_append_c(h, (hi << 4) | lo);
            }
            mmcs_regkey_setval(cur, name, 7, (uint8_t *)h->str, h->len);
            g_string_free(h, TRUE);
        }
    }
    g_strfreev(lines);
    g_free(txt);
    mmcs_regvt_handles = g_new0(struct mmcs_regkey *, 64);
    mmcs_regvt_nhandles = 64;
    mmcs_regvt_armed = 1;
    fprintf(stderr, "MMCS: REGVT FileSys api-set registry service armed "
            "from %s (HKLM tree, %u top-level subkeys)\n",
            path, mmcs_regvt_root->nsub);
}

/* handle <-> key: 0x8100idx00 | slot — index in the handle table */
static struct mmcs_regkey *mmcs_regvt_h2k(uint32_t hkey)
{
    if (!mmcs_regvt_armed) {
        return NULL;
    }
    if (hkey == MMCS_REGVT_HKLM) {
        return mmcs_regvt_root;
    }
    uint32_t idx = hkey & 0xFFFF;
    if ((hkey & 0xFFFF0000u) != 0x81000000u || idx >= mmcs_regvt_nhandles) {
        return NULL;
    }
    return mmcs_regvt_handles[idx];
}

static uint32_t mmcs_regvt_k2h(struct mmcs_regkey *k)
{
    for (uint32_t i = 0; i < mmcs_regvt_nhandles; i++) {
        if (mmcs_regvt_handles[i] == k) {
            return 0x81000000u | i;
        }
    }
    return 0;
}

/* RegOpenKeyExW: resolve (hkey, subkey) — subkey is UTF-16LE guest
 * memory, already read by the helper hook. Returns the new HKEY or 0. */
uint32_t mmcs_regvt_open(uint32_t hkey, const char *subkey);
uint32_t mmcs_regvt_open(uint32_t hkey, const char *subkey)
{
    struct mmcs_regkey *k = mmcs_regvt_h2k(hkey);
    if (!k) {
        return 0;
    }
    if (!subkey || !*subkey) {
        return hkey;    /* open of the key itself */
    }
    const char *p = subkey;
    while (*p) {
        const char *sep = strchr(p, '\\');
        size_t n = sep ? (size_t)(sep - p) : strlen(p);
        gchar *comp = g_strndup(p, n);
        k = mmcs_regkey_find(k, comp);
        g_free(comp);
        if (!k) {
            return 0;
        }
        p += n;
        while (*p == '\\') {
            p++;
        }
    }
    uint32_t h = mmcs_regvt_k2h(k);
    if (h) {
        return h;
    }
    for (uint32_t i = 0; i < mmcs_regvt_nhandles; i++) {
        if (!mmcs_regvt_handles[i]) {
            mmcs_regvt_handles[i] = k;
            return 0x81000000u | i;
        }
    }
    return 0;
}

/* RegQueryValueExW: fills type/data-len/data. Returns 0 on hit,
 * 2 (ERROR_FILE_NOT_FOUND) when the value does not exist. */
uint32_t mmcs_regvt_query(uint32_t hkey, const char *name,
                          uint32_t *type, uint32_t *len,
                          const uint8_t **data);
uint32_t mmcs_regvt_query(uint32_t hkey, const char *name,
                          uint32_t *type, uint32_t *len,
                          const uint8_t **data)
{
    struct mmcs_regkey *k = mmcs_regvt_h2k(hkey);
    if (!k) {
        return 2;
    }
    if (!name || !*name) {
        /* default value: not present in the tree ground truth */
        return 2;
    }
    for (unsigned i = 0; i < k->nvals; i++) {
        struct mmcs_regval *v = &k->vals[i];
        if (g_ascii_strcasecmp(v->name, name) == 0) {
            if (type) {
                *type = v->type;
            }
            if (len) {
                *len = v->len;
            }
            if (data) {
                *data = v->data;
            }
            return 0;
        }
    }
    return 2;
}

/* RegEnumKeyExW: idx-th subkey name (ASCII; caller widens it). */
int mmcs_regvt_enum_key(uint32_t hkey, uint32_t idx,
                        const char **name);
int mmcs_regvt_enum_key(uint32_t hkey, uint32_t idx,
                        const char **name)
{
    struct mmcs_regkey *k = mmcs_regvt_h2k(hkey);
    if (!k || idx >= k->nsub) {
        return 259;     /* ERROR_NO_MORE_ITEMS */
    }
    *name = k->sub[idx]->name;
    return 0;
}

/* RegEnumValueW: idx-th value. */
int mmcs_regvt_enum_value(uint32_t hkey, uint32_t idx,
                          const char **name, uint32_t *type,
                          uint32_t *len, const uint8_t **data);
int mmcs_regvt_enum_value(uint32_t hkey, uint32_t idx,
                          const char **name, uint32_t *type,
                          uint32_t *len, const uint8_t **data)
{
    struct mmcs_regkey *k = mmcs_regvt_h2k(hkey);
    if (!k || idx >= k->nvals) {
        return 259;
    }
    struct mmcs_regval *v = &k->vals[idx];
    *name = v->name;
    if (type) {
        *type = v->type;
    }
    if (len) {
        *len = v->len;
    }
    if (data) {
        *data = v->data;
    }
    return 0;
}

/* RegQueryInfoKeyW counters. Returns 0 on valid handle. */
int mmcs_regvt_query_info(uint32_t hkey, uint32_t *nsub,
                          uint32_t *maxsub, uint32_t *nvals,
                          uint32_t *maxvalname, uint32_t *maxval);
int mmcs_regvt_query_info(uint32_t hkey, uint32_t *nsub,
                          uint32_t *maxsub, uint32_t *nvals,
                          uint32_t *maxvalname, uint32_t *maxval)
{
    struct mmcs_regkey *k = mmcs_regvt_h2k(hkey);
    if (!k) {
        return 6;       /* ERROR_INVALID_HANDLE */
    }
    *nsub = k->nsub;
    *nvals = k->nvals;
    uint32_t ms = 0, mv = 0, mm = 0;
    for (unsigned i = 0; i < k->nsub; i++) {
        uint32_t l = strlen(k->sub[i]->name);
        if (l > ms) {
            ms = l;
        }
    }
    for (unsigned i = 0; i < k->nvals; i++) {
        uint32_t l = strlen(k->vals[i].name);
        if (l > mv) {
            mv = l;
        }
        if (k->vals[i].len > mm) {
            mm = k->vals[i].len;
        }
    }
    *maxsub = ms;
    *maxvalname = mv;
    *maxval = mm;
    return 0;
}

/* RegSetValueExW: apply into the fork tree (RAM-only). */
void mmcs_regvt_set(uint32_t hkey, const char *name, uint32_t type,
                    const uint8_t *data, uint32_t len);
void mmcs_regvt_set(uint32_t hkey, const char *name, uint32_t type,
                    const uint8_t *data, uint32_t len)
{
    struct mmcs_regkey *k = mmcs_regvt_h2k(hkey);
    if (!k) {
        return;
    }
    mmcs_regkey_setval(k, name && *name ? name : "(default)", type, data, len);
}

int mmcs_regvt_is_armed(void);
int mmcs_regvt_is_armed(void)
{
    return mmcs_regvt_armed;
}

/* MMCS fork (L29 v2): synthesize the REGISTERED FileSys api set — a
 * methods table + per-API `trapa #0x73` stubs carved in the FSVT page
 * (phys 0x1F020400 table / 0x1F020800 stubs, P1 0x9F02....), bound
 * into the cell [c00835c0] AT FIRST FAULT (the loader's CopyRegions is
 * long done by then — the L28 seed-time binds were re-zeroed, fault
 * -time writes survive). The stubs raise TRA=0x1CC with the full
 * calling convention intact (r4-r7 + stack args at [r15+16..]); the
 * helper.c trapa hook answers from the hive and returns to pr. The
 * FS methods (0xb4/0xb8/0xd0/0xd4) point straight at fsdmgr's
 * FSINT_* implementations; unknown methods at the existing all-stub
 * (mov #-1,r0; rts) = the guarded-failure path of an unregistered
 * optional method. */
#define MMCS_REGVT_TABLE_PA   (MMCS_FSVT_PAGE + 0x400)
#define MMCS_REGVT_TABLE_P1   (MMCS_FSVT_P1 + 0x400)
#define MMCS_REGVT_STUBS_PA   (MMCS_FSVT_PAGE + 0x800)
#define MMCS_REGVT_STUBS_P1   (MMCS_FSVT_P1 + 0x800)
#define MMCS_REGVT_NMETHODS   152   /* 149 real entries + margin */
/* the registry method slots (stock kmisc.c numbering) */
static const struct {
    uint16_t off;       /* byte offset in the methods table */
} mmcs_regvt_methods[] = {
    { 17 * 4 },         /* RegCloseKey    */
    { 18 * 4 },         /* RegCreateKeyExW */
    { 21 * 4 },         /* RegEnumValueW  */
    { 22 * 4 },         /* RegEnumKeyExW  */
    { 23 * 4 },         /* RegOpenKeyExW  */
    { 24 * 4 },         /* RegQueryInfoKeyW */
    { 25 * 4 },         /* RegQueryValueExW */
    { 26 * 4 },         /* RegSetValueExW  */
};
static const struct { uint16_t off; uint32_t fn; } mmcs_regvt_fs[] = {
    { 0xb4, 0xc02c8ca4 },   /* FSINT_RegisterAFSEx  */
    { 0xb8, 0xc02c8db0 },   /* FSINT_DeregisterAFS  */
    { 0xd0, 0xc02c8c60 },   /* FSINT_RegisterAFSName */
    { 0xd4, 0xc02c8e50 },   /* FSINT_DeregisterAFSName */
};

/* the stub target for a byte offset into the methods table (0 when
 * the offset has no entry — the caller falls to the all-stub). */
uint32_t mmcs_regvt_method(uint32_t off);
uint32_t mmcs_regvt_method(uint32_t off)
{
    if (!mmcs_regvt_armed) {
        return 0;
    }
    for (unsigned i = 0; i < ARRAY_SIZE(mmcs_regvt_fs); i++) {
        if (mmcs_regvt_fs[i].off == off) {
            return mmcs_regvt_fs[i].fn;
        }
    }
    for (unsigned i = 0; i < ARRAY_SIZE(mmcs_regvt_methods); i++) {
        if (mmcs_regvt_methods[i].off == off) {
            return MMCS_REGVT_STUBS_P1 + 8 * i;
        }
    }
    /* L30: the REAL vendor methods routed into the table at bind time
     * (immune to the cell flip — the register-level re-drive uses the
     * same target the table holds). */
    if ((off & 3) == 0 && off < 4 * mmcs_regvt_real_n) {
        return mmcs_regvt_real[off / 4];
    }
    return 0;
}

/* one-shot: build table+stubs, bind the cell. Needs the CPU for the
 * softmmu write of the cell (k.coredll RW page c0083000). */
int mmcs_regvt_bind(CPUState *cs);
int mmcs_regvt_bind(CPUState *cs)
{
    static int done;
    if (done || !mmcs_regvt_armed) {
        return done;
    }
    done = 1;
    /* all-stub fill first (every unknown method = the guarded -1) */
    for (unsigned i = 0; i < MMCS_REGVT_NMETHODS; i++) {
        uint32_t v = MMCS_FSVT_STUB;
        cpu_physical_memory_write(MMCS_REGVT_TABLE_PA + 4 * i, &v, 4);
    }
    for (unsigned i = 0; i < ARRAY_SIZE(mmcs_regvt_fs); i++) {
        uint32_t v = mmcs_regvt_fs[i].fn;
        cpu_physical_memory_write(MMCS_REGVT_TABLE_PA + mmcs_regvt_fs[i].off,
                                  &v, 4);
    }
    for (unsigned i = 0; i < ARRAY_SIZE(mmcs_regvt_methods); i++) {
        /* NB: trapa is 0xC3nn — the L20-era REGFIX planted 0xC771 (a
         * MOVA!) as its "trapa #0x71", so that hook never fired at
         * all (the "fsdmgr bypasses the filesys stub" boundary). */
        uint32_t code[2] = { 0xC373, 0x00090009 };  /* trapa #0x73; nop;nop */
        uint32_t v = MMCS_REGVT_STUBS_P1 + 8 * i;
        cpu_physical_memory_write(MMCS_REGVT_TABLE_PA + mmcs_regvt_methods[i].off,
                                  &v, 4);
        cpu_physical_memory_write(MMCS_REGVT_STUBS_PA + 8 * i, code,
                                  sizeof code);
    }
    /* MMCS fork (L30): route every remaining method to the REAL
     * implementation from the vendor's own CreateAPISet("FileSys")
     * methods array — the 149-entry literal block in filesys .text at
     * c00b1358 (XIP): GetFileAttributesW +0x1c -> c00cb8c4, Signal-
     * Started +0x108 -> c00badf0 (the internal-event SET that wakes
     * the signaler's post-FSReady wait — the kernel's pSignalStarted
     * = coredll ordinal 639 = this method), etc. NULL entries keep
     * the all-stub (-1) = the unregistered-optional-method semantics
     * (the real table ships NULLs too, e.g. method 84). The registry
     * stubs above and the FSINT_* overrides stay (both proven). */
    {
        const uint32_t tbl_va = 0xc00b1358;
        const struct {
            uint32_t va, size, rom, flags, off;
        } *row = mmcs_srvt_find(tbl_va);
        if (row) {
            uint32_t real[149];
            if (address_space_read(&address_space_memory,
                                   mmcs_rom_pa(row->rom)
                                   + (tbl_va - row->va),
                                   MEMTXATTRS_UNSPECIFIED,
                                   real, sizeof real) == MEMTX_OK) {
                unsigned nreal = 0;
                memcpy(mmcs_regvt_real, real, sizeof real);
                mmcs_regvt_real_n = ARRAY_SIZE(real);
                for (unsigned i = 0; i < ARRAY_SIZE(real)
                                && 4 * i < 4 * MMCS_REGVT_NMETHODS; i++) {
                    uint32_t off = 4 * i, v = real[i];
                    unsigned k;
                    bool synth = false;
                    for (k = 0; k < ARRAY_SIZE(mmcs_regvt_methods); k++) {
                        if (mmcs_regvt_methods[k].off == off) {
                            synth = true;
                        }
                    }
                    for (k = 0; k < ARRAY_SIZE(mmcs_regvt_fs); k++) {
                        if (mmcs_regvt_fs[k].off == off) {
                            synth = true;
                        }
                    }
                    if (synth || !v) {
                        continue;
                    }
                    cpu_physical_memory_write(MMCS_REGVT_TABLE_PA + off,
                                              &v, 4);
                    nreal++;
                }
                mmcs_regvt_real_methods = nreal;
            }
        }
    }
    uint32_t tbl = MMCS_REGVT_TABLE_P1;
    cpu_memory_rw_debug(cs, 0xc00835c0, (uint8_t *)&tbl, 4, 1);
    {
        uint32_t chk[2] = { 0, 0 };
        cpu_physical_memory_read(MMCS_REGVT_STUBS_PA, chk, 8);
        uint32_t cell = 0;
        cpu_memory_rw_debug(cs, 0xc00835c0, (uint8_t *)&cell, 4, 0);
        fprintf(stderr, "MMCS: REGVT FileSys api-set cell [c00835c0] bound "
                        "-> methods table P1 %08x (8 registry stubs + %u "
                        "FSINT + %u real vendor methods + all-stub); "
                        "stub[0] chk=%04x cell=%08x\n",
                tbl, (unsigned)ARRAY_SIZE(mmcs_regvt_fs),
                mmcs_regvt_real_methods, chk[0], cell);
    }
    return 1;
}

uint32_t mmcs_regvt_stubs_p1(void);
uint32_t mmcs_regvt_stubs_p1(void)
{
    return MMCS_REGVT_STUBS_P1;
}

/* Guest string read for the REGVT hooks: cpu_memory_rw_debug translates
 * through the GUEST UTLB, but the servant module pages (fsdmgr/filesys
 * .text string pools — the value-name literals the mount lane passes)
 * are served QEMU-side by SRVPG/IATFIX without guest UTLB entries, so
 * the debug read returns zeros. Fall back to the SRP2 manifest: XIP
 * sections read straight from flash, non-XIP from the seeded scratch. */
int mmcs_regvt_read(CPUState *cs, uint32_t va, uint8_t *buf, int len);
int mmcs_regvt_read(CPUState *cs, uint32_t va, uint8_t *buf, int len)
{
    if (va < 0x10000 || va >= 0xFFFF0000u) {
        return -1;
    }
    if (cpu_memory_rw_debug(cs, va, buf, len, 0) == 0
        && (buf[0] | buf[1])) {
        return 0;
    }
    const void *sec = mmcs_srvt_find(va & ~0xFFFu);
    if (!sec) {
        sec = mmcs_srvt_find(va);
    }
    if (sec) {
        const struct { uint32_t va, size, rom, flags, off; } *s = sec;
        if (s->off == 0xffffffffu) {
            /* XIP: the flash bytes at the manifest rom PA */
            uint32_t pa = mmcs_rom_pa(s->rom) + (va - s->va);
            if (va >= s->va && va + len <= s->va + s->size) {
                cpu_physical_memory_read(pa, buf, len);
                return 0;
            }
        } else {
            uint32_t o = va - s->va;
            if (va >= s->va && o + len <= s->size) {
                memcpy(buf, mmcs_srvt_blob + s->off + o, len);
                return 0;
            }
        }
    }
    /* P1 kernel ROM identity fallback */
    if (va >= 0x90800000 && va < 0x97000000) {
        cpu_physical_memory_read(va - 0x80000000, buf, len);
        return 0;
    }
    return -1;
}

/* ---- "mmcs/regvt": the runtime-mutated registry hive tree ---- */
#define MMCS_SNAP_RK 8192
#define MMCS_SNAP_RV 16384
#define MMCS_SNAP_RN (256 * 1024)
#define MMCS_SNAP_RD (1024 * 1024)
struct MmcsRegvtSnap {
    int32_t armed;
    int32_t nrk, nrv, nname, ndata;
    int32_t rk_parent[MMCS_SNAP_RK];
    int32_t rk_nameoff[MMCS_SNAP_RK];
    int32_t rv_key[MMCS_SNAP_RV];
    int32_t rv_nameoff[MMCS_SNAP_RV];
    int32_t rv_type[MMCS_SNAP_RV];
    int32_t rv_len[MMCS_SNAP_RV];
    int32_t rv_dataoff[MMCS_SNAP_RV];
    uint8_t names[MMCS_SNAP_RN];
    uint8_t data[MMCS_SNAP_RD];
    int32_t hkeys[64];
};
static struct MmcsRegvtSnap mmcs_regvt_snap;

static int mmcs_regvt_snap_name(struct MmcsRegvtSnap *s, const char *n)
{
    size_t l = strlen(n) + 1;
    if (s->nname + l > MMCS_SNAP_RN) {
        return -1;
    }
    int off = s->nname;
    memcpy(s->names + s->nname, n, l);
    s->nname += l;
    return off;
}

static int mmcs_regvt_flatten(struct MmcsRegvtSnap *s,
                              struct mmcs_regkey *k, int32_t parent)
{
    if (s->nrk >= MMCS_SNAP_RK) {
        return -1;
    }
    int32_t idx = s->nrk++;
    int no = mmcs_regvt_snap_name(s, k->name);
    if (no < 0) {
        return -1;
    }
    s->rk_parent[idx] = parent;
    s->rk_nameoff[idx] = no;
    for (unsigned i = 0; i < k->nsub; i++) {
        if (mmcs_regvt_flatten(s, k->sub[i], idx)) {
            return -1;
        }
    }
    for (unsigned i = 0; i < k->nvals; i++) {
        struct mmcs_regval *v = &k->vals[i];
        if (s->nrv >= MMCS_SNAP_RV || v->len > MMCS_SNAP_RD
            || s->ndata + v->len > MMCS_SNAP_RD) {
            return -1;
        }
        int vo = mmcs_regvt_snap_name(s, v->name ? v->name : "");
        if (vo < 0) {
            return -1;
        }
        s->rv_key[s->nrv] = idx;
        s->rv_nameoff[s->nrv] = vo;
        s->rv_type[s->nrv] = v->type;
        s->rv_len[s->nrv] = v->len;
        s->rv_dataoff[s->nrv] = s->ndata;
        memcpy(s->data + s->ndata, v->data, v->len ? v->len : 0);
        s->ndata += v->len;
        s->nrv++;
    }
    return 0;
}

static void mmcs_regkey_free(struct mmcs_regkey *k)
{
    for (unsigned i = 0; i < k->nsub; i++) {
        mmcs_regkey_free(k->sub[i]);
    }
    g_free(k->sub);
    for (unsigned i = 0; i < k->nvals; i++) {
        g_free(k->vals[i].name);
        g_free(k->vals[i].data);
    }
    g_free(k->vals);
    g_free(k->name);
    g_free(k);
}

static int mmcs_regvt_pre_save(void *opaque)
{
    struct MmcsRegvtSnap *s = opaque;
    memset(s, 0, sizeof *s);
    for (unsigned i = 0; i < 64; i++) {
        s->hkeys[i] = -1;
    }
    s->armed = mmcs_regvt_armed;
    if (!mmcs_regvt_armed || !mmcs_regvt_root) {
        return 0;
    }
    if (mmcs_regvt_flatten(s, mmcs_regvt_root, -1)) {
        fprintf(stderr, "MMCS-SNAP: REGVT tree exceeds snapshot caps "
                "(keys=%d vals=%d names=%d data=%d) - SAVE FAILED\n",
                s->nrk, s->nrv, s->nname, s->ndata);
        return -1;
    }
    /* second pass: map live key pointers to saved indices by
     * re-walking the same DFS order (flatten order == visit order) */
    {
        struct mmcs_regkey *stack_order[MMCS_SNAP_RK];
        int n = 0;
        /* iterative DFS matching mmcs_regvt_flatten's order */
        struct mmcs_regkey *root = mmcs_regvt_root;
        struct { struct mmcs_regkey *k; unsigned next_sub; } st[512];
        int sp = 0;
        st[sp].k = root;
        st[sp].next_sub = 0;
        stack_order[n++] = root;
        while (sp >= 0 && n < MMCS_SNAP_RK) {
            struct mmcs_regkey *k = st[sp].k;
            if (st[sp].next_sub < k->nsub) {
                struct mmcs_regkey *c = k->sub[st[sp].next_sub++];
                st[++sp].k = c;
                st[sp].next_sub = 0;
                stack_order[n++] = c;
            } else {
                sp--;
            }
        }
        for (unsigned i = 0; i < mmcs_regvt_nhandles && i < 64; i++) {
            if (!mmcs_regvt_handles[i]) {
                continue;
            }
            for (int j = 0; j < n; j++) {
                if (stack_order[j] == mmcs_regvt_handles[i]) {
                    s->hkeys[i] = j;
                    break;
                }
            }
        }
    }
    return 0;
}

static int mmcs_regvt_post_load(void *opaque, int version_id)
{
    struct MmcsRegvtSnap *s = opaque;
    if (!s->armed || s->nrk <= 0) {
        return 0;
    }
    /* rebuild the tree over the env-loaded one (same env re-parses the
     * same .reg file; the saved tree carries the runtime mutations) */
    struct mmcs_regkey **keys = g_new0(struct mmcs_regkey *, s->nrk);
    for (int i = 0; i < s->nrk; i++) {
        keys[i] = mmcs_regkey_new((const char *)s->names + s->rk_nameoff[i]);
    }
    for (int i = 0; i < s->nrv; i++) {
        struct mmcs_regkey *k = keys[s->rv_key[i]];
        mmcs_regkey_setval(k, (const char *)s->names + s->rv_nameoff[i],
                           s->rv_type[i], s->data + s->rv_dataoff[i],
                           s->rv_len[i]);
    }
    for (int i = 1; i < s->nrk; i++) {        /* key 0 == root */
        struct mmcs_regkey *p = keys[s->rk_parent[i]];
        if (p->nsub == p->subcap) {
            p->subcap = p->subcap ? p->subcap * 2 : 8;
            p->sub = g_renew(struct mmcs_regkey *, p->sub, p->subcap);
        }
        p->sub[p->nsub++] = keys[i];
    }
    if (mmcs_regvt_root) {
        mmcs_regkey_free(mmcs_regvt_root);
    }
    mmcs_regvt_root = keys[0];
    if (mmcs_regvt_handles) {
        g_free(mmcs_regvt_handles);
    }
    mmcs_regvt_handles = g_new0(struct mmcs_regkey *, 64);
    mmcs_regvt_nhandles = 64;
    for (unsigned i = 0; i < 64; i++) {
        if (s->hkeys[i] >= 0 && s->hkeys[i] < s->nrk) {
            mmcs_regvt_handles[i] = keys[s->hkeys[i]];
        }
    }
    mmcs_regvt_armed = 1;
    g_free(keys);
    fprintf(stderr, "MMCS-SNAP: REGVT hive restored (%d keys, %d values)\n",
            s->nrk, s->nrv);
    return 0;
}

static const VMStateDescription vmstate_mmcs_regvt = {
    .name = "mmcs/regvt",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = mmcs_regvt_pre_save,
    .post_load = mmcs_regvt_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_INT32(armed, struct MmcsRegvtSnap),
        VMSTATE_INT32(nrk, struct MmcsRegvtSnap),
        VMSTATE_INT32(nrv, struct MmcsRegvtSnap),
        VMSTATE_INT32(nname, struct MmcsRegvtSnap),
        VMSTATE_INT32(ndata, struct MmcsRegvtSnap),
        VMSTATE_INT32_ARRAY(rk_parent, struct MmcsRegvtSnap, MMCS_SNAP_RK),
        VMSTATE_INT32_ARRAY(rk_nameoff, struct MmcsRegvtSnap, MMCS_SNAP_RK),
        VMSTATE_INT32_ARRAY(rv_key, struct MmcsRegvtSnap, MMCS_SNAP_RV),
        VMSTATE_INT32_ARRAY(rv_nameoff, struct MmcsRegvtSnap, MMCS_SNAP_RV),
        VMSTATE_INT32_ARRAY(rv_type, struct MmcsRegvtSnap, MMCS_SNAP_RV),
        VMSTATE_INT32_ARRAY(rv_len, struct MmcsRegvtSnap, MMCS_SNAP_RV),
        VMSTATE_INT32_ARRAY(rv_dataoff, struct MmcsRegvtSnap, MMCS_SNAP_RV),
        VMSTATE_UINT8_ARRAY(names, struct MmcsRegvtSnap, MMCS_SNAP_RN),
        VMSTATE_UINT8_ARRAY(data, struct MmcsRegvtSnap, MMCS_SNAP_RD),
        VMSTATE_INT32_ARRAY(hkeys, struct MmcsRegvtSnap, 64),
        VMSTATE_END_OF_LIST()
    }
};

/* the vmstate hook (called from mmcs.c's mmcs_vmstate_register — the
 * registration position between the machine vmsd and the helper vmsd
 * is preserved) */
void mmcs_regvt_vmstate_register(void)
{
    vmstate_register(NULL, 0, &vmstate_mmcs_regvt, &mmcs_regvt_snap);
}
