/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <uapi/asm-generic/errno.h>
#include <pgtable.h>
#include <kpmalloc.h>
#include <linux/err.h>
#include <linux/string.h>
#include <symbol.h>
#include <kallsyms.h>
#include <cache.h>
#include <common.h>
#include <linux/fs.h>
#include <uapi/linux/fs.h>
#include <hotpatch.h>
#include <asm/current.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <hook.h>

#include "module.h"
#include "relo.h"

#define SZ_128M 0x08000000

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (typeof(x))(a)-1)

#define align(X) ALIGN(X, page_size)

#define elf_check_arch(x) ((x)->e_machine == EM_AARCH64)

#define ARCH_SHF_SMALL 0

static inline bool strstarts(const char *str, const char *prefix)
{
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

static char *next_string(char *string, unsigned long *secsize)
{
    while (string[0]) {
        string++;
        if ((*secsize)-- <= 1) return 0;
    }
    while (!string[0]) {
        string++;
        if ((*secsize)-- <= 1) return 0;
    }
    return string;
}

/* Update size with this section: return offset. */
static long get_offset(struct module *mod, unsigned int *size, Elf_Shdr *sechdr, unsigned int section)
{
    long ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
    *size = ret + sechdr->sh_size;
    return ret;
}

static char *get_next_modinfo(const struct load_info *info, const char *tag, char *prev)
{
    char *p;
    unsigned int taglen = strlen(tag);
    Elf_Shdr *infosec = &info->sechdrs[info->index.info];
    unsigned long size = infosec->sh_size;
    char *modinfo = (char *)info->hdr + infosec->sh_offset;
    if (prev) {
        size -= prev - modinfo;
        modinfo = next_string(prev, &size);
    }
    for (p = modinfo; p; p = next_string(p, &size)) {
        if (strncmp(p, tag, taglen) == 0 && p[taglen] == '=') return p + taglen + 1;
    }
    return 0;
}

static char *get_modinfo(const struct load_info *info, const char *tag)
{
    return get_next_modinfo(info, tag, 0);
}

static int find_sec(const struct load_info *info, const char *name)
{
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if ((shdr->sh_flags & SHF_ALLOC) && strcmp(info->secstrings + shdr->sh_name, name) == 0) return i;
    }
    return 0;
}

static void *get_sh_base(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    void *addr = (void *)info->hdr + infosec->sh_offset;
    return addr;
}

static unsigned long get_sh_size(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    return infosec->sh_entsize;
}

static void layout_sections(struct module *mod, struct load_info *info)
{
    static unsigned long const masks[][2] = {
        /* NOTE: all executable code must be the first section in this array; otherwise modify the text_size finder in the two loops below */
        { SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
        { SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
        { SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
        { ARCH_SHF_SMALL | SHF_ALLOC, 0 }
    };

    for (int i = 0; i < info->hdr->e_shnum; i++)
        info->sechdrs[i].sh_entsize = ~0UL;

    // todo: tslf alloc all rwx and not page aligned
    for (int m = 0; m < sizeof(masks) / sizeof(masks[0]); ++m) {
        for (int i = 0; i < info->hdr->e_shnum; ++i) {
            Elf_Shdr *s = &info->sechdrs[i];
            if ((s->sh_flags & masks[m][0]) != masks[m][0] || (s->sh_flags & masks[m][1]) || s->sh_entsize != ~0UL)
                continue;
            s->sh_entsize = get_offset(mod, &mod->size, s, i);
            // const char *sname = info->secstrings + s->sh_name;
        }
        switch (m) {
        case 0: /* executable */
            mod->size = align(mod->size);
            mod->text_size = mod->size;
            break;
        case 1: /* RO: text and ro-data */
            mod->size = align(mod->size);
            mod->ro_size = mod->size;
            break;
        case 2:
            break;
        case 3: /* whole */
            mod->size = align(mod->size);
            break;
        }
    }
}

static bool is_core_symbol(const Elf_Sym *src, const Elf_Shdr *sechdrs, unsigned int shnum)
{
    const Elf_Shdr *sec;
    if (src->st_shndx == SHN_UNDEF || src->st_shndx >= shnum || !src->st_name) return false;
    sec = sechdrs + src->st_shndx;
    if (!(sec->sh_flags & SHF_ALLOC) || !(sec->sh_flags & SHF_EXECINSTR)) return false;
    return true;
}

/* Change all symbols so that st_value encodes the pointer directly. */
static int simplify_symbols(struct module *mod, const struct load_info *info)
{
    Elf_Shdr *symsec = &info->sechdrs[info->index.sym];
    Elf_Sym *sym = (void *)symsec->sh_addr;
    unsigned long secbase;
    unsigned int i;
    int ret = 0;

    for (i = 1; i < symsec->sh_size / sizeof(Elf_Sym); i++) {
        const char *name = info->strtab + sym[i].st_name;
        switch (sym[i].st_shndx) {
        case SHN_COMMON:
            if (!strncmp(name, "__gnu_lto", 9)) {
                logkd("Please compile with -fno-common\n");
                ret = -ENOEXEC;
            }
            break;
        case SHN_ABS:
            break;
        case SHN_UNDEF:
            unsigned long addr = symbol_lookup_name(name);
            // kernel symbol cause overflow in relocation
            // if (!addr) addr = kallsyms_lookup_name(name);
            if (!addr) {
                logke("unknown symbol: %s\n", name);
                ret = -ENOENT;
                break;
            }
            sym[i].st_value = addr;
            break;
        default:
            secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
            sym[i].st_value += secbase;
            break;
        }
    }
    return ret;
}

static int apply_relocations(struct module *mod, const struct load_info *info)
{
    int rc = 0;
    unsigned int i;
    for (i = 1; i < info->hdr->e_shnum; i++) {
        unsigned int infosec = info->sechdrs[i].sh_info;
        if (infosec >= info->hdr->e_shnum) continue;
        if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC)) continue;
        if (info->sechdrs[i].sh_type == SHT_REL) {
            rc = apply_relocate(info->sechdrs, info->strtab, info->index.sym, i, mod);
        } else if (info->sechdrs[i].sh_type == SHT_RELA) {
            rc = apply_relocate_add(info->sechdrs, info->strtab, info->index.sym, i, mod);
        }
        if (rc < 0) break;
    }
    return rc;
}

// todo: free .strtab and .symtab after relocation
static void layout_symtab(struct module *mod, struct load_info *info)
{
    Elf_Shdr *symsect = info->sechdrs + info->index.sym;
    Elf_Shdr *strsect = info->sechdrs + info->index.str;
    const Elf_Sym *src;
    unsigned int i, nsrc, ndst, strtab_size = 0;

    /* Put symbol section at end of module. */
    symsect->sh_flags |= SHF_ALLOC;
    symsect->sh_entsize = get_offset(mod, &mod->size, symsect, info->index.sym);

    src = (void *)info->hdr + symsect->sh_offset;
    nsrc = symsect->sh_size / sizeof(*src);

    /* strtab always starts with a nul, so offset 0 is the empty string. */
    strtab_size = 1;
    /* Compute total space required for the core symbols' strtab. */
    for (ndst = i = 0; i < nsrc; i++) {
        if (i == 0 || is_core_symbol(src + i, info->sechdrs, info->hdr->e_shnum)) {
            strtab_size += strlen(&info->strtab[src[i].st_name]) + 1;
            ndst++;
        }
    }

    /* Append room for core symbols at end. */
    info->symoffs = ALIGN(mod->size, symsect->sh_addralign ?: 1);
    info->stroffs = mod->size = info->symoffs + ndst * sizeof(Elf_Sym);
    mod->size += strtab_size;

    /* Put string table section at end of module. */
    strsect->sh_flags |= SHF_ALLOC;
    strsect->sh_entsize = get_offset(mod, &mod->size, strsect, info->index.str);
}

static int rewrite_section_headers(struct load_info *info)
{
    info->sechdrs[0].sh_addr = 0;
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (shdr->sh_type != SHT_NOBITS && info->len < shdr->sh_offset + shdr->sh_size) {
            return -ENOEXEC;
        }
        /* Mark all sections sh_addr with their address in the temporary image. */
        shdr->sh_addr = (size_t)info->hdr + shdr->sh_offset;
    }
    return 0;
}

static int move_module(struct module *mod, struct load_info *info)
{
    // todo:
    logki("alloc module size: %llx\n", mod->size);
    mod->start = kp_malloc_exec(mod->size);
    if (!mod->start) {
        return -ENOMEM;
    }
    memset(mod->start, 0, mod->size);

    /* Transfer each section which specifies SHF_ALLOC */
    logkd("final section addresses:\n");

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        void *dest;
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (!(shdr->sh_flags & SHF_ALLOC)) continue;

        dest = mod->start + shdr->sh_entsize;
        const char *sname = info->secstrings + shdr->sh_name;

        logkd("    %s %llx %llx\n", sname, dest, shdr->sh_size);

        if (shdr->sh_type != SHT_NOBITS) memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);

        shdr->sh_addr = (unsigned long)dest;

        if (!mod->init && !strcmp(".kpm.init", sname)) mod->init = (mod_initcall_t *)dest;

        if (!strcmp(".kpm.ctl0", sname)) mod->ctl0 = (mod_ctl0call_t *)dest;
        if (!strcmp(".kpm.ctl1", sname)) mod->ctl1 = (mod_ctl1call_t *)dest;

        if (!mod->exit && !strcmp(".kpm.exit", sname)) mod->exit = (mod_exitcall_t *)dest;

        if (!mod->info.base && !strcmp(".kpm.info", sname)) mod->info.base = (const char *)dest;
    }
    mod->info.name = info->info.name - info->info.base + mod->info.base;
    mod->info.version = info->info.version - info->info.base + mod->info.base;

    if (info->info.license) mod->info.license = info->info.license - info->info.base + mod->info.base;
    if (info->info.author) mod->info.author = info->info.author - info->info.base + mod->info.base;
    if (info->info.description) mod->info.description = info->info.description - info->info.base + mod->info.base;

    return 0;
}

static int setup_load_info(struct load_info *info)
{
    int rc = 0;
    info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
    info->secstrings = (void *)info->hdr + info->sechdrs[info->hdr->e_shstrndx].sh_offset;

    if ((rc = rewrite_section_headers(info))) {
        logke("rewrite section error\n");
        return rc;
    }

    if (!find_sec(info, ".kpm.init") || !find_sec(info, ".kpm.exit")) {
        logke("no .kpm.init or .kpm.exit section\n");
        return -ENOEXEC;
    }

    info->index.info = find_sec(info, ".kpm.info");
    if (!info->index.info) {
        logke("no .kpm.info section\n");
        return -ENOEXEC;
    }
    info->info.base = get_sh_base(info, ".kpm.info");
    info->info.size = get_sh_size(info, ".kpm.info");

    const char *name = get_modinfo(info, "name");
    if (!name) {
        logke("module name not found\n");
        return -ENOEXEC;
    }
    info->info.name = name;
    logkd("loading module: \n");
    logkd("    name: %s\n", name);

    const char *version = get_modinfo(info, "version");
    if (!version) {
        logkd("module version not found\n");
        return -ENOEXEC;
    }
    info->info.version = version;
    logkd("    version: %s\n", version);

    const char *license = get_modinfo(info, "license");
    info->info.license = license;
    logkd("    license: %s\n", license);

    const char *author = get_modinfo(info, "author");
    info->info.author = author;
    logkd("    author: %s\n", author);
    const char *description = get_modinfo(info, "description");
    info->info.description = description;
    logkd("    description: %s\n", description);

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        if (info->sechdrs[i].sh_type == SHT_SYMTAB) {
            info->index.sym = i;
            info->index.str = info->sechdrs[i].sh_link;
            info->strtab = (char *)info->hdr + info->sechdrs[info->index.str].sh_offset;
            break;
        }
    }

    if (info->index.sym == 0) {
        logkd("module has no symbols (stripped?)\n");
        return -ENOEXEC;
    }
    return 0;
}

static int elf_header_check(struct load_info *info)
{
    if (info->len <= sizeof(*(info->hdr))) return -ENOEXEC;
    if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) || info->hdr->e_type != ET_REL || !elf_check_arch(info->hdr) ||
        info->hdr->e_shentsize != sizeof(Elf_Shdr))
        return -ENOEXEC;
    if (info->hdr->e_shoff >= info->len || (info->hdr->e_shnum * sizeof(Elf_Shdr) > info->len - info->hdr->e_shoff))
        return -ENOEXEC;
    return 0;
}

struct module modules = { 0 };
static spinlock_t module_lock;

static struct module *find_module_locked(const char *name)
{
    struct module *pos;
    list_for_each_entry(pos, &modules.list, list)
    {
        if (!strcmp(name, pos->info.name)) return pos;
    }
    return 0;
}

struct module *find_module(const char *name)
{
    struct module *mod;
    if (!name) return 0;
    list_for_each_entry_rcu(mod, &modules.list, list) {
        if (!strcmp(name, mod->info.name)) return mod;
    }
    return 0;
}

static struct module *module_get_live(const char *name, long *error)
{
    struct module *mod;

    spin_lock(&module_lock);
    mod = find_module_locked(name);
    if (!mod) {
        *error = -ENOENT;
    } else if (!module_lifecycle_try_get_control(
                   &mod->lifecycle, (uintptr_t)current)) {
        *error = -EBUSY;
        mod = 0;
    } else {
        *error = 0;
    }
    spin_unlock(&module_lock);
    return mod;
}

static void module_put(struct module *mod)
{
    spin_lock(&module_lock);
    if (!module_lifecycle_put_control(&mod->lifecycle)) {
        spin_unlock(&module_lock);
        logkfe("module active call underflow: %s\n", mod->info.name);
        return;
    }
    spin_unlock(&module_lock);
}

static int module_wait_idle(struct module *mod)
{
    /* Exit is now outside an RCU read-side section.  Keep the wait bounded:
     * a module callback that does not return must retain its text and make the
     * caller retry unload instead of freezing a CPU or freeing live code. */
    for (unsigned int i = 0; i < 10000000; i++) {
        unsigned int active;
        spin_lock(&module_lock);
        active = mod->lifecycle.active_calls;
        spin_unlock(&module_lock);
        if (!active) return 0;
        asm volatile("yield" ::: "memory");
    }
    return -EBUSY;
}

static void module_destroy(struct module *mod)
{
    if (mod->args) kvfree(mod->args);
    if (mod->ctl_args) kvfree(mod->ctl_args);
    kp_free_exec(mod->start);
    kvfree(mod);
}

static int module_retire(struct module *mod)
{
    if (!kfunc(synchronize_rcu)) return -ENOSYS;
    spin_lock(&module_lock);
    list_del_rcu(&mod->list);
    spin_unlock(&module_lock);
    synchronize_rcu();
    return 0;
}

static long module_call_exit(struct module *mod, void *__user reserved)
{
    for (unsigned int attempt = 0; attempt < 16; attempt++) {
        long rc = (*mod->exit)(reserved);
        if (rc == -(long)HOOK_DEFERRED ||
            rc == -(long)HOOK_READER_BUSY) {
            if (hook_cleanup_pending() && hook_cleanup_drain()) return rc;
            continue;
        }
        if (rc) return rc;
        if (!hook_cleanup_pending()) return 0;
        if (hook_cleanup_drain()) return -EBUSY;
    }
    return -EBUSY;
}

long load_module(const void *data, int len, const char *args, const char *event, void *__user reserved)
{
    struct load_info load_info = { .len = len, .hdr = data };
    struct load_info *info = &load_info;
    long rc = 0;

    if (!hook_management_context_ok()) return -EBUSY;

    if ((rc = elf_header_check(info))) goto out;
    if ((rc = setup_load_info(info))) goto out;

    struct module *mod = (struct module *)vmalloc(sizeof(struct module));
    if (!mod) return -ENOMEM;
    memset(mod, 0, sizeof(struct module));
    module_lifecycle_init(&mod->lifecycle);

    if (args) {
        mod->args = vmalloc(strlen(args) + 1);
        if (!mod->args) {
            rc = -ENOMEM;
            goto free1;
        }
        strcpy(mod->args, args);
    }

    layout_sections(mod, info);
    layout_symtab(mod, info);

    if ((rc = move_module(mod, info))) goto free;
    if ((rc = simplify_symbols(mod, info))) goto free;
    if ((rc = apply_relocations(mod, info))) goto free;

    flush_icache_all();

    /* Reserve the name before init so concurrent loads cannot both publish
     * the same module.  LOADING entries are visible to list/info but reject
     * control and unload until init reaches a terminal state. */
    spin_lock(&module_lock);
    if (find_module_locked(mod->info.name)) {
        spin_unlock(&module_lock);
        logkfd("%s exist\n", mod->info.name);
        rc = -EEXIST;
        goto free;
    }
    INIT_LIST_HEAD(&mod->list);
    list_add_tail_rcu(&mod->list, &modules.list);
    spin_unlock(&module_lock);

    rc = (*mod->init)(mod->args, event, reserved);

    if (!rc) {
        spin_lock(&module_lock);
        module_lifecycle_mark_live(&mod->lifecycle);
        spin_unlock(&module_lock);
        logkfi("[%s] succeed with [%s] \n", mod->info.name, args);
        goto out;
    } else {
        long exit_rc;
        long idle_rc;
        spin_lock(&module_lock);
        mod->lifecycle.init_error = rc;
        spin_unlock(&module_lock);
        logkfi("[%s] failed with [%s] error: %d, try exit ...\n", mod->info.name, args, rc);
        exit_rc = module_call_exit(mod, reserved);
        if (exit_rc) {
            spin_lock(&module_lock);
            module_lifecycle_mark_exit_failed(&mod->lifecycle, exit_rc);
            spin_unlock(&module_lock);
            logkfe("[%s] init rollback failed: %ld; module retained for unload retry\n",
                   mod->info.name, exit_rc);
            goto out;
        }
        if (hook_cleanup_pending()) {
            spin_lock(&module_lock);
            module_lifecycle_mark_exit_failed(&mod->lifecycle, -EBUSY);
            spin_unlock(&module_lock);
            logkfe("[%s] init rollback left deferred hooks; module retained\n",
                   mod->info.name);
            goto out;
        }
        spin_lock(&module_lock);
        module_lifecycle_mark_retiring(&mod->lifecycle);
        spin_unlock(&module_lock);
        idle_rc = module_wait_idle(mod);
        if (idle_rc) {
            spin_lock(&module_lock);
            module_lifecycle_mark_exit_done(&mod->lifecycle);
            mod->lifecycle.exit_error = idle_rc;
            spin_unlock(&module_lock);
            logkfe("[%s] init rollback completed but references remain rc=%ld; module retained\n",
                   mod->info.name, idle_rc);
            goto out;
        }
        idle_rc = module_retire(mod);
        if (idle_rc) {
            spin_lock(&module_lock);
            module_lifecycle_mark_exit_done(&mod->lifecycle);
            mod->lifecycle.exit_error = idle_rc;
            spin_unlock(&module_lock);
            logkfe("[%s] ordinary RCU grace unavailable rc=%ld; module retained\n",
                   mod->info.name, idle_rc);
            goto out;
        }
        module_destroy(mod);
        goto out;
    }

free:
    if (mod->args) kvfree(mod->args);
    kp_free_exec(mod->start);
free1:
    kvfree(mod);
out:
    return rc;
}

long unload_module(const char *name, void *__user reserved)
{
    if (!name) return -EINVAL;
    if (!hook_management_context_ok()) return -EBUSY;
    logkfe("name: %s\n", name);

    long rc = 0;
    enum module_lifecycle_state previous_state;
    bool exit_already_done;

    spin_lock(&module_lock);
    struct module *mod = find_module_locked(name);
    if (!mod) {
        spin_unlock(&module_lock);
        return -ENOENT;
    }

    if (module_lifecycle_is_control_owner(
            &mod->lifecycle, (uintptr_t)current)) {
        spin_unlock(&module_lock);
        return -EBUSY;
    }

    if (!module_lifecycle_begin_unload(&mod->lifecycle, &previous_state,
                                       &exit_already_done)) {
        spin_unlock(&module_lock);
        return -EBUSY;
    }
    spin_unlock(&module_lock);

    rc = module_wait_idle(mod);
    if (rc) {
        spin_lock(&module_lock);
        module_lifecycle_restore(&mod->lifecycle, previous_state, rc);
        spin_unlock(&module_lock);
        logkfe("name: %s has active calls; unload retained rc=%ld\n",
               name, rc);
        return rc;
    }

    /* Deliberately outside rcu_read_lock and module_lock: exit may need a
     * grace period or bounded wait.  The EXITING state prevents new calls. */
    if (!exit_already_done) {
        rc = module_call_exit(mod, reserved);
        if (rc) {
            spin_lock(&module_lock);
            module_lifecycle_mark_exit_failed(&mod->lifecycle, rc);
            spin_unlock(&module_lock);
            logkfe("name: %s exit failed rc=%ld; module text retained for retry\n",
                   name, rc);
            return rc;
        }
    }

    if (hook_cleanup_pending()) {
        spin_lock(&module_lock);
        module_lifecycle_mark_exit_failed(&mod->lifecycle, -EBUSY);
        spin_unlock(&module_lock);
        logkfe("name: %s exit left deferred hooks; module text retained\n",
               name);
        return -EBUSY;
    }

    spin_lock(&module_lock);
    module_lifecycle_mark_retiring(&mod->lifecycle);
    spin_unlock(&module_lock);
    rc = module_wait_idle(mod);
    if (rc) {
        spin_lock(&module_lock);
        module_lifecycle_mark_exit_done(&mod->lifecycle);
        mod->lifecycle.exit_error = rc;
        spin_unlock(&module_lock);
        logkfe("name: %s exit completed but references remain rc=%ld; module retained\n",
               name, rc);
        return rc;
    }
    rc = module_retire(mod);
    if (rc) {
        spin_lock(&module_lock);
        module_lifecycle_mark_exit_done(&mod->lifecycle);
        mod->lifecycle.exit_error = rc;
        spin_unlock(&module_lock);
        logkfe("name: %s ordinary RCU grace unavailable rc=%ld; module retained\n",
               name, rc);
        return rc;
    }
    module_destroy(mod);

    logkfi("name: %s, rc: %ld\n", name, rc);
    return rc;
}

long load_module_path(const char *path, const char *args, void *__user reserved)
{
    long rc = 0;
    logkfd("%s\n", path);
    if (!path) return -EINVAL;
    if (!hook_management_context_ok()) return -EBUSY;

    struct file *filp = filp_open(path, O_RDONLY, 0);
    if (unlikely(!filp || IS_ERR(filp))) {
        logkfe("open module: %s error\n", path);
        rc = PTR_ERR(filp);
        goto out;
    }
    loff_t len = vfs_llseek(filp, 0, SEEK_END);
    logkfd("module size: %llx\n", len);
    vfs_llseek(filp, 0, SEEK_SET);

    void *data = vmalloc(len);
    if (!data) {
        rc = -ENOMEM;
        goto out;
    }
    memset(data, 0, len);

    loff_t pos = 0;
    kernel_read(filp, data, len, &pos);
    filp_close(filp, 0);

    if (pos != len) {
        logkfe("read module: %s error\n", path);
        rc = -EIO;
        goto free;
    }

    rc = load_module(data, len, args, "load-file", reserved);
free:
    kvfree(data);
out:
    return rc;
}

long module_control0(const char *name, const char *ctl_args, char *__user out_msg, int outlen)
{
    if (!name || !ctl_args) return -EINVAL;
    if (!hook_management_context_ok()) return -EBUSY;
    int args_len = strlen(ctl_args);
    if (args_len <= 0) return -EINVAL;

    logkfi("name %s, args: %s\n", name, ctl_args);

    long rc = 0;
    struct module *mod = module_get_live(name, &rc);
    if (!mod) return rc;

    if (!*mod->ctl0) {
        logkfe("no ctl0\n");
        rc = -ENOSYS;
        goto put;
    }

    if (mod->ctl_args) kvfree(mod->ctl_args);

    mod->ctl_args = vmalloc(args_len + 1);
    if (!mod->ctl_args) {
        rc = -ENOMEM;
        goto put;
    }

    strcpy(mod->ctl_args, ctl_args);

    rc = (*mod->ctl0)(mod->ctl_args, out_msg, outlen);

    logkfi("name: %s, rc: %ld\n", name, rc);
put:
    module_put(mod);
    return rc;
}

long module_control1(const char *name, void *a1, void *a2, void *a3)
{
    if (!name) return -EINVAL;
    if (!hook_management_context_ok()) return -EBUSY;
    logkfi("name %s, a1: %llx, a2: %llx, a3: %llx\n", name, a1, a2, a3);
    long rc = 0;
    struct module *mod = module_get_live(name, &rc);
    if (!mod) return rc;

    if (!*mod->ctl1) {
        logkfe("no ctl1\n");
        rc = -ENOSYS;
        goto put;
    }

    rc = (*mod->ctl1)(a1, a2, a3);

    logkfi("name: %s, rc: %ld\n", name, rc);
put:
    module_put(mod);
    return rc;
}

int get_module_nums()
{
    struct module *pos;
    int n = 0;
    spin_lock(&module_lock);
    list_for_each_entry(pos, &modules.list, list)
    {
        n++;
    }
    spin_unlock(&module_lock);

    logkfd("%d\n", n);
    return n;
}

int list_modules(char *out_names, int size)
{
    if (!out_names || size <= 0) return -EINVAL;

    struct module *pos;
    int off = 0;
    spin_lock(&module_lock);
    list_for_each_entry(pos, &modules.list, list)
    {
        int written;
        int remaining;
        if (off >= size - 1) break;
        remaining = size - off;
        written = snprintf(out_names + off, remaining, "%s\n",
                           pos->info.name);
        if (written < 0) break;
        if (written >= remaining) {
            off = size - 1;
            break;
        }
        off += written;
    }
    if (off > 0) out_names[off - 1] = '\0';
    spin_unlock(&module_lock);
    return off;
}

int get_module_info(const char *name, char *out_info, int size)
{
    if (size <= 0) return 0;
    if (!name || !out_info) return -EINVAL;

    spin_lock(&module_lock);
    struct module *mod = find_module_locked(name);
    if (!mod) {
        spin_unlock(&module_lock);
        return -ENOENT;
    }
    if (!module_lifecycle_try_get_info(&mod->lifecycle)) {
        spin_unlock(&module_lock);
        return -EBUSY;
    }
    spin_unlock(&module_lock);

    int sz = snprintf(out_info, size - 1,
                      "name=%s\n"
                      "version=%s\n"
                      "license=%s\n"
                      "author=%s\n"
                      "description=%s\n"
                      "args=%s\n",
                      mod->info.name, mod->info.version, mod->info.license, mod->info.author, mod->info.description,
                      mod->args);

    if (sz > 0) {
        int terminator = sz - 1;
        if (terminator >= size - 1) terminator = size - 2;
        if (terminator >= 0) out_info[terminator] = '\0';
    }
    logkfd("%s", out_info);
    spin_lock(&module_lock);
    if (!module_lifecycle_put_info(&mod->lifecycle)) {
        spin_unlock(&module_lock);
        logkfe("module info reference underflow: %s\n", name);
        return -EIO;
    }
    spin_unlock(&module_lock);
    return sz;
}

void module_init()
{
    INIT_LIST_HEAD(&modules.list);
    spin_lock_init(&module_lock);
}
