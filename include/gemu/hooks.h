
#ifndef GEMU_HOOKS_H
#define GEMU_HOOKS_H

#include<stdint.h>
#include<stddef.h>
#include<stdbool.h>
#include "qemu/typedefs.h"
#include "win_spector.h"
#include "fastcheck.h"

// New callbacks can be added here:
enum callback
{
    CB_BEFORE_TB_EXEC,
    CB_AFTER_TB_EXEC,
    EXIT_FROM_API
};

typedef struct
{
    target_ulong addr;

    struct callback_pair
    {
        enum callback cb;
        void* cb_func;
    } *callbacks;

    int callback_count;

    out_parameter_list_t out_parameter_list;
    char dll_name[256];
    char func_name[256];
    bool is32bit;
} hook_t;

typedef void (*hook_callback_func)(target_ulong pc, CPUState *cpu, TranslationBlock *tb, char *dll_name,
                                   char *func_name, WinThread *thread, out_parameter out_parameters[], int number_of_outparameters, bool is32bit);

typedef struct
{
    struct qht *addr_symbol_map;
    FastCheck fc;
    void (*output)(const char *message, ...);
} Hooker;

Hooker *init_hooker(int hook_hashtable_bucket_size);

void hkr_destroy(Hooker *h);

bool hk_add_cb_pair(hook_t *hook, enum callback cb, void* cb_func);

bool hkr_add_new_hook(Hooker *h, hook_t hook);

bool hkr_remove_hook(Hooker *h, target_ulong pc);

bool hkr_try_exec_hook(Hooker *h, target_ulong address, CPUState *cpu, TranslationBlock *tb, WinThread *thread, enum callback cb);

void* find_cb_func(hook_t *hook, enum callback cb);

#endif //GEMU_HOOKS_H
