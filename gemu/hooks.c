#include "gemu/fastcheck.h"
#include "gemu/hooks.h"

#include <stdio.h>
#include <stdlib.h>

// Returns true when the two hooks have the same address
#define FC_SIZE 100000

static bool hook_cmp(const void *a, const void *b)
{
    hook_t *ha = (hook_t *) a;
    hook_t *hb = (hook_t *) b;

    return ha->addr == hb->addr;
}

Hooker *init_hooker(int hook_hashtable_bucket_size)
{
    Hooker *h = malloc(sizeof(Hooker));
    if (h == NULL) {
        return NULL;
    }

    h->addr_symbol_map = malloc(sizeof(struct qht));
    if (h->addr_symbol_map == NULL) {
        free(h);
        return NULL;
    }
    fc_init(&h->fc, FC_SIZE);
    qht_init(h->addr_symbol_map, hook_cmp, hook_hashtable_bucket_size, 0);
    return h;
}

void hkr_destroy(Hooker *h)
{
    if (h != NULL) {
        qht_destroy(h->addr_symbol_map);
        free(h->addr_symbol_map);
        free(h);
    }
}

bool hkr_add_new_hook(Hooker *h, hook_t hook)
{
    hook_t *new_hook = malloc(sizeof(hook_t));
    if (new_hook != NULL) {
        *new_hook = hook;
        return qht_insert(h->addr_symbol_map, new_hook, hook.addr, NULL);
    }
    return false;
}

bool hkr_remove_hook(Hooker *h, target_ulong pc)
{
    hook_t lookup_hook = {
            .addr = pc,
    };

    hook_t *found_hook = qht_lookup(h->addr_symbol_map, &lookup_hook, pc);
    if (found_hook == NULL) {
        printf("could not find hook to remove, which is totally bonkers %lX\n", pc);
    }
    bool result = qht_remove(h->addr_symbol_map, found_hook, pc);
    if (result){
        free(found_hook);
    }
    return result;
}

void* find_cb_func(hook_t *hook, enum callback cb)
{
    if (hook == NULL) {
        return NULL;
    }

    for (int i = 0; i < hook->callback_count; i++) {
        if (hook->callbacks[i].cb == cb) {
            return hook->callbacks[i].cb_func;
        }
    }

    return NULL;
}

// Calls the callback function if address is hooked.
// Returns True if hook was found, False if address is not hooked
bool hkr_try_exec_hook(Hooker *h, target_ulong address, CPUState *cpu, TranslationBlock *tb, WinThread *thread, enum callback cb)
{
    hook_t lookup_hook = {
            .addr = address,
    };

    hook_t *found_hook = qht_lookup(h->addr_symbol_map, &lookup_hook, address);
    if (found_hook == NULL) {
        return false;
    }

    hook_callback_func cb_func = find_cb_func(found_hook, cb);
    if (cb_func == NULL) {
        return false;
    }

    int n = found_hook->out_parameter_list.number_of_outparameters;
    cb_func(address, cpu, tb, found_hook->dll_name, found_hook->func_name, thread, found_hook->out_parameter_list.out_parameters, n, found_hook->is32bit);
    return true;
}


bool hk_add_cb_pair(hook_t *hook, enum callback cb, void* cb_func)
{
    if (hook == NULL || cb_func == NULL) {
        return false;
    }

    // Reallocate memory for the callbacks array, taking into account the new callback pair
    struct callback_pair *temp = realloc(hook->callbacks, sizeof(struct callback_pair) * (hook->callback_count + 1));

    // Check if reallocation was successful
    if (temp == NULL) {
        return false;
    }

    // If successful, update the pointer
    hook->callbacks = temp;

    // Add the new callback pair at the end of the array
    hook->callbacks[hook->callback_count].cb = cb;
    hook->callbacks[hook->callback_count].cb_func = cb_func;

    // Update the callback count
    hook->callback_count++;

    return true;
}
