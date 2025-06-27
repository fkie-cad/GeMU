// Credits: Leander Kohler

#include "gemu/fastcheck.h"

void fc_init(FastCheck *fc, guint64 size)
{
    fc->array_size = size;
    fc->bit_array = g_malloc0(size / 8);
    g_mutex_init(&fc->mutex);
}

void fc_destroy(FastCheck *fc)
{
    g_free(fc->bit_array);
    g_mutex_clear(&fc->mutex);
}

// Primitive hash functions
uint64_t hash1(target_ulong x, uint64_t array_size)
{
    return (x * 7) % array_size;
}

uint64_t hash2(target_ulong x, uint64_t array_size)
{
    return (x * 13) % array_size;
}

// Set an vaddr in the FastCheck table
void fc_set(FastCheck *fc, target_ulong vaddr)
{
    g_mutex_lock(&fc->mutex);
    if (fc->min_vaddr == 0 || vaddr < fc->min_vaddr)
    {
        fc->min_vaddr = vaddr;
    }
    if (fc->max_vaddr == 0 || vaddr > fc->max_vaddr)
    {
        fc->max_vaddr = vaddr;
    }
    target_ulong index1 = hash1(vaddr, fc->array_size);
    target_ulong index2 = hash2(vaddr, fc->array_size);
    fc->bit_array[index1 / 8] |= (1 << (index1 % 8));
    fc->bit_array[index2 / 8] |= (1 << (index2 % 8));
    g_mutex_unlock(&fc->mutex);
}

// Check if an vaddr exists in the FastCheck table
gboolean fc_is_hooked(FastCheck *fc, target_ulong vaddr)
{
    if (vaddr < fc->min_vaddr || vaddr > fc->max_vaddr)
    {
        return FALSE;
    }

    // No lock required as this function is read-only and called after all adds are complete
    target_ulong index1 = hash1(vaddr, fc->array_size);
    target_ulong index2 = hash2(vaddr, fc->array_size);
    gboolean exists = ((fc->bit_array[index1 / 8] >> (index1 % 8)) & 1) &&
                      ((fc->bit_array[index2 / 8] >> (index2 % 8)) & 1);
    return exists;
}
