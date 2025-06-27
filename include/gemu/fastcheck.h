// Credits: Leander Kohler

#ifndef FASTCHECK_H
#define FASTCHECK_H

#include <glib.h>
#include <stdint.h>
#include "qemu/typedefs.h"
// include target_ulong from qemu

typedef struct {
  guint8 *bit_array;
  guint64 array_size;
  GMutex mutex;
  target_ulong min_vaddr;
  target_ulong max_vaddr;
} FastCheck;

void fc_init(FastCheck *fc, guint64 size);
void fc_destroy(FastCheck *fc);
void fc_set(FastCheck *fc, target_ulong vaddr);
gboolean fc_is_hooked(FastCheck *fc, target_ulong vaddr);
uint64_t hash1(target_ulong x, uint64_t array_size);
uint64_t hash2(target_ulong x, uint64_t array_size);

#endif // FASTCHECK_H
