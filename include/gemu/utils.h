
#ifndef GEMU_UTILS_H
#define GEMU_UTILS_H

#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qemu/typedefs.h"
#include "disas/disas.h"
#include "exec/address-spaces.h"

target_ulong get_current_asid(CPUState *cpu);

target_ulong get_current_pc(CPUState *cpu);

int gemu_physical_memory_rw(hwaddr addr, uint8_t *buf, int len, bool is_write);

int gemu_virtual_memory_rw(CPUState *env, target_ulong addr, uint8_t *buf,
                           int len, bool is_write);

// Reads UNICODE string from guest memory via virtual address to buffer
// Returns number of characters read
uint32_t guest_wstrncpy(CPUState *cpu, char *buf, size_t maxlen,
                        target_ulong guest_va);

uint32_t guest_astrncpy(CPUState *cpu, char *buf, size_t maxlen,
                        target_ulong guest_va);

bool in_kernel_mode(const CPUState *cpu);

void over_write_qemu_substring(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_va, bool is_ansi);

void replaceSubstring(char *str, const char *oldSubstr, const char *newSubstr);
#endif // GEMU_UTILS_H
