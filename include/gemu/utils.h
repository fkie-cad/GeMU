
#ifndef GEMU_UTILS_H
#define GEMU_UTILS_H

#include "cJSON.h"
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

static inline int gemu_physical_memory_read(hwaddr addr, uint8_t *buf, int len) {
    return gemu_physical_memory_rw(addr, buf, len, false);
}

static inline int gemu_physical_memory_write(hwaddr addr, const uint8_t *buf, int len) {
    return gemu_physical_memory_rw(addr, (uint8_t *)buf, len, true);
}

int gemu_virtual_memory_rw(CPUState *env, target_ulong addr, uint8_t *buf,
                           int len, bool is_write);

static inline int gemu_virtual_memory_read(CPUState *env, target_ulong addr,
                                           uint8_t *buf, int len) {
    return gemu_virtual_memory_rw(env, addr, buf, len, false);
}

static inline int gemu_virtual_memory_write(CPUState *env, target_ulong addr,
                                            const uint8_t *buf, int len) {
    return gemu_virtual_memory_rw(env, addr, (uint8_t *)buf, len, true);
}

// Reads from a different process's address space by temporarily swapping the
// page-table base (cr[3]/ASID), then restoring it. Safe because the read path
// does its own page walk from cr[3] rather than trusting the TLB. The swap is
// restored unconditionally, so callers can't leak the borrowed address space.
// Defined in utils.c (not inline here) because it dereferences the target
// CPU state, which is only complete in per-target translation units.
int gemu_virtual_memory_read_in_asid(CPUState *env, target_ulong asid,
                                     target_ulong addr, uint8_t *buf, int len);

// Reads UNICODE string from guest memory via virtual address to buffer
// Returns number of characters read
uint32_t guest_wstrncpy(CPUState *cpu, char *buf, size_t maxlen,
                        target_ulong guest_va);

uint32_t guest_astrncpy(CPUState *cpu, char *buf, size_t maxlen,
                        target_ulong guest_va);

bool in_kernel_mode(const CPUState *cpu);

// Narrows a UTF-16LE buffer into a NUL-terminated narrow string by keeping the
// low byte of each code unit. dst_length is the full size of dst including the
// terminator, so the caller must size dst accordingly.
void copy_wide_to_normal_string(unsigned char *dst, unsigned char *src, size_t dst_length);

void over_write_qemu_substring(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_va, bool is_ansi);

bool gemu_dump_buffer_to_file(const uint8_t *buf, size_t length, const char *filename);

char *read_file(const char *filename);

cJSON *parse_file(const char *filename);
#endif // GEMU_UTILS_H
