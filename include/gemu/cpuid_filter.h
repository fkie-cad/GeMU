#ifndef GEMU_CPUID_FILTER_H
#define GEMU_CPUID_FILTER_H

#include <stdint.h>
#include <stdbool.h>

extern bool gemu_hide_hypervisor;

void gemu_filter_cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx,
                       uint32_t *ecx, uint32_t *edx);

#endif
