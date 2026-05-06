#include "gemu/cpuid_filter.h"
#include <string.h>

bool gemu_hide_hypervisor = false;

/*
 * Realistic brand string to replace "QEMU Virtual CPU version X.X.X".
 * Must be exactly 48 bytes (including padding). Packed as 12 uint32_t
 * values across leaves 0x80000002, 0x80000003, 0x80000004.
 */
static const char fake_brand[48] =
    "Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz\0\0\0\0\0\0\0\0";

static void filter_brand_string(uint32_t leaf, uint32_t *eax, uint32_t *ebx,
                                uint32_t *ecx, uint32_t *edx)
{
    int offset = (leaf - 0x80000002) * 16;
    memcpy(eax, &fake_brand[offset + 0], 4);
    memcpy(ebx, &fake_brand[offset + 4], 4);
    memcpy(ecx, &fake_brand[offset + 8], 4);
    memcpy(edx, &fake_brand[offset + 12], 4);
}

void gemu_filter_cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx,
                       uint32_t *ecx, uint32_t *edx)
{
    if (!gemu_hide_hypervisor) {
        return;
    }

    switch (leaf) {
    case 1:
        /* Clear CPUID_EXT_HYPERVISOR (bit 31 of ECX) */
        *ecx &= ~(1u << 31);
        break;
    case 0x80000002:
    case 0x80000003:
    case 0x80000004:
        /* Replace brand string to hide "QEMU Virtual CPU" */
        filter_brand_string(leaf, eax, ebx, ecx, edx);
        break;
    case 0x8000000A:
        /* Zero out AMD SVM features to hide virtualization capabilities */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    default:
        if (leaf >= 0x40000000 && leaf <= 0x400000FF) {
            /* Zero out hypervisor info leaves */
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    }
}
