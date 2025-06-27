#include "gemu/utils.h"

/*
  returns current asid or address-space id.
  architecture-independent
*/
target_ulong get_current_asid(CPUState *cpu) {
#if defined(TARGET_X86_64)
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    return env->cr[3];
#else
#error "get_current_asid() not implemented for target architecture."
    return 0;
#endif
}

target_ulong get_current_pc(CPUState *cpu)
{
    if (cpu == NULL) {
        return 0;
    }

    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    target_ulong cs_base = env->segs[R_CS].base;
    return cs_base + env->eip;
}

bool in_kernel_mode(const CPUState *cpu)
{
    if (cpu->env_ptr->eip > 0xffff800000000000){
        return true;
    }
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
#if defined(TARGET_X86_64)
    return ((env->hflags & HF_CPL_MASK) == 0);
#else
#error "in_kernel_mode() not implemented for target architecture."
    return false;
#endif
}


/* (not kernel-doc)
 * gemu_physical_memory_rw() - Copy data between host and guest.
 * @addr: Guest physical addr of start of read or write.
 * @buf: Host pointer to a buffer either containing the data to be
 *    written to guest memory, or into which data will be copied
 *    from guest memory.
 * @len: The number of bytes to copy
 * @is_write: If true, then buf will be copied into guest
 *    memory, else buf will be copied out of guest memory.
 *
 * Either reads memory out of the guest into a buffer if
 * (is_write==false), or writes data from a buffer into guest memory
 * (is_write==true). Note that buf has to be big enough for read or
 * write indicated by len.
 *
 * Return:
 * * MEMTX_OK      - Read/write succeeded
 * * MEMTX_ERROR   - An error
 */
int gemu_physical_memory_rw(hwaddr addr, uint8_t *buf, int len,
                                           bool is_write) {
    hwaddr l = len;
    hwaddr addr1;
    MemoryRegion *mr = address_space_translate(&address_space_memory, addr,
                                               &addr1, &l, is_write, MEMTXATTRS_UNSPECIFIED);

    if (!memory_access_is_direct(mr, is_write)) {
        // fail for MMIO regions of physical address space
        return MEMTX_ERROR;
    }
    void *ram_ptr = qemu_map_ram_ptr(mr->ram_block, addr1);

    if (is_write) {
        memcpy(ram_ptr, buf, len);
    } else {
        memcpy(buf, ram_ptr, len);
    }
    return MEMTX_OK;
}

/* (not kernel-doc)
 * gemu_virtual_memory_rw() - Copy data between host and guest.
 * @env: Cpu sate.
 * @addr: Guest virtual addr of start of read or write.
 * @buf: Host pointer to a buffer either containing the data to be
 *    written to guest memory, or into which data will be copied
 *    from guest memory.
 * @len: The number of bytes to copy
 * @is_write: If true, then buf will be copied into guest
 *    memory, else buf will be copied out of guest memory.
 *
 * Either reads memory out of the guest into a buffer if
 * (is_write==false), or writes data from a buffer into guest memory
 * (is_write==true). Note that buf has to be big enough for read or
 * write indicated by len. Also note that if the virtual address is
 * not mapped, then the read or write will fail.
 *
 * We switch into privileged mode if the access fails. The mode is always reset
 * before we return.
 *
 * Return:
 * * 0      - Read/write succeeded
 * * -1     - An error
 */
int gemu_virtual_memory_rw(CPUState *env, target_ulong addr,
                                          uint8_t *buf, int len, bool is_write) {
    int l;
    int ret;
    hwaddr phys_addr;
    target_ulong page;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        phys_addr = cpu_get_phys_page_debug(env, page);
        // If we failed and we CAN go into it, toggle modes and try again
        if (phys_addr == -1) {
            phys_addr = cpu_get_phys_page_debug(env, page);
        }

        // No physical page mapped, abort
        if (phys_addr == -1) {
            return -1;
        }

        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len) {
            l = len;
        }
        phys_addr += (addr & ~TARGET_PAGE_MASK);
        ret = gemu_physical_memory_rw(phys_addr, buf, l, is_write);

        // Failed and privileged mode wasn't already enabled - enable priv and retry if we can
        if (ret != MEMTX_OK) {
            ret = gemu_physical_memory_rw(phys_addr, buf, l, is_write);
        }
        // Still failed, even after potential privileged switch, abort
        if (ret != MEMTX_OK) {
            return ret;
        }

        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}

void replaceSubstring(char *str, const char *oldSubstr, const char *newSubstr) {
    char buffer[1024];  // Temporary buffer to store the result
    char *pos;
    int oldLen = strlen(oldSubstr);

    buffer[0] = '\0';  // Initialize buffer to an empty string
    char *start = str; // Keep track of the original starting point

    // Loop through the original string, replacing occurrences of oldSubstr
    while ((pos = strstr(str, oldSubstr)) != NULL) {
        // Copy part of the string before the old substring into buffer
        strncat(buffer, str, pos - str);  // Copy characters before oldSubstr

        // Append the new substring to the buffer
        strcat(buffer, newSubstr);

        // Move str pointer forward past the old substring
        str = pos + oldLen;
    }

    // Append the remaining part of the original string after the last occurrence
    strcat(buffer, str);  // Copy the unprocessed part after the last match

    // Copy the modified result back to the original string (starting point)
    strcpy(start, buffer);
}


void over_write_qemu_substring(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_va, bool is_ansi){
    int offset = 1;
    if (is_ansi == false)
        offset = 2;
    unsigned i;
    if (strstr(buf, "QEMU")) {
        replaceSubstring(buf, "QEMU", "GeMU");
        for (i = 0; i < maxlen; i++) {
            gemu_virtual_memory_rw(cpu, guest_va + offset * i, (uint8_t *) &buf[i], 1, 1);
            if (buf[i] == 0) {
                break;
            }
        }
    }
    if (strstr(buf, "qemu")){
        replaceSubstring(buf, "qemu", "gemu");
        for (i = 0; i < maxlen; i++) {
            gemu_virtual_memory_rw(cpu, guest_va + offset *  i, (uint8_t *) &buf[i], 1, 1);
            if (buf[i] == 0) {
                break;
            }
        }
    }
    return;
}

uint32_t guest_wstrncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_va) {
    buf[0] = 0;
    unsigned i;
    for (i = 0; i < maxlen; i++) {
        gemu_virtual_memory_rw(cpu, guest_va + 2 * i, (uint8_t *) &buf[i], 1, 0);
        if (buf[i] == 0) {
            break;
        }
    }
    buf[maxlen - 1] = 0;
    over_write_qemu_substring(cpu, buf, (i + 1) * 2, guest_va, false);
    return i;
}

uint32_t guest_astrncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_va) {
    buf[0] = 0;
    unsigned i;
    for (i = 0; i < maxlen; i++) {
        gemu_virtual_memory_rw(cpu, guest_va + i, (uint8_t *) &buf[i], 1, 0);
        if (buf[i] == 0) {
            break;
        }
    }
    buf[maxlen - 1] = 0;
    over_write_qemu_substring(cpu, buf, i + 1, guest_va, true);
    for (i = 0; i < maxlen; i++) {
        gemu_virtual_memory_rw(cpu, guest_va + i, (uint8_t *) &buf[i], 1, 0);
        if (buf[i] == 0) {
            break;
        }
    }
    return i;
}
