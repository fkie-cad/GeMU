#include "gemu/utils.h"
#include <sys/stat.h>

static bool dumps_dir_initialized = false;

// Ensures the dumps directory exists (called once)
static void ensure_dumps_dir(void) {
    if (!dumps_dir_initialized) {
        mkdir("dumps", 0777);
        dumps_dir_initialized = true;
    }
}

bool gemu_dump_buffer_to_file(const uint8_t *buf, size_t length, const char *filename) {
    if (buf == NULL || length == 0 || filename == NULL) {
        return false;
    }

    ensure_dumps_dir();

    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Error opening dump file");
        return false;
    }

    size_t written = fwrite(buf, 1, length, file);
    fclose(file);

    if (written != length) {
        perror("Error writing dump file");
        return false;
    }

    printf("Data successfully written to %s\n", filename);
    return true;
}

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

// Reads from a different process's address space by temporarily swapping the
// page-table base (cr[3]/ASID), then restoring it. Safe because the read path
// does its own page walk from cr[3] rather than trusting the TLB. The swap is
// restored unconditionally, so callers can't leak the borrowed address space.
int gemu_virtual_memory_read_in_asid(CPUState *env, target_ulong asid,
                                     target_ulong addr, uint8_t *buf, int len) {
    target_ulong saved = env->env_ptr->cr[3];
    env->env_ptr->cr[3] = asid;
    int ret = gemu_virtual_memory_read(env, addr, buf, len);
    env->env_ptr->cr[3] = saved;
    return ret;
}

static const char *strings_to_replace[] = {
    "qemu",
    "vbox",
    NULL,
};


// collision prevention: result != last result. earlier results may be repeated
// result will have `len` characters -> requires buffer of size `len+1`
static void random_alpha_string(char *out, size_t len) {
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static char last[64];
    static size_t last_len = 0;

    bool collision;
    do {
        for (size_t i = 0; i < len; i++) {
            out[i] = charset[rand() % (sizeof(charset) - 1)];
        }
        out[len] = '\0';
        collision = (len == last_len && memcmp(out, last, len + 1) == 0);
    } while (collision);

    memcpy(last, out, len + 1);
    last_len = len;
}

void copy_wide_to_normal_string(unsigned char *dst, unsigned char *src, size_t dst_length) {
    for (size_t i = 0; i < dst_length-1; i++) {
        dst[i] = src[2*i];
    }
    dst[dst_length-1] = '\0';
}

// guest_va: address to overwrite string at
// buf: contents of guest_address as ansi string
// maxlen: in symbols not byte, including null terminator
// is ansi -> only relevant for guest_va for writing back
void over_write_qemu_substring(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_va, bool is_ansi){
    int offset = is_ansi ? 1 : 2;
    unsigned i;
    bool modified = false;

    for (size_t s = 0; strings_to_replace[s] != NULL; s++) {
        const char *target = strings_to_replace[s];
        size_t target_len = strlen(target);
        size_t len = strlen(buf);
        char *pos = buf;
        while (len >= target_len && pos <= buf + len - target_len) {
            if (strncasecmp(pos, target, target_len) == 0) {
                char replacement[target_len + 1];
                random_alpha_string(replacement, target_len);
                memcpy(pos, replacement, target_len);
                modified = true;
                pos += target_len;
            } else {
                pos++;
            }
        }
    }

    if (modified) {
        for (i = 0; i < maxlen; i++) {
            gemu_virtual_memory_write(cpu, guest_va + offset * i, (uint8_t *) &buf[i], 1);
            if (buf[i] == 0) {
                break;
            }
        }
    }
}

// maxlen: maximum size of corresponding ansi string buffer in bytes including terminator
uint32_t guest_wstrncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_va) {
    buf[0] = 0;
    unsigned i;
    for (i = 0; i < maxlen; i++) {
        gemu_virtual_memory_read(cpu, guest_va + 2 * i, (uint8_t *) &buf[i], 1);
        if (buf[i] == 0) {
            break;
        }
    }
    buf[maxlen - 1] = 0;
    // i+1 <= maxlen
    over_write_qemu_substring(cpu, buf, i + 1, guest_va, false);
    return i;
}

// maxlen: maximum size of buffer in bytes including terminator
uint32_t guest_astrncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_va) {
    buf[0] = 0;
    unsigned i;
    for (i = 0; i < maxlen; i++) {
        gemu_virtual_memory_read(cpu, guest_va + i, (uint8_t *) &buf[i], 1);
        if (buf[i] == 0) {
            break;
        }
    }
    buf[maxlen - 1] = 0;
    over_write_qemu_substring(cpu, buf, i + 1, guest_va, true);
    for (i = 0; i < maxlen; i++) {
        gemu_virtual_memory_read(cpu, guest_va + i, (uint8_t *) &buf[i], 1);
        if (buf[i] == 0) {
            break;
        }
    }
    return i;
}

char *read_file(const char *filename) {
    FILE *file = NULL;
    long length = 0;
    char *content = NULL;
    size_t read_chars = 0;

    /* open in read binary mode */
    file = fopen(filename, "rb");
    if (file == NULL) {
        goto cleanup;
    }

    /* get the length */
    if (fseek(file, 0, SEEK_END) != 0) {
        goto cleanup;
    }
    length = ftell(file);
    if (length < 0) {
        goto cleanup;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        goto cleanup;
    }

    /* allocate content buffer */
    content = (char *) malloc((size_t) length + sizeof(""));
    if (content == NULL) {
        goto cleanup;
    }

    /* read the file into memory */
    read_chars = fread(content, sizeof(char), (size_t) length, file);
    if ((long) read_chars != length) {
        free(content);
        content = NULL;
        goto cleanup;
    }
    content[read_chars] = '\0';

    cleanup:
    if (file != NULL) {
        fclose(file);
    }

    return content;
}

cJSON *parse_file(const char *filename) {
    cJSON *parsed = NULL;
    char *content = read_file(filename);

    parsed = cJSON_Parse(content);

    if (content != NULL) {
        free(content);
    }

    return parsed;
}