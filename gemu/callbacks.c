#include "gemu/callbacks.h"
#include "gemu/fastcheck.h"
#include "gemu/mappedwaitinglist.h"
#include "gemu/gemu.h"
#include "exec/translator.h"
#include "gemu/utils.h"
#include "gemu/win_spector.h"
#include "gemu/syscalltable.h"
#include <time.h>
#include "monitor/monitor.h"
#include "gemu/xxhash64.h"
#include "qemu/xxhash.h"

bool gemu_use_memcb = false;
bool gemu_use_exec = false;
bool gemu_use_translation = false;
bool gemu_use_syscall = true;
bool gemu_use_codecarver = false;

bool gemu_use_tracing = false;
 // This should be set to true by default. This will make it impossible to miss compilation in case setup is delayed.
bool gemu_compile_syscall_helper = true;
int counter = 0;
long long extracted_data_size = 0;

#define MAX_DUMP_COUNT 100000
#define MAX_EXTRACTED_SIZE 10000000000LL  // 10GB

bool* getWrittenFlagForNode(struct MappedMemoryNode* mmapNode) {
    Gemu *gemu_instance = gemu_get_instance();
    WinProcess* other_process = get_WinProcess_for_pid(gemu_instance->win_spec, mmapNode->other_ID);
    if (other_process == NULL) {
        return NULL;
    }
    hwaddr start = mmapNode->other_start;
    hwaddr end = mmapNode->other_start + mmapNode->other_size;

    struct Node* current = other_process->new_sections->head;
    while (current != NULL) {
        if (current->start < end && current->end > start) {
            if (current->is_shared)
                return current->written_to.shared_written_to;
        }
        current = current->next;
    }
    return NULL;
}


bool convertToSharedWrittenBit(struct MappedMemoryNode* mmapNode, struct DoubleLinkedList* doubleList) {
    bool found = false;
    hwaddr start = mmapNode->start;
    hwaddr end = mmapNode->start + mmapNode->size;

    bool* other_writtenflag = NULL;
    if (mmapNode->other_ID != 0){
        other_writtenflag = getWrittenFlagForNode(mmapNode);
    }

    struct Node* current = doubleList->head;
    while (current != NULL) {
        if (current->start < end && current->end > start) {
            found = true;
            if (!current->is_shared) {
                current->is_shared = true;
                current->shared_map_start = start;
                current->shared_map_end = end;
                current->shared_other_start = mmapNode->other_start;
                current->shared_other_end = mmapNode->other_start + mmapNode->other_size;
                current->shared_other_pid = mmapNode->other_ID;
                if (other_writtenflag == NULL) {
                    bool* writtenflag = (bool*) malloc(sizeof(bool));
                    *writtenflag = current->written_to.local_written_to;
                    current->written_to.shared_written_to = writtenflag;
                }
                else {
                    current->written_to.shared_written_to = other_writtenflag;
                }
            }
        }
        current = current->next;
    }
    return found;
}


bool iterateAndUpdateList(struct SingleLinkedList* singleList, struct DoubleLinkedList* doubleList) {
    struct MappedMemoryNode* current = singleList->head;
    struct MappedMemoryNode* prev = NULL;

    while (current != NULL) {
        bool shouldRemove = convertToSharedWrittenBit(current, doubleList);

        if (shouldRemove) {
            if (prev == NULL) {
                singleList->head = current->next;
            } else {
                prev->next = current->next;
            }

            struct MappedMemoryNode* temp = current;
            current = current->next;
            free(temp);
        } else {
            prev = current;
            current = current->next;
        }
    }
    return singleList->head == NULL;
}


ModuleNode* is_within_range(ModuleNode* head, hwaddr start, hwaddr end) {
    ModuleNode* current = head;
    while (current != NULL) {
        if (start >= current->base && end <= current->base + current->size) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}


static void process_mapped_sections_waitinglist(Gemu *gemu_instance, WinProcess *process) {
    struct SingleLinkedList *list = getMemoryMappedList(gemu_instance->mapped_sections_waitinglist, process->ID);
    if (list == NULL) {
        return;
    }

    bool list_is_empty = iterateAndUpdateList(list, process->new_sections);
    if (list_is_empty) {
        removeList(gemu_instance->mapped_sections_waitinglist, process->ID);
    }
}


void check_for_unpacking(CPUState *cpu, TranslationBlock *tb, WinProcess *process, Gemu *gemu_instance){
    if (counter > MAX_DUMP_COUNT || extracted_data_size > MAX_EXTRACTED_SIZE) {
        return;
    }
    // checking for unpacking

    struct Node* temp_section = NULL;

    if (process->cache_section == NULL || !(cpu->env_ptr->eip >= process->cache_section->start && cpu->env_ptr->eip < process->cache_section->end)){
        temp_section = getNodeForAddress(cpu->env_ptr->eip, process->new_sections);
        process->cache_section = temp_section;
    }
    else {
        temp_section = process->cache_section;
    }

    // getting the temp section

    if (temp_section == NULL) {
        process->cache_section = NULL;
        print_memory_map(cpu, process);
        temp_section = getNodeForAddress(cpu->env_ptr->eip, process->new_sections);
        process->cache_section = temp_section;
    }

    //getting the memory map

    struct SingleLinkedList* list = getMemoryMappedList(gemu_instance->mapped_sections_waitinglist, process->ID);
    if (list != NULL) {
        bool list_is_empty = iterateAndUpdateList(list, process->new_sections);
        if (list_is_empty == true) {
            removeList(gemu_instance->mapped_sections_waitinglist, process->ID);
        }
    }
    if (temp_section == NULL) {
        return;
    }
    if (getWrittenToFlag(temp_section)) {
        struct DoubleLinkedList new_list;
        copyList(&new_list, process->new_sections);
        reduceList(&new_list);
        struct Node* section = getNodeForAddress(cpu->env_ptr->eip, &new_list);
        if(process->cache_section_written != NULL && (
            (process->cache_section_written->start >= section->start && process->cache_section_written->start <= section->end) ||
            (process->cache_section_written->end >= section->start && process->cache_section_written->end <= section->end)
        ))
            process->cache_section_written = NULL;

        hwaddr dump_start = section->start;
        hwaddr dump_end = section->end;

        // For shared sections (injected via ZwMapViewOfSection), use the full mapped
        // range instead of relying on page table walk results, which may miss
        // demand-paged pages.
        if (section->is_shared && section->shared_map_start != 0 &&
            section->shared_map_end > section->shared_map_start) {
            printf("dump expansion: section=[0x%lx-0x%lx] shared_map=[0x%lx-0x%lx]\n",
                   section->start, section->end, section->shared_map_start, section->shared_map_end);
            if (section->shared_map_end > dump_end)
                dump_end = section->shared_map_end;
        }

        uint64_t length = dump_end - dump_start;
        printf("dumping: [0x%lx - 0x%lx] length=0x%lx is_shared=%d\n",
               dump_start, dump_end, length, section->is_shared);
        uint8_t *buf = malloc(length + 1);
        gemu_virtual_memory_read(cpu, dump_start, buf, length);

        // For shared sections, pages may not be present in the target process
        // (demand-paged). Fill zero pages by reading from the source process.
        if (section->is_shared && section->shared_other_pid != 0 &&
            section->shared_other_start != 0) {
            Gemu *gemu_inst = gemu_get_instance();
            WinProcess *source_proc = get_WinProcess_for_pid(
                gemu_inst->win_spec, section->shared_other_pid);
            if (source_proc != NULL) {
                target_ulong original_cr3 = cpu->env_ptr->cr[3];
                target_ulong source_cr3 = source_proc->ASID;
                hwaddr other_start = section->shared_other_start;
                uint64_t other_length = section->shared_other_end - section->shared_other_start;

                printf("shared dump: reading zero pages from source pid=%llu "
                       "cr3=0x%lx other=[0x%lx-0x%lx]\n",
                       section->shared_other_pid, source_cr3,
                       other_start, other_start + other_length);

                cpu->env_ptr->cr[3] = source_cr3;
                for (uint64_t offset = 0; offset < length; offset += TARGET_PAGE_SIZE) {
                    uint64_t remaining = length - offset;
                    uint64_t chunk = remaining < TARGET_PAGE_SIZE ? remaining : TARGET_PAGE_SIZE;

                    bool is_zero = true;
                    for (uint64_t i = 0; i < chunk; i++) {
                        if (buf[offset + i] != 0) {
                            is_zero = false;
                            break;
                        }
                    }

                    if (is_zero && offset < other_length) {
                        gemu_virtual_memory_read(cpu, other_start + offset,
                                                 buf + offset, chunk);
                    }
                }
                cpu->env_ptr->cr[3] = original_cr3;
            }
        }

        extracted_data_size += length;
        char filename[261];
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC_RAW, &now);
        wi_extract_module_list(cpu, process);
        ModuleNode* module = is_within_range(process->current_modules, temp_section->start, temp_section->end);
        if (module != NULL) {
            snprintf(filename, sizeof(filename), "dumps/%llu_0x%lx_%s_%lu_dump_nr_%d", process->ID, dump_start, module->file,
                    (now.tv_sec - start_time->tv_sec) * 1000 + (now.tv_nsec - start_time->tv_nsec) / 1000000, counter);
        }
        else{
            snprintf(filename, sizeof(filename), "dumps/%llu_0x%lx_mw_%lu_dump_nr_%d", process->ID, dump_start, (now.tv_sec - start_time->tv_sec) * 1000 + (now.tv_nsec - start_time->tv_nsec) / 1000000, counter);
        }
        unsetWrittenFlagForRange(dump_start, dump_end, process->new_sections);
        counter += 1;
        gemu_dump_buffer_to_file(buf, length, filename);
        free(buf);
        freeList(&new_list);
    }
}

void gemu_cb_before_tb_exec(CPUState *cpu, TranslationBlock *tb, bool is_chained)
{

    if (cpu == NULL || tb == NULL || in_kernel_mode(cpu)) {
        return;
    }
    Gemu *gemu_instance = gemu_get_instance();

    gboolean is_hooked = fc_is_hooked(&gemu_instance->hooker->fc, cpu->env_ptr->eip);
    if (!is_hooked)
    {
       return;
    }

    WinProcess *process = wi_current_process(gemu_instance->win_spec, cpu, true);
    if (process == NULL) {
        // Exit early if the current program is not the one we want to watch
        return;
    }
    QWORD processid;
    QWORD threadid;
    get_current_pid_and_tid(cpu, &processid, &threadid, process);

    target_ulong rip = cpu->env_ptr->eip;
    WinThread* thread = wi_current_thread(process, threadid);

    if (!is_chained) {
        if (thread->length_last_bb == tb->size && thread->base_last_bb == rip) {
            // printf("skipping duplicate BB for %llu:%llu:0x%lx,%i\n", process->ID, threadid, rip, tb->size);
            return;
        }
    }

    thread->length_last_bb = tb->size;
    thread->base_last_bb = rip;


    hkr_try_exec_hook(gemu_instance->hooker, rip, cpu, tb, process, CB_BEFORE_TB_EXEC);
    hkr_try_exec_hook(gemu_instance->hooker, rip, cpu, tb, process, EXIT_FROM_API);

    return;
}


void gemu_cb_tracing(CPUState *cpu, TranslationBlock *tb, bool is_chained){
    // There should be no double basic blocks since this is called behind the execution
    if (cpu == NULL || tb == NULL || in_kernel_mode(cpu) ) {
        return;
    }

    Gemu *gemu_instance = gemu_get_instance();
    WinProcess *process = wi_current_process(gemu_instance->win_spec, cpu, true);
    if (process == NULL) {
        // Exit early if the current program is not the one we want to watch
        return;
    }

    QWORD processid;
    QWORD threadid;
    get_current_pid_and_tid(cpu, &processid, &threadid, process);

    printf("B:%llu:%llu:0x%lx,%i\n", processid, threadid, cpu->env_ptr->eip, tb->size);
}


WinProcess* gemu_helper_get_current_process(void){

    Gemu *gemu_instance = gemu_get_instance();

    CPUState *cpu_new = current_cpu;

    WinProcess *process = wi_current_process(gemu_instance->win_spec, cpu_new, true);
    if (process == NULL) {
        return NULL;
    }
    return process;
}


void gemu_cb_syscall(CPUX86State *cpu, int next_eip_addend)
{
    if (cpu == NULL || ((cpu->hflags & HF_CPL_MASK) == 0)) {
        return;
    }
    Gemu *gemu_instance = gemu_get_instance();

    syscall_t syscall_enum = lookup_syscall_enum(gemu_instance, cpu->regs[R_EAX] & 0xfff, &gemu_helper_get_current_process);
    if (syscall_enum == 0){
        return;
    }

    CPUState *cpu_new = current_cpu;

    WinProcess *process = wi_current_process(gemu_instance->win_spec, cpu_new, true);
    if (process == NULL || !g_hash_table_contains(gemu_instance->pids_to_lookout_for, GINT_TO_POINTER(process->ID))) {
        // Exit early if the current program is not the one we want to watch
        return;
    }

    // char* funcname = lookup_syscall(gemu_instance, &process->Process, cpu->regs[R_EAX]);
    // const char* funcname2 = SYSCALL_NAMES[syscall_enum];
    
    // printf("SYSCALL: %lx %s\n", cpu->regs[R_EAX], funcname2);
    //print_module_nodes(process->current_modules);
    pipe_logger_before_syscall_exec_enum(cpu_new, syscall_enum, process);

    //printf("%llu:E,0x%lx,%i\n", thread->Process.ID, cpu->env_ptr->eip, tb->size);
    return;
}

void gemu_cb_sysret(CPUX86State *cpu)
{
    if (cpu == NULL) {
        return;
    }

    Gemu *gemu_instance = gemu_get_instance();
    CPUState *cpu_state = current_cpu;

    WinProcess *process = wi_current_process(gemu_instance->win_spec, cpu_state, true);
    if (process == NULL) {
        return;
    }

    if (!g_hash_table_contains(gemu_instance->pids_to_lookout_for, GINT_TO_POINTER(process->ID))) {
        return;
    }

    QWORD pid, tid;
    get_current_pid_and_tid(cpu_state, &pid, &tid, process);
    WinThread* current_thread = wi_current_thread(process, tid);

    if (gemu_use_tracing) {
        print_module_nodes(process->current_modules, process->ID);
    }
    syscall_hook_t* return_hook = &current_thread->syscall_return_hook;
    if(return_hook->active == false){
        // sysret without hooked syscall
        return;
    }

    pipe_logger_after_syscall_exec(cpu_state, process, return_hook);
    return_hook->active = false;
}

void gemu_cb_after_block_translation(CPUState *cpu, TranslationBlock *tb)
{
    if (cpu == NULL || tb == NULL || in_kernel_mode(cpu) ) {
        return;
    }
    Gemu *gemu_instance = gemu_get_instance();
    WinProcess *process = wi_current_process(gemu_instance->win_spec, cpu, true);
    if (process == NULL) {
        // Exit early if the current program is not the one we want to watch
        return;
    }
    check_for_unpacking(cpu, tb, process, gemu_instance);
    if (gemu_use_codecarver) {
        gemu_dump_code_pages(cpu, process);
    }
}

#define KERNEL_SPACE_BOUNDARY 0xffff800000000000

static bool is_addr_in_cached_section(WinProcess *process, target_ulong addr) {
    struct Node *cached = process->cache_section_written;
    return cached != NULL && addr >= cached->start && addr <= cached->end;
}

static struct Node *find_or_refresh_section(CPUState *cpu, WinProcess *process, target_ulong addr) {
    struct Node *section = getNodeForAddress(addr, process->new_sections);

    if (section == NULL) {
        process->cache_section = NULL;
        print_memory_map(cpu, process);
        section = getNodeForAddress(addr, process->new_sections);
    }

    return section;
}

void gemu_cb_phys_memory_written(CPUArchState *env, target_ulong addr, uint64_t val, size_t size, uintptr_t retaddr)
{
    if (env == NULL || addr > KERNEL_SPACE_BOUNDARY) {
        return;
    }

    CPUState *cpu = env_cpu(env);
    Gemu *gemu_instance = gemu_get_instance();

    WinProcess *process = wi_current_process(gemu_instance->win_spec, cpu, true);
    if (process == NULL) {
        return;
    }

    if (is_addr_in_cached_section(process, addr)) {
        return;
    }

    struct Node *section = find_or_refresh_section(cpu, process, addr);
    process->cache_section_written = section;

    process_mapped_sections_waitinglist(gemu_instance, process);

    if (section != NULL) {
        setWrittenFlag(section, true);
        process->has_pending_writes = true;
    }
}

void update_memory_map_from_env(CPUArchState *env){
    if (env == NULL) {
        return;
    }
    CPUState *cpu = env_cpu(env);
    if (in_kernel_mode(cpu)) {
        return;
    }
    Gemu *gemu_instance = gemu_get_instance();
    WinProcess *process = wi_current_process(gemu_instance->win_spec, cpu, true);
    if (process == NULL) {
        return;
    }
    print_memory_map(cpu, process);
}

#define HASH_SCAN_SIZE 0x400

static uint64_t create_compound_hash(hwaddr start, uint64_t length, const uint8_t *scan_buf, size_t scan_len) {
    uint64_t content_hash = xxhash64_buf(scan_buf, scan_len);

    return qemu_xxhash64_4(start, length, content_hash, 0);
}

static bool is_section_already_dumped(Gemu *gemu_instance, hwaddr start, uint64_t length,
                                       const uint8_t *scan_buf, size_t scan_len) {
    gpointer hash_key = (gpointer)(uintptr_t)create_compound_hash(start, length, scan_buf, scan_len);

    if (g_hash_table_contains(gemu_instance->dumped_hashes, hash_key))
        return true;

    g_hash_table_add(gemu_instance->dumped_hashes, hash_key);
    return false;
}

static bool dump_section_to_file(CPUState *cpu, struct Node *section, WinProcess *process) {
    uint64_t length = section->end - section->start;
    struct timespec now;
    char filename[261];

    uint8_t *buf = malloc(length);

    gemu_virtual_memory_read(cpu, section->start, buf, length);

    clock_gettime(CLOCK_MONOTONIC_RAW, &now);

    unsigned long elapsed_ms = (now.tv_sec - start_time->tv_sec) * 1000 +
                               (now.tv_nsec - start_time->tv_nsec) / 1000000;
    snprintf(filename, sizeof(filename), "dumps/%llu_0x%lx_code_%lu_dump_nr_%d",
             process->ID, section->start, elapsed_ms, counter);
    counter++;
    extracted_data_size += length;

    bool result = gemu_dump_buffer_to_file(buf, length, filename);
    free(buf);
    return result;
}

void gemu_dump_code_pages(CPUState *cpu, WinProcess *process) {
    if (!process->has_pending_writes) {
        return;
    }

    if (counter > MAX_DUMP_COUNT || extracted_data_size > MAX_EXTRACTED_SIZE) {
        return;
    }

    process->has_pending_writes = false;

    Gemu *gemu_instance = gemu_get_instance();

    if (process->sections_dirty) {
        freeList(&process->reduced_sections);
        process->reduced_sections.head = NULL;
        copyList(&process->reduced_sections, process->new_sections);
        reduceList(&process->reduced_sections);
        process->sections_dirty = false;
    }

    for (struct Node *current = process->reduced_sections.head; current != NULL; current = current->next) {
        // Re-check rate limit inside loop
        if (counter > MAX_DUMP_COUNT || extracted_data_size > MAX_EXTRACTED_SIZE) {
            break;
        }

        if (!getWrittenToFlag(current)) {
            continue;
        }

        uint64_t length = current->end - current->start;

        size_t scan_len = length < HASH_SCAN_SIZE ? length : HASH_SCAN_SIZE;
        uint8_t scan_buf[HASH_SCAN_SIZE] = {0};

        int ret = gemu_virtual_memory_read(cpu, current->start, scan_buf, scan_len);
        if (ret != 0) {
            fprintf(stderr, "Failed to read memory for hash at 0x%lx\n", current->start);
            continue;
        }

        if (is_section_already_dumped(gemu_instance, current->start, length, scan_buf, scan_len)) {
            continue;
        }

        dump_section_to_file(cpu, current, process);
        unsetWrittenFlagForRange(current->start, current->end, process->new_sections);
    }
}
