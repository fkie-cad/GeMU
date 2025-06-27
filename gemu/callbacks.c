#define USE_SYSCALL_NAMES
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

bool gemu_use_memcb = false;
bool gemu_use_exec = false;
bool gemu_use_translation = false;
bool gemu_use_syscall = true;
 // This should be set to true by default. This will make it impossible to miss compilation in case setup is delayed.
bool gemu_compile_syscall_helper = true;
int counter = 0;
long long extracted_data_size = 0;


bool* getWrittenFlagForNode(struct MappedMemoryNode* mmapNode) {
    Gemu *gemu_instance = gemu_get_instance();
    WinThread* other_thread = get_winthread_for_pid(gemu_instance->win_spec, mmapNode->other_ID);
    if (other_thread == NULL) {
        return NULL;
    }
    hwaddr start = mmapNode->other_start;
    hwaddr end = mmapNode->other_start + mmapNode->other_size;

    struct Node* current = other_thread->new_sections->head;
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
            // Remove the current node from the list
            if (prev == NULL) {
                // Removing the head node
                singleList->head = current->next;
            } else {
                // Removing a node that is not the head
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


void check_for_unpacking(CPUState *cpu, TranslationBlock *tb, WinThread *thread, Gemu *gemu_instance){
    if (counter > 100000 || extracted_data_size > 10e+9) {
        return;
    }
    // checking for unpacking

    struct Node* temp_section = NULL;

    if (thread->cache_section == NULL || !(cpu->env_ptr->eip >= thread->cache_section->start && cpu->env_ptr->eip < thread->cache_section->end)){
        struct Node* temp_section = getNodeForAddress(cpu->env_ptr->eip, thread->new_sections);
        thread->cache_section = temp_section;
    }
    else {
        temp_section = thread->cache_section;
    }

    // getting the temp section

    if (temp_section == NULL) {
        thread->cache_section = NULL;
        print_memory_map(cpu, thread);
        temp_section = getNodeForAddress(cpu->env_ptr->eip, thread->new_sections);
        thread->cache_section = temp_section;
    }

    //getting the memory map

    struct SingleLinkedList* list = getMemoryMappedList(gemu_instance->mapped_sections_waitinglist, thread->Process.ID);
    if (list != NULL) {
        bool list_is_empty = iterateAndUpdateList(list, thread->new_sections);
        if (list_is_empty == true) {
            removeList(gemu_instance->mapped_sections_waitinglist, thread->Process.ID);
        }
    }
    if (getWrittenToFlag(temp_section)) {
        struct DoubleLinkedList new_list;
        copyList(&new_list, thread->new_sections);
        reduceList(&new_list);
        struct Node* section = getNodeForAddress(cpu->env_ptr->eip, &new_list);
        if(thread->cache_section_written != NULL && (
            (thread->cache_section_written->start >= section->start && thread->cache_section_written->start <= section->end) ||
            (thread->cache_section_written->end >= section->start && thread->cache_section_written->end <= section->end) 
        ))
            thread->cache_section_written = NULL;

        uint64_t length = section->end - section->start;
        uint8_t *buf = malloc(length + 1);
        gemu_virtual_memory_rw(cpu, section->start, buf, length, false);
        extracted_data_size += length;
        char filename[261];
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC_RAW, &now);
        wi_extract_module_list(cpu, thread);
        ModuleNode* module = is_within_range(thread->current_modules, temp_section->start, temp_section->end);
        if (module != NULL) {
            sprintf(filename, "dumps/%llu_0x%lx_%s_%lu_dump_nr_%d", thread->Process.ID, section->start, module->file,
                    (now.tv_sec - start_time->tv_sec) * 1000 + (now.tv_nsec - start_time->tv_nsec) / 1000000, counter);
        }
        else{
            sprintf(filename, "dumps/%llu_0x%lx_mw_%lu_dump_nr_%d", thread->Process.ID, section->start, (now.tv_sec - start_time->tv_sec) * 1000 + (now.tv_nsec - start_time->tv_nsec) / 1000000, counter);
        }
        unsetWrittenFlagForRange(section->start, section->end, thread->new_sections);
        counter += 1;
        mkdir("dumps", 0777);
        FILE* file = fopen(filename, "wb");
        if (file != NULL && length != 0) {
            fwrite(buf, 1, length, file);
            fclose(file);
            printf("Data successfully written to %s\n", filename);
        } else {
            perror("Error opening file");
        }
        free(buf);
        freeList(&new_list);
    }
}

void gemu_cb_before_tb_exec(CPUState *cpu, TranslationBlock *tb)
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

    WinThread *thread = wi_current_thread(gemu_instance->win_spec, cpu, true);
    if (thread == NULL) {
        // Exit early if the current program is not the one we want to watch
        return;
    }

    target_ulong rip = cpu->env_ptr->eip;
    hkr_try_exec_hook(gemu_instance->hooker, rip, cpu, tb, thread, CB_BEFORE_TB_EXEC);
    hkr_try_exec_hook(gemu_instance->hooker, rip, cpu, tb, thread, EXIT_FROM_API);

    return;
}


WinProcess* gemu_helper_get_current_process(void){

    Gemu *gemu_instance = gemu_get_instance();

    CPUState *cpu_new = current_cpu;

    WinThread *thread = wi_current_thread(gemu_instance->win_spec, cpu_new, true);
    if (thread == NULL) {
        return NULL;
    }
    return &thread->Process;
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

    WinThread *thread = wi_current_thread(gemu_instance->win_spec, cpu_new, true);
    if (thread == NULL || !g_hash_table_contains(gemu_instance->pids_to_lookout_for, GINT_TO_POINTER(thread->Process.ID))) {
        // Exit early if the current program is not the one we want to watch
        return;
    }

    // char* funcname = lookup_syscall(gemu_instance, &thread->Process, cpu->regs[R_EAX]);
    const char* funcname2 = SYSCALL_NAMES[syscall_enum];
    
    printf("SYSCALL: %lx %s\n", cpu->regs[R_EAX], funcname2);
    pipe_logger_before_syscall_exec_enum(cpu_new, syscall_enum, thread);

    //printf("%llu:E,0x%lx,%i\n", thread->Process.ID, cpu->env_ptr->eip, tb->size);
    return;
}

void gemu_cb_sysret(CPUX86State *cpu)
{
    if (cpu == NULL) {
        return;
    }
    Gemu *gemu_instance = gemu_get_instance();

    CPUState *cpu_new = current_cpu;

    WinThread *thread = wi_current_thread(gemu_instance->win_spec, cpu_new, true);
    if (thread == NULL || !g_hash_table_contains(gemu_instance->pids_to_lookout_for, GINT_TO_POINTER(thread->Process.ID))) {
        // Exit early if the current program is not the one we want to watch
        return;
    }

    if(thread->syscall_return_hook.active == false){
        // sysret without hooked syscall"
        return;
    }
    pipe_logger_after_syscall_exec(cpu_new, thread);
    thread->syscall_return_hook.active = false;
}

void gemu_cb_after_block_translation(CPUState *cpu, TranslationBlock *tb)
{
    if (cpu == NULL || tb == NULL || in_kernel_mode(cpu) ) {
        return;
    }

    Gemu *gemu_instance = gemu_get_instance();
    WinThread *thread = wi_current_thread(gemu_instance->win_spec, cpu, true);
    if (thread == NULL) {
        // Exit early if the current program is not the one we want to watch
        return;
    }

    //QWORD processid;
    //QWORD threadid;
    //get_current_pid_and_tid(cpu, &processid, &threadid);
    //printf("%llu:%llu:B:0x%lx,%i\n", thread->Process.ID, thread->ThreadId, cpu->env_ptr->eip, tb->size);
    //thread->ThreadId = threadid;
    //printf("%llu:B:0x%lx,%i\n", thread->Process.ID, cpu->env_ptr->eip, tb->size);

    check_for_unpacking(cpu, tb, thread, gemu_instance);
}



void gemu_cb_phys_memory_written(CPUArchState *env, target_ulong addr, uint64_t val, size_t size, uintptr_t retaddr)
{
    CPUState *cpu = env_cpu(env);
    if (env == NULL || addr > 0xffff800000000000) {
        return;
    }

    Gemu *gemu_instance = gemu_get_instance();

    WinThread *thread = wi_current_thread(gemu_instance->win_spec, cpu, true);
    if (thread == NULL) {
        // Exit early if the current program is not the one we want to watch
        return;
    }

    if(thread->cache_section_written != NULL && addr >= thread->cache_section_written->start && addr <= thread->cache_section_written->end)
        return;
    struct Node* section = getNodeForAddress(addr, thread->new_sections);

    if (section == NULL) {
        thread->cache_section = NULL;
        print_memory_map(cpu, thread);
        section = getNodeForAddress(addr, thread->new_sections);
    }
    thread->cache_section_written = section;

    struct SingleLinkedList* list = getMemoryMappedList(gemu_instance->mapped_sections_waitinglist, thread->Process.ID);
    if (list != NULL) {
        bool list_is_empty = iterateAndUpdateList(list, thread->new_sections);
        if (list_is_empty == true) {
            removeList(gemu_instance->mapped_sections_waitinglist, thread->Process.ID);
        }
    }

    if (section != NULL) {
        setWrittenFlag(section, true);
    }
}

void update_memory_map_from_env(CPUArchState *env){
    CPUState *cpu = env_cpu(env);
    if (env == NULL || in_kernel_mode(cpu)) {
        return;
    }
    Gemu *gemu_instance = gemu_get_instance();
    WinThread *thread = wi_current_thread(gemu_instance->win_spec, cpu, true);
    if (thread == NULL) {
        // Exit early if the current program is not the one we want to watch
        return;
    }
    print_memory_map(cpu, thread);
}
