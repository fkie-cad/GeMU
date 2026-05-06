#define USE_SYSCALL_NAMES
#include "gemu/gemu.h"
#include "gemu/calling_conventions.h"
#include "gemu/parameter_types.h"
#include "gemu/cJSON.h"
#include "gemu/fastcheck.h"
#include "gemu/memorymapper.h"
#include "gemu/mappedwaitinglist.h"
#include "glib.h"
#include "gemu/apidoc.h"
#include "gemu/hooks.h"
#include "gemu/win_spector.h"
#include "gemu/dotnet_spector.h"
#include "syscalltable.c"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

Gemu *gemu_instance = NULL;

extern bool gemu_use_exec;
extern bool gemu_use_syscall;
extern bool gemu_compile_syscall_helper;

static void pipe_logger_before_tb_exec(target_ulong pc, CPUState *cpu,
                                       TranslationBlock *tb, hook_t *hook, WinProcess *process);



#define IdxInLineDLLName 0
#define IdxInLineFunctionName 1
#define IdxInLineAddress 2
#define IdxInLineBitness 3

int file_counter = 0;
long long extracted_data_size_files = 0;
char symbolmapping[256];
char apidoc[256];
// Add programs(substring is matched) to this comma separated list, no space
// between.
char WATCHED_PROGRAMS[256];
char tracking_mode_str[256];
char dotnet_mode_str[256];
char syscalltable[256];
// struct timespec* start_time = NULL;


QWORD dereference_pointer(CPUState *cpu, QWORD value, int times, bool is32bit) {
    if (is32bit){
        value = value & (DWORD)(-1);
    }
    if (value == 0) {
        return 0;
    }
    int size = is32bit ? 4 : 8;
    for (int i = 0; i < times; i++) {
        QWORD new_value = 0;
        gemu_virtual_memory_read(cpu, value, (uint8_t *) &new_value, size);
        value = new_value;
    }
    return value;
}



cJSON *read_parameters(Gemu *gemu_instance, CPUState *cpu, const char *func_name,
                       const char *dll_name, out_parameter_list_t *out_parameter_list,
                       WinProcess *process, CallingConvention cc) {
    cJSON *output = cJSON_CreateObject();
    cJSON_AddStringToObject(output, "func", func_name);
    cJSON_AddStringToObject(output, "dll_name", dll_name);
    out_parameter_list->number_of_outparameters = 0;

    FunctionApi *function_entry = get_function_api(gemu_instance->parameter_lookup, func_name);
    if (function_entry == NULL) {
        return output;
    }
    int outparameter = 0;
    for (int i = 0; i < function_entry->num_parameters; i++) {
        FunctionParameter *parameter = &function_entry->parameters[i];
        QWORD value = get_parameter(cpu, i, cc);
        if (is_in_parameter(parameter)) {
            dispatch_type_handler(cpu, parameter, value, output, process, cc_is32bit(cc));
        }
        if (is_out_parameter(parameter)) {
            out_parameter_list->out_parameters[outparameter].address = value;
            out_parameter_list->out_parameters[outparameter].parameter_number = i;
            outparameter += 1;
        }
    }
    out_parameter_list->number_of_outparameters = outparameter;
    return output;
}

cJSON *read_out_parameters(Gemu *gemu, CPUState *cpu, const char *func_name,
                           const char *dll_name, int number_of_outparameters,
                           out_parameter out_parameters[], WinProcess *process,
                           CallingConvention cc) {
    cJSON *output = cJSON_CreateObject();
    cJSON_AddStringToObject(output, "func", func_name);
    cJSON_AddStringToObject(output, "dll_name", dll_name);
    if (number_of_outparameters <= 0) {
        return output;
    }

    FunctionApi *function_entry = get_function_api(gemu_instance->parameter_lookup, func_name);
    if (function_entry == NULL) {
        return output;
    }
    for (int i = 0; i < number_of_outparameters; i++) {
        FunctionParameter *parameter = &function_entry->parameters[out_parameters[i].parameter_number];
        QWORD addr = out_parameters[i].address;
        dispatch_type_handler(cpu, parameter, addr, output, process, cc_is32bit(cc));
    }
    return output;
}

void handle_ZwOpenProcess_Exit(cJSON *output, WinProcess *process) {
    // {"func":"ZwOpenProcess","dll_name":"ntdll.dll","ProcessHandle":48,"ClientId":2796}
    // printf("insert %i and %i to handle dict of process %lli\n",
    //        cJSON_GetObjectItemCaseSensitive(output, "ProcessHandle")->valueint,
    //        cJSON_GetObjectItemCaseSensitive(output, "ClientId")->valueint,
    //        process->ID);
    if (cJSON_GetObjectItemCaseSensitive(output, "ProcessHandle")->valueint > 0 &&
        cJSON_GetObjectItemCaseSensitive(output, "ClientId")->valueint > 0) {
        g_hash_table_insert(
                process->process_handles,
                GINT_TO_POINTER(cJSON_GetObjectItemCaseSensitive(output, "ProcessHandle")
                        ->valueint),
                GINT_TO_POINTER(cJSON_GetObjectItemCaseSensitive(output, "ClientId")
                        ->valueint));
    }
}


void handle_ZwMapViewOfSection_exit(Gemu *gemu_instance, WinProcess *process, cJSON* output) {
    // printf("I am in ZwMapViewOfSection\n");
    int sectionHandle = cJSON_GetObjectItemCaseSensitive(output, "SectionHandle")->valueint;
    int handle = cJSON_GetObjectItemCaseSensitive(output, "hProcess")->valueint;
    hwaddr remoteAddress = cJSON_GetObjectItemCaseSensitive(output, "remoteAddress")->valueint;
    size_t ViewSize = cJSON_GetObjectItemCaseSensitive(output, "ViewSize")->valueint;
    target_ulong pid = process->ID;
    if (g_hash_table_contains(process->process_handles, GINT_TO_POINTER(handle))) {
        pid = (target_ulong) g_hash_table_lookup(process->process_handles, GINT_TO_POINTER(handle));
        // printf("ZwMapViewOfSection injection into PID %li\n", pid);
        struct MappedRange* rangeptr = g_hash_table_lookup(process->section_handles, GINT_TO_POINTER(sectionHandle));
        if (rangeptr == NULL) {
            // printf("could not find the correct range for the handle therefore a shared state is not possible\n");
            addMappedMemoryNodeToList(gemu_instance->mapped_sections_waitinglist, pid, remoteAddress, ViewSize, 0, 0, 0);
            printList(getMemoryMappedList(gemu_instance->mapped_sections_waitinglist, pid));
        }
        else {
            // printf("I found the range in the other process :)\n");
            addMappedMemoryNodeToList(gemu_instance->mapped_sections_waitinglist, pid, remoteAddress, ViewSize, process->ID, rangeptr->start, rangeptr->size);
            addMappedMemoryNodeToList(gemu_instance->mapped_sections_waitinglist, process->ID, rangeptr->start, rangeptr->size, pid, remoteAddress, ViewSize);
            // printf("i added the nodes to both lists\n");
        }
        return;
    }
    if (remoteAddress > 0 && ViewSize > 0) {
        addMappedMemoryNodeToList(gemu_instance->mapped_sections_waitinglist, pid, remoteAddress, ViewSize, 0, 0, 0);
        printList(getMemoryMappedList(gemu_instance->mapped_sections_waitinglist, pid));
        struct MappedRange* rangeptr = (struct MappedRange*) malloc(sizeof(struct MappedRange));
        rangeptr->start = remoteAddress;
        rangeptr->size = ViewSize;
        // printf("inserting into process->section_handles\n");
        g_hash_table_insert(process->section_handles, GINT_TO_POINTER(sectionHandle), rangeptr);
        // printf("successfully inserted\n");
    }
}

static void handle_NtCreateUserProcess_exit(Gemu *gemu_instance, WinProcess *process, cJSON* output, CPUState* cpu) {
    // printf("I am in NtCreateUserProcess\n");
    int pAttributeList = cJSON_GetObjectItemCaseSensitive(output, "AttributeList")->valueint;
    if(pAttributeList == 0){
        printf("Warning: Could not get PID from NtCreateUserProcess. AttributeList is NULL.\n");
        return;
    }
    
    target_ulong size_of_list;
    target_ulong ptr_current_attribute;
    PS_ATTRIBUTE current_attribute;
    gemu_virtual_memory_read(cpu, pAttributeList, (uint8_t*) &size_of_list, sizeof(size_of_list));
    ptr_current_attribute = pAttributeList + (sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE));
    CLIENT_ID64 client_id = {.ProcessId = 0, .ThreadId = 0};
    for (; ptr_current_attribute + sizeof(PS_ATTRIBUTE) <= pAttributeList + size_of_list; ptr_current_attribute += sizeof(PS_ATTRIBUTE)){
        gemu_virtual_memory_read(cpu, ptr_current_attribute, (uint8_t*) &current_attribute, sizeof(current_attribute));
        if (current_attribute.Attribute == PS_ATTRIBUTE_CLIENT_ID){
            gemu_virtual_memory_read(cpu, current_attribute.ValuePtr, (uint8_t*) &client_id, current_attribute.Size);
            break;
        }
    }

    if (client_id.ProcessId == 0){
        // printf("Warning: Could not get PID from NtCreateUserProcess. AttributeList did not contain PID.\n");
        return;
    }

    target_ulong process_handle = cJSON_GetObjectItemCaseSensitive(output, "ProcessHandle")->valueint;
    printf("PROCESS_CREATED parent=%llu child=%llu image=unknown\n",
           process->ID, client_id.ProcessId);
    g_hash_table_insert(gemu_instance->pids_to_lookout_for,
                        GINT_TO_POINTER(client_id.ProcessId), NULL);
    g_hash_table_insert(process->process_handles, GINT_TO_POINTER((int)process_handle), GINT_TO_POINTER((int)client_id.ProcessId));
    // printf("adding %lu, %llu to process handles\n", process_handle, client_id.ProcessId);
}

void pipe_logger_after_syscall_exec(CPUState *cpu, WinProcess* process, syscall_hook_t* hook) {
    target_ulong ret = get_return_value(cpu, CC_SYSCALL_64);
    Gemu *gemu = gemu_get_instance();
    int number_of_outparameters = hook->out_parameter_list.number_of_outparameters;
    const char* func_name = SYSCALL_NAMES[hook->syscall_enum];
    const char* dll_name = "syscall";
    out_parameter* out_parameters = hook->out_parameter_list.out_parameters;

    cJSON *output = read_out_parameters(gemu, cpu, func_name, dll_name,
                                        number_of_outparameters, out_parameters, process,
                                        CC_SYSCALL_64);

    // Merge in-parameters from entry into the output
    if (hook->in_parameters) {
        cJSON *item = hook->in_parameters->child;
        while (item) {
            cJSON *next = item->next;
            if (!cJSON_GetObjectItemCaseSensitive(output, item->string)) {
                cJSON_DetachItemViaPointer(hook->in_parameters, item);
                cJSON_AddItemToObject(output, item->string, item);
            }
            item = next;
        }
        cJSON_Delete(hook->in_parameters);
        hook->in_parameters = NULL;
    }

    QWORD pid;                                                                                                                                                                     
    QWORD tid;
    get_current_pid_and_tid(cpu, &pid, &tid, process);    
    printf("%llu:%llu:$-%s -> %li\n", pid, tid, cJSON_PrintUnformatted(output), ret);

    switch (hook->syscall_enum)
    {
        case NtOpenProcess:
            handle_ZwOpenProcess_Exit(output, process);
            break;

        case NtMapViewOfSection:
            handle_ZwMapViewOfSection_exit(gemu, process, output);
            break;

        case NtCreateUserProcess:
            handle_NtCreateUserProcess_exit(gemu, process, output, cpu);
            break;
    
        default:
            break;
    }

    cJSON_Delete(output);
}


static void pipe_logger_after_tb_exec(target_ulong pc, CPUState *cpu,
                                      TranslationBlock *tb, hook_t *hook, WinProcess *process) {
    target_ulong ret = get_return_value(cpu, hook->cc);
    Gemu *gemu = gemu_get_instance();
    const char *func_name = hook->func_name;
    const char *dll_name = hook->dll_name;
    int number_of_outparameters = hook->out_parameter_list.number_of_outparameters;
    out_parameter *out_parameters = hook->out_parameter_list.out_parameters;

    cJSON *output = read_out_parameters(gemu, cpu, func_name, dll_name,
                                        number_of_outparameters, out_parameters, process, hook->cc);

    // Merge in-parameters from entry into the output
    if (hook->in_parameters) {
        cJSON *item = hook->in_parameters->child;
        while (item) {
            cJSON *next = item->next;
            if (!cJSON_GetObjectItemCaseSensitive(output, item->string)) {
                cJSON_DetachItemViaPointer(hook->in_parameters, item);
                cJSON_AddItemToObject(output, item->string, item);
            }
            item = next;
        }
    }

    QWORD pid;
    QWORD tid;
    get_current_pid_and_tid(cpu, &pid, &tid, process);
    printf("%llu:%llu:$-%s -> %li\n", pid, tid, cJSON_PrintUnformatted(output), ret);

    //load library is always interesting, for DOTNET and WINAPI case
    if (unlikely(strncmp(func_name, "LoadLibrary", 11) == 0)) {
        wi_extract_module_list(cpu, process);
        handle_loaded_library(process->current_modules);
        // print_module_nodes(process->current_modules);
    }

    if (gemu_instance->tracking_mode & TRACKING_BASICBLOCK_WINAPI){
        if (strcmp(func_name, "ZwOpenProcess") == 0) {
            handle_ZwOpenProcess_Exit(output, process);
        }
        if (strcmp(func_name, "ZwMapViewOfSection") == 0) {
            handle_ZwMapViewOfSection_exit(gemu, process, output);
        }
    }

    if (gemu_instance->tracking_mode & TRACKING_BASICBLOCK_DOTNET){
        if (unlikely(strncmp(func_name, "getJit", 6) == 0)) {
            handle_getJit_exit(gemu, ret, cpu, hook->cc);
        }
        if (strcmp(func_name, "compileMethod") == 0) {
            int native_address = cJSON_GetObjectItemCaseSensitive(output, "nativeEntry")->valueint;
            handle_jit_compile_method(cpu, cJSON_GetObjectItemCaseSensitive(output, "corinfo_method_info")->valueint, native_address, pipe_logger_before_tb_exec, cc_is32bit(hook->cc));
        }
    }

    cJSON_Delete(output);
    // in_parameters is freed by hkr_remove_hook via cJSON_Delete on the hook
    hkr_remove_hook(gemu->hooker, pc);
}

void handle_ZwTerminateProcess(Gemu *gemu_instance, CPUState *cpu,
                                 WinProcess *process, const char *dll_name,
                                 const char *func_name, out_parameter_list_t *out_parameter_list,
                                 CallingConvention cc) {
    cJSON *output = read_parameters(gemu_instance, cpu, func_name, dll_name,
                                    out_parameter_list, process, cc);
    int handle = cJSON_GetObjectItemCaseSensitive(output, "ProcessHandle")->valueint;
    // This is hacky, but in most cases, handle 7 is the current process
    if ((handle == 0) || (handle == 7)) { 
        printf("Removing PID %lli\n", process->ID);
        //dump_all_binaries(cpu, process);
        g_hash_table_remove(gemu_instance->pids_to_lookout_for,
                            (gpointer) process->ID);
        if (g_hash_table_size(gemu_instance->pids_to_lookout_for) == 0) {
            printf("No more PIDs to monitor. Exiting...\n");
            gemu_destroy();
        }
    }
}

void dump_WriteVirtualMemory(cJSON *output, CPUState *cpu, WinProcess *process, int pid){
    QWORD start = cJSON_GetObjectItemCaseSensitive(output, "Buffer")->valueint;
    QWORD addr =
            cJSON_GetObjectItemCaseSensitive(output, "BaseAddress")->valueint;
    QWORD size =
            cJSON_GetObjectItemCaseSensitive(output, "NumberOfBytesToWrite")
                    ->valueint;
    if (size > 0x40000000 || extracted_data_size_files > 10e+9 || file_counter > 100000) {
        return;
    }
    uint8_t *buf = malloc(size + 1);
    extracted_data_size_files += size;
    gemu_virtual_memory_read(cpu, start, buf, size);
    char filename[261];
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &now);
    int timestamp = (now.tv_sec - start_time->tv_sec) * 1000 + (now.tv_nsec - start_time->tv_nsec) / 1000000;
    sprintf(filename, "dumps/%llu_%u_zwwritevirtualmemory_0x%llx_%u_dump_nr_%d", process->ID, pid, addr, timestamp, file_counter);
    file_counter += 1;
    gemu_dump_buffer_to_file(buf, size, filename);
    free(buf);
}

void handle_ZwWriteVirtualMemory(Gemu *gemu_instance, CPUState *cpu,
                                 WinProcess *process, const char *dll_name,
                                 const char *func_name, out_parameter_list_t *out_parameter_list,
                                 CallingConvention cc) {
    cJSON *output = read_parameters(gemu_instance, cpu, func_name, dll_name,
                                    out_parameter_list, process, cc);
    int handle = cJSON_GetObjectItemCaseSensitive(output, "ProcessHandle")->valueint;
    if (g_hash_table_contains(process->process_handles, GINT_TO_POINTER(handle))) {
        int pid = GPOINTER_TO_INT(g_hash_table_lookup(process->process_handles, GINT_TO_POINTER(handle)));
        printf("found injection into PID %i\n", pid);
        g_hash_table_insert(gemu_instance->pids_to_lookout_for, GINT_TO_POINTER(pid),
                            NULL);
        dump_WriteVirtualMemory(output, cpu, process, pid);

    }
    else if (handle > 10000) {
        dump_WriteVirtualMemory(output, cpu, process, process->ID);
    }
}

void handle_ZwWriteFile(Gemu *gemu_instance, CPUState *cpu, WinProcess *process,
                        const char *dll_name, const char *func_name, out_parameter_list_t *out_parameter_list,
                        CallingConvention cc) {
    cJSON *output = read_parameters(gemu_instance, cpu, func_name, dll_name,
                                    out_parameter_list, process, cc);

    if (file_counter > 10000 ||  extracted_data_size_files > 10e+9) {
        return;
    }

    QWORD start = cJSON_GetObjectItemCaseSensitive(output, "Buffer")->valueint;
    QWORD size = cJSON_GetObjectItemCaseSensitive(output, "Length")->valueint;
    if (size > 0x40000000) {
        return;
    }
    uint8_t *buf = malloc(size + 1);
    gemu_virtual_memory_read(cpu, start, buf, size);
    extracted_data_size_files += size;
    char filename[261];
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &now);
    QWORD filehandle = cJSON_GetObjectItemCaseSensitive(output, "FileHandle")->valueint;
    sprintf(filename, "dumps/%llu_%llu_writtenfile_%lu_nr_%d", process->ID, filehandle,
            (now.tv_sec - start_time->tv_sec) * 1000 + (now.tv_nsec - start_time->tv_nsec) / 1000000, file_counter);
    file_counter += 1;
    gemu_dump_buffer_to_file(buf, size, filename);
    free(buf);
}

static void handle_NtOpenFile(Gemu *gemu_instance, CPUState *cpu, WinProcess *process,
                        const char *dll_name, const char *func_name, out_parameter_list_t *out_parameter_list,
                        CallingConvention cc) {

    if (!(gemu_instance->tracking_mode & TRACKING_ACTIVATE_DOTNET_BB_IF_FOUND)){
        return;
    }

    // printf("I'm in NtOpenFile\n")
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING object_name;

    cJSON *output = read_parameters(gemu_instance, cpu, func_name, dll_name,
                                    out_parameter_list, process, cc);

    QWORD attributes_addr = cJSON_GetObjectItemCaseSensitive(output, "ObjectAttributes")->valueint;

    cJSON_Delete(output);

    gemu_virtual_memory_read(cpu, attributes_addr, (uint8_t*) &attributes, sizeof(attributes));
    gemu_virtual_memory_read(cpu, attributes.ObjectName, (uint8_t*) &object_name, sizeof(object_name));

    if(sizeof(attributes) != attributes.Length){
        printf("missmatch in OBJECT_ATTRIBUTES size\n!");
    }
    char buf[256];
    int maxread = 256;
    if (object_name.Length < 256){
        maxread = object_name.Length;
    }

    guest_wstrncpy(cpu, buf, maxread, object_name.Buffer);

    printf("File Object Name %s\n", buf);

    if (strcasestr(buf, "mscoree")){
        printf("FOUND .NET\n");
        gemu_dotnet_found(gemu_instance);
    }

}

bool handle_special_apis(Gemu *gemu_instance, CPUState *cpu, const char *dll_name,
                         const char *func_name, WinProcess *process, out_parameter_list_t *out_parameter_list,
                         CallingConvention cc) {
    if (!(gemu_instance->tracking_mode & TRACKING_BASICBLOCK_WINAPI)){
        return false;
    }

    if (strcmp(func_name, "ZwTerminateProcess") == 0) {
        // printf("handling a special API %s for ZwTerminateProcess\n", func_name);
        handle_ZwTerminateProcess(gemu_instance, cpu, process, dll_name, func_name,
                                  out_parameter_list, cc);
        return true;
    }
    if (strcmp(func_name, "ZwOpenProcess") == 0) {
        // printf("handling a special API %s for ZwOpenProcess\n", func_name);
        return true;
     }
    if (strcmp(func_name, "ZwWriteVirtualMemory") == 0) {
        // printf("handling a special API %s for ZwWriteVirtualMemory\n", func_name);
        handle_ZwWriteVirtualMemory(gemu_instance, cpu, process, dll_name,
                                    func_name, out_parameter_list, cc);
    }
    if (strcmp(func_name, "ZwAllocateVirtualMemory") == 0) {
        // printf("handling a special API %s for ZwAllocateVirtualMemory\n", func_name);
        return true;
    }
    if (strcmp(func_name, "ZwWriteFile") == 0) {
        // printf("handling a special API %s for ZwWriteFile\n", func_name);
        handle_ZwWriteFile(gemu_instance, cpu, process, dll_name, func_name, out_parameter_list, cc);
        return true;
    }
    if (strcmp(func_name, "ZwMapViewOfSection") == 0) {
        // printf("handling a special API %s for ZwMapViewOfSection\n", func_name);
        return true;
    }
    return false;
}

static bool handle_special_syscall_apis_enum(Gemu *gemu_instance, CPUState *cpu, const char *dll_name,
                         syscall_t syscall, WinProcess *process, syscall_hook_t *hook,
                         CallingConvention cc) {
    const char* func_name = SYSCALL_NAMES[syscall];
    switch (syscall){
        case NtTerminateProcess:
            // printf("handling a special API %s for NtTerminateProcess\n", func_name);
            handle_ZwTerminateProcess(gemu_instance, cpu, process, dll_name, func_name,
                                    &hook->out_parameter_list, cc);
            return true;
        case NtOpenProcess:
            // printf("handling a special API %s for NtOpenProcess\n", func_name);
            return true;
        case NtWriteVirtualMemory:
            // printf("handling a special API %s for NtWriteVirtualMemory\n", func_name);
            handle_ZwWriteVirtualMemory(gemu_instance, cpu, process, dll_name,
                                        func_name, &hook->out_parameter_list, cc);
            return true;
        case NtAllocateVirtualMemory:
            // printf("handling a special API %s for NtAllocateVirtualMemory\n", func_name);
            return true;
        case NtWriteFile:
            // printf("handling a special API %s for NtWriteFile\n", func_name);
            handle_ZwWriteFile(gemu_instance, cpu, process, dll_name, func_name,
                               &hook->out_parameter_list, cc);
            return true;
        case NtMapViewOfSection:
            // printf("handling a special API %s for NtMapViewOfSection\n", func_name);
            return true;
        case NtCreateUserProcess:
            // printf("handling a special API %s for NtCreateUserProcess\n", func_name);
            return true;
        case NtOpenFile:
            // printf("handling a special API %s for NtOpenFile\n", func_name);
            handle_NtOpenFile(gemu_instance, cpu, process, dll_name, func_name,
                              &hook->out_parameter_list, cc);
            return true;
        default:
            return false;
    }
}


void pipe_logger_before_syscall_exec_enum(CPUState *cpu,
                                     syscall_t syscall, WinProcess *process) {
    CallingConvention cc = CC_SYSCALL_64;
    Gemu *gemu_instance = gemu_get_instance();

    QWORD pid, tid;
    get_current_pid_and_tid(cpu, &pid, &tid, process);
    WinThread* current_thread = wi_current_thread(process, tid);
    syscall_hook_t* hook_ptr = &current_thread->syscall_return_hook;
    if (hook_ptr->active) {
        printf("ALARM: SYSCALLS DO NOT WORK AS WE THOUGHT THEY DID!\n");
        printf("IF YOU SEE THIS MESSAGE PLEASE REPORT IT TO THE DEVELOPERS\n");
    }
    hook_ptr->active = true;
    hook_ptr->out_parameter_list.number_of_outparameters = -2;
    hook_ptr->syscall_enum = syscall;
    const char *dll_name = "syscall";
    const char* func_name = SYSCALL_NAMES[syscall];

    handle_special_syscall_apis_enum(gemu_instance, cpu, dll_name, syscall, process, hook_ptr, cc);

    cJSON *output = read_parameters(gemu_instance, cpu, func_name, dll_name,
                                    &hook_ptr->out_parameter_list, process, cc);

    printf("%llu:%llu:$+%s\n", pid, tid, cJSON_PrintUnformatted(output));
    cJSON_DeleteItemFromObjectCaseSensitive(output, "func");
    cJSON_DeleteItemFromObjectCaseSensitive(output, "dll_name");
    hook_ptr->in_parameters = output;
    // output is now owned by the hook's in_parameters — freed at exit
}


static void pipe_logger_before_tb_exec(target_ulong pc, CPUState *cpu,
                                       TranslationBlock *tb, hook_t *hook, WinProcess *process) {

    Gemu *gemu_instance = gemu_get_instance();
    const char *dll_name = hook->dll_name;
    const char *func_name = hook->func_name;
    CallingConvention cc = hook->cc;

    hook_t newHook = {.addr = 0,
            .callbacks = NULL,
            .callback_count = 0,
            .dll_name = "",
            .func_name = "",
            .out_parameter_list.number_of_outparameters = -2,
            .in_parameters = NULL,
            .cc = cc};

    if (unlikely(strncmp(func_name, "Zw", 2) == 0)) {
        handle_special_apis(gemu_instance, cpu, dll_name, func_name, process, &newHook.out_parameter_list, cc);
    }

    bool succ_cb_before_tb =
            hk_add_cb_pair(&newHook, EXIT_FROM_API, pipe_logger_after_tb_exec);
    if (!succ_cb_before_tb) {
        g_printerr("Failed to add callback pair for hook: %s:%s\n", dll_name,
                   func_name);
        return;
    }
    g_utf8_strncpy(newHook.dll_name, dll_name, sizeof(newHook.dll_name) - 1);
    g_utf8_strncpy(newHook.func_name, func_name, sizeof(newHook.func_name) - 1);

    newHook.addr = get_return_address(cpu, cc);
    cJSON *output = read_parameters(gemu_instance, cpu, func_name, dll_name,
                                    &newHook.out_parameter_list, process, cc);

    QWORD pid;
    QWORD tid;
    get_current_pid_and_tid(cpu, &pid, &tid, process);
    printf("%llu:%llu:$+%s\n", pid, tid, cJSON_PrintUnformatted(output));

    if (strstr(func_name, "CreateProcess") != NULL) {
        cJSON *cmd = cJSON_GetObjectItemCaseSensitive(output, "lpCommandLine");
        if (cmd == NULL)
            cmd = cJSON_GetObjectItemCaseSensitive(output, "CommandLine");
        cJSON *app = cJSON_GetObjectItemCaseSensitive(output, "lpApplicationName");
        if (app == NULL)
            app = cJSON_GetObjectItemCaseSensitive(output, "ApplicationName");
        const char *command = (cmd && cmd->valuestring && cmd->valuestring[0]) ? cmd->valuestring :
                              (app && app->valuestring && app->valuestring[0]) ? app->valuestring : "unknown";
        printf("PROCESS_CREATING parent=%llu command=%s\n", pid, command);
    }

    // Remove func and dll_name from output before storing as in_parameters
    // (these are already in the hook struct and will be re-added at exit)
    cJSON_DeleteItemFromObjectCaseSensitive(output, "func");
    cJSON_DeleteItemFromObjectCaseSensitive(output, "dll_name");
    newHook.in_parameters = output;

    if (hkr_add_new_hook(gemu_instance->hooker, newHook) && newHook.addr != 0) {
        fc_set(&gemu_instance->hooker->fc, newHook.addr);
    }

    if (gemu_instance->tracking_mode & TRACKING_BASICBLOCK_DOTNET){
        if (unlikely(strncmp(func_name, "compileMethod", 13) == 0)) {
            handle_jit_compile_method(cpu, cJSON_GetObjectItemCaseSensitive(output, "corinfo_method_info")->valueint, 0, pipe_logger_before_tb_exec, cc_is32bit(hook->cc));
        }
    }
    // output is now owned by the hook's in_parameters — freed at exit
}


void handle_getJit_exit(Gemu *gemu_instance, target_ulong result, CPUState *cpu, CallingConvention cc) {
    printf("FOUND getJit result: 0x%lX\n", result);
    target_ulong compile_method;
    compile_method = dereference_pointer(cpu, result, 2, cc_is32bit(cc));
    printf("FOUND compileMethod at: 0x%lX\n", compile_method);
    int success = hook_address("compileMethod", "clrjit.dll", (target_long)compile_method,
                               pipe_logger_before_tb_exec,
                               cc_is32bit(cc) ? CC_THISCALL_32 : CC_WIN64);
    if (success == 1){
        printf("hooking might have worked\n");
    } else {
        printf("hooking has failed\n");
    }
}

// Function to insert a ModuleNode into the sorted list
bool insert_sorted_module_node(ModuleNode **head, ModuleNode *new_node) {
    if (*head == NULL || (*head)->base >= new_node->base) {
        new_node->next = *head;
        *head = new_node;
    } else {
        ModuleNode *current = *head;
        while (current->next != NULL && current->next->base < new_node->base) {
            current = current->next;
        }
        if(current->next != NULL && current->next->base == new_node->base){
            return false;
        }
        new_node->next = current->next;
        current->next = new_node;
    }
    return true;
}

// Helper function to convert a string to lowercase
void to_lowercase(char *str) {
    for (; *str; ++str) {
        *str = tolower(*str);
    }
}


void free_list(ModuleNode* head) {
    ModuleNode* temp;
    while (head != NULL) {
        temp = head;
        head = head->next;
        free(temp);
    }
}

void print_module_nodes(ModuleNode *head) {
    ModuleNode *current = head;
    printf("printing modules that have been saved\n");
    while (current != NULL) {
        printf("Base: 0x%llX, Size: 0x%llX, File: %s\n", current->base, current->size, current->file);
        current = current->next;
    }
}

// Function to extract the module list and insert nodes based on file list
// FIXME const strings
void wi_extract_module_list(CPUState *cpu, WinProcess *process) {
    CPUX86State *env = cpu->env_ptr;
    ModuleNode *head = NULL;

    bool isSysWOW64 = false;

    // extract modules 64bit
    TEB64 teb;
    PEB64 peb;
    SegmentCache gs = env->segs[R_GS];
    gemu_virtual_memory_read(cpu, gs.base, (uint8_t *) &teb, sizeof teb);
    gemu_virtual_memory_read(cpu, teb.ProcessEnvironmentBlock, (uint8_t *) &peb, sizeof peb);
    PEB_LDR_DATA64 ldr_data;
    LDR_DATA_TABLE_ENTRY64 currentModule;
    gemu_virtual_memory_read(cpu, peb.Ldr, (uint8_t *) &ldr_data, sizeof ldr_data);
    LIST_ENTRY* next_module = ldr_data.InMemoryOrderModuleList.Flink;
    // start extracting 64bit modules
    do {
        //substract sizeof(LIST_ENTRY), because we use MemoryOrder instead of LoadOrder
        //Using MemoryOrder, because it seems to contain no loops.
        gemu_virtual_memory_read(cpu, (target_ulong) next_module-sizeof(LIST_ENTRY), (uint8_t *) &currentModule, sizeof currentModule);
        char *current_module_name = malloc(currentModule.FullDllName.u.Length + 1);
        guest_wstrncpy(cpu, current_module_name, currentModule.FullDllName.u.Length + 1, currentModule.FullDllName.Buffer);

        to_lowercase(current_module_name);
        if (strcmp("c:\\windows\\system32\\wow64.dll", current_module_name) == 0){
            isSysWOW64 = true;
        }

        ModuleNode *new_node = malloc(sizeof(ModuleNode));
        new_node->size = currentModule.SizeOfImage;
        new_node->file = current_module_name;
        new_node->base = currentModule.DllBase;
        new_node->next = NULL;

        bool no_duplicate = insert_sorted_module_node(&head, new_node);
        if (!no_duplicate){
            break;
        }

        if (next_module == currentModule.InMemoryOrderLinks.Flink) {
            break;
        }
        next_module = currentModule.InMemoryOrderLinks.Flink;
    } while (next_module != ldr_data.InMemoryOrderModuleList.Flink);

    if (isSysWOW64) {
        // extract modules 64bit
        TEB32 teb32;
        PEB32 peb32;
        SegmentCache fs = env->segs[R_FS];
        gemu_virtual_memory_read(cpu, fs.base, (uint8_t *) &teb32, sizeof teb32);
        gemu_virtual_memory_read(cpu, teb32.ProcessEnvironmentBlock, (uint8_t *) &peb32, sizeof peb32);
        if (peb32.Ldr == 0) {
            process->current_modules = head;
            return;
        }
        PEB_LDR_DATA32 ldr_data;
        LDR_DATA_TABLE_ENTRY32 currentModule;
        gemu_virtual_memory_read(cpu, peb32.Ldr, (uint8_t *) &ldr_data, sizeof ldr_data);
        DWORD next_module = ldr_data.InMemoryOrderModuleListFlink;
        do {
            gemu_virtual_memory_read(cpu, next_module, (uint8_t *) &currentModule, sizeof currentModule);
            if (currentModule.DllBase != 0) {
                char *current_module_name = malloc(currentModule.FullDllName.Length + 1);
                guest_wstrncpy(cpu, current_module_name, currentModule.FullDllName.Length + 1, currentModule.FullDllName.Buffer);

                to_lowercase(current_module_name);
                if (strncmp(current_module_name, "c:\\windows\\system32\\", 20) == 0){
                    memcpy(current_module_name+11, "syswow64", 8);
                }

                ModuleNode *new_node = malloc(sizeof(ModuleNode));
                new_node->size = currentModule.SizeOfImage;
                new_node->file = current_module_name;
                new_node->base = currentModule.DllBase;
                new_node->next = NULL;

                bool no_duplicate = insert_sorted_module_node(&head, new_node);
                if (!no_duplicate){
                    break;
                }
            }
            if (next_module == currentModule.InMemoryOrderLinksFlink) {
                break;
            }
            next_module = currentModule.InMemoryOrderLinksFlink;
        } while (next_module != ldr_data.InMemoryOrderModuleListFlink);
    }
    free_list(process->current_modules);
    process->current_modules = head;
}

void try_extract_kernel32_address(Gemu *gemu_instance, CPUState *cpu, WinProcess *process){
    wi_extract_module_list(cpu, process);
    ModuleNode* current = process->current_modules;
    while (current != NULL) {
        if (strcmp(current->file,"c:\\windows\\syswow64\\kernelbase.dll") == 0){
            // printf("found kernel\n");
            gemu_instance->kernel32_32bit_found = true;
            handle_loaded_library(process->current_modules);
            return;
        }
        if (strcmp(current->file,"c:\\windows\\system32\\kernelbase.dll") == 0){
            // printf("found kernel\n");
            gemu_instance->kernel32_64bit_found = true;
            handle_loaded_library(process->current_modules);
            return;
        }
        current = current->next;
    }
}

static void free_g_ptr_array(gpointer data) {
    g_ptr_array_free((GPtrArray *)data, TRUE);  // TRUE to free the array elements as well
}

static GHashTable *process_file(const gchar *file_path) {
    GError *error = NULL;
    GIOChannel *channel = g_io_channel_new_file(file_path, "r", &error);

    if (error) {
        g_printerr("Error opening file: %s\n", error->message);
        g_error_free(error);
        return NULL;
    }

    gchar *line;

    GHashTable *hash_table
    = g_hash_table_new_full (g_str_hash,  /* Hash function  */
                            g_str_equal, /* Comparator     */
                            g_free,
                            free_g_ptr_array);  /* Val destructor */

    GPtrArray *function_entries;

    while (g_io_channel_read_line(channel, &line, NULL, NULL, &error) ==
           G_IO_STATUS_NORMAL) {
        gchar **parts = g_strsplit(line, ";", 0);
        to_lowercase(parts[IdxInLineDLLName]);
        function_entries = g_hash_table_lookup(hash_table, (gpointer)parts[IdxInLineDLLName]);
        if (function_entries == NULL){
            function_entries = g_ptr_array_new_with_free_func((GDestroyNotify) g_strfreev);
            g_hash_table_insert(hash_table, (gpointer)g_strdup(parts[IdxInLineDLLName]), function_entries);
        }
        g_ptr_array_add(function_entries, parts);
        g_free(line);
    }

    if (error) {
        g_printerr("Error reading file: %s\n", error->message);
        g_error_free(error);
    }

    g_io_channel_unref(channel);

    return hash_table;
}


static gboolean read_dynamic_symbols_txt(const GPtrArray *function_entries, target_long correction) {
    if (function_entries) {
        for (guint i = 0; i < function_entries->len; ++i) {
            gchar **parts = g_ptr_array_index(function_entries, i);
            if (g_strv_length(parts) != 4) {
                printf("Invalid line in symbols.txt: %s\n", parts[0]);
                return 0;
            }
            g_strstrip(parts[IdxInLineBitness]); // remove trailing whitespace
            CallingConvention cc = cc_from_string(parts[IdxInLineBitness]);
            target_ulong addr = (target_long)g_ascii_strtoull(parts[IdxInLineAddress], NULL, 10) + correction;
            hook_address(parts[IdxInLineFunctionName], parts[IdxInLineDLLName], addr, pipe_logger_before_tb_exec, cc);
        }
        return 1;
    }
    return 0;
}


void handle_loaded_library(ModuleNode *head) {
    ModuleNode *current = head;
    
    GPtrArray *functions;
    GHashTable *hash_table_modules = gemu_get_instance()->modules_to_hook;


    while (current != NULL) {
        functions = g_hash_table_lookup(hash_table_modules, (gpointer)current->file);
        if (functions != NULL){
            // printf("FOUND %s BASE: 0x%llX\n", current->file, current->base);
            bool succ_symb_read = read_dynamic_symbols_txt(functions, current->base);
            if (!succ_symb_read) {
                g_printerr("Error reading symbols file\n");
            }
            g_hash_table_remove(hash_table_modules, (gpointer)current->file);
        }
        current = current->next;
    }
}

gboolean hook_address(const char *func_name, const char *dll_name,
                      target_long address, void *function, CallingConvention cc) {
    hook_t newHook = {.addr = 0,
            .callbacks = NULL,
            .callback_count = 0,
            .dll_name = "",
            .func_name = "",
            .out_parameter_list.number_of_outparameters = -1,
            .in_parameters = NULL,
            .cc = cc};


    g_utf8_strncpy(newHook.dll_name, dll_name,
                    sizeof(newHook.dll_name) - 1);
    g_utf8_strncpy(newHook.func_name, func_name,
                    sizeof(newHook.func_name) - 1);


    bool succ_cb_before_tb = hk_add_cb_pair(&newHook, CB_BEFORE_TB_EXEC, function);

    if (!succ_cb_before_tb) {
        g_printerr("Failed to add callback pair for hook\n");
        return 0;
    }

    newHook.addr = address;
    if (hkr_add_new_hook(gemu_instance->hooker, newHook)) {
        fc_set(&gemu_instance->hooker->fc, newHook.addr);
        // g_print("Hooked [%llu | %012llX] %s!%s\n", newHook.addr,
        // newHook.addr,
        //        newHook.func_name, newHook.dll_name);
    } else {
        g_printerr("Hook [%ld | %012lX] %s!%s could not be added", newHook.addr,
                    newHook.addr, newHook.func_name, newHook.dll_name);
        return 0;
    }
    return 1;
}


#define check_type_size(_type, _expected) \
    if (sizeof(_type) != _expected) { \
        printf("ERROR: type " #_type " has wrong size! Expected 0x%lX, got %lX\n", (size_t)_expected, sizeof(_type)); \
    }

#define check_peb_offset(_out_okay, _struct, _member, _expected) \
    if (offsetof(_struct, _member) != _expected) { \
        printf("ERROR: PEB offset of member " #_member " is wrong. Expected 0x%lX, got 0x%lX\n", offsetof(_struct, _member), ((size_t)_expected)); \
        _out_okay = 0; \
    } else { \
        printf("PEB offset of " #_member " is okay.\n"); \
    }


static TrackingMode get_tracking_mode_from_str(char* tracking_mode_str, char* dotnet_mode_str){
    TrackingMode result = TRACKING_OFF;
    if (strcasecmp(tracking_mode_str, "SYSCALL") == 0 || tracking_mode_str[0] == 0) { //default
        result |= TRACKING_SYSCALLS;
    } else if (strcasecmp(tracking_mode_str, "BASICBLOCK") == 0) {
        result |= TRACKING_BASICBLOCK_WINAPI;
    } else if (strcasecmp(tracking_mode_str, "BOTH") == 0) {
        result |= TRACKING_BASICBLOCK_WINAPI | TRACKING_SYSCALLS;
    } else {
        printf("ERROR: TRACKING MODE NOT OKAY!\n");
        exit(2);
    }

    if (strcasecmp(dotnet_mode_str, "ON") == 0) {
        result |= TRACKING_BASICBLOCK_DOTNET;
    } else if (strcasecmp(dotnet_mode_str, "AUTO") == 0) {
        if (result & TRACKING_BASICBLOCK_WINAPI){
            result |= TRACKING_BASICBLOCK_DOTNET;
        } else {
            result |= TRACKING_ACTIVATE_DOTNET_BB_IF_FOUND;
        }
    } else if (strcasecmp(dotnet_mode_str, "OFF") == 0 || dotnet_mode_str[0] == 0) {  //default
        // do nothing
    } else {
        printf("ERROR: DOTNET MODE NOT OKAY!\n");
        exit(2);
    }
    return result;
}

static void gemu_refresh_tracking_mode(Gemu *gemu){
    printf("refresh tracking mode settings\n");
    TrackingMode tracking_mode = gemu->tracking_mode;
    gemu_use_exec = gemu->recording && (tracking_mode & TRACKING_BASICBLOCK);
    gemu_compile_syscall_helper = (tracking_mode & TRACKING_SYSCALLS);
    gemu_use_syscall = gemu->recording && gemu_compile_syscall_helper;
}

void gemu_dotnet_found(Gemu *gemu){
    gemu->tracking_mode &= ~TRACKING_ACTIVATE_DOTNET_BB_IF_FOUND;
    gemu->tracking_mode |= TRACKING_BASICBLOCK_DOTNET;
    gemu_refresh_tracking_mode(gemu);
}

void gemu_start_recording(void){
    printf("gemu starts recording\n");
    Gemu* gemu = gemu_get_instance();
    gemu->recording = true;
    gemu_refresh_tracking_mode(gemu);
}

void gemu_init(void) {
    printf("Initializing Gemu...\n");
    int peb_okay = 1;
    printf("Checking PEB...\n");
    check_type_size(INT64, 8);
    check_type_size(QWORD, 8);
    check_type_size(INT32, 4);
    check_type_size(DWORD, 4);
    check_type_size(union LARGE_INTEGER, 8);
    check_peb_offset(peb_okay, PEB64, Mutant, 0x008);
    check_peb_offset(peb_okay, PEB64, NumberOfProcessors, 0x0B8);
    check_peb_offset(peb_okay, PEB64, dummy02, 0x0BC);
    check_peb_offset(peb_okay, PEB64, CriticalSectionTimeout, 0x0C0);
    check_peb_offset(peb_okay, PEB64, HeapSegmentReserve, 0x0C8);
    check_peb_offset(peb_okay, PEB64, MaximumNumberOfHeaps, 0x0EC);
    check_peb_offset(peb_okay, PEB64, OSBuildNumber, 0x120);
    if (!peb_okay) {
        printf("ERROR: PEB NOT OKAY!\n");
        exit(1);
    } else {
        printf("PEB is okay.\n");
    }

    // Process Tracking Mode
    printf("tracking_mode_str: '%s'\n", tracking_mode_str);
    printf("dotnet_mode_str: '%s'\n", dotnet_mode_str);
    TrackingMode tracking_mode = get_tracking_mode_from_str(tracking_mode_str, dotnet_mode_str);
    printf("tracking_mode: 0x%x\n", tracking_mode);

    Gemu instance = {
            .hooker = init_hooker(100000),
            .win_spec = init_windows_introspecter(200, WATCHED_PROGRAMS),
            .parameter_lookup = init_apidoc(apidoc),
            .syscall_lookup = parse_file(syscalltable),
            .syscall_lookup_for_build = NULL,
            .syscall_lookup_for_build_enum = NULL,
            .pids_to_lookout_for = g_hash_table_new(NULL, NULL),
            .mapped_sections_waitinglist = allocateHashMap(),
            .kernel32_32bit_found = false,
            .kernel32_64bit_found = false,
            .modules_to_hook = process_file(symbolmapping),
            .tracking_mode = tracking_mode,
            .recording = false,
            .dumped_hashes = g_hash_table_new(g_direct_hash, g_direct_equal)
    };

    gemu_refresh_tracking_mode(&instance);

    gemu_instance = malloc(sizeof(instance));
    if (gemu_instance == NULL) {
        perror("Memory could not be allocated for Gemu instance");
        exit(EXIT_FAILURE);
    }
    *gemu_instance = instance;
    init_type_handlers();
    printf("Done initializing Gemu\n");
}

Gemu *gemu_get_instance(void) {
    if (gemu_instance == NULL) {
        gemu_init();
    }
    return gemu_instance;
}

void gemu_destroy(void) {
    if (gemu_instance != NULL) {
        hkr_destroy(gemu_instance->hooker);
        wi_destroy(gemu_instance->win_spec);
        g_hash_table_destroy(gemu_instance->dumped_hashes);
        free(gemu_instance);
        gemu_instance = NULL;
        exit(0);
    }
    printf("Exiting Gemu\n");
}
