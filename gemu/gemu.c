#define USE_SYSCALL_NAMES
#define USE_KEY_VALUE_INFORMATION_CLASS_NAMES
#include "gemu/gemu.h"
#include "gemu/calling_conventions.h"
#include "gemu/parameter_types.h"
#include "gemu/cJSON.h"
#include "gemu/fastcheck.h"
#include "gemu/memorymapper.h"
#include "gemu/mappedwaitinglist.h"
#include "gemu/base64.h"
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

static void handle_NtQueryValueKey(Gemu *gemu_instance, CPUState *cpu, WinProcess *process,
                        const char *dll_name, const char *func_name, cJSON *output);



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
    if (cJSON_GetObjectItemCaseSensitive(output, "ProcessHandle") &&
        cJSON_GetObjectItemCaseSensitive(output, "ClientId") &&
        cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "ProcessHandle")) > 0 &&
        cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "ClientId")) > 0) {
        g_hash_table_insert(
                process->process_handles,
                GINT_TO_POINTER((int)cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "ProcessHandle"))),
                GINT_TO_POINTER((int)cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "ClientId"))));
    }
}


void handle_ZwDuplicateObject_exit(cJSON *output, WinProcess *process) {
    int source_process_handle = (int)cJSON_GetUint64Value(
        cJSON_GetObjectItemCaseSensitive(output, "SourceProcessHandle"));
    uint64_t source_handle_raw =
        cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "SourceHandle"));
    uint64_t target_handle_raw =
        cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "TargetHandle"));
    if (target_handle_raw == 0 || target_handle_raw > INT_MAX) {
        return; // Invalid target, return
    }
    int target_handle = (int)target_handle_raw;

    // The handle we resolve the PID from is normally SourceHandle. When
    // SourceHandle is NtCurrentProcess (the (HANDLE)-1 pseudo-handle), the
    // caller is asking for a handle to the process that SourceProcessHandle
    // refers to, so we look that one up instead. Match both the 64-bit and
    // 32-bit guest representations of -1.
    int lookup_handle;
    const char *kind;
    if (source_handle_raw == (uint64_t)-1 || source_handle_raw == 0xFFFFFFFF) { // pseudo handle, use current process
        lookup_handle = source_process_handle;
        kind = "pseudo-handle -> ";
    } else {
        lookup_handle = (int)source_handle_raw; // use given non-pseudo handle
        kind = "";
    }
    if (lookup_handle <= 0 ||
        !g_hash_table_contains(process->process_handles,
                               GINT_TO_POINTER(lookup_handle))) {
        return;
    }

    int pid = GPOINTER_TO_INT(g_hash_table_lookup(
        process->process_handles, GINT_TO_POINTER(lookup_handle)));
    printf("ZwDuplicateObject: %starget_handle=%d maps to PID %d\n",
           kind, target_handle, pid);
    g_hash_table_insert(process->process_handles, GINT_TO_POINTER(target_handle),
                        GINT_TO_POINTER(pid));
}


void handle_ZwMapViewOfSection_exit(Gemu *gemu_instance, WinProcess *process, cJSON* output) {
    // printf("I am in ZwMapViewOfSection\n");
    if (!cJSON_GetObjectItemCaseSensitive(output, "SectionHandle")) {
        return;
    }
    int sectionHandle = (int)cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "SectionHandle"));
    int handle = (int)cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "hProcess"));
    hwaddr remoteAddress = cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "remoteAddress"));
    size_t ViewSize = cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "ViewSize"));
    target_ulong pid = process->ID;
    if (g_hash_table_contains(process->process_handles, GINT_TO_POINTER(handle))) {
        pid = (target_ulong) g_hash_table_lookup(process->process_handles, GINT_TO_POINTER(handle));
        printf("ZwMapViewOfSection injection into PID %li\n", pid);
        g_hash_table_insert(gemu_instance->pids_to_lookout_for, GINT_TO_POINTER(pid), NULL);
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
    target_ulong pAttributeList = cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "AttributeList"));
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

    target_ulong process_handle = cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "ProcessHandle"));
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

        case NtDuplicateObject:
            handle_ZwDuplicateObject_exit(output, process);
            break;

        case NtQueryValueKey:
            if (ret == 0)
                handle_NtQueryValueKey(gemu, cpu, process, dll_name, func_name, output);
            break;

        default:
            break;
    }

    cJSON_Delete(output);
}


// Upper bound for guest-controlled registry value/struct sizes. Lengths read
// from guest memory are clamped to this to avoid unbounded allocations driven
// by a malicious guest.
#define REGISTRY_VALUE_MAX_LENGTH (1u << 20) // 1 MiB

// Bounds-safe lookups: kind/class come from guest-controlled data, so an
// out-of-range value must not index past the name tables.
static const char *key_value_kind_name(KEY_VALUE_INFORMATION_KIND kind) {
    if ((size_t) kind >= sizeof(KEY_VALUE_INFORMATION_KIND_NAMES) / sizeof(KEY_VALUE_INFORMATION_KIND_NAMES[0]))
        return "REG_VALUE_INVALID";
    return KEY_VALUE_INFORMATION_KIND_NAMES[kind];
}

static const char *key_value_class_name(KEY_VALUE_INFORMATION_CLASS cls) {
    if ((size_t) cls >= sizeof(KEY_VALUE_INFORMATION_CLASS_NAMES) / sizeof(KEY_VALUE_INFORMATION_CLASS_NAMES[0]))
        return "InvalidKeyValueInfoClass";
    return KEY_VALUE_INFORMATION_CLASS_NAMES[cls];
}

static void extract_registry_data_by_kind(CPUState *cpu, KEY_VALUE_INFORMATION_KIND kind, unsigned char *data, cJSON *output, size_t data_length, target_ulong guest_va) {
    // data is data_length bytes of UTF-16LE; clamp the guest-controlled length,
    // then size for one byte per code unit plus a NUL terminator. Allocate on
    // the heap rather than the stack so a large (or malicious) length can't
    // exhaust the stack.
    if (data_length > REGISTRY_VALUE_MAX_LENGTH)
        data_length = REGISTRY_VALUE_MAX_LENGTH;
    size_t buf_len = (data_length >> 1) + 1;
    switch (kind) {
        case RegValueString:
        case RegValueExpandString: {
            unsigned char *buf = malloc(buf_len);
            if (buf == NULL)
                break;
            copy_wide_to_normal_string(buf, data, buf_len);
            over_write_qemu_substring(cpu, (char *) buf, data_length, guest_va, false);
            cJSON_AddStringToObject(output, "Data", (char *) buf);
            free(buf);
            break;
        }

        case RegValueDword: {
            if (data_length < sizeof(DWORD))
                break;
            DWORD extracted_dword = *((DWORD*) data);
            cJSON_AddNumberToObject(output, "Data", extracted_dword);
            break;
        }

        case RegValueMultiString: {
            unsigned char *buf = malloc(buf_len);
            if (buf == NULL)
                break;
            copy_wide_to_normal_string(buf, data, buf_len);
            over_write_qemu_substring(cpu, (char *) buf, data_length, guest_va, false);
            cJSON *json_array = cJSON_CreateArray();
            unsigned char *current_string = buf;
            for (size_t i = 1; i < buf_len; i++) {
                if (buf[i] == '\0') {
                    if (buf[i-1] == '\0')
                        break;
                    cJSON_AddItemToArray(json_array, cJSON_CreateString((const char*)current_string));
                    current_string = &buf[i+1];
                }
            }
            cJSON_AddItemToObject(output, "Data", json_array);
            free(buf);
            break;
        }

        case RegValueBinary: {
            size_t output_length;
            unsigned char *base64_string = base64_encode((const unsigned char *)data, data_length, &output_length);
            if ((int64_t) output_length > 0)
                cJSON_AddStringToObject(output, "Data", (char *) base64_string);
            free(base64_string);
            break;
        }

        default:
            printf("Key Value Kind not implemented yet:  %s\n", key_value_kind_name(kind));
            break;
    }
}

static void handle_NtQueryValueKey(Gemu *gemu_instance, CPUState *cpu, WinProcess *process,
                        const char *dll_name, const char *func_name, cJSON *output) {

    // NtQueryValueKey's ResultLength out-param is a PULONG (always 32-bit
    // regardless of guest bitness); read the actual length the kernel wrote
    // back through that pointer.
    target_ulong result_length_ptr = cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "ResultLength"));
    uint32_t reported_length = 0;
    gemu_virtual_memory_read(cpu, result_length_ptr, (uint8_t*) &reported_length, sizeof(reported_length));

    cJSON *class_item = cJSON_GetObjectItemCaseSensitive(output, "KeyValueInformationClass");
    if (class_item == NULL)
        return;
    KEY_VALUE_INFORMATION_CLASS value_information_class = class_item->valueint;
    PVOID_64 value = (PVOID_64) cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "KeyValueInformation"));

    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "KeyValueInformationClass", key_value_class_name(value_information_class));

    // result_length is guest-controlled; clamp it so the read/allocation below
    // can't be driven to an arbitrary size by the guest. complete_struct is
    // exactly result_length bytes, so every guest-supplied offset/length read
    // from it must be validated against result_length to avoid heap over-reads.
    size_t result_length = reported_length;
    if (result_length > REGISTRY_VALUE_MAX_LENGTH)
        result_length = REGISTRY_VALUE_MAX_LENGTH;

    KEY_VALUE_INFORMATION_KIND type;
    unsigned char *complete_struct = malloc(result_length);
    if (complete_struct == NULL) {
        cJSON_Delete(result);
        return;
    }
    gemu_virtual_memory_read(cpu, value, (uint8_t*) complete_struct, result_length);

    switch (value_information_class) {
        case KeyValueFullInformation: {
            // Need at least the fixed header to read the length/offset fields.
            size_t header = offsetof(KEY_VALUE_FULL_INFORMATION_32, Data);
            if (result_length < header)
                break;

            PKEY_VALUE_FULL_INFORMATION_32 kv_full_info = (PKEY_VALUE_FULL_INFORMATION_32) complete_struct;
            type = (KEY_VALUE_INFORMATION_KIND) kv_full_info->Type;

            cJSON_AddNumberToObject(result, "TitleIndex", kv_full_info->TitleIndex);
            cJSON_AddStringToObject(result, "Type", key_value_kind_name(type));
            cJSON_AddNumberToObject(result, "DataLength", kv_full_info->DataLength);
            cJSON_AddNumberToObject(result, "NameLength", kv_full_info->NameLength);

            if (kv_full_info->NameLength > 0) {
                // The name sits right after the header; clamp its length to the
                // bytes actually present in complete_struct.
                size_t name_length = kv_full_info->NameLength;
                if (name_length > result_length - header)
                    name_length = result_length - header;
                size_t name_buf_len = (name_length >> 1) + 1;
                unsigned char *name_buf = malloc(name_buf_len);
                if (name_buf != NULL) {
                    copy_wide_to_normal_string(name_buf, (unsigned char *) &kv_full_info->Data, name_buf_len);
                    target_ulong name_va = value + offsetof(KEY_VALUE_FULL_INFORMATION_32, Data);
                    over_write_qemu_substring(cpu, (char *) name_buf, name_length, name_va, false);
                    cJSON_AddStringToObject(result, "Name", (char *) name_buf);
                    free(name_buf);
                }
            } else {
                cJSON_AddStringToObject(result, "Name", "");
            }

            // DataOffset/DataLength are guest-controlled; only descend if the
            // described region lies within complete_struct.
            if (kv_full_info->DataOffset <= result_length) {
                size_t data_length = kv_full_info->DataLength;
                if (data_length > result_length - kv_full_info->DataOffset)
                    data_length = result_length - kv_full_info->DataOffset;
                target_ulong data_va = value + kv_full_info->DataOffset;
                extract_registry_data_by_kind(cpu, type, complete_struct + kv_full_info->DataOffset, result, data_length, data_va);
            }
            break;
        }
        case KeyValuePartialInformation: {
            size_t header = offsetof(KEY_VALUE_PARTIAL_INFORMATION_32, Data);
            if (result_length < header)
                break;

            PKEY_VALUE_PARTIAL_INFORMATION_32 kv_partial_info = (PKEY_VALUE_PARTIAL_INFORMATION_32) complete_struct;
            type = (KEY_VALUE_INFORMATION_KIND) kv_partial_info->Type;

            cJSON_AddNumberToObject(result, "TitleIndex", kv_partial_info->TitleIndex);
            cJSON_AddStringToObject(result, "Type", key_value_kind_name(type));
            cJSON_AddNumberToObject(result, "DataLength", kv_partial_info->DataLength);

            // Data follows the header; clamp its length to what's present.
            size_t data_length = kv_partial_info->DataLength;
            if (data_length > result_length - header)
                data_length = result_length - header;
            target_ulong data_va = value + offsetof(KEY_VALUE_PARTIAL_INFORMATION_32, Data);
            extract_registry_data_by_kind(cpu, type, &(kv_partial_info->Data), result, data_length, data_va);
            break;
        }
        default:
            printf("KeyValueInformationClass NOT YET IMPLEMENTED!\n");
            break;
    }

    free(complete_struct);

    char *result_string = cJSON_PrintUnformatted(result);
    printf("&NtQueryValueKey: %s\n", result_string);
    cJSON_free(result_string);
    cJSON_Delete(result);
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
        if (strcmp(func_name, "ZwDuplicateObject") == 0) {
            handle_ZwDuplicateObject_exit(output, process);
        }
        if (strcmp(func_name, "NtQueryValueKey") == 0 && ret == 0) {
            handle_NtQueryValueKey(gemu, cpu, process, dll_name, func_name, output);
        }
    }

    if (gemu_instance->tracking_mode & TRACKING_BASICBLOCK_DOTNET){
        if (unlikely(strncmp(func_name, "getJit", 6) == 0)) {
            handle_getJit_exit(gemu, ret, cpu, hook->cc);
        }
        if (strcmp(func_name, "compileMethod") == 0) {
            target_ulong native_address = cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "nativeEntry"));
            handle_jit_compile_method(cpu, cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "corinfo_method_info")), native_address, pipe_logger_before_tb_exec, cc_is32bit(hook->cc));
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
    int handle = (int)cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "ProcessHandle"));
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
    QWORD start = cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "Buffer"));
    QWORD addr = cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "BaseAddress"));
    QWORD size = cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "NumberOfBytesToWrite"));
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
    int handle = (int)cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "ProcessHandle"));
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

    QWORD start = cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "Buffer"));
    QWORD size = cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "Length"));
    if (size > 0x40000000) {
        return;
    }
    uint8_t *buf = malloc(size + 1);
    gemu_virtual_memory_read(cpu, start, buf, size);
    extracted_data_size_files += size;
    char filename[261];
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &now);
    QWORD filehandle = cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "FileHandle"));
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

    QWORD attributes_addr = cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "ObjectAttributes"));

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
    if (strcmp(func_name, "ZwDuplicateObject") == 0) {
        return true;
    }
    if (strcmp(func_name, "NtQueryValueKey") == 0) {
        // handled at exit in pipe_logger_after_tb_exec; nothing to do on entry
        return true;
    }
    return false;
}

// WIP: patches a NULL timeout on NtAlpcSendWaitReceivePort to 100ms to prevent
// an infinite block when the target ALPC service is not running.
// TODO: Implement for Basic Block tracking mode?
static void handle_NtAlpcSendWaitReceivePort_entry(CPUState *cpu) {
    QWORD timeout_ptr = get_parameter(cpu, 7, CC_SYSCALL_64);
    if (timeout_ptr != 0) {
        return;
    }
    INT64 timeout_value = -1000000; // 100ms relative timeout in 100ns units
    target_ulong rsp = cpu->env_ptr->regs[R_ESP];
    target_ulong timeout_addr = rsp - 16;
    gemu_virtual_memory_write(cpu, timeout_addr, (uint8_t *)&timeout_value, 8);
    gemu_virtual_memory_write(cpu, rsp + (8 + 7 * 8), (uint8_t *)&timeout_addr, 8);
    printf("NtAlpcSendWaitReceivePort: patched NULL timeout to 100ms\n");
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
        case NtDuplicateObject:
            // SourceProcessHandle is captured via the generic in_parameters
            // mechanism and read from the merged output at exit
            return true;
        case NtAlpcSendWaitReceivePort:
            handle_NtAlpcSendWaitReceivePort_entry(cpu);
            return true;
        case NtQueryValueKey:
            // handled at exit in pipe_logger_after_syscall_exec; nothing to do on entry
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
            handle_jit_compile_method(cpu, cJSON_GetUint64Value(cJSON_GetObjectItemCaseSensitive(output, "corinfo_method_info")), 0, pipe_logger_before_tb_exec, cc_is32bit(hook->cc));
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

void print_module_nodes(ModuleNode *head, unsigned long long pid) {
    ModuleNode *current = head;
    printf("printing modules that have been saved for pid %llu\n", pid);
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
