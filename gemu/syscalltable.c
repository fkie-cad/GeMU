#define USE_SYSCALL_NAMES
#include "gemu/syscalltable.h"

#include <stdio.h>

static const cJSON *get_syscalls_for_build(Gemu *gemu_instance, const WinProcess* process) {
    // TODO(OPTIMIZE): This build number lookup and string conversion needs to be done only once
    //                 since it cannot change between processes on the same guest.
    const int build_number = process->PEB.OSBuildNumber;

    printf("OS BUILD NUMBER: %d\n", build_number);
    char build_number_str[12];  // 12 should be more than enough. Current highest build number: 25398
    snprintf(build_number_str, 12, "%d", build_number);

    const cJSON *syscalls_for_build = NULL;
    syscalls_for_build = cJSON_GetObjectItemCaseSensitive(gemu_instance->syscall_lookup,
                                                          build_number_str);
    return syscalls_for_build;
}

const char *lookup_syscall(Gemu *gemu_instance, const WinProcess* process, const int syscall_number) {
    const cJSON *syscalls_for_build = gemu_instance->syscall_lookup_for_build;
    if(!syscalls_for_build){
        syscalls_for_build = get_syscalls_for_build(gemu_instance, process);
        gemu_instance->syscall_lookup_for_build = syscalls_for_build;
    }

    char syscall_number_str[12];  // 12 should be more than enough. Current highest syscall has 4 digits
    snprintf(syscall_number_str, 12, "%d", syscall_number);

    if (!cJSON_IsObject(syscalls_for_build)) {
        return "BUILD NOT FOUND";
    }

    const cJSON *syscall = NULL;
    syscall = cJSON_GetObjectItemCaseSensitive(syscalls_for_build,
                                               syscall_number_str);
    if (!cJSON_IsString(syscall)) {
        return "SYSCALL NOT FOUND";
    }

    return syscall->valuestring;
}



static GHashTable *get_syscalls_for_build_enum(Gemu *gemu_instance, const WinProcess* process) {
    const cJSON *syscalls_for_build = get_syscalls_for_build(gemu_instance, process);
    // TODO: Free
    GHashTable* syscalls_for_build_enum = g_hash_table_new(g_direct_hash, g_direct_equal);
    // char syscall_number_str[12];  // 12 should be more than enough. Current highest syscall has 4 digits
    cJSON* syscall_entry;
    int syscall_number;
    char* syscall_name;
    cJSON_ArrayForEach(syscall_entry, syscalls_for_build) {
        syscall_number = strtol(syscall_entry->string, NULL, 10);
        syscall_name = syscall_entry->valuestring;
        for(int syscall_enum=1; syscall_enum<NUM_SYSCALLS; syscall_enum++){
            if(strcmp(syscall_name, SYSCALL_NAMES[syscall_enum]) == 0){
                g_hash_table_insert(syscalls_for_build_enum, GINT_TO_POINTER(syscall_number), GINT_TO_POINTER(syscall_enum));
            }
        }
    }
    return syscalls_for_build_enum;
} 


syscall_t lookup_syscall_enum(Gemu *gemu_instance, const int syscall_number, WinProcess* (*get_process) (void)) {
    const GHashTable *syscalls_for_build_enum = gemu_instance->syscall_lookup_for_build_enum;
    if(!syscalls_for_build_enum){
        WinProcess * process = get_process();
        if(!process){
            return UNKNOWN_SYSCALL;
        }
        syscalls_for_build_enum = get_syscalls_for_build_enum(gemu_instance, process);
        gemu_instance->syscall_lookup_for_build_enum = syscalls_for_build_enum;
    }
    return GPOINTER_TO_INT(g_hash_table_lookup((GHashTable *)syscalls_for_build_enum, GINT_TO_POINTER(syscall_number)));
}