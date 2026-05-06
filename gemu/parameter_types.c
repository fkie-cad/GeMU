#include "gemu/parameter_types.h"
#include "gemu/gemu.h"
#include "gemu/utils.h"
#include <string.h>

static int count_dereferences(const char *s) {
    int i = 0;
    while (*s) {
        if (*s == '*') { i++; }
        s++;
    }
    return i;
}

#define MAX_TYPE_HANDLERS 32

typedef enum {
    MATCH_TYPE_NAMES,   // param->type is in a null-terminated list
    MATCH_PARAM_NAMES,  // param->name is in a null-terminated list
} MatchMode;

typedef struct {
    MatchMode mode;
    const char **names;
    type_handler_fn fn;
} TypeHandlerEntry;

static TypeHandlerEntry handler_table[MAX_TYPE_HANDLERS];
static int handler_count = 0;
static type_handler_fn default_handler = NULL;

// --- registration ---

void register_type_name_handler(const char **type_names, type_handler_fn fn) {
    if (handler_count >= MAX_TYPE_HANDLERS) {
        fprintf(stderr, "parameter_types: MAX_TYPE_HANDLERS (%d) exceeded, increase the limit\n", MAX_TYPE_HANDLERS);
        abort();
    }
    handler_table[handler_count++] = (TypeHandlerEntry){
        .mode  = MATCH_TYPE_NAMES,
        .names = type_names,
        .fn    = fn,
    };
}

void register_param_name_handler(const char **param_names, type_handler_fn fn) {
    if (handler_count >= MAX_TYPE_HANDLERS) {
        fprintf(stderr, "parameter_types: MAX_TYPE_HANDLERS (%d) exceeded, increase the limit\n", MAX_TYPE_HANDLERS);
        abort();
    }
    handler_table[handler_count++] = (TypeHandlerEntry){
        .mode  = MATCH_PARAM_NAMES,
        .names = param_names,
        .fn    = fn,
    };
}

// --- dispatch ---

static bool matches(const TypeHandlerEntry *entry, const FunctionParameter *param) {
    switch (entry->mode) {
        case MATCH_TYPE_NAMES:
            for (int i = 0; entry->names[i]; i++) {
                if (strcmp(entry->names[i], param->type) == 0) {
                    return true;
                }
            }
            return false;
        case MATCH_PARAM_NAMES:
            for (int i = 0; entry->names[i]; i++) {
                if (strcmp(entry->names[i], param->name) == 0) {
                    return true;
                }
            }
            return false;
        default:
            return false;
    }
}

void dispatch_type_handler(CPUState *cpu, const FunctionParameter *param,
                           QWORD value, cJSON *output, WinProcess *process,
                           bool is32bit) {
    for (int i = 0; i < handler_count; i++) {
        if (matches(&handler_table[i], param)) {
            handler_table[i].fn(cpu, param, value, output, process, is32bit);
            return;
        }
    }
    if (default_handler) {
        default_handler(cpu, param, value, output, process, is32bit);
    }
}

// --- built-in handlers ---

static const char *PSTR[] = {"Windows.Win32.Foundation.PSTR", "LPCWSTR", NULL};
static const char *PWSTR[] = {"Windows.Win32.Foundation.PWSTR", "LPCSTR", NULL};
static const char *PROCESS_INFORMATION_PARAS[] = {
    "Windows.Win32.System.Threading.PROCESS_INFORMATION*",
    "LPPROCESS_INFORMATION", NULL};
static const char *DO_NOT_DEREFRENCE[] = {"lpBaseAddress", "lpAddress", "*BaseAddress",
                                          "PVOID", "ULONG",
                                          "corinfo_method_info",
                                          NULL};
static const char *DO_NOT_DEREFRENCE_TYPES[] = {"*CLIENT_ID", NULL};

static bool handle_pstr(CPUState *cpu, const FunctionParameter *param,
                        QWORD value, cJSON *output, WinProcess *process, bool is32bit) {
    char *s = malloc(256);
    guest_astrncpy(cpu, s, 256, value);
    cJSON_AddStringToObject(output, param->name, s);
    free(s);
    return true;
}

static bool handle_pwstr(CPUState *cpu, const FunctionParameter *param,
                         QWORD value, cJSON *output, WinProcess *process, bool is32bit) {
    char *s = malloc(512);
    guest_wstrncpy(cpu, s, 512, value);
    cJSON_AddStringToObject(output, param->name, s);
    free(s);
    return true;
}

static void fill_processinformation(CPUState *cpu, QWORD value, cJSON *processinformation,
                                    WinProcess *process, bool is32bit) {
    DWORD dwProcessId, dwThreadId;
    QWORD hProcess, hThread;

    if (is32bit) {
        PROCESS_INFORMATION32 process_info;
        gemu_virtual_memory_read(cpu, value, (uint8_t *) &process_info, sizeof process_info);
        dwProcessId = process_info.dwProcessId;
        dwThreadId  = process_info.dwThreadId;
        hProcess    = process_info.hProcess;
        hThread     = process_info.hThread;
    } else {
        PROCESS_INFORMATION64 process_info;
        gemu_virtual_memory_read(cpu, value, (uint8_t *) &process_info, sizeof process_info);
        dwProcessId = process_info.dwProcessId;
        dwThreadId  = process_info.dwThreadId;
        hProcess    = process_info.hProcess;
        hThread     = process_info.hThread;
    }

    Gemu *gemu = gemu_get_instance();
    printf("NEW PID: %i\n", dwProcessId);
    printf("PROCESS_CREATED parent=%llu child=%i image=unknown\n", process->ID, dwProcessId);
    g_hash_table_insert(gemu->pids_to_lookout_for, GINT_TO_POINTER(dwProcessId), NULL);
    cJSON_AddNumberToObject(processinformation, "ProcessId", dwProcessId);
    cJSON_AddNumberToObject(processinformation, "ThreadId", dwThreadId);
    cJSON_AddNumberToObject(processinformation, "hProcess", hProcess);
    cJSON_AddNumberToObject(processinformation, "hThread", hThread);
    g_hash_table_insert(process->process_handles, GINT_TO_POINTER(hProcess), GINT_TO_POINTER(dwProcessId));
}

static bool handle_process_information(CPUState *cpu, const FunctionParameter *param,
                                       QWORD value, cJSON *output, WinProcess *process,
                                       bool is32bit) {
    cJSON *process_information = cJSON_AddObjectToObject(output, param->name);
    fill_processinformation(cpu, value, process_information, process, is32bit);
    return true;
}

static bool handle_do_not_dereference(CPUState *cpu, const FunctionParameter *param,
                                      QWORD value, cJSON *output, WinProcess *process,
                                      bool is32bit) {
    cJSON_AddNumberToObject(output, param->name, value);
    return true;
}

static bool handle_dereference_default(CPUState *cpu, const FunctionParameter *param,
                                       QWORD value, cJSON *output, WinProcess *process,
                                       bool is32bit) {
    int dereferences = count_dereferences(param->type);
    cJSON_AddNumberToObject(output, param->name,
                            dereference_pointer(cpu, value, dereferences, is32bit));
    return true;
}

void init_type_handlers(void) {
    register_type_name_handler(PSTR,                       handle_pstr);
    register_type_name_handler(PWSTR,                      handle_pwstr);
    register_type_name_handler(PROCESS_INFORMATION_PARAS,  handle_process_information);
    register_type_name_handler(DO_NOT_DEREFRENCE_TYPES,    handle_do_not_dereference);
    register_param_name_handler(DO_NOT_DEREFRENCE,         handle_do_not_dereference);
    default_handler = handle_dereference_default;
}
