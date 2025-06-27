
#ifndef GEMU_WIN_SPECTOR_HPP
#define GEMU_WIN_SPECTOR_HPP

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "qemu/typedefs.h"
#include "utils.h"
#include "qemu/qht.h"
#include "peb_teb.h"
#include "glib.h"
#include "memorymapper.h"
#include "gemu/syscallenums.h"

typedef QWORD PVOID, PUNICODE_STRING, PWSTR_;
typedef WORD USHORT;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR_  Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  QWORD           Length; //ULONG
  HANDLE          RootDirectory;
  PUNICODE_STRING ObjectName;
  QWORD           Attributes; //ULONG
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE
{
    target_ulong Attribute;
    target_ulong Size;
    union
    {
        target_ulong Value;
        target_ulong ValuePtr;
    };
    target_ulong ReturnLength;
} PS_ATTRIBUTE;

typedef struct
{
    target_ulong TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST;

static const target_ulong PS_ATTRIBUTE_CLIENT_ID = 0x10003;


typedef target_ulong ASID;

typedef struct _Module_List {
    char* FullName;
    QWORD Base;
    DWORD Size;
} Module_List;

typedef struct
{
    unsigned long long int ID; // ProcessID
    char *ImagePathName; // ProcessName
    ASID ASID;
    PEB64 PEB;
    RTL_USER_PROCESS_PARAMETERS64 ProcessParameters;
    struct Module_List *module_list;
    GHashTable *stack_depth;
} WinProcess;

typedef enum {BITNESS_UNKNOWN = 0, BITNESS_32 = 1, BITNESS_64 = 2} Bitness;


typedef struct{
    int parameter_number;
    int address;
} out_parameter;

typedef struct
{
    out_parameter out_parameters[10];
    int number_of_outparameters;
} out_parameter_list_t;

typedef struct
{
    out_parameter_list_t out_parameter_list;
    bool active;
    // char func_name[256];
    syscall_t syscall_enum;
} syscall_hook_t;
typedef struct
{
    unsigned long long int ThreadId;
    WinProcess Process;
    bool is_excluded;
    void* process_handles;
    void* section_handles;
    void* sections_in_other_processes;
    struct DoubleLinkedList* new_sections;
    struct Node* cache_section;
    struct Node* cache_section_written;
    void* current_modules;
    Bitness bitness;
    syscall_hook_t syscall_return_hook;
} WinThread;

typedef struct
{
    struct qht *asid_winthread_map;
    void* pid_winthread_map;
    char *watched_programs;
} WindowsIntrospecter;

extern struct timespec* start_time;

WindowsIntrospecter *init_windows_introspecter(int bucket_size, const char *watched_programs);

void wi_destroy(WindowsIntrospecter *w);

void wi_add_thread(WindowsIntrospecter *w, target_ulong asid, WinThread *winthread);

WinThread *wi_current_thread(WindowsIntrospecter *w, CPUState *cpu, bool addthread);

WinThread *wi_extract_thread_from_memory(WindowsIntrospecter *w, CPUState *cpu, target_ulong asid);

WinThread *wi_extract_thread_from_memory_with_env(WindowsIntrospecter *w, CPUArchState *env, target_ulong asid);

WinThread *get_winthread_for_pid(WindowsIntrospecter *w, target_ulong id);

void get_current_pid_and_tid(CPUState *cpu, QWORD *processid, QWORD *threadid);

void get_pid_and_tid_from_teb_address(target_ulong teb_address, CPUState *cpu, QWORD *processid, QWORD *threadid);

char* get_stack_depth_indicator(WinThread *thread);

void print_memory_map(CPUState *cpu, WinThread *thread);

bool is_thread_excluded(WindowsIntrospecter *w, WinThread *t);

struct qht *init_asid_winthread_map(int bucket_size);

void free_value(gpointer data);


#endif //GEMU_WIN_SPECTOR_HPP
