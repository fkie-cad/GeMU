
#ifndef GEMU_H
#define GEMU_H

#include "cJSON.h"
#include "hooks.h"
#include "utils.h"
#include "win_spector.h"
#include "calling_conventions.h"
#include <time.h>

typedef enum {
  TRACKING_OFF                         = 0x0000,
  TRACKING_SYSCALLS                    = 0x0001,
  TRACKING_BASICBLOCK_WINAPI           = 0x0010,
  TRACKING_BASICBLOCK_DOTNET           = 0x0020,
  TRACKING_ACTIVATE_DOTNET_BB_IF_FOUND = 0x0100,
  TRACKING_BASICBLOCK = TRACKING_BASICBLOCK_DOTNET | TRACKING_BASICBLOCK_WINAPI
} TrackingMode;

typedef struct {
  Hooker *hooker;
  WindowsIntrospecter *win_spec;
  void *parameter_lookup;
  const void *syscall_lookup_for_build;
  const void *syscall_lookup_for_build_enum;
  void *syscall_lookup;
  void *pids_to_lookout_for;
  void *all_seen_pids;
  void *mapped_sections_waitinglist;
  bool kernel32_64bit_found;
  bool kernel32_32bit_found;
  void *modules_to_hook;
  bool recording;
  TrackingMode tracking_mode;
  GHashTable *dumped_hashes;
} Gemu;

typedef struct Module {
  unsigned int base;
  unsigned int size;
  char path[256];
  struct Module *next;
} Module;

typedef struct ModuleNode {
  QWORD size;
  char *file;
  QWORD base;
  struct ModuleNode *next;
} ModuleNode;

void gemu_init(void);

Gemu *gemu_get_instance(void);

void gemu_destroy(void);

bool handle_special_apis(Gemu *gemu_instance, CPUState *cpu, const char *dll_name,
                         const char *func_name, WinProcess *process, out_parameter_list_t* out_parameter_list,
                         bool is32Bit);

void handle_ZwWriteFile(Gemu *gemu_instance, CPUState *cpu, WinProcess *process,
                        const char *dll_name, const char *func_name, out_parameter_list_t* out_parameter_list,
                        bool is32Bit);

void handle_ZwWriteVirtualMemory(Gemu *gemu_instance, CPUState *cpu,
                                 WinProcess *process, const char *dll_name,
                                 const char *func_name, out_parameter_list_t* out_parameter_list, bool is32Bit);

void handle_ZwTerminateProcess(Gemu *gemu_instance, CPUState *cpu,
                               WinProcess *process, const char *dll_name,
                               const char *func_name, out_parameter_list_t* out_parameter_list, bool is32Bit);

void handle_ZwMapViewOfSection_exit(Gemu *gemu_instance, WinProcess *process,
                                    cJSON *output);

void handle_ZwOpenProcess_Exit(cJSON *output, WinProcess *process);

cJSON *read_out_parameters(Gemu *gemu, CPUState *cpu, const char *func_name,
                           const char *dll_name, int number_of_outparameters,
                           out_parameter out_parameters[], WinProcess *process, bool is32bit);

cJSON *read_parameters(Gemu *gemu, CPUState *cpu, const char *func_name,
                       const char *dll_name, out_parameter_list_t *out_parameter_list,
                       WinProcess *process, bool is32bit);



QWORD dereference_pointer(CPUState *cpu, QWORD value, int times, bool is32bit);


void wi_extract_module_list(CPUState *cpu, WinProcess *process);

void dump_WriteVirtualMemory(cJSON *output, CPUState *cpu, WinProcess *process,
                             int pid);

bool insert_sorted_module_node(ModuleNode **head, ModuleNode *new_node);

void to_lowercase(char *str);

void free_list(ModuleNode *head);

void print_module_nodes(ModuleNode *head);

Module *create_module(unsigned int base, unsigned int size, const char *path);

void insert_sorted(Module **head, Module *new_module);

Module *parse_modules(const char *filename);

void try_extract_kernel32_address(Gemu *gemu_instance, CPUState *cpu, WinProcess *process);

void pipe_logger_before_syscall_exec_enum(CPUState *cpu,
                                     syscall_t syscall, WinProcess *process);


void pipe_logger_after_syscall_exec(CPUState *cpu, WinProcess* process, syscall_hook_t* hook);

void gemu_start_recording(void);

gboolean hook_address(const char* func_name, const char *dll_name, target_long address, void* function);

void handle_getJit_exit(Gemu *gemu_instance, target_ulong result, CPUState *cpu, bool is32bit);

void handle_loaded_library(ModuleNode *head);

void gemu_dotnet_found(Gemu *gemu);

#endif // GEMU_H
