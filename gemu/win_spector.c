
#include "gemu/win_spector.h"
#include "gemu/cJSON.h"
#include "gemu/gemu.h"
#include "gemu/memorymapper.h"
#include "glib.h"
#include "include/sysemu/memory_mapping.h"
#include "monitor/monitor.h"
#include "qapi/qapi-commands-misc.h"
#include <time.h>

#define CONTAINING_RECORD(address, type, field)                                \
  ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))

struct timespec *start_time = NULL;

static bool winthread_cmp(const void *a, const void *b) {
  WinThread *wa = (WinThread *)a;
  WinThread *wb = (WinThread *)b;

  return wa->Process.ASID == wb->Process.ASID;
}

struct qht *init_asid_winthread_map(int bucket_size) {
  struct qht *ht = malloc(sizeof(struct qht));
  if (!ht) {
    perror("Failed to allocate QHT");
    return NULL;
  }
  qht_init(ht, winthread_cmp, bucket_size, 0);
  return ht;
}

WindowsIntrospecter *init_windows_introspecter(int bucket_size,
                                               const char *watched_programs) {
  WindowsIntrospecter *w = malloc(sizeof(WindowsIntrospecter));
  w->asid_winthread_map = init_asid_winthread_map(bucket_size);
  w->pid_winthread_map = g_hash_table_new(NULL, NULL);
  w->watched_programs = strdup(watched_programs);
  printf("Initialized WindowsIntrospecter, watching processes of: %s\n",
         w->watched_programs);
  return w;
}

void wi_destroy(WindowsIntrospecter *w) {
  printf("Destroying WindowsIntrospecter...\n");
  qht_destroy(w->asid_winthread_map);
  free(w->asid_winthread_map);
  free(w);
  printf("Done destroying WindowsIntrospecter\n");
}

void wi_add_thread(WindowsIntrospecter *w, target_ulong asid,
                   WinThread *winthread) {
    if (winthread->Process.ImagePathName[0] == '\0' || winthread->Process.ID == 0) {
        return;
    }
  printf("ADDING TO THE LOOKUPS, %llu, %lu, %lu, %s\n", winthread->Process.ID,
         winthread->Process.ASID, asid, winthread->Process.ImagePathName);
  if (w->asid_winthread_map == NULL) {
    perror("ASID-WinThread map not initialized");
    return;
  }
  if (!qht_insert(w->asid_winthread_map, winthread, asid, NULL)) {
    perror("Failed to insert WinThread into ASID-WinThread map");
  }
  g_hash_table_insert(w->pid_winthread_map,
                      GINT_TO_POINTER(winthread->Process.ID), winthread);
}

bool is_thread_excluded(WindowsIntrospecter *w, WinThread *t) {
  if (w->watched_programs == NULL || strlen(w->watched_programs) == 0) {
    perror("Watched programs not initialized");
    return false;
  }

  size_t len = strlen(w->watched_programs);
  // Allocate memory for copy (+1 for null terminator)
  char *watched_processes_copy = malloc(len + 1);

  if (watched_processes_copy == NULL) {
    fprintf(stderr, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  strncpy(watched_processes_copy, w->watched_programs, len);
  watched_processes_copy[len] = '\0';

  char *watched_process = strtok(watched_processes_copy, ",");
  while (watched_process != NULL) {
    if (strcasestr(t->Process.ImagePathName, watched_process) != NULL) {
      free(watched_processes_copy);
      Gemu *gemu = gemu_get_instance();
      g_hash_table_insert(gemu->pids_to_lookout_for, (gpointer)t->Process.ID,
                          NULL);
      g_print("Including ASID %lu program=%s\n", t->Process.ASID,
              t->Process.ImagePathName);
      if (start_time == NULL) {
        start_time = malloc(sizeof(struct timespec));
        clock_gettime(CLOCK_MONOTONIC_RAW, start_time);
      }
      return false;
    }
    watched_process = strtok(NULL, ",");
  }
  free(watched_processes_copy);
  return true;
}

WinThread *get_winthread_for_pid(WindowsIntrospecter *w, target_ulong id) {
  return g_hash_table_lookup(w->pid_winthread_map, (gconstpointer)id);
}

WinThread *wi_current_thread(WindowsIntrospecter *w, CPUState *cpu,
                             bool add_thread) {
  target_ulong asid = cpu->env_ptr->cr[3];
  // WinProcess is cached
  WinThread cmpThread = {
      .Process = {
          .ID = 0,
          .ASID = asid,
      },
      .is_excluded = false
  };

  WinThread *thread =
      (WinThread *)qht_lookup(w->asid_winthread_map, &cmpThread, asid);

  if (!thread) {
    // WinProcess is not cached, add it to cache
    thread = wi_extract_thread_from_memory(w, cpu, asid);
    if (add_thread) {
      wi_add_thread(w, asid, thread);
    }
  }

  Gemu *gemu = gemu_get_instance();

  if (thread == NULL || !g_hash_table_contains(gemu->pids_to_lookout_for, GINT_TO_POINTER(thread->Process.ID))) {
    return NULL;
  }

  if (gemu->tracking_mode & TRACKING_BASICBLOCK){ // This if clause contains code to identify kernel for api hooking
    if (thread->bitness == BITNESS_UNKNOWN && thread->Process.ImagePathName[0] != '\0'){
      wi_extract_module_list(cpu, thread);
      ModuleNode* current = thread->current_modules;
      while (current != NULL) {
        if (strcmp(current->file,"c:\\windows\\system32\\wow64.dll") == 0){
          thread->bitness = BITNESS_32;
          break;
        }
        if (strcmp(current->file,"c:\\windows\\system32\\kernel32.dll") == 0){
          thread->bitness = BITNESS_64;
          break;
        }
        current = current->next;
      }
    }

    if (thread->bitness == BITNESS_32 && !gemu->kernel32_32bit_found){
      try_extract_kernel32_address(gemu, cpu, thread);
    }
    if (thread->bitness == BITNESS_64 && !gemu->kernel32_64bit_found){
      try_extract_kernel32_address(gemu, cpu, thread);
    }
  }

  return thread;
}

void print_memory_map(CPUState *cpu, WinThread *thread) {
  struct DoubleLinkedList *latest_sections =
      (struct DoubleLinkedList *)malloc(sizeof(struct DoubleLinkedList));
  latest_sections->head = NULL;
  get_memory_map(cpu->env_ptr, latest_sections);
  if (latest_sections->head == NULL)
    return;


  copy_written_to_flags(latest_sections, thread->new_sections);
  // If thread->new-sections is freed, cache_section  and cache_section_written point to garbage!
  // ...so we set it to NULL instead
  thread->cache_section = NULL;
  thread->cache_section_written = NULL;
  freeList(thread->new_sections);
  thread->new_sections = latest_sections;
}

void get_current_pid_and_tid(CPUState *cpu, QWORD *processid, QWORD *threadid) {
  TEB64 teb;
  CPUX86State *env = cpu->env_ptr;
  SegmentCache gs = env->segs[R_GS];
  gemu_virtual_memory_rw(cpu, gs.base, (uint8_t *)&teb, sizeof teb, false);
  *processid = teb.ClientId.ProcessId;
  *threadid = teb.ClientId.ThreadId;
}

WinThread *wi_extract_thread_from_memory(WindowsIntrospecter *w, CPUState *cpu,
                                         target_ulong asid) {
  TEB64 teb;
  PEB64 peb;
  RTL_USER_PROCESS_PARAMETERS64 processParameters;

  CPUX86State *env = cpu->env_ptr;
  SegmentCache gs = env->segs[R_GS];
  // Read TEB
  gemu_virtual_memory_rw(cpu, gs.base, (uint8_t *)&teb, sizeof teb, false);
  // Read PEB
  gemu_virtual_memory_rw(cpu, teb.ProcessEnvironmentBlock, (uint8_t *)&peb,
                         sizeof peb, false);
  // Read ProcessParameters of PEB
  gemu_virtual_memory_rw(cpu, peb.ProcessParameters,
                         (uint8_t *)&processParameters,
                         sizeof processParameters, false);

  // Read ImagePathName
  char *imagePathName = malloc(processParameters.ImagePathName.u.Length + 1);
  // TODO: Lifetime of imagePathName needs to be free-ed
  guest_wstrncpy(cpu, imagePathName, processParameters.ImagePathName.u.Length,
                 processParameters.ImagePathName.Buffer);

  struct DoubleLinkedList *list =
      (struct DoubleLinkedList *)malloc(sizeof(struct DoubleLinkedList));
  list->head = NULL;

  struct DoubleLinkedList *new_sections =
      (struct DoubleLinkedList *)malloc(sizeof(struct DoubleLinkedList));
  new_sections->head = NULL;

  WinThread *newThreadPtr = malloc(sizeof(WinThread));
  WinThread newThread = {
      .process_handles = g_hash_table_new(NULL, NULL),
      .section_handles = g_hash_table_new(NULL, NULL),
      .Process =
          {
              .ID = teb.ClientId.ProcessId,
              .ASID = asid,
              .PEB = peb,
              .ImagePathName = imagePathName,
              .ProcessParameters = processParameters,
          },
      .is_excluded = false,
      .new_sections = new_sections,
      .cache_section = NULL,
      .cache_section_written = NULL,
      .current_modules = NULL,
      .bitness = BITNESS_UNKNOWN,
      .syscall_return_hook.active = false
  };
  newThread.is_excluded = is_thread_excluded(w, &newThread);
  *newThreadPtr = newThread;
  newThreadPtr->new_sections = list;

  return newThreadPtr;
}
