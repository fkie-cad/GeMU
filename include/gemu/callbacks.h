#ifndef GEMU_CALLBACKS_H
#define GEMU_CALLBACKS_H


#include <stdint.h>
#include "qemu/typedefs.h"
#include "memorymapper.h"
#include "mappedwaitinglist.h"
#include "win_spector.h"
#include "gemu.h"

void gemu_cb_before_tb_exec(CPUState *cpu, TranslationBlock *tb);

void gemu_cb_phys_memory_written(CPUArchState *env, target_ulong addr, uint64_t val, size_t size, uintptr_t retaddr);

void gemu_cb_after_block_translation(CPUState *cpu, TranslationBlock *tb);

void update_memory_map_from_env(CPUArchState *env);

void check_for_unpacking(CPUState *cpu, TranslationBlock *tb, WinProcess *thread, Gemu *gemu_instance);

bool iterateAndUpdateList(struct SingleLinkedList* singleList, struct DoubleLinkedList* doubleList);

bool convertToSharedWrittenBit(struct MappedMemoryNode* mmapNode, struct DoubleLinkedList* doubleList);

bool* getWrittenFlagForNode(struct MappedMemoryNode* mmapNode);

WinProcess* gemu_helper_get_current_process(void);

void gemu_cb_syscall(CPUX86State *cpu, int next_eip_addend);

void gemu_cb_sysret(CPUX86State *cpu);

ModuleNode* is_within_range(ModuleNode* head, hwaddr start, hwaddr end);

#endif //GEMU_CALLBACKS_H
