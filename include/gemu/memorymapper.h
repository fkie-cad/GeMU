//
// Created by thorsten on 17.01.24.
//

#ifndef GEMU_MEMORYMAPPER_H
#define GEMU_MEMORYMAPPER_H

#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "exec/hwaddr.h"

struct Node {
    hwaddr start;
    hwaddr end;
    bool dumped;
    bool is_shared; // Flag to indicate if the written_to is shared
    union {
        bool local_written_to;
        bool* shared_written_to;
    } written_to;
    // For shared nodes: the full mapped range from ZwMapViewOfSection
    hwaddr shared_map_start;
    hwaddr shared_map_end;
    // The other process's mapping (source process has all pages present)
    hwaddr shared_other_start;
    hwaddr shared_other_end;
    unsigned long long int shared_other_pid;
    struct Node* prev;
    struct Node* next;
};

struct DoubleLinkedList {
    struct Node* head;
};

struct MappedRange {
    hwaddr start;
    size_t size;
};

void displayList(struct DoubleLinkedList* list);

void reduceList(struct DoubleLinkedList* list);

void freeList(struct DoubleLinkedList* list);

struct Node* createNode(hwaddr start, hwaddr end);

void copy_written_to_flags(struct DoubleLinkedList* list, struct DoubleLinkedList* written_to);

void copyList(struct DoubleLinkedList* newList, struct DoubleLinkedList* list);

void convertToSharedWrittenTo(struct Node* node, bool* shared_written_to);

bool getWrittenToFlag(struct Node* node);

void setWrittenFlag(struct Node* node, bool bit);

void unsetWrittenFlagForRange(hwaddr start, hwaddr end, struct DoubleLinkedList* list);

struct Node* append(struct DoubleLinkedList* list, hwaddr start, hwaddr end);

struct Node* getNodeForAddress(hwaddr addr, struct DoubleLinkedList* list);

void get_memory_map(CPUArchState* env, struct DoubleLinkedList* list);

char* getFileName(char* path);

#endif //GEMU_MEMORYMAPPER_H
