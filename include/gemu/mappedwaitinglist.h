//
// Created by thorsten on 04.07.24.
//

#ifndef GEMU_MAPPEDWAITINGLIST_H
#define GEMU_MAPPEDWAITINGLIST_H

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include "glib.h"

typedef unsigned long hwaddr;
typedef int pid_t;

struct MappedMemoryNode {
    hwaddr start;
    size_t size;
    hwaddr other_start;
    size_t other_size;
    unsigned long long int other_ID;
    struct MappedMemoryNode* next;
};

struct SingleLinkedList {
    struct MappedMemoryNode* head;
};


GHashTable* allocateHashMap(void);

struct SingleLinkedList* allocateNewList(void);

void putList(GHashTable* hashMap, pid_t pid, struct SingleLinkedList* list);

struct SingleLinkedList* getMemoryMappedList(GHashTable* hashMap, pid_t pid);

void removeList(GHashTable* hashMap, pid_t pid);

void freeMemoryMappedList(struct SingleLinkedList* list);

void printList(struct SingleLinkedList* list);

void addMappedMemoryNodeToList(GHashTable* hashMap, pid_t pid, hwaddr start, size_t size, unsigned long long int other_ID, hwaddr other_start, size_t other_size);

#endif //GEMU_MAPPEDWAITINGLIST_H
