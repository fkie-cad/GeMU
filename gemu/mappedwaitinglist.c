#include "gemu/mappedwaitinglist.h"


GHashTable* allocateHashMap(void) {
    GHashTable* hashMap = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (hashMap == NULL) {
        perror("Failed to allocate memory for hash map");
        exit(EXIT_FAILURE);
    }
    return hashMap;
}


struct SingleLinkedList* allocateNewList(void) {
    struct SingleLinkedList* newList = (struct SingleLinkedList*)malloc(sizeof(struct SingleLinkedList));
    if (newList == NULL) {
        perror("Failed to allocate memory for new list");
        exit(EXIT_FAILURE);
    }
    newList->head = NULL;
    return newList;
}

void putList(GHashTable* hashMap, pid_t pid, struct SingleLinkedList* list) {
    g_hash_table_insert(hashMap, GINT_TO_POINTER(pid), list);
}

struct SingleLinkedList* getMemoryMappedList(GHashTable* hashMap, pid_t pid) {
    gpointer list = g_hash_table_lookup(hashMap, GINT_TO_POINTER(pid));
    return (struct SingleLinkedList*)list;
}

void removeList(GHashTable* hashMap, pid_t pid) {
    g_hash_table_remove(hashMap, GINT_TO_POINTER(pid));
}

void freeMemoryMappedList(struct SingleLinkedList* list) {
    struct MappedMemoryNode* current = list->head;
    while (current != NULL) {
        struct MappedMemoryNode* temp = current;
        current = current->next;
        free(temp);
    }
    free(list);
}

void addMappedMemoryNodeToList(GHashTable* hashMap, pid_t pid, hwaddr start, size_t size, unsigned long long int other_ID, hwaddr other_start, size_t other_size) {
    // Get the list from the hash map
    struct SingleLinkedList* list = getMemoryMappedList(hashMap, pid);

    // If the list does not exist, allocate it and put it in the hash map
    if (list == NULL) {
        list = allocateNewList();
        putList(hashMap, pid, list);
    }

    // Check if a MappedMemoryNode with the exact same address and size already exists
    struct MappedMemoryNode* current = list->head;
    while (current != NULL) {
        if (current->start == start && current->size == size) {
            // MappedMemoryNode already exists, do not insert a new one
            return;
        }
        current = current->next;
    }

    // Create a new MappedMemoryNode
    struct MappedMemoryNode* newMappedMemoryNode = (struct MappedMemoryNode*)malloc(sizeof(struct MappedMemoryNode));
    if (newMappedMemoryNode == NULL) {
        perror("Failed to allocate memory for new MappedMemoryNode");
        exit(EXIT_FAILURE);
    }
    newMappedMemoryNode->start = start;
    newMappedMemoryNode->size = size;
    newMappedMemoryNode->next = NULL;
    newMappedMemoryNode->other_size = other_size;
    newMappedMemoryNode->other_start = other_start;
    newMappedMemoryNode->other_ID = other_ID;

    // Insert the new MappedMemoryNode at the beginning of the list
    newMappedMemoryNode->next = list->head;
    list->head = newMappedMemoryNode;
}

void printList(struct SingleLinkedList* list) {
    struct MappedMemoryNode* current = list->head;
    while (current != NULL) {
        printf("MappedMemoryNode: Start Address = 0x%lx, Size = %zu\n", current->start, current->size);
        current = current->next;
    }
}
