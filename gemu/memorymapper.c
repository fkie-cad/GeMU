#include "gemu/memorymapper.h"
#include "gemu/callbacks.h"
#include "gemu/gemu.h"
#include "gemu/win_spector.h"
#include <stdio.h>
#include <stdlib.h>

static hwaddr addr_canonical(CPUArchState *env, hwaddr addr)
{
#ifdef TARGET_X86_64
    if (env->cr[4] & CR4_LA57_MASK) {
        if (addr & (1ULL << 56)) {
            addr |= (hwaddr)-(1LL << 57);
        }
    } else {
        if (addr & (1ULL << 47)) {
            addr |= (hwaddr)-(1LL << 48);
        }
    }
#endif
    return addr;
}

char* getFileName(char* path) {
    // Find the last occurrence of the backslash character
    char* lastBackslash = strrchr(path, '\\');
    if (lastBackslash != NULL) {
        // Return the part of the string after the last backslash
        printf("i am returning %s", lastBackslash + 1);
        return lastBackslash + 1;
    } else {
        // If there is no backslash, return the whole path
        printf("I am returning  the whole path\n");
        return path;
    }
}


struct Node* createNode(hwaddr start, hwaddr end) {
    struct Node* newNode = (struct Node*)malloc(sizeof(struct Node));
    newNode->start = start;
    newNode->end = end;
    newNode->is_shared = false;
    newNode->written_to.local_written_to = false;
    newNode->prev = NULL;
    newNode->next = NULL;
    return newNode;
}

struct DoubleLinkedList* getNodesInRange(hwaddr start, hwaddr size, struct DoubleLinkedList* list) {
    struct DoubleLinkedList* result = (struct DoubleLinkedList*)malloc(sizeof(struct DoubleLinkedList));
    result->head = NULL;

    hwaddr end = start + size;
    struct Node* current = list->head;

    while (current != NULL) {
        if (current->end > start && current->start < end) {
            // Node overlaps with the specified range
            append(result, current->start, current->end);
            // Copy the written_to flag (shared or local)
            result->head->is_shared = current->is_shared;
            if (current->is_shared) {
                result->head->written_to.shared_written_to = current->written_to.shared_written_to;
            } else {
                result->head->written_to.local_written_to = current->written_to.local_written_to;
            }
        }
        current = current->next;
    }

    return result;
}

void setWrittenFlag(struct Node* node, bool bit) {
    if (node->is_shared) {
        *node->written_to.shared_written_to = bit; // Dereference the pointer to assign the value
    } else {
        node->written_to.local_written_to = bit;
    }
}

void unsetWrittenFlagForRange(hwaddr start, hwaddr end, struct DoubleLinkedList* list){
    struct Node* current = list->head;
    while (current != NULL) {
        if (current->end >= start && current->start <= end) {
            setWrittenFlag(current, false);
        }
        current = current->next;
    }
}

bool getWrittenToFlag(struct Node* node) {
    if (node->is_shared) {
        return *node->written_to.shared_written_to;
    } else {
        return node->written_to.local_written_to;
    }
}

void convertToSharedWrittenTo(struct Node* node, bool* shared_written_to) {
        node->is_shared = true;
        node->written_to.shared_written_to = shared_written_to;
}

void copyList(struct DoubleLinkedList* newList, struct DoubleLinkedList* list) {
    newList->head = NULL;

    struct Node* current = list->head;
    while (current != NULL) {
        append(newList, current->start, current->end);
        current = current->next;
    }
}

struct Node* getNodeForAddress(hwaddr addr, struct DoubleLinkedList* list) {
    struct Node* current = list->head;

    while (current != NULL) {
        if (addr >= current->start && addr < current->end) {
            return current;
        }
        current = current->next;
    }

    return NULL; // Address not found in any node range
}


void copy_written_to_flags(struct DoubleLinkedList* list, struct DoubleLinkedList* written_to) {
    struct Node* current_written_to = written_to->head;
    while (current_written_to != NULL) {
        if (current_written_to->is_shared || (!current_written_to->is_shared && current_written_to->written_to.local_written_to)) {
            struct Node* current_new_node = list->head;
            while (current_new_node != NULL) {
                if (!(current_new_node->end <= current_written_to->start || current_written_to->end <= current_new_node->start)) {
                    if (current_written_to->is_shared) {
                        current_new_node->is_shared = true;
                        current_new_node->written_to.shared_written_to = current_written_to->written_to.shared_written_to;
                    } else {
                        current_new_node->is_shared = false;
                        current_new_node->written_to.local_written_to = true;
                    }
                }
                current_new_node = current_new_node->next;
            }
        }
        current_written_to = current_written_to->next;
    }
}

void append(struct DoubleLinkedList* list, hwaddr start, hwaddr end) {
    struct Node* newNode = createNode(start, end);
    if (list->head == NULL) {
        list->head = newNode;
    } else {
        struct Node* current = list->head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = newNode;
        newNode->prev = current;
    }
}

void reduceList(struct DoubleLinkedList* list) {
    struct Node* current = list->head;
    while (current != NULL && current->next != NULL) {
        if (current->end >= current->next->start) {
            // Merge adjacent nodes
            current->end = (current->end > current->next->end) ? current->end : current->next->end;

            struct Node* temp = current->next;
            current->next = current->next->next;
            if (current->next != NULL) {
                current->next->prev = current;
            }
            free(temp);
        } else {
            current = current->next;
        }
    }
}

void freeList(struct DoubleLinkedList* list) {
    struct Node* current = list->head;
    while (current != NULL) {
        struct Node* temp = current;
        current = current->next;
        free(temp);
    }
}

void displayList(struct DoubleLinkedList* list) {
    struct Node* current = list->head;
    while (current != NULL) {
        bool written_flag = current->is_shared ? *current->written_to.shared_written_to : current->written_to.local_written_to;
        const char* shared_indicator = current->is_shared ? "shared" : "local";
        printf("(0x%lx, 0x%lx, written: %s, %s)\n", current->start, current->end, written_flag ? "true" : "false", shared_indicator);
        current = current->next;
    }
    printf("\n");
}

static bool add_mem_to_list(struct DoubleLinkedList* list, CPUArchState *env,
                            hwaddr *pstart, int *plast_prot,
                            hwaddr end, int prot)
{
    int prot1;
    prot1 = *plast_prot;
    if (prot != prot1) {
        if (*pstart != -1) {
            if (prot1 & PG_USER_MASK){
                append(list, addr_canonical(env, *pstart), addr_canonical(env, end));
            }
            else {
                return false;
            }
        }
        if (prot != 0)
            *pstart = end;
        else
            *pstart = -1;
        *plast_prot = prot;
    }
    return true;
}

static void get_mem_info_32(struct DoubleLinkedList* list, CPUArchState *env)
{
    unsigned int l1, l2;
    int prot, last_prot;
    uint32_t pgd, pde, pte;
    hwaddr start, end;

    pgd = env->cr[3] & ~0xfff;
    last_prot = 0;
    start = -1;
    for(l1 = 0; l1 < 1024; l1++) {
        cpu_physical_memory_read(pgd + l1 * 4, &pde, 4);
        pde = le32_to_cpu(pde);
        end = l1 << 22;
        if (pde & PG_PRESENT_MASK) {
            if ((pde & PG_PSE_MASK) && (env->cr[4] & CR4_PSE_MASK)) {
                prot = pde & (PG_USER_MASK | PG_RW_MASK | PG_PRESENT_MASK);
                add_mem_to_list(list, env, &start, &last_prot, end, prot);
            } else {
                for(l2 = 0; l2 < 1024; l2++) {
                    cpu_physical_memory_read((pde & ~0xfff) + l2 * 4, &pte, 4);
                    pte = le32_to_cpu(pte);
                    end = (l1 << 22) + (l2 << 12);
                    if (pte & PG_PRESENT_MASK) {
                        prot = pte & pde &
                               (PG_USER_MASK | PG_RW_MASK | PG_PRESENT_MASK);
                    } else {
                        prot = 0;
                    }
                    add_mem_to_list(list, env, &start, &last_prot, end, prot);
                }
            }
        } else {
            prot = 0;
            add_mem_to_list(list, env, &start, &last_prot, end, prot);
        }
    }
    /* Flush last range */
    add_mem_to_list(list, env, &start, &last_prot, (hwaddr)1 << 32, 0);
}

static void get_mem_info_pae32(struct DoubleLinkedList* list, CPUArchState *env)
{
    unsigned int l1, l2, l3;
    int prot, last_prot;
    uint64_t pdpe, pde, pte;
    uint64_t pdp_addr, pd_addr, pt_addr;
    hwaddr start, end;

    pdp_addr = env->cr[3] & ~0x1f;
    last_prot = 0;
    start = -1;
    for (l1 = 0; l1 < 4; l1++) {
        cpu_physical_memory_read(pdp_addr + l1 * 8, &pdpe, 8);
        pdpe = le64_to_cpu(pdpe);
        end = l1 << 30;
        if (pdpe & PG_PRESENT_MASK) {
            pd_addr = pdpe & 0x3fffffffff000ULL;
            for (l2 = 0; l2 < 512; l2++) {
                cpu_physical_memory_read(pd_addr + l2 * 8, &pde, 8);
                pde = le64_to_cpu(pde);
                end = (l1 << 30) + (l2 << 21);
                if (pde & PG_PRESENT_MASK) {
                    if (pde & PG_PSE_MASK) {
                        prot = pde & (PG_USER_MASK | PG_RW_MASK |
                                      PG_PRESENT_MASK);
                        add_mem_to_list(list, env, &start, &last_prot, end, prot);
                    } else {
                        pt_addr = pde & 0x3fffffffff000ULL;
                        for (l3 = 0; l3 < 512; l3++) {
                            cpu_physical_memory_read(pt_addr + l3 * 8, &pte, 8);
                            pte = le64_to_cpu(pte);
                            end = (l1 << 30) + (l2 << 21) + (l3 << 12);
                            if (pte & PG_PRESENT_MASK) {
                                prot = pte & pde & (PG_USER_MASK | PG_RW_MASK |
                                                    PG_PRESENT_MASK);
                            } else {
                                prot = 0;
                            }
                            add_mem_to_list(list, env, &start, &last_prot, end, prot);
                        }
                    }
                } else {
                    prot = 0;
                    add_mem_to_list(list, env, &start, &last_prot, end, prot);
                }
            }
        } else {
            prot = 0;
            add_mem_to_list(list, env, &start, &last_prot, end, prot);
        }
    }
    /* Flush last range */
    add_mem_to_list(list, env, &start, &last_prot, (hwaddr)1 << 32, 0);
}


#ifdef TARGET_X86_64
static void get_mem_info_la48(struct DoubleLinkedList* list, CPUArchState *env)
{
    int prot, last_prot;
    uint64_t l1, l2, l3, l4;
    uint64_t pml4e, pdpe, pde, pte;
    uint64_t pml4_addr, pdp_addr, pd_addr, pt_addr, start, end;

    pml4_addr = env->cr[3] & 0x3fffffffff000ULL;
    last_prot = 0;
    start = -1;
    for (l1 = 0; l1 < 512; l1++) {
        cpu_physical_memory_read(pml4_addr + l1 * 8, &pml4e, 8);
        pml4e = le64_to_cpu(pml4e);
        end = l1 << 39;
        if (pml4e & PG_PRESENT_MASK) {
            pdp_addr = pml4e & 0x3fffffffff000ULL;
            for (l2 = 0; l2 < 512; l2++) {
                cpu_physical_memory_read(pdp_addr + l2 * 8, &pdpe, 8);
                pdpe = le64_to_cpu(pdpe);
                end = (l1 << 39) + (l2 << 30);
                if (pdpe & PG_PRESENT_MASK) {
                    if (pdpe & PG_PSE_MASK) {
                        prot = pdpe & (PG_USER_MASK | PG_RW_MASK |
                                       PG_PRESENT_MASK);
                        prot &= pml4e;
                        if (!add_mem_to_list(list, env, &start, &last_prot, end, prot))
                            return;
                    } else {
                        pd_addr = pdpe & 0x3fffffffff000ULL;
                        for (l3 = 0; l3 < 512; l3++) {
                            cpu_physical_memory_read(pd_addr + l3 * 8, &pde, 8);
                            pde = le64_to_cpu(pde);
                            end = (l1 << 39) + (l2 << 30) + (l3 << 21);
                            if (pde & PG_PRESENT_MASK) {
                                if (pde & PG_PSE_MASK) {
                                    prot = pde & (PG_USER_MASK | PG_RW_MASK |
                                                  PG_PRESENT_MASK);
                                    prot &= pml4e & pdpe;
                                    if (!add_mem_to_list(list, env, &start, &last_prot, end, prot))
                            return;
                                } else {
                                    pt_addr = pde & 0x3fffffffff000ULL;
                                    for (l4 = 0; l4 < 512; l4++) {
                                        cpu_physical_memory_read(pt_addr
                                                                 + l4 * 8,
                                                                 &pte, 8);
                                        pte = le64_to_cpu(pte);
                                        end = (l1 << 39) + (l2 << 30) +
                                            (l3 << 21) + (l4 << 12);
                                        if (pte & PG_PRESENT_MASK) {
                                            prot = pte & (PG_USER_MASK | PG_RW_MASK |
                                                          PG_PRESENT_MASK);
                                            prot &= pml4e & pdpe & pde;
                                        } else {
                                            prot = 0;
                                        }
                                        if (!add_mem_to_list(list, env, &start, &last_prot, end, prot))
                            return;
                                    }
                                }
                            } else {
                                prot = 0;
                                if (!add_mem_to_list(list, env, &start, &last_prot, end, prot))
                            return;
                            }
                        }
                    }
                } else {
                    prot = 0;
                    if (!add_mem_to_list(list, env, &start, &last_prot, end, prot))
                            return;
                }
            }
        } else {
            prot = 0;
            if (!add_mem_to_list(list, env, &start, &last_prot, end, prot))
                            return;
        }
    }
    /* Flush last range */
    if (!add_mem_to_list(list, env, &start, &last_prot, (hwaddr)1 << 48, 0))
        return;
}

static void get_mem_info_la57(struct DoubleLinkedList* list, CPUArchState *env)
{
    int prot, last_prot;
    uint64_t l0, l1, l2, l3, l4;
    uint64_t pml5e, pml4e, pdpe, pde, pte;
    uint64_t pml5_addr, pml4_addr, pdp_addr, pd_addr, pt_addr, start, end;

    pml5_addr = env->cr[3] & 0x3fffffffff000ULL;
    last_prot = 0;
    start = -1;
    for (l0 = 0; l0 < 512; l0++) {
        cpu_physical_memory_read(pml5_addr + l0 * 8, &pml5e, 8);
        pml5e = le64_to_cpu(pml5e);
        end = l0 << 48;
        if (!(pml5e & PG_PRESENT_MASK)) {
            prot = 0;
            if (!add_mem_to_list(list, env, &start, &last_prot, end, prot))
                                        return;
            continue;
        }

        pml4_addr = pml5e & 0x3fffffffff000ULL;
        for (l1 = 0; l1 < 512; l1++) {
            cpu_physical_memory_read(pml4_addr + l1 * 8, &pml4e, 8);
            pml4e = le64_to_cpu(pml4e);
            end = (l0 << 48) + (l1 << 39);
            if (!(pml4e & PG_PRESENT_MASK)) {
                prot = 0;
                if (!add_mem_to_list(list, env, &start, &last_prot, end, prot))
                                        return;
                continue;
            }

            pdp_addr = pml4e & 0x3fffffffff000ULL;
            for (l2 = 0; l2 < 512; l2++) {
                cpu_physical_memory_read(pdp_addr + l2 * 8, &pdpe, 8);
                pdpe = le64_to_cpu(pdpe);
                end = (l0 << 48) + (l1 << 39) + (l2 << 30);
                if (pdpe & PG_PRESENT_MASK) {
                    prot = 0;
                    if (!add_mem_to_list(list, env, &start, &last_prot, end, prot))
                                        return;
                    continue;
                }

                if (pdpe & PG_PSE_MASK) {
                    prot = pdpe & (PG_USER_MASK | PG_RW_MASK |
                            PG_PRESENT_MASK);
                    prot &= pml5e & pml4e;
                    if (!add_mem_to_list(list, env, &start, &last_prot, end, prot))
                                        return;
                    continue;
                }

                pd_addr = pdpe & 0x3fffffffff000ULL;
                for (l3 = 0; l3 < 512; l3++) {
                    cpu_physical_memory_read(pd_addr + l3 * 8, &pde, 8);
                    pde = le64_to_cpu(pde);
                    end = (l0 << 48) + (l1 << 39) + (l2 << 30) + (l3 << 21);
                    if (pde & PG_PRESENT_MASK) {
                        prot = 0;
                        if (!add_mem_to_list(list, env, &start, &last_prot, end, prot))
                                        return;
                        continue;
                    }

                    if (pde & PG_PSE_MASK) {
                        prot = pde & (PG_USER_MASK | PG_RW_MASK |
                                PG_PRESENT_MASK);
                        prot &= pml5e & pml4e & pdpe;
                        if (!add_mem_to_list(list, env, &start, &last_prot, end, prot))
                                        return;
                        continue;
                    }

                    pt_addr = pde & 0x3fffffffff000ULL;
                    for (l4 = 0; l4 < 512; l4++) {
                        cpu_physical_memory_read(pt_addr + l4 * 8, &pte, 8);
                        pte = le64_to_cpu(pte);
                        end = (l0 << 48) + (l1 << 39) + (l2 << 30) +
                            (l3 << 21) + (l4 << 12);
                        if (pte & PG_PRESENT_MASK) {
                            prot = pte & (PG_USER_MASK | PG_RW_MASK |
                                    PG_PRESENT_MASK);
                            prot &= pml5e & pml4e & pdpe & pde;
                        } else {
                            prot = 0;
                        }
                        if (!add_mem_to_list(list, env, &start, &last_prot, end, prot))
                                        return;
                    }
                }
            }
        }
    }
    /* Flush last range */
    if (!add_mem_to_list(list, env, &start, &last_prot, end, prot))
                                        return;
}
#endif /* TARGET_X86_64 */

void get_memory_map(CPUArchState* env, struct DoubleLinkedList* list)
{
    if (!(env->cr[0] & CR0_PG_MASK)) {
        printf("PG disabled\n");
        return;
    }
    if (env->cr[4] & CR4_PAE_MASK) {
        if (env->hflags & HF_LMA_MASK) {
            if (env->cr[4] & CR4_LA57_MASK) {
                get_mem_info_la57(list, env);
            } else {
                get_mem_info_la48(list, env);
            }
        } else
        {
            get_mem_info_pae32(list, env);
        }
    } else {
        get_mem_info_32(list, env);
    }
}
