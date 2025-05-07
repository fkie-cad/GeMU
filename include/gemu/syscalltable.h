#ifndef GEMU_SYSCALLTABLE_H
#define GEMU_SYSCALLTABLE_H

#include "gemu/gemu.h"
#include "gemu/syscallenums.h"
#include "glib.h"

// Return char must not be freed, it lives inside the loaded cJSON lookup table.
const char *lookup_syscall(Gemu *gemu_instance, const WinProcessInner* process, const int syscall_number);

syscall_t lookup_syscall_enum(Gemu *gemu_instance, const int syscall_number, WinProcessInner* (*get_process) (void));

#endif //GEMU_SYSCALLTABLE_H
