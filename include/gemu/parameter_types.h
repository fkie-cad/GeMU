
#ifndef GEMU_PARAMETER_TYPES_H
#define GEMU_PARAMETER_TYPES_H

#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "gemu/apidoc.h"
#include "gemu/win_spector.h"
#include "gemu/cJSON.h"
#include "gemu/peb_teb.h"
#include <stdbool.h>

/*
 * A type handler is a function that knows how to serialize one parameter
 * into the output JSON object. It receives the parameter descriptor, the
 * raw value (pointer or scalar), and the current context. Returns true if
 * it handled the parameter, false to fall through to the next handler.
 */
typedef bool (*type_handler_fn)(CPUState *cpu, const FunctionParameter *param,
                                QWORD value, cJSON *output, WinProcess *process,
                                bool is32bit);

/*
 * Register a handler that fires when parameter->type is in type_names
 * (null-terminated list of strings).
 */
void register_type_name_handler(const char **type_names, type_handler_fn fn);

/*
 * Register a handler that fires when parameter->name is in param_names
 * (null-terminated list of strings).
 */
void register_param_name_handler(const char **param_names, type_handler_fn fn);


/*
 * Try registered handlers in registration order. Returns true if a handler
 * matched and ran, false if none matched.
 */
void dispatch_type_handler(CPUState *cpu, const FunctionParameter *param,
                           QWORD value, cJSON *output, WinProcess *process,
                           bool is32bit);

/*
 * Register all built-in type handlers. Must be called once during init.
 */
void init_type_handlers(void);

#endif // GEMU_PARAMETER_TYPES_H
