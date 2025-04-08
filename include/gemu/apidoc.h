#ifndef GEMU_APIDOC_H
#define GEMU_APIDOC_H

#include "glib.h"
#include "utils.h"

typedef GHashTable *Apidoc;
typedef cJSON *FunctionApi;


Apidoc init_apidoc(char* apidoc_path);

FunctionApi get_function_api(Apidoc apidoc, char* function_name);

#endif // GEMU_APIDOC_H