#ifndef GEMU_APIDOC_H
#define GEMU_APIDOC_H

#include "glib.h"
#include "utils.h"

typedef GHashTable Apidoc;
typedef cJSON FunctionParameter;

typedef struct {
  cJSON *parameters;
  cJSON *return_type;
} FunctionApi;


typedef enum {
  PARAMETER_IN  = 0x0001,
  PARAMETER_OUT = 0x0010,
  PARAMETER_OPT = 0x0100,
} ParameterAttribute;


Apidoc* init_apidoc(char* apidoc_path);

FunctionApi* get_function_api(Apidoc* apidoc, char* function_name);

bool is_in_parameter(Apidoc* apidoc, FunctionParameter* parameter);

bool is_out_parameter(Apidoc* apidoc, FunctionParameter* parameter);

#endif // GEMU_APIDOC_H