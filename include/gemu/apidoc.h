#ifndef GEMU_APIDOC_H
#define GEMU_APIDOC_H

#include "glib.h"
#include "utils.h"

typedef GHashTable Apidoc;

#define MAX_PARAMETERS 10

typedef enum {
  PARAMETER_IN  = 0x0001,
  PARAMETER_OUT = 0x0010,
  PARAMETER_OPT = 0x0100,
} ParameterAttribute;

typedef struct{
  ParameterAttribute attributes;
  char *type;
  char *name;
} FunctionParameter;

typedef struct {
  FunctionParameter parameters[MAX_PARAMETERS];
  int num_parameters;
  cJSON *return_type;
} FunctionApi;


Apidoc* init_apidoc(char* apidoc_path);

FunctionApi* get_function_api(Apidoc* apidoc, const char* function_name);

bool is_in_parameter(FunctionParameter* parameter);

bool is_out_parameter(FunctionParameter* parameter);

#endif // GEMU_APIDOC_H