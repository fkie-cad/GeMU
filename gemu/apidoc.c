#include "gemu/apidoc.h"


Apidoc init_apidoc(char* apidoc_path){
    return parse_file(apidoc_path);
}

FunctionApi get_function_api(Apidoc apidoc, char* function_name){
    return cJSON_GetObjectItemCaseSensitive(apidoc, function_name);
}