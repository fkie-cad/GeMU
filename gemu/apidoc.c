#include "gemu/apidoc.h"


void* init_apidoc(char* apidoc_path){
    return parse_file(apidoc_path);
}