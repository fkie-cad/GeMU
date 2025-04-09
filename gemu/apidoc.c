#include "gemu/apidoc.h"


static FunctionApi* convert_function_entry(cJSON* json_apidoc_entry){
    FunctionApi *function_api = malloc(sizeof(FunctionApi));
    function_api->parameters = cJSON_DetachItemFromObjectCaseSensitive(json_apidoc_entry, "parameters");
    // NOTE: Not used right now
    // function_api->return_type = cJSON_DetachItemFromObjectCaseSensitive(json_apidoc_entry, "return_type");
    cJSON_Delete(json_apidoc_entry);
    return function_api;
}

static Apidoc* apidoc_to_hashtable(cJSON* json_apidoc){
    cJSON* json_apidoc_entry = NULL;
    char* current_key;

    GHashTable *hash_table
    = g_hash_table_new_full (g_str_hash,  /* Hash function  */
                            g_str_equal, /* Comparator     */
                            g_free,
                            g_free);  /* Val destructor */
    while ((json_apidoc_entry =  cJSON_GetArrayItem(json_apidoc, 0)) != NULL){
        current_key = (gpointer)g_strdup(json_apidoc_entry->string);
        cJSON_DetachItemViaPointer(json_apidoc, json_apidoc_entry);
        g_hash_table_insert(
            hash_table,
            current_key,
            convert_function_entry(json_apidoc_entry)
        );
    }

    cJSON_Delete(json_apidoc);
    return hash_table;
}


Apidoc* init_apidoc(char* apidoc_path){
    printf("initialize apidoc\n");
    cJSON* json_apidoc = parse_file(apidoc_path);
    return apidoc_to_hashtable(json_apidoc);
}

//maybe force inline?
FunctionApi *get_function_api(Apidoc* apidoc, char* function_name){
    FunctionApi *result = g_hash_table_lookup(apidoc, (gpointer)function_name);
    return result;
    // return cJSON_GetObjectItemCaseSensitive(apidoc, function_name);
}