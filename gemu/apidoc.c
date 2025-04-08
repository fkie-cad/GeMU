#include "gemu/apidoc.h"


Apidoc init_apidoc(char* apidoc_path){
    printf("initialize apidoc\n");

    cJSON* json_apidoc = parse_file(apidoc_path);
    cJSON* json_apidoc_entry = NULL;
    char* current_key;

    GHashTable *hash_table
    = g_hash_table_new_full (g_str_hash,  /* Hash function  */
                            g_str_equal, /* Comparator     */
                            g_free,
                            g_free);  /* Val destructor */
    while ((json_apidoc_entry =  cJSON_GetArrayItem(json_apidoc, 0)) != NULL){
        current_key = json_apidoc_entry->string;
        g_hash_table_insert(
            hash_table,
            (gpointer)g_strdup(current_key),
            json_apidoc_entry
        );
        cJSON_DetachItemFromArray(json_apidoc, 0);
    }

    cJSON_Delete(json_apidoc);
    return hash_table;
}

//maybe force inline?
FunctionApi get_function_api(Apidoc apidoc, char* function_name){
    FunctionApi result = g_hash_table_lookup(apidoc, (gpointer)function_name);
    return result;
    // return cJSON_GetObjectItemCaseSensitive(apidoc, function_name);
}