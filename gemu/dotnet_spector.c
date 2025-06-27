#include "gemu/dotnet_spector.h"
#include "gemu/utils.h"
#include "gemu/gemu.h"
#include <stdio.h>

#define fill_struct(cpu, address, struct_ptr) gemu_virtual_memory_rw(cpu, address, (uint8_t *) struct_ptr, sizeof(*struct_ptr), 0);
#define METHOD_DESC_ALIGNMENT 8; //64bit only

void handle_jit_compile_method(CPUState *cpu, target_ulong info_ptr, target_ulong native_address, void* native_code_hook_function){
    //TODO: only for 64 bit so far
    // read MethodInfo
    CORINFO_METHOD_INFO_PARTIAL_64 method_info;
    printf("read info at 0x%lX\n", info_ptr);
    fill_struct(cpu, info_ptr, &method_info);
    printf("ftn: 0x%llX ", method_info.ftn);
    printf("scope: 0x%llX ", method_info.scope);
    printf("ilcode: 0x%llX ", method_info.ILCode);
    printf("ilcodesize: 0x%X ", method_info.ILCodeSize);
    printf("maxstack: 0x%X ", method_info.maxStack);
    printf("ehcount: 0x%X ", method_info.EHcount);
    printf("\n");

    //read IL
    uint64_t limited_il_size = method_info.ILCodeSize;
    if (limited_il_size > 0x1000){
        limited_il_size = 0x1000;
    }
    uint8_t il_code[0x1000];

    gemu_virtual_memory_rw(cpu, method_info.ILCode, il_code, limited_il_size, 0);
    for(int i = 0; i<limited_il_size; i++){
        printf("%02hhx ", il_code[i]);
        if (i%32==31){
            printf("\n");
        }
    }
    printf("\n");

    // read method desc
    METHOD_DESC method_desc;
    fill_struct(cpu, method_info.ftn, &method_desc);
    QWORD first_method_desc_address = method_info.ftn - (QWORD)method_desc.m_chunkIndex*METHOD_DESC_ALIGNMENT;
    QWORD method_chunk_address = first_method_desc_address - sizeof(METHOD_DESC_CHUNK);
    printf("method_desc_address: 0x%llX, chunkindex: 0x%hhX, first_method_desc_address: 0x%llX, method_chunk_address: 0x%llX, flags_and_tokenremainder: 0x%X\n",
        method_info.ftn, method_desc.m_chunkIndex, first_method_desc_address, method_chunk_address, method_desc.m_wFlags3AndTokenRemainder);

    METHOD_DESC_CHUNK chunk;
    fill_struct(cpu, method_chunk_address, &chunk);

    //NOTE: This is required for older .NET Framework versions
    chunk.m_methodTable += method_chunk_address;
    chunk.m_next += method_chunk_address;

    printf("chunk Data... method_table: 0x%llX, next_chunk: 0x%llX, size_minus_one: 0x%hhx, count_minus_one:0x%hhX, flags and tokenrange: 0x%hX\n",
    chunk.m_methodTable, chunk.m_next, chunk.m_size, chunk.m_count, chunk.m_flagsAndTokenRange);

    DWORD tokremainder = method_desc.m_wFlags3AndTokenRemainder & 0x0FFF;
    DWORD tokrange = chunk.m_flagsAndTokenRange & 0x0FFF;
    QWORD token = (tokrange << 12) | tokremainder | 0x06000000;
    printf("\ntoken (unclear from which module...): 0x%llX\n", token);

    METHOD_TABLE method_table;
    fill_struct(cpu, chunk.m_methodTable, &method_table);
    printf("method table data... basesize: 0x%X\n, module: 0x%llX\n",
        method_table.m_BaseSize, method_table.m_pModule);
    printf("\n");

    // 16 instead of 8 for old .NET Framework
    DWORD typedef_token = ((method_table.m_dwFlags2 >> 16)  | 0x2000000);
    printf("typedef token: 0x%X\n", typedef_token);

    uint8_t buf[256];
    gemu_virtual_memory_rw(cpu, chunk.m_methodTable, buf, 128,0);

    WORD slot_num = method_desc.m_wSlotNumber;
    if ((method_desc.m_wFlags & 0x8000) == 0){
        slot_num &= 0x3ff;
    }
    QWORD slot_address = (chunk.m_methodTable + ((slot_num >> 3) << 3) + 0x40) + ((slot_num & 7) << 3);
    QWORD slot;
    printf("\nslot num: 0x%X, slot address: 0x%llX\n", slot_num, slot_address);
    gemu_virtual_memory_rw(cpu, slot_address, (uint8_t*)&slot, sizeof(slot), 0);
    printf("slot(points to code): 0x%llX\n\n", slot);

    EEClass class;
    fill_struct(cpu, method_table.m_pEEClass, &class);
    printf("EEClass: method_table: 0x%llX\n\n", class.m_pMethodTable);

    MODULE module;
    fill_struct(cpu, method_table.m_pModule, &module);
    printf("\n");
    printf("module... peAssembly address:%llX simple_name address: 0x%llX\n",
        module.m_pPEAssembly, module.m_pSimpleName);
    printf("\n");

    PEAssembly assembly;
    fill_struct(cpu, module.m_pPEAssembly, &assembly);
    printf("PE File/Image Address: 0x%llX, MDImport Address: 0x%llX \n", assembly.m_PEImage, assembly.m_pMDImport);
    printf("\n");

    PEFile pefile;
    fill_struct(cpu, assembly.m_PEImage, &pefile);
    printf("indirection of .NET Framework 4. PE File -> PE Image: 0x%llX\n\n", pefile.m_PEImage);


    PEImage image;
    fill_struct(cpu, pefile.m_PEImage, &image);
    printf("PE Image... Flat image at 0x%llx, Loaded image at 0x%llx\n", image.m_pLayouts[IMAGE_FLAT], image.m_pLayouts[IMAGE_LOADED]);
    printf("\n");

    PEImageLayout layout_flat, layout_loaded;

    fill_struct(cpu, image.m_pLayouts[IMAGE_FLAT], &layout_flat);
    fill_struct(cpu, image.m_pLayouts[IMAGE_LOADED], &layout_loaded);
    printf("PEImage Layout... \n");
    printf("Flat  : Base 0x%llX, size 0x%x \n", layout_flat.m_base, layout_flat.m_size);
    printf("Loaded: Base 0x%llX, size 0x%x \n", layout_loaded.m_base, layout_loaded.m_size);
    printf("\n");

    buf[0] = buf[1] = '?';
    buf[2] = 0;
    gemu_virtual_memory_rw(cpu, layout_flat.m_base, buf, 2, 0);
    printf("Flat base content starts with: %s\n", buf);
    buf[0] = buf[1] = '?';
    buf[2] = 0;
    gemu_virtual_memory_rw(cpu, layout_loaded.m_base, buf, 2, 0);
    printf("Loaded base content starts with: %s\n", buf);
    printf("\n");

    char simple_name[100];

    fill_struct(cpu, module.m_pSimpleName, simple_name);
    printf("\n");


    if(native_address != 0){
        char hook_name[100];
        static unsigned long jitted_functions_count = 0;
        sprintf(hook_name, "JIT_0x%llX_0x%lX", token, jitted_functions_count);
        jitted_functions_count++;
        printf("address to hook: 0x%lX, name %s\n", native_address, hook_name);
        hook_address(hook_name, "CIL", native_address, native_code_hook_function);
    }

}

