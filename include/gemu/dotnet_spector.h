#ifndef GEMU_DOTNET_SPECTOR_H
#define GEMU_DOTNET_SPECTOR_H

#include <stdint.h>
#include "qemu/typedefs.h"
#include "gemu/peb_teb.h"

// struct defs for .NET //
typedef uint16_t UINT16;

typedef struct {
    QWORD ftn;
    QWORD scope;
    QWORD ILCode;
    DWORD ILCodeSize;
    DWORD maxStack;
    DWORD EHcount;
}  CORINFO_METHOD_INFO_PARTIAL_64;

#pragma pack(1)
typedef struct{
    UINT16      m_wFlags3AndTokenRemainder;
    BYTE        m_chunkIndex;
    BYTE        m_bFlags4; // Used to hold more flags
    WORD m_wSlotNumber; // The slot number of this MethodDesc in the vtable array.
    WORD m_wFlags; // See MethodDescFlags
} METHOD_DESC;
#pragma pack()


typedef QWORD PTR_MethodTable, PTR_MethodDescChunk, PTR_Module, PTR_MethodTableAuxiliaryData, PerInstInfo_t, PTR_InterfaceInfo;
// #pragma pack(1)
typedef struct{
    PTR_MethodTable m_methodTable;
    PTR_MethodDescChunk  m_next;
    BYTE                 m_size;        // The size of this chunk minus 1 (in multiples of MethodDesc::ALIGNMENT)
    BYTE                 m_count;       // The number of MethodDescs in this chunk minus 1
    UINT16               m_flagsAndTokenRange;
    // Followed by array of method descs...
} METHOD_DESC_CHUNK;
// #pragma pack()

#pragma pack(1)
typedef struct{
    DWORD           m_dwFlags;      //0
    DWORD           m_BaseSize;     //4
    DWORD           m_dwFlags2;     //8 (includes a at offset 16)
    WORD            m_wNumVirtuals; //c
    WORD            m_wNumInterfaces;//e
    PTR_MethodTable m_pParentMethodTable; //0x10
    PTR_Module      m_pModule; //0x18
    PTR_MethodTableAuxiliaryData m_pAuxiliaryData;
    QWORD           m_pEEClass;
    PerInstInfo_t   m_pPerInstInfo;
    PTR_InterfaceInfo   m_pInterfaceMap;
} METHOD_TABLE;
#pragma pack()
// end struct defs

typedef QWORD PTR_CUTF8, PTR_PEAssembly, PTR_Assembly, PTR_VOID, PTR_LoaderAllocator;
typedef uint8_t LookupMap[32], CrstExplicitInit[136];
#pragma pack(1)
typedef struct {
    // parent
    // LookupMap               m_TypeRefToMethodTableMap;
    // LookupMap               m_ManifestModuleReferencesMap;
    // LookupMap               m_MemberRefMap;
    // CrstExplicitInit        m_LookupTableCrst;
    // PTR_LoaderAllocator     m_loaderAllocator;
    // child
    PTR_CUTF8               m_pSimpleName; // Cached simple name for better performance and easier diagnostics
    const WCHAR*            m_path;        // Cached path for easier diagnostics
    PTR_PEAssembly          m_pPEAssembly; // at 0x10
    PTR_VOID                m_baseAddress; // Cached base address for easier diagnostics //at 0x18
    DWORD                   m_dwTransientFlags; // 0x20
    DWORD                   m_dwPersistedFlags; // 0x24
    QWORD                   m_pVASigCookieBlock; //0x28
    PTR_Assembly            m_pAssembly; //0x30
    // CrstExplicitInit        m_Crst;
    // ISymUnmanagedReader *   m_pISymUnmanagedReader;
    // CrstExplicitInit        m_ISymUnmanagedReaderCrst;
    // PTR_CGrowableStream     m_pIStreamSym;
    // LookupMap m_TypeDefToMethodTableMap;
    // LookupMap m_MethodDefToDescMap;
    // LookupMap m_ILCodeVersioningStateMap;
    // LookupMap m_FieldDefToDescMap;
    // LookupMap m_GenericParamToDescMap;
    // ILStubCache                *m_pILStubCache;
    // ULONG m_DefaultDllImportSearchPathsAttributeValue;
    // PTR_EEClassHashTable    m_pAvailableClasses;
    // PTR_EETypeHashTable     m_pAvailableParamTypes;
    // CrstExplicitInit        m_InstMethodHashTableCrst;
    // PTR_InstMethodHashTable m_pInstMethodHashTable;
    // DWORD                   m_dwDebuggerJMCProbeCount;
} MODULE;
#pragma pack()

typedef QWORD PTR_PEImage, PTR_IMDInternalImport;
typedef struct {
    // IL image, NULL if dynamic
    PTR_PEImage              m_PEImage;
    char filler[0x28];
    PTR_IMDInternalImport m_pMDImport; //0x30
} PEAssembly;

typedef QWORD BundleFileLocation, SimpleRWLock, PTR_PEImageLayout;
typedef char SString[16]; // not sure if correct for framework
typedef int BOOL, LONG;
typedef unsigned int ULONG;

typedef struct {
    char _filler[0x18];
    QWORD m_PEImage;
} PEFile; //needed because of old .NET Framework 4


enum image_layout_type_t
{
    IMAGE_FLAT=0,
    IMAGE_LOADED=1,
    IMAGE_COUNT=2
};

typedef struct {
    const SString   m_path;
    ULONG     m_pathHash;
    LONG      m_refCount;

    // means this is a unique (deduped) instance.
    BOOL      m_bInHashMap;

    // If this image is located within a single-file bundle, the location within the bundle.
    // If m_bundleFileLocation is valid, it takes precedence over m_path for loading.
    BundleFileLocation m_bundleFileLocation;

    // valid handle if we tried to open the file/path and succeeded.
    HANDLE m_hFile;

    DWORD m_dwPEKind;
    DWORD m_dwMachine;

    // This variable will have the data of module name.
    // It is only used by DAC to remap fusion loaded modules back to
    // disk IL. This really is a workaround. The real fix is for fusion loader
    // hook (public API on hosting) to take an additional file name hint.
    // We are piggy backing on the fact that module name is the same as file name!!!
    SString   m_sModuleFileNameHintUsedByDac; // This is only used by DAC
    SimpleRWLock *m_pLayoutLock;
    // see image_layout_type_t
    PTR_PEImageLayout m_pLayouts[IMAGE_COUNT]; // should be at 0x50 and 0x58
    PTR_IMDInternalImport m_pMDImport;
} PEImage;

typedef QWORD TADDR, PTR_IMAGE_NT_HEADERS, PTR_IMAGE_COR20_HEADER, PTR_READYTORUN_HEADER;
typedef DWORD COUNT_T;
typedef struct {
    TADDR               m_base;
    COUNT_T             m_size;     // size of file on disk, as opposed to OptionalHeaders.SizeOfImage
    ULONG               m_flags;

    PTR_IMAGE_NT_HEADERS   m_pNTHeaders;
    PTR_IMAGE_COR20_HEADER m_pCorHeader;
    PTR_READYTORUN_HEADER  m_pReadyToRunHeader;
} PEImageLayout;

typedef QWORD addresslist[150];

typedef QWORD PTR_GuidInfo, PTR_EEClassOptionalFields, PTR_FieldDesc;
#pragma pack(1)
typedef struct {
    // C_ASSERTs in Jitinterface.cpp need this to be public to check the offset.
    // Put it first so the offset rarely changes, which just reduces the number of times we have to fiddle
    // with the offset.
    PTR_GuidInfo m_pGuidInfo;  // The cached guid information for interfaces.
    // Layout rest of fields below from largest to smallest to lessen the chance of wasting bytes with
    // compiler injected padding (especially with the difference between pointers and DWORDs on 64-bit).
    PTR_EEClassOptionalFields m_rpOptionalFields;
    // TODO: Remove this field. It is only used by SOS and object validation for stress.
    PTR_MethodTable m_pMethodTable;
    PTR_FieldDesc m_pFieldDescList;
    PTR_MethodDescChunk m_pChunks;
    //OBJECTHANDLE    m_ohDelegate;
    //ComCallWrapperTemplate *m_pccwTemplate;   // points to interop data structures used when this type is exposed to COM
    DWORD m_dwAttrClass;
    DWORD m_VMFlags;
    // NOTE: Following BYTE fields are laid out together so they'll fit within the same DWORD for efficient
    // structure packing.
    BYTE m_NormType;
    BYTE m_cbBaseSizePadding;       // How many bytes of padding are included in BaseSize

    WORD m_NumInstanceFields;
    WORD m_NumMethods;
    WORD m_NumStaticFields;
    WORD m_NumHandleStatics;
    WORD m_NumThreadStaticFields;
    WORD m_NumHandleThreadStatics;
    WORD m_NumNonVirtualSlots;
    DWORD m_NonGCStaticFieldBytes;
    DWORD m_NonGCThreadStaticFieldBytes;
} EEClass;
#pragma pack()


//////////////////

void handle_jit_compile_method(CPUState *cpu, target_ulong info_ptr, target_ulong native_address, void* native_code_hook_function);

#endif //GEMU_DOTNET_SPECTOR_H
