// From https://bytepointer.com/resources/index.htm / https://bytepointer.com/resources/tebpeb64.htm
// [TEB/PEB UNDER 64-BIT WINDOWS]
// This file represents the 64-bit PEB and associated data structures for 64-bit Windows
// This PEB is allegedly valid between XP thru [at least] Windows 8
//
// [REFERENCES]
//      http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_x64.html
//      http://terminus.rewolf.pl/terminus/structures/ntdll/_TEB64_x86.html
//      https://github.com/giampaolo/psutil/commit/babd2b73538fcb6f3931f0ab6d9c100df6f37bcb     (RTL_USER_PROCESS_PARAMETERS)
//      https://redplait.blogspot.com/2011/09/w8-64bit-teb-peb.html                             (TEB)
//
// [CHANGELIST]
//    2018-05-02:   -now can be compiled alongside windows.h (without changes) or by defining WANT_ALL_WINDOWS_H_DEFINITIONS so this file can be used standalone
//                  -this file may also be included alongside tebpeb32.h which can be found at http://bytepointer.com/resources/tebpeb32.h
//                  -64-bit types no longer clash with the 32-bit ones; e.g. UNICODE_STRING64, RTL_USER_PROCESS_PARAMETERS64, PEB64 (same result whether 32 or 64-bit compiler is used)
//                  -added more QWORD aliases (i.e. HANDLE64 and PTR64) so underlying types are clearer, however most PEB members remain generic QWORD placeholders for now
//                  -fixed missing semicolon bug in UNICODE_STRING64
//                  -added prliminary RTL_USER_PROCESS_PARAMETERS64 and TEB64 with offsets
//                  -included byte offsets for PEB64
//
//    2017-08-25:   initial public release
//

#ifndef GEMU_PEB_TEB_H
#define GEMU_PEB_TEB_H


//
// base types
//


//always declare 64-bit types
#ifdef _MSC_VER
//Visual C++
    typedef unsigned __int64    QWORD;
    typedef __int64             INT64;
#else
//GCC
typedef unsigned long long QWORD;
typedef long long INT64;
#endif
typedef QWORD PTR64;
typedef QWORD HANDLE64;

//UNCOMMENT line below if you are not including windows.h
#define WANT_ALL_WINDOWS_H_DEFINITIONS
#ifdef WANT_ALL_WINDOWS_H_DEFINITIONS

//base types
typedef unsigned char BYTE;
typedef char CHAR;
typedef unsigned short WORD;
typedef short INT16;
typedef unsigned int DWORD;
typedef int INT32;
//typedef unsigned __int64        QWORD;
//typedef __int64                 INT64;
typedef void *HANDLE;
typedef unsigned short WCHAR;

//base structures
union LARGE_INTEGER {
    struct {
        DWORD LowPart;
        INT32 HighPart;
    } u;
    INT64 QuadPart;
};

union ULARGE_INTEGER {
    struct {
        DWORD LowPart;
        DWORD HighPart;
    } u;
    QWORD QuadPart;
};

#endif //#ifdef WANT_ALL_WINDOWS_H_DEFINITIONS

struct UNICODE_STRING64 {
    union {
        struct {
            WORD Length;
            WORD MaximumLength;
        } u;
        QWORD dummyalign;
    };
    QWORD Buffer;
};

struct UNICODE_STRING {
    WORD Length;
    WORD MaximumLength;
    DWORD Buffer;
};

typedef struct _CLIENT_ID64 {
    QWORD ProcessId;
    QWORD ThreadId;
} CLIENT_ID64;


//NOTE: the members of this structure are not yet complete
typedef struct _RTL_USER_PROCESS_PARAMETERS64 {
    BYTE Reserved1[16];                 //0x00
    QWORD Reserved2[5];                  //0x10
    struct UNICODE_STRING64 CurrentDirectoryPath;          //0x38
    HANDLE64 CurrentDirectoryHandle;        //0x48
    struct UNICODE_STRING64 DllPath;                       //0x50
    struct UNICODE_STRING64 ImagePathName;                 //0x60
    struct UNICODE_STRING64 CommandLine;                   //0x70
    PTR64 Environment;                   //0x80
} RTL_USER_PROCESS_PARAMETERS64;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    QWORD DllBase;
    QWORD EntryPoint;
    DWORD SizeOfImage;
    struct UNICODE_STRING64 FullDllName;
    struct UNICODE_STRING64 BaseDllName;
    QWORD Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            QWORD SectionPointer;
            QWORD CheckSum;
        };
    };
    union
    {
        QWORD TimeDateStamp;
        QWORD LoadedImports;
    };
    QWORD * EntryPointActivationContext;
    QWORD PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
    //DWORD InLoadOrderLinksFlink;
    //DWORD InLoadOrderLinksBlink;
    //DWORD InMemoryOrderLinksFlink;
    //DWORD InMemoryOrderLinksBlink;
    DWORD InMemoryOrderLinksFlink;
    DWORD InMemoryOrderLinksBlink;
    DWORD DllBase;
    DWORD EntryPoint;
    DWORD SizeOfImage;
    struct UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    DWORD Reserved5[3];
    union {
        int CheckSum;
        DWORD Reserved6;
    };
    DWORD TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB_LDR_DATA64
{
    QWORD Length;
    BYTE Initialized;
    QWORD SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    QWORD EntryInProgress;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

typedef struct _PEB_LDR_DATA32
{
    BYTE       Reserved1[12];
    DWORD      Reserved2[4];
    DWORD InMemoryOrderModuleListFlink;
    DWORD InMemoryOrderModuleListBlink;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;


//
// PEB64 structure - TODO: comb more through http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_x64.html and add OS delineations and Windows 10 updates
//
// The structure represented here is a work-in-progress as only members thru offset 0x320 are listed; the actual sizes per OS are:
//    0x0358    XP/WS03
//    0x0368    Vista
//    0x037C    Windows 7
//    0x0388    Windows 8
//    0x07A0    Windows 10
//
typedef struct {
    union {
        struct {
            BYTE InheritedAddressSpace;                                 //0x000
            BYTE ReadImageFileExecOptions;                              //0x001
            BYTE BeingDebugged;                                         //0x002
            BYTE _SYSTEM_DEPENDENT_01;                                  //0x003
        } flags;
        QWORD dummyalign;
    } dword0;
    QWORD Mutant;                             //0x0008
    QWORD ImageBaseAddress;                   //0x0010
    PTR64 Ldr;                                //0x0018
    PTR64 ProcessParameters;                  //0x0020 / pointer to RTL_USER_PROCESS_PARAMETERS64
    QWORD SubSystemData;                      //0x0028
    QWORD ProcessHeap;                        //0x0030
    QWORD FastPebLock;                        //0x0038
    QWORD _SYSTEM_DEPENDENT_02;               //0x0040
    QWORD _SYSTEM_DEPENDENT_03;               //0x0048
    QWORD _SYSTEM_DEPENDENT_04;               //0x0050
    union {
        QWORD KernelCallbackTable;                //0x0058
        QWORD UserSharedInfoPtr;                  //0x0058
    };
    DWORD SystemReserved;                     //0x0060
    DWORD _SYSTEM_DEPENDENT_05;               //0x0064
    QWORD _SYSTEM_DEPENDENT_06;               //0x0068
    QWORD TlsExpansionCounter;                //0x0070
    QWORD TlsBitmap;                          //0x0078
    DWORD TlsBitmapBits[2];                   //0x0080
    QWORD ReadOnlySharedMemoryBase;           //0x0088
    QWORD _SYSTEM_DEPENDENT_07;               //0x0090
    QWORD ReadOnlyStaticServerData;           //0x0098
    QWORD AnsiCodePageData;                   //0x00A0
    QWORD OemCodePageData;                    //0x00A8
    QWORD UnicodeCaseTableData;               //0x00B0
    DWORD NumberOfProcessors;                 //0x00B8
    union {
        DWORD NtGlobalFlag;                       //0x00BC
        DWORD dummy02;                            //0x00BC
    };
    union LARGE_INTEGER CriticalSectionTimeout;             //0x00C0
    QWORD HeapSegmentReserve;                 //0x00C8
    QWORD HeapSegmentCommit;                  //0x00D0
    QWORD HeapDeCommitTotalFreeThreshold;     //0x00D8
    QWORD HeapDeCommitFreeBlockThreshold;     //0x00E0
    DWORD NumberOfHeaps;                      //0x00E8
    DWORD MaximumNumberOfHeaps;               //0x00EC
    QWORD ProcessHeaps;                       //0x00F0
    QWORD GdiSharedHandleTable;               //0x00F8
    QWORD ProcessStarterHelper;               //0x0100
    QWORD GdiDCAttributeList;                 //0x0108
    QWORD LoaderLock;                         //0x0110
    DWORD OSMajorVersion;                     //0x0118
    DWORD OSMinorVersion;                     //0x011C
    WORD OSBuildNumber;                      //0x0120
    WORD OSCSDVersion;                       //0x0122
    DWORD OSPlatformId;                       //0x0124
    DWORD ImageSubsystem;                     //0x0128
    DWORD ImageSubsystemMajorVersion;         //0x012C
    QWORD ImageSubsystemMinorVersion;         //0x0130
    union {
        QWORD ImageProcessAffinityMask;           //0x0138
        QWORD ActiveProcessAffinityMask;          //0x0138
    };
    QWORD GdiHandleBuffer[30];                //0x0140
    QWORD PostProcessInitRoutine;             //0x0230
    QWORD TlsExpansionBitmap;                 //0x0238
    DWORD TlsExpansionBitmapBits[32];         //0x0240
    QWORD SessionId;                          //0x02C0
    union ULARGE_INTEGER AppCompatFlags;                     //0x02C8
    union ULARGE_INTEGER AppCompatFlagsUser;                 //0x02D0
    QWORD pShimData;                          //0x02D8
    QWORD AppCompatInfo;                      //0x02E0
    struct UNICODE_STRING64 CSDVersion;                         //0x02E8
    QWORD ActivationContextData;              //0x02F8
    QWORD ProcessAssemblyStorageMap;          //0x0300
    QWORD SystemDefaultActivationContextData; //0x0308
    QWORD SystemAssemblyStorageMap;           //0x0310
    QWORD MinimumStackCommit;                 //0x0318

} PEB64; //struct PEB64

//
// TEB64 structure - preliminary structure; the portion listed current at least as of Windows 8
//
typedef struct TEB64 {
    BYTE NtTib[56];                          //0x0000 / NT_TIB64 structure
    PTR64 EnvironmentPointer;                 //0x0038
    CLIENT_ID64 ClientId;                           //0x0040
    PTR64 ActiveRpcHandle;                    //0x0050
    PTR64 ThreadLocalStoragePointer;          //0x0058
    PTR64 ProcessEnvironmentBlock;            //0x0060 / ptr to PEB64
    DWORD LastErrorValue;                     //0x0068
    DWORD CountOfOwnedCriticalSections;       //0x006C
    PTR64 CsrClientThread;                    //0x0070
    PTR64 Win32ThreadInfo;                    //0x0078
    DWORD User32Reserved[26];                 //0x0080
    DWORD UserReserved[6];                    //0x00E8
    PTR64 WOW32Reserved;                      //0x0100
    DWORD CurrentLocale;                      //0x0108
    DWORD FpSoftwareStatusRegister;           //0x010C
    PTR64 SystemReserved1[54];                //0x0110
    DWORD ExceptionCode;                      //0x02C0
    PTR64 ActivationContextStackPointer;      //0x02C8

} TEB64; //struct TEB64

//0x248 bytes (sizeof)
typedef struct PEB32{
    BYTE InheritedAddressSpace;                                            //0x0
    BYTE ReadImageFileExecOptions;                                         //0x1
    BYTE BeingDebugged;                                                    //0x2
    union
    {
        BYTE BitField;                                                     //0x3
        struct
        {
            BYTE ImageUsesLargePages:1;                                    //0x3
            BYTE IsProtectedProcess:1;                                     //0x3
            BYTE IsLegacyProcess:1;                                        //0x3
            BYTE IsImageDynamicallyRelocated:1;                            //0x3
            BYTE SkipPatchingUser32Forwarders:1;                           //0x3
            BYTE SpareBits:3;                                              //0x3
        };
    };
    DWORD Mutant;                                                           //0x4
    DWORD ImageBaseAddress;                                                 //0x8
    DWORD Ldr;                                                              //0xc
    DWORD ProcessParameters;                                                //0x10
    DWORD SubSystemData;                                                    //0x14
    DWORD ProcessHeap;                                                      //0x18
    DWORD FastPebLock;                                                      //0x1c
    DWORD AtlThunkSListPtr;                                                 //0x20
    DWORD IFEOKey;                                                          //0x24
    union
    {
        DWORD CrossProcessFlags;                                            //0x28
        struct
        {

            DWORD ProcessInJob:1;                                           //0x28
            DWORD ProcessInitializing:1;                                    //0x28
            DWORD ProcessUsingVEH:1;                                        //0x28
            DWORD ProcessUsingVCH:1;                                        //0x28
            DWORD ProcessUsingFTH:1;                                        //0x28
            DWORD ReservedBits0:27;                                         //0x28
        };
    };
    union
    {
        DWORD KernelCallbackTable;                                          //0x2c
        DWORD UserSharedInfoPtr;                                            //0x2c
    };
    DWORD SystemReserved[1];                                                //0x30
    DWORD AtlThunkSListPtr32;                                               //0x34
    DWORD ApiSetMap;                                                        //0x38
    DWORD TlsExpansionCounter;                                              //0x3c
    DWORD TlsBitmap;                                                        //0x40
    DWORD TlsBitmapBits[2];                                                 //0x44
    DWORD ReadOnlySharedMemoryBase;                                         //0x4c
    DWORD HotpatchInformation;                                              //0x50
    DWORD ReadOnlyStaticServerData;                                         //0x54
    DWORD AnsiCodePageData;                                                 //0x58
    DWORD OemCodePageData;                                                  //0x5c
    DWORD UnicodeCaseTableData;                                             //0x60
    DWORD NumberOfProcessors;                                               //0x64
    DWORD NtGlobalFlag;                                                     //0x68
    QWORD CriticalSectionTimeout;                            //0x70
    DWORD HeapSegmentReserve;                                               //0x78
    DWORD HeapSegmentCommit;                                                //0x7c
    DWORD HeapDeCommitTotalFreeThreshold;                                   //0x80
    DWORD HeapDeCommitFreeBlockThreshold;                                   //0x84
    DWORD NumberOfHeaps;                                                    //0x88
    DWORD MaximumNumberOfHeaps;                                             //0x8c
    DWORD ProcessHeaps;                                                     //0x90
    DWORD GdiSharedHandleTable;                                             //0x94
    DWORD ProcessStarterHelper;                                             //0x98
    DWORD GdiDCAttributeList;                                               //0x9c
    DWORD LoaderLock;                                                       //0xa0
    DWORD OSMajorVersion;                                                   //0xa4
    DWORD OSMinorVersion;                                                   //0xa8
    BYTE OSBuildNumber;                                                   //0xac
    BYTE OSCSDVersion;                                                    //0xae
    DWORD OSPlatformId;                                                     //0xb0
    DWORD ImageSubsystem;                                                   //0xb4
    DWORD ImageSubsystemMajorVersion;                                       //0xb8
    DWORD ImageSubsystemMinorVersion;                                       //0xbc
    DWORD ActiveProcessAffinityMask;                                        //0xc0
    DWORD GdiHandleBuffer[34];                                              //0xc4
    DWORD PostProcessInitRoutine;                                           //0x14c
    DWORD TlsExpansionBitmap;                                               //0x150
    DWORD TlsExpansionBitmapBits[32];                                       //0x154
    DWORD SessionId;                                                        //0x1d4
    QWORD AppCompatFlags;                                   //0x1d8
    QWORD AppCompatFlagsUser;                               //0x1e0
    DWORD pShimData;                                                        //0x1e8
    DWORD AppCompatInfo;                                                    //0x1ec
    struct UNICODE_STRING CSDVersion;                                            //0x1f0
    DWORD ActivationContextData;                                            //0x1f8
    DWORD ProcessAssemblyStorageMap;                                        //0x1fc
    DWORD SystemDefaultActivationContextData;                               //0x200
    DWORD SystemAssemblyStorageMap;                                         //0x204
    DWORD MinimumStackCommit;                                               //0x208
    DWORD FlsCallback;                                                      //0x20c
    DWORD FlsListHead;                                        //0x210
    DWORD FlsBitmap;                                                        //0x218
    DWORD FlsBitmapBits[4];                                                 //0x21c
    DWORD FlsHighIndex;                                                     //0x22c
    DWORD WerRegistrationData;                                              //0x230
    DWORD WerShipAssertPtr;                                                 //0x234
    DWORD pContextData;                                                     //0x238
    DWORD pImageHeaderHash;                                                 //0x23c
    union
    {
        DWORD TracingFlags;                                                 //0x240
        struct
        {
            DWORD HeapTracingEnabled:1;                                     //0x240
            DWORD CritSecTracingEnabled:1;                                  //0x240
            DWORD SpareTracingBits:30;                                      //0x240
        };
    };
} PEB32;

typedef struct _CLIENT_ID32
{
    DWORD UniqueProcess;                                                    //0x0
    DWORD UniqueThread;                                                     //0x4
} CLIENT_ID32;

//0xfe4 bytes (sizeof)
typedef struct _TEB32
{
    DWORD ExceptionList;                                                    //0x0
    DWORD StackBase;                                                        //0x4
    DWORD StackLimit;                                                       //0x8
    DWORD SubSystemTib;                                                     //0xc
    union
    {
        DWORD FiberData;                                                    //0x10
        DWORD Version;                                                      //0x10
    };
    DWORD ArbitraryUserPointer;                                             //0x14
    DWORD Self;                                                             //0x18
    DWORD EnvironmentPointer;                                               //0x1c
    DWORD UniqueProcess;                                                    //0x20
    DWORD UniqueThread;                                                     //0x24
    DWORD ActiveRpcHandle;                                                  //0x28
    DWORD ThreadLocalStoragePointer;                                        //0x2c
    DWORD ProcessEnvironmentBlock;                                          //0x30
    DWORD LastErrorValue;                                                   //0x34
    DWORD CountOfOwnedCriticalSections;                                     //0x38
    DWORD CsrClientThread;                                                  //0x3c
    DWORD Win32ThreadInfo;                                                  //0x40
    DWORD User32Reserved[26];                                               //0x44
    DWORD UserReserved[5];                                                  //0xac
    DWORD WOW32Reserved;                                                    //0xc0
    DWORD CurrentLocale;                                                    //0xc4
    DWORD FpSoftwareStatusRegister;                                         //0xc8
    DWORD SystemReserved1[54];                                              //0xcc
    int ExceptionCode;                                                     //0x1a4
    DWORD ActivationContextStackPointer;                                    //0x1a8
    BYTE SpareBytes[36];                                                   //0x1ac
    DWORD TxFsContext;                                                      //0x1d0
    DWORD GdiTebBatch;                                    //0x1d4
    DWORD RealClientId;                                       //0x6b4
    DWORD GdiCachedProcessHandle;                                           //0x6bc
    DWORD GdiClientPID;                                                     //0x6c0
    DWORD GdiClientTID;                                                     //0x6c4
    DWORD GdiThreadLocalInfo;                                               //0x6c8
    DWORD Win32ClientInfo[62];                                              //0x6cc
    DWORD glDispatchTable[233];                                             //0x7c4
    DWORD glReserved1[29];                                                  //0xb68
    DWORD glReserved2;                                                      //0xbdc
    DWORD glSectionInfo;                                                    //0xbe0
    DWORD glSection;                                                        //0xbe4
    DWORD glTable;                                                          //0xbe8
    DWORD glCurrentRC;                                                      //0xbec
    DWORD glContext;                                                        //0xbf0
    DWORD LastStatusValue;                                                  //0xbf4
    struct UNICODE_STRING StaticUnicodeString;                                   //0xbf8
    BYTE StaticUnicodeBuffer[261];                                         //0xc00
    DWORD DeallocationStack;                                                //0xe0c
    DWORD TlsSlots[64];                                                     //0xe10
    DWORD TlsLinks;                                           //0xf10
    DWORD Vdm;                                                              //0xf18
    DWORD ReservedForNtRpc;                                                 //0xf1c
    DWORD DbgSsReserved[2];                                                 //0xf20
    DWORD HardErrorMode;                                                    //0xf28
    DWORD Instrumentation[9];                                               //0xf2c
    DWORD ActivityId;                                                //0xf50
    DWORD SubProcessTag;                                                    //0xf60
    DWORD EtwLocalData;                                                     //0xf64
    DWORD EtwTraceData;                                                     //0xf68
    DWORD WinSockData;                                                      //0xf6c
    DWORD GdiBatchCount;                                                    //0xf70
    union
    {
        DWORD CurrentIdealProcessor;                     //0xf74
        DWORD IdealProcessorValue;                                          //0xf74
        struct
        {
            BYTE ReservedPad0;                                             //0xf74
            BYTE ReservedPad1;                                             //0xf75
            BYTE ReservedPad2;                                             //0xf76
            BYTE IdealProcessor;                                           //0xf77
        };
    };
    DWORD GuaranteedStackBytes;                                             //0xf78
    DWORD ReservedForPerf;                                                  //0xf7c
    DWORD ReservedForOle;                                                   //0xf80
    DWORD WaitingOnLoaderLock;                                              //0xf84
    DWORD SavedPriorityState;                                               //0xf88
    DWORD SoftPatchPtr1;                                                    //0xf8c
    DWORD ThreadPoolData;                                                   //0xf90
    DWORD TlsExpansionSlots;                                                //0xf94
    DWORD MuiGeneration;                                                    //0xf98
    DWORD IsImpersonating;                                                  //0xf9c
    DWORD NlsCache;                                                         //0xfa0
    DWORD pShimData;                                                        //0xfa4
    DWORD HeapVirtualAffinity;                                              //0xfa8
    DWORD CurrentTransactionHandle;                                         //0xfac
    DWORD ActiveFrame;                                                      //0xfb0
    DWORD FlsData;                                                          //0xfb4
    DWORD PreferredLanguages;                                               //0xfb8
    DWORD UserPrefLanguages;                                                //0xfbc
    DWORD MergedPrefLanguages;                                              //0xfc0
    DWORD MuiImpersonation;                                                 //0xfc4
    union
    {
        volatile BYTE CrossTebFlags;                                      //0xfc8
        BYTE SpareCrossTebBits;                                        //0xfc8
    };
    union
    {
        BYTE SameTebFlags;                                                //0xfca
        struct
        {
            BYTE SafeThunkCall:1;                                         //0xfca
            BYTE InDebugPrint:1;                                          //0xfca
            BYTE HasFiberData:1;                                          //0xfca
            BYTE SkipThreadAttach:1;                                      //0xfca
            BYTE WerInShipAssertCode:1;                                   //0xfca
            BYTE RanProcessInit:1;                                        //0xfca
            BYTE ClonedThread:1;                                          //0xfca
            BYTE SuppressDebugMsg:1;                                      //0xfca
            BYTE DisableUserStackWalk:1;                                  //0xfca
            BYTE RtlExceptionAttached:1;                                  //0xfca
            BYTE InitialThread:1;                                         //0xfca
            BYTE SpareSameTebBits:5;                                      //0xfca
        };
    };
    DWORD TxnScopeEnterCallback;                                            //0xfcc
    DWORD TxnScopeExitCallback;                                             //0xfd0
    DWORD TxnScopeContext;                                                  //0xfd4
    DWORD LockCount;                                                        //0xfd8
    DWORD SpareDWORD0;                                                      //0xfdc
    DWORD ResourceRetValue;                                                 //0xfe0
} TEB32;

typedef struct _PROCESS_INFORMATION64 {
    QWORD hProcess;
    QWORD hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
} PROCESS_INFORMATION64, *PPROCESS_INFORMATION64, *LPPROCESS_INFORMATION64;

typedef struct _PROCESS_INFORMATION32 {
    DWORD hProcess;
    DWORD hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
} PROCESS_INFORMATION32, *PPROCESS_INFORMATION32, *LPPROCESS_INFORMATION32;


#endif //GEMU_PEB_TEB_H
