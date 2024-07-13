#pragma once

#pragma once


#include<Windows.h>

#define SW2_HEADER_H_



#define SW2_SEED 0xBE5BD965
#define SW2_ROL8(v) (v << 8 | v >> 24)
#define SW2_ROR8(v) (v >> 8 | v << 24)
#define SW2_ROX8(v) ((SW2_SEED % 2) ? SW2_ROL8(v) : SW2_ROR8(v))
#define SW2_MAX_ENTRIES 500
#define SW2_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

// Typedefs are prefixed to avoid pollution.

#pragma once
#include <Windows.h>  
/*
    header file that contains our own definition of LDR_DATA_TABLE_ENTRY & PEB  ( and the needed structs to define them )
*/
#define STRUCTS
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef PVOID PACTIVATION_CONTEXT;
typedef PVOID PRTL_USER_PROCESS_PARAMETERS;
typedef PVOID PAPI_SET_NAMESPACE;
// https://www.nirsoft.net/kernel_struct/vista/PEB_LDR_DATA.html

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	ULONG                 Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


// https://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html  
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PACTIVATION_CONTEXT EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// https://github.com/processhacker/phnt/blob/master/ntpebteb.h#L69



typedef struct _PEB

{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		};
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PSLIST_HEADER AtlThunkSListPtr;
	PVOID IFEOKey;

	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ProcessImagesHotPatched : 1; // REDSTONE5
			ULONG ReservedBits0 : 24;
		};
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PAPI_SET_NAMESPACE ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID SharedData; // HotpatchInformation
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData; // PCPTABLEINFO
	PVOID OemCodePageData; // PCPTABLEINFO
	PVOID UnicodeCaseTableData; // PNLSTABLEINFO
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	ULARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps; // PHEAP
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PRTL_CRITICAL_SECTION LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	KAFFINITY ActiveProcessAffinityMask;
	ULONG GdiHandleBuffer[60];
	PVOID PostProcessInitRoutine;
	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];
	ULONG SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA
	UNICODE_STRING CSDVersion;
	PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
	PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
	PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
	PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
	SIZE_T MinimumStackCommit;
	PVOID SparePointers[2]; // 19H1 (previously FlsCallback to FlsHighIndex)
	PVOID PatchLoaderData;
	PVOID ChpeV2ProcessInfo; // _CHPEV2_PROCESS_INFO
	ULONG AppModelFeatureState;
	ULONG SpareUlongs[2];
	USHORT ActiveCodePage;
	USHORT OemCodePage;
	USHORT UseCaseMapping;
	USHORT UnusedNlsField;
	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
	union
	{
		PVOID pContextData; // WIN7
		PVOID pUnused; // WIN10
		PVOID EcCodeBitMap; // WIN11
	};
	PVOID pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	PRTL_CRITICAL_SECTION TppWorkerpListLock;
	LIST_ENTRY TppWorkerpList;
	PVOID WaitOnAddressHashTable[128];
	PVOID TelemetryCoverageHeader; // REDSTONE3
	ULONG CloudFileFlags;
	ULONG CloudFileDiagFlags; // REDSTONE4
	CHAR PlaceholderCompatibilityMode;
	CHAR PlaceholderCompatibilityModeReserved[7];
	struct _LEAP_SECOND_DATA* LeapSecondData; // REDSTONE5
	union
	{
		ULONG LeapSecondFlags;
		struct
		{
			ULONG SixtySecondEnabled : 1;
			ULONG Reserved : 31;
		};
	};
	ULONG NtGlobalFlag2;
	ULONGLONG ExtendedFeatureDisableMask; // since WIN11
} PEB, * PPEB;




typedef struct _SW2_SYSCALL_ENTRY
{
	DWORD Hash;
	DWORD Address;
} SW2_SYSCALL_ENTRY, * PSW2_SYSCALL_ENTRY;

typedef struct _SW2_SYSCALL_LIST
{
	DWORD Count;
	SW2_SYSCALL_ENTRY Entries[SW2_MAX_ENTRIES];
} SW2_SYSCALL_LIST, * PSW2_SYSCALL_LIST;

typedef struct _SW2_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} SW2_PEB_LDR_DATA, * PSW2_PEB_LDR_DATA;

typedef struct _SW2_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} SW2_LDR_DATA_TABLE_ENTRY, * PSW2_LDR_DATA_TABLE_ENTRY;

typedef struct _SW2_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PSW2_PEB_LDR_DATA Ldr;
} SW2_PEB, * PSW2_PEB;

DWORD SW2_HashSyscall(PCSTR FunctionName);
BOOL SW2_PopulateSyscallList(void);
EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash);

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif


typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;


////////////api////////////
extern "C" {
	using virloc = NTSTATUS(NTAPI*)(
		IN HANDLE           ProcessHandle,    // Process handle in where to allocate memory
		IN OUT PVOID* BaseAddress,     // The returned allocated memory's base address
		IN ULONG_PTR        ZeroBits,         // Always set to '0'
		IN OUT PSIZE_T      RegionSize,       // Size of memory to allocate
		IN ULONG            AllocationType,   // MEM_COMMIT | MEM_RESERVE
		IN ULONG            Protect           // Page protection 
		);


	using Writeproc = NTSTATUS(NTAPI*)(
		IN HANDLE ProcessHandle,
		IN PVOID BaseAddress,
		IN PVOID Buffer,
		IN SIZE_T NumberOfBytesToWrite,
		OUT PSIZE_T NumberOfBytesWritten OPTIONAL);




	using createthread = NTSTATUS(NTAPI*)(
		OUT PHANDLE ThreadHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN HANDLE ProcessHandle,
		IN PVOID StartRoutine,
		IN PVOID Argument OPTIONAL,
		IN ULONG CreateFlags,
		IN SIZE_T ZeroBits,
		IN SIZE_T StackSize,
		IN SIZE_T MaximumStackSize,
		IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);


	using waitt = NTSTATUS(NTAPI*)(
		IN HANDLE ObjectHandle,
		IN BOOLEAN Alertable,
		IN PLARGE_INTEGER TimeOut OPTIONAL);

	using NtClose = NTSTATUS(NTAPI*)(IN HANDLE Handle);




	using delayexec = NTSTATUS(NTAPI*)(
		IN BOOLEAN              Alertable,      // Whether an alert can be delivered when the object is waiting
		IN PLARGE_INTEGER       DelayInterval   // Pointer to LARGE_INTEGER structure specifying time to wait for
		);


}




