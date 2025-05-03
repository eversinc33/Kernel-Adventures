#include <ntifs.h>
#include <ntddk.h>

typedef struct _DBGKD_DEBUG_DATA_HEADER64 {
    LIST_ENTRY64 List;
    ULONG           OwnerTag;
    ULONG           Size;
} DBGKD_DEBUG_DATA_HEADER64, * PDBGKD_DEBUG_DATA_HEADER64;

typedef struct _KDDEBUGGER_DATA64
{
	DBGKD_DEBUG_DATA_HEADER64 Header;
	ULONG64   KernBase;
	ULONG64   BreakpointWithStatus;
	ULONG64   SavedContext;
	USHORT    ThCallbackStack;
	USHORT    NextCallback;
	USHORT    FramePointer;
	USHORT    PaeEnabled;
	ULONG64   KiCallUserMode;
	ULONG64   KeUserCallbackDispatcher;
	ULONG64   PsLoadedModuleList;
	ULONG64   PsActiveProcessHead;
	ULONG64   PspCidTable;
	ULONG64   ExpSystemResourcesList;
	ULONG64   ExpPagedPoolDescriptor;
	ULONG64   ExpNumberOfPagedPools;
	ULONG64   KeTimeIncrement;
	ULONG64   KeBugCheckCallbackListHead;
	ULONG64   KiBugcheckData;
	ULONG64   IopErrorLogListHead;
	ULONG64   ObpRootDirectoryObject;
	ULONG64   ObpTypeObjectType;
	ULONG64   MmSystemCacheStart;
	ULONG64   MmSystemCacheEnd;
	ULONG64   MmSystemCacheWs;
	ULONG64   MmPfnDatabase;
	ULONG64   MmSystemPtesStart;
	ULONG64   MmSystemPtesEnd;
	ULONG64   MmSubsectionBase;
	ULONG64   MmNumberOfPagingFiles;
	ULONG64   MmLowestPhysicalPage;
	ULONG64   MmHighestPhysicalPage;
	ULONG64   MmNumberOfPhysicalPages;
	ULONG64   MmMaximumNonPagedPoolInBytes;
	ULONG64   MmNonPagedSystemStart;
	ULONG64   MmNonPagedPoolStart;
	ULONG64   MmNonPagedPoolEnd;
	ULONG64   MmPagedPoolStart;
	ULONG64   MmPagedPoolEnd;
	ULONG64   MmPagedPoolInformation;
	ULONG64   MmPageSize;
	ULONG64   MmSizeOfPagedPoolInBytes;
	ULONG64   MmTotalCommitLimit;
	ULONG64   MmTotalCommittedPages;
	ULONG64   MmSharedCommit;
	ULONG64   MmDriverCommit;
	ULONG64   MmProcessCommit;
	ULONG64   MmPagedPoolCommit;
	ULONG64   MmExtendedCommit;
	ULONG64   MmZeroedPageListHead;
	ULONG64   MmFreePageListHead;
	ULONG64   MmStandbyPageListHead;
	ULONG64   MmModifiedPageListHead;
	ULONG64   MmModifiedNoWritePageListHead;
	ULONG64   MmAvailablePages;
	ULONG64   MmResidentAvailablePages;
	ULONG64   PoolTrackTable;
	ULONG64   NonPagedPoolDescriptor;
	ULONG64   MmHighestUserAddress;
	ULONG64   MmSystemRangeStart;
	ULONG64   MmUserProbeAddress;
	ULONG64   KdPrintCircularBuffer;
	ULONG64   KdPrintCircularBufferEnd;
	ULONG64   KdPrintWritePointer;
	ULONG64   KdPrintRolloverCount;
	ULONG64   MmLoadedUserImageList;
	ULONG64   NtBuildLab;
	ULONG64   KiNormalSystemCall;
	ULONG64   KiProcessorBlock;
	ULONG64   MmUnloadedDrivers;
	ULONG64   MmLastUnloadedDriver;
	ULONG64   MmTriageActionTaken;
	ULONG64   MmSpecialPoolTag;
	ULONG64   KernelVerifier;
	ULONG64   MmVerifierData;
	ULONG64   MmAllocatedNonPagedPool;
	ULONG64   MmPeakCommitment;
	ULONG64   MmTotalCommitLimitMaximum;
	ULONG64   CmNtCSDVersion;
	ULONG64   MmPhysicalMemoryBlock;
	ULONG64   MmSessionBase;
	ULONG64   MmSessionSize;
	ULONG64   MmSystemParentTablePage;
	ULONG64   MmVirtualTranslationBase;
	USHORT    OffsetKThreadNextProcessor;
	USHORT    OffsetKThreadTeb;
	USHORT    OffsetKThreadKernelStack;
	USHORT    OffsetKThreadInitialStack;
	USHORT    OffsetKThreadApcProcess;
	USHORT    OffsetKThreadState;
	USHORT    OffsetKThreadBStore;
	USHORT    OffsetKThreadBStoreLimit;
	USHORT    SizeEProcess;
	USHORT    OffsetEprocessPeb;
	USHORT    OffsetEprocessParentCID;
	USHORT    OffsetEprocessDirectoryTableBase;
	USHORT    SizePrcb;
	USHORT    OffsetPrcbDpcRoutine;
	USHORT    OffsetPrcbCurrentThread;
	USHORT    OffsetPrcbMhz;
	USHORT    OffsetPrcbCpuType;
	USHORT    OffsetPrcbVendorString;
	USHORT    OffsetPrcbProcStateContext;
	USHORT    OffsetPrcbNumber;
	USHORT    SizeEThread;
	ULONG64   KdPrintCircularBufferPtr;
	ULONG64   KdPrintBufferSize;
	ULONG64   KeLoaderBlock;
	USHORT    SizePcr;
	USHORT    OffsetPcrSelfPcr;
	USHORT    OffsetPcrCurrentPrcb;
	USHORT    OffsetPcrContainedPrcb;
	USHORT    OffsetPcrInitialBStore;
	USHORT    OffsetPcrBStoreLimit;
	USHORT    OffsetPcrInitialStack;
	USHORT    OffsetPcrStackLimit;
	USHORT    OffsetPrcbPcrPage;
	USHORT    OffsetPrcbProcStateSpecialReg;
	USHORT    GdtR0Code;
	USHORT    GdtR0Data;
	USHORT    GdtR0Pcr;
	USHORT    GdtR3Code;
	USHORT    GdtR3Data;
	USHORT    GdtR3Teb;
	USHORT    GdtLdt;
	USHORT    GdtTss;
	USHORT    Gdt64R3CmCode;
	USHORT    Gdt64R3CmTeb;
	ULONG64   IopNumTriageDumpDataBlocks;
	ULONG64   IopTriageDumpDataBlocks;
} KDDEBUGGER_DATA64, * PKDDEBUGGER_DATA64;

typedef struct _KDDEBUGGER_DATA_ADDITION64
{
	ULONG64   VfCrashDataBlock;
	ULONG64   MmBadPagesDetected;
	ULONG64   MmZeroedPageSingleBitErrorsDetected;
	ULONG64   EtwpDebuggerData;
	USHORT    OffsetPrcbContext;
	USHORT    OffsetPrcbMaxBreakpoints;
	USHORT    OffsetPrcbMaxWatchpoints;
	ULONG     OffsetKThreadStackLimit;
	ULONG     OffsetKThreadStackBase;
	ULONG     OffsetKThreadQueueListEntry;
	ULONG     OffsetEThreadIrpList;
	USHORT    OffsetPrcbIdleThread;
	USHORT    OffsetPrcbNormalDpcState;
	USHORT    OffsetPrcbDpcStack;
	USHORT    OffsetPrcbIsrStack;
	USHORT    SizeKDPC_STACK_FRAME;
	USHORT    OffsetKPriQueueThreadListHead;
	USHORT    OffsetKThreadWaitReason;
	USHORT    Padding;
	ULONG64   PteBase;
	ULONG64   RetpolineStubFunctionTable;
	ULONG     RetpolineStubFunctionTableSize;
	ULONG     RetpolineStubOffset;
	ULONG     RetpolineStubSize;
} KDDEBUGGER_DATA_ADDITION64, * PKDDEBUGGER_DATA_ADDITION64;

typedef struct _DUMP_HEADER
{
	ULONG Signature;
	ULONG ValidDump;
	ULONG MajorVersion;
	ULONG MinorVersion;
	ULONG_PTR DirectoryTableBase;
	ULONG_PTR PfnDataBase;
	PLIST_ENTRY PsLoadedModuleList;
	PLIST_ENTRY PsActiveProcessHead;
	ULONG MachineImageType;
	ULONG NumberProcessors;
	ULONG BugCheckCode;
	ULONG_PTR BugCheckParameter1;
	ULONG_PTR BugCheckParameter2;
	ULONG_PTR BugCheckParameter3;
	ULONG_PTR BugCheckParameter4;
	CHAR VersionUser[32];
	struct _KDDEBUGGER_DATA64* KdDebuggerDataBlock;
} DUMP_HEADER, * PDUMP_HEADER;

#define DUMP_BLOCK_SIZE 0x40000
#define KDDEBUGGER_DATA_OFFSET 0x2080

extern "C"
ULONG
NTAPI
KeCapturePersistentThreadState(
	IN PCONTEXT Context,
	IN PKTHREAD Thread,
	IN ULONG BugCheckCode,
	IN ULONG BugCheckParameter1,
	IN ULONG BugCheckParameter2,
	IN ULONG BugCheckParameter3,
	IN ULONG BugCheckParameter4,
	OUT PVOID VirtualAddress
);

typedef struct _HANDLE_TABLE_ENTRY_INFO
{
	ULONG AuditMask;                
	ULONG MaxRelativeAccessMask;    
} HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;

typedef struct _HANDLE_TABLE_ENTRY
{
	union                                          
	{
		ULONG64 VolatileLowValue;                   
		ULONG64 LowValue;                          
		ULONG64 RefCountField;                      
		_HANDLE_TABLE_ENTRY_INFO* InfoTable;        
		struct
		{
			ULONG64 Unlocked : 1;       
			ULONG64 RefCnt : 16;       
			ULONG64 Attributes : 3;       
			ULONG64 ObjectPointerBits : 44;       
		};
	};
	union
	{
		ULONG64 HighValue;                         
		_HANDLE_TABLE_ENTRY* NextFreeHandleEntry;  
	};
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE
{
	ULONG       NextHandleNeedingPool;  
	LONG        ExtraInfoPages;         
	ULONG64     TableCode;             
	PEPROCESS   QuotaProcess;           
	_LIST_ENTRY HandleTableList;        
	ULONG       UniqueProcessId;        
} HANDLE_TABLE, * PHANDLE_TABLE;

typedef BOOLEAN(*EXDESTROYHANDLE)(PHANDLE_TABLE HandleTable, HANDLE Handle, PHANDLE_TABLE_ENTRY HandleTableEntry);
typedef PHANDLE_TABLE_ENTRY(*EXPLOOKUPHANDLETABLEENTRY)(PHANDLE_TABLE HandleTable, HANDLE ExHandle);

// --------------------------------------------------------

EXDESTROYHANDLE g_ExDestroyHandle;
EXPLOOKUPHANDLETABLEENTRY g_ExpLookupHandleTableEntry;
_KDDEBUGGER_DATA64* g_KdBlock;

/**
 * Find a pattern with a mask applied.
 * E.g. FindPatter(base_addr, module_size, "\xDE\xAD\x00\xAf", "xx?x")
 * ? denotes a masked byte that could be anything
 */
PVOID
EvscFindPattern(
	PVOID addr,
	SIZE_T searchLength,
	PCHAR pattern,
	PCHAR mask
)
{
	SIZE_T patternLen = strlen(mask);
	if (searchLength < patternLen)
		return NULL; // Prevent out-of-bounds search

	for (INT i = 0; i < (searchLength - patternLen); ++i)
	{
		BOOLEAN match = TRUE;

		for (INT j = 0; j < patternLen; ++j)
		{
			if (mask[j] != '?')
			{
				if (pattern[j] != *(PCHAR)((ULONG_PTR)addr + i + j))
				{
					match = FALSE;
					break;
				}
			}
		}

		if (match)
		{
			return (PVOID)((ULONG_PTR)addr + i);
		}
	}

	return NULL;
}

VOID 
InitializeDebuggerBlock()
{
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&context);

	PDUMP_HEADER dumpHeader = (PDUMP_HEADER)ExAllocatePoolWithTag(NonPagedPool, DUMP_BLOCK_SIZE, 'kekW');
    if (dumpHeader)
    {
        KeCapturePersistentThreadState(&context, NULL, 0, 0, 0, 0, 0, dumpHeader);
        RtlCopyMemory(&g_KdBlock, (PUCHAR)dumpHeader + KDDEBUGGER_DATA_OFFSET, sizeof(g_KdBlock));

        ExFreePool(dumpHeader);
    }
}

VOID
UnloadDriver(
	PDRIVER_OBJECT pDriverObject
)
{
	UNREFERENCED_PARAMETER(pDriverObject);
}

NTSTATUS
RemoveEntryFromPspCidTable(
	HANDLE handle
)
{
	auto cidEntry = g_ExpLookupHandleTableEntry(*(PHANDLE_TABLE*)g_KdBlock->PspCidTable, handle);
	if (cidEntry != NULL)
	{
		g_ExDestroyHandle(*(PHANDLE_TABLE*)g_KdBlock->PspCidTable, handle, cidEntry);
		return STATUS_SUCCESS;
	}
	return STATUS_NOT_FOUND;
}

EXTERN_C
NTSTATUS 
DriverEntry(
	IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING registryPath
)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(registryPath);

	pDriverObject->DriverUnload = UnloadDriver;

	InitializeDebuggerBlock();
	DbgPrintEx(0, 0, "[*] PspCidTable at 0x%llx\n", g_KdBlock->PspCidTable);

	// TODO: sigscan for ExpLookupHandleTableEntry and ExDestroyHandle with EvscFindPattern

	return RemoveEntryFromPspCidTable(PsGetCurrentProcessId());
}

