#include <ntifs.h>
#include "memory.hpp"

typedef INT (__fastcall* ORIGINAL_FUNCTION)(int a1, int a2, int a3, int a4, int a5, __int64 a6, __int64 a7, int a8);

ORIGINAL_FUNCTION g_pOriginalFunction;
ULONG_PTR g_dataPtrAddress;

INT __fastcall HookedFunction(int a1, int a2, int a3, int a4, int a5, __int64 a6, __int64 a7, int a8);

EXTERN_C
{
	VOID
		DriverUnload(
		_In_ PDRIVER_OBJECT DriverObject
	) {
		UNREFERENCED_PARAMETER(DriverObject);
		_InterlockedExchangePointer((PVOID*)g_dataPtrAddress, g_pOriginalFunction);
		DbgPrint("[*] Driver unloaded\n");
	}

	NTSTATUS 
		DriverEntry(
		_In_ PDRIVER_OBJECT   DriverObject,
		_In_ PUNICODE_STRING  RegistryPath
	) {
		UNREFERENCED_PARAMETER(RegistryPath);
		DbgPrint("[*] Driver Init\n");

		DriverObject->DriverUnload = DriverUnload;

		KAPC_STATE apcState = { 0 };

		//
		// Resolve Winlogon PEPROCESS to be able to attach to it and read session drivers
		// 
		UNICODE_STRING sWinLogon = RTL_CONSTANT_STRING(L"winlogon.exe");
		HANDLE winlogonPid = Memory::EvscGetPidFromProcessName(sWinLogon);
		DbgPrint("[*] winLogonPid: 0x%x\n", HandleToULong(winlogonPid));
		if (!winlogonPid)
		{
			DbgPrint("[!] Could not find winlogon.exe PID\n");
			return STATUS_NOT_FOUND;
		}
		PsLookupProcessByProcessId(winlogonPid, &g_pWinlogon);
		if (!g_pWinlogon)
		{
			DbgPrint("[!] Could not find winlogon.exe\n");
			return STATUS_NOT_FOUND;
		}

		//
		// Setup shared memory for comms
		//
		if (!NT_SUCCESS(Memory::EvscCreateSharedMemory()))
		{
			DbgPrint("[!] Could not create shared memory\n");
			return STATUS_FAILED_DRIVER_ENTRY;
		}

		KeStackAttachProcess(g_pWinlogon, &apcState);
		{
			// 
			// Resolve NtUserCreateWindowStation
			//
			PVOID funcAddr = Memory::EvscGetSystemRoutineAddress(L"win32kbase.sys", "NtUserCreateWindowStation");
			if (!funcAddr)
			{
				KeUnstackDetachProcess(&apcState);
				return STATUS_NOT_FOUND;
			}
			DbgPrint("[*] NtUserCreateWindowStation found at 0x%llx\n", (ULONG_PTR)funcAddr);

			// 
			// Find the dataPtr. The ApiSet* routine follows immediately after in memory so we can just 
			// search from the NtUser* function start
			//
			ULONG_PTR dataPtrPattern = (ULONG_PTR)Memory::EvscFindPattern(
				(PVOID)(funcAddr),
				200, 
				"\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0", 
				"xxx????xxx"
			);

			if (dataPtrPattern)
			{
				DbgPrint("    Pattern : 0x%llx\r\n", dataPtrPattern);
				UINT32 offset = *(PUINT32)(dataPtrPattern + 3);
				DbgPrint("    Offset  : 0x%lx\r\n", offset);
				g_dataPtrAddress = dataPtrPattern + offset + 3 + 4;
				DbgPrint("    .data ptr addr : 0x%llx\r\n", g_dataPtrAddress);
			}
			else
			{
				DbgPrint("[!] Pattern not found\r\n");
				KeUnstackDetachProcess(&apcState);
				return STATUS_NOT_FOUND;
			}

			// 
			// Swap with our hook and save original in g_pOriginalFunction
			//
			*(PVOID*)&g_pOriginalFunction /* kekw pointers */ = _InterlockedExchangePointer((PVOID*)g_dataPtrAddress, HookedFunction);
			DbgPrint("[*] .data ptr hooked\r\n");

		}
		KeUnstackDetachProcess(&apcState);

		return STATUS_SUCCESS;
	}
}

INT HookedFunction(int a1, int a2, int a3, int a4, int a5, __int64 a6, __int64 a7, int a8)
{
	DbgPrint("[*] Hook triggered\r\n");

	if (ExGetPreviousMode() == UserMode && g_pSharedMemory)
	{
		// Read command payload
		KAPC_STATE apc = { 0 };
		KeStackAttachProcess(g_pWinlogon, &apc);
		PAYLOAD payload = *(PAYLOAD*)g_pSharedMemory;
		DbgPrint("[*] Got command: %i\r\n", payload.cmdType);
		(*((PAYLOAD*)g_pSharedMemory)).executed = 1;
		(*((PAYLOAD*)g_pSharedMemory)).status = 0;
		KeUnstackDetachProcess(&apc);
	}

	return g_pOriginalFunction(a1, a2, a3, a4, a5, a6, a7, a8);
}
