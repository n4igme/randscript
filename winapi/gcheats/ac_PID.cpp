#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>

// Function to retrieve the process ID by name
DWORD GetProcId(const std::wstring& procName) {
    DWORD procId = 0;

    // Take a snapshot of all running processes
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to take snapshot." << std::endl;
        return 0;
    }

    // Initialize the PROCESSENTRY32 structure
    PROCESSENTRY32W procEntry;
    procEntry.dwSize = sizeof(procEntry);

    // Get the first process
    if (Process32FirstW(hSnap, &procEntry)) {
        do {
            // Compare process name (case-insensitive)
            if (!_wcsicmp(procEntry.szExeFile, procName.c_str())) {
                procId = procEntry.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &procEntry));
    } else {
        std::wcerr << L"Failed to retrieve process." << std::endl;
    }

    CloseHandle(hSnap);
    return procId;
}

int main() {
    std::wstring processName = L"ac_client.exe"; // AssaultCube's process name

    DWORD pid = GetProcId(processName);

    if (pid) {
        std::wcout << L"Process ID for " << processName << L": " << pid << std::endl;
    } else {
        std::wcout << L"Process not found." << std::endl;
    }

    return 0;
}
