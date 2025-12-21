#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

DWORD GetProcId(const wchar_t* procName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W procEntry;
    procEntry.dwSize = sizeof(procEntry);

    if (Process32FirstW(hSnap, &procEntry)) {
        do {
            if (!_wcsicmp(procEntry.szExeFile, procName)) {
                procId = procEntry.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &procEntry));
    }

    CloseHandle(hSnap);
    return procId;
}

int main() {
    DWORD pid = GetProcId(L"ac_client.exe");

    if (!pid) {
        std::cerr << "Game not running!" << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process!" << std::endl;
        return 1;
    }

    DWORD ammoAddress = 0x50F4F4; // Example static address (you may need to resolve pointer chains later)
    int newAmmo = 999;

    if (WriteProcessMemory(hProcess, (LPVOID)ammoAddress, &newAmmo, sizeof(newAmmo), nullptr)) {
        std::cout << "Ammo modified!" << std::endl;
    } else {
        std::cerr << "Write failed!" << std::endl;
    }

    CloseHandle(hProcess);
    return 0;
}
