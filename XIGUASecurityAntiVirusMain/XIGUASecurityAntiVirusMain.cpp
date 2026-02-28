#include <iostream>
#include <string>
#include <conio.h>
#include <windows.h>
#include <tlhelp32.h>
#include "detours.h"

using namespace std;

BOOL InjectDllToProcess(DWORD dwProcessId, const char* lpDllPath)
{
    if (dwProcessId == 0 || lpDllPath == NULL || *lpDllPath == '\0') {
        return FALSE;
    }
    
    if (GetFileAttributesA(lpDllPath) == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (hProcess == NULL) {
        cout << "Error: Cannot open process. Error code: " << GetLastError() << endl;
        return FALSE;
    }
    
    SIZE_T dwPathSize = strlen(lpDllPath) + 1;
    LPVOID lpRemoteMemory = VirtualAllocEx(hProcess, NULL, dwPathSize, MEM_COMMIT, PAGE_READWRITE);
    if (lpRemoteMemory == NULL) {
        cout << "Error: Cannot allocate memory in target process. Error code: " << GetLastError() << endl;
        CloseHandle(hProcess);
        return FALSE;
    }
    
    if (!WriteProcessMemory(hProcess, lpRemoteMemory, lpDllPath, dwPathSize, NULL)) {
        cout << "Error: Cannot write to target process memory. Error code: " << GetLastError() << endl;
        VirtualFreeEx(hProcess, lpRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        cout << "Error: Cannot get kernel32.dll handle" << endl;
        VirtualFreeEx(hProcess, lpRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    FARPROC lpLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (lpLoadLibraryA == NULL) {
        cout << "Error: Cannot get LoadLibraryA address" << endl;
        VirtualFreeEx(hProcess, lpRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpLoadLibraryA, lpRemoteMemory, 0, NULL);
    if (hThread == NULL) {
        cout << "Error: Cannot create remote thread. Error code: " << GetLastError() << endl;
        VirtualFreeEx(hProcess, lpRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    WaitForSingleObject(hThread, INFINITE);
    
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, lpRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    cout << "Hook DLL injected successfully into process ID: " << dwProcessId << endl;
    return TRUE;
}

DWORD FindProcessByName(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    wchar_t wProcessName[256];
    MultiByteToWideChar(CP_UTF8, 0, processName, -1, wProcessName, 256);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, wProcessName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return 0;
}

void InjectHookToProcess(const char* processName) {
    DWORD pid = FindProcessByName(processName);
    if (pid != 0) {
        char dllPath[MAX_PATH];
        GetModuleFileNameA(NULL, dllPath, MAX_PATH);
        
        char* pLastBackslash = strrchr(dllPath, '\\');
        if (pLastBackslash) {
            *pLastBackslash = '\0';
        }
        strcat_s(dllPath, MAX_PATH, "\\XIGUASecurityAntiVirusHook.dll");
        
        InjectDllToProcess(pid, dllPath);
    } else {
        cout << "Process not found: " << processName << endl;
    }
}

bool ManageProtectedPID(DWORD pid, bool protect) {
    HANDLE hMapFile = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        sizeof(DWORD) * 100,
        "XiguaSecurityProtectedPIDs"
    );
    
    if (!hMapFile) {
        cout << "Error: Cannot open shared memory for protected PIDs" << endl;
        return false;
    }
    
    DWORD* pSharedPIDs = (DWORD*)MapViewOfFile(
        hMapFile,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        sizeof(DWORD) * 100
    );
    
    if (!pSharedPIDs) {
        cout << "Error: Cannot map shared memory" << endl;
        CloseHandle(hMapFile);
        return false;
    }
    
    bool found = false;
    if (protect) {
        for (int i = 0; i < 100; i++) {
            if (pSharedPIDs[i] == 0) {
                pSharedPIDs[i] = pid;
                cout << "Protected PID: " << pid << " at index " << i << endl;
                found = true;
                break;
            }
        }
    } else {
        for (int i = 0; i < 100; i++) {
            if (pSharedPIDs[i] == pid) {
                pSharedPIDs[i] = 0;
                cout << "Unprotected PID: " << pid << " from index " << i << endl;
                found = true;
                break;
            }
        }
    }
    
    UnmapViewOfFile(pSharedPIDs);
    CloseHandle(hMapFile);
    
    return found;
}

void ListProtectedPIDs() {
    HANDLE hMapFile = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        sizeof(DWORD) * 100,
        "XIGUASecurityProtectedPIDs"
    );
    
    if (!hMapFile) {
        cout << "Error: Cannot open shared memory for protected PIDs" << endl;
        return;
    }
    
    DWORD* pSharedPIDs = (DWORD*)MapViewOfFile(
        hMapFile,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        sizeof(DWORD) * 100
    );
    
    if (!pSharedPIDs) {
        cout << "Error: Cannot map shared memory" << endl;
        CloseHandle(hMapFile);
        return;
    }
    
    cout << "Protected PIDs:" << endl;
    int count = 0;
    for (int i = 0; i < 100; i++) {
        if (pSharedPIDs[i] != 0) {
            cout << "  " << pSharedPIDs[i] << endl;
            count++;
        }
    }
    
    if (count == 0) {
        cout << "  (none)" << endl;
    }
    
    UnmapViewOfFile(pSharedPIDs);
    CloseHandle(hMapFile);
}

// Global hook handle for SetWindowsHookEx
static HHOOK g_hGlobalHook = NULL;

// Function to inject hook into all processes using SetWindowsHookEx
BOOL InjectHookGlobal(const char* dllPath)
{
    // Load the DLL to get the hook procedure address
    HMODULE hDll = LoadLibraryA(dllPath);
    if (!hDll) {
        cout << "Error: Cannot load DLL: " << dllPath << " (Error: " << GetLastError() << ")" << endl;
        return FALSE;
    }
    
    // Get the hook procedure address
    HOOKPROC hookProc = (HOOKPROC)GetProcAddress(hDll, "GlobalHookProc");
    if (!hookProc) {
        cout << "Error: Cannot find GlobalHookProc in DLL" << endl;
        FreeLibrary(hDll);
        return FALSE;
    }
    
    // Install global hook - this will inject the DLL into all GUI processes
    // WH_CALLWNDPROC is used as the hook type (any message-based hook would work)
    g_hGlobalHook = SetWindowsHookEx(WH_CALLWNDPROC, hookProc, hDll, 0);
    
    if (!g_hGlobalHook) {
        cout << "Error: SetWindowsHookEx failed (Error: " << GetLastError() << ")" << endl;
        FreeLibrary(hDll);
        return FALSE;
    }
    
    cout << "Global hook installed successfully!" << endl;
    cout << "DLL will be injected into all GUI processes." << endl;
    cout << "Press any key to remove the hook..." << endl;
    
    // Wait for user input
    _getch();
    
    // Remove the hook
    UnhookWindowsHookEx(g_hGlobalHook);
    g_hGlobalHook = NULL;
    
    cout << "Global hook removed." << endl;
    
    // Note: The DLL will remain loaded in processes until they exit
    // This is a limitation of SetWindowsHookEx - we can't force unload
    
    FreeLibrary(hDll);
    return TRUE;
}

void ShowUsage() {
    cout << "Usage:" << endl;
    cout << "  " << "XIGUASecurityAntiVirusMain.exe" << " Hook <process_name>  - Inject hook into specific process" << endl;
    cout << "  " << "XIGUASecurityAntiVirusMain.exe" << " HookAll              - Inject hook into all GUI processes (Global)" << endl;
    cout << "  " << "XIGUASecurityAntiVirusMain.exe" << " ProtectProcess <pid>  - Protect process from termination" << endl;
    cout << "  " << "XIGUASecurityAntiVirusMain.exe" << " UnprotectProcess <pid> - Remove protection from process" << endl;
    cout << "  " << "XIGUASecurityAntiVirusMain.exe" << " List               - List protected processes" << endl;
    cout << endl;
    cout << "Examples:" << endl;
    cout << "  " << "XIGUASecurityAntiVirusMain.exe" << " Hook notepad.exe" << endl;
    cout << "  " << "XIGUASecurityAntiVirusMain.exe" << " Hook explorer.exe" << endl;
    cout << "  " << "XIGUASecurityAntiVirusMain.exe" << " HookAll" << endl;
    cout << "  " << "XIGUASecurityAntiVirusMain.exe" << " ProtectProcess 1234" << endl;
    cout << "  " << "XIGUASecurityAntiVirusMain.exe" << " UnprotectProcess 1234" << endl;
}

int main(int argc, char* argv[])
{
    SetConsoleOutputCP(CP_UTF8);
    
    cout << "Xigua Security AntiVirus Hook Injector" << endl;
    cout << "=====================================" << endl;
    
    if (argc >= 2) {
        string command = argv[1];
        
        if (command == "Hook" && argc >= 3) {
            char* processName = argv[2];
            cout << "Injecting hook into process: " << processName << endl;
            InjectHookToProcess(processName);
            return 0;
        }
        else if (command == "HookAll") {
            cout << "Installing global hook into all GUI processes..." << endl;
            
            char dllPath[MAX_PATH];
            GetModuleFileNameA(NULL, dllPath, MAX_PATH);
            
            char* pLastBackslash = strrchr(dllPath, '\\');
            if (pLastBackslash) {
                *pLastBackslash = '\0';
            }
            strcat_s(dllPath, MAX_PATH, "\\XIGUASecurityAntiVirusHook.dll");
            
            InjectHookGlobal(dllPath);
            return 0;
        }
        else if (command == "ProtectProcess" && argc >= 3) {
            DWORD pid = atoi(argv[2]);
            cout << "Protecting process PID: " << pid << endl;
            ManageProtectedPID(pid, true);
            return 0;
        }
        else if (command == "UnprotectProcess" && argc >= 3) {
            DWORD pid = atoi(argv[2]);
            cout << "Unprotecting process PID: " << pid << endl;
            ManageProtectedPID(pid, false);
            return 0;
        }
        else if (command == "List") {
            ListProtectedPIDs();
            return 0;
        }
        else {
            cout << "Unknown command: " << command << endl;
            ShowUsage();
            return 1;
        }
    }
    
    ShowUsage();
    return 1;
}
