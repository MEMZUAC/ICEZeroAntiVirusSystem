#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdarg.h>
#include <vector>
#include <algorithm>
#include <string>
#include "detours.h"

// NTSTATUS status codes
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022)
#endif

// NT API type definitions
typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;

// UNICODE_STRING structure
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;   
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// OBJECT_ATTRIBUTES structure
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
// Link with Winsock library
#pragma comment(lib, "Ws2_32.lib")

// Simple native TCP scanner client (MuChenLinker)
// forward declare logging function used by MuChenLinker
static void LogDebugA(const char* fmt, ...);

class MuChenLinker {
public:
    MuChenLinker() : m_sock(INVALID_SOCKET), m_available(false), m_port(0) {
        InitializeCriticalSection(&m_cs);
    }
    ~MuChenLinker() {
        Cleanup();
        DeleteCriticalSection(&m_cs);
    }

    bool Init(int port) {
        EnterCriticalSection(&m_cs);
        m_port = port;
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
            LeaveCriticalSection(&m_cs);
            return false;
        }

        m_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_sock == INVALID_SOCKET) {
            WSACleanup();
            LeaveCriticalSection(&m_cs);
            return false;
        }

        struct sockaddr_in srv;
        ZeroMemory(&srv, sizeof(srv));
        srv.sin_family = AF_INET;
        // prefer InetPton to avoid deprecated inet_addr
        InetPtonA(AF_INET, "127.0.0.1", &srv.sin_addr);
        srv.sin_port = htons((unsigned short)port);

        // connect with short timeout
        u_long mode = 1; // non-blocking
        ioctlsocket(m_sock, FIONBIO, &mode);
        connect(m_sock, (struct sockaddr*)&srv, sizeof(srv));

        fd_set wf;
        FD_ZERO(&wf);
        FD_SET(m_sock, &wf);
        timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
        int sel = select(0, NULL, &wf, NULL, &tv);
            if (sel > 0 && FD_ISSET(m_sock, &wf)) {
            // set back to blocking
            mode = 0;
            ioctlsocket(m_sock, FIONBIO, &mode);
            m_available = true;
            LogDebugA("MuChenLinker: connected to scanner");
        } else {
            closesocket(m_sock);
            m_sock = INVALID_SOCKET;
            WSACleanup();
            m_available = false;
            LogDebugA("MuChenLinker: scanner not available");
        }

        LeaveCriticalSection(&m_cs);
        // If connected, try to activate engine so it will accept scan commands
        if (m_available) {
            // short timeout for activation
            int timeout = 1000;
            setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
            const char* act = "Active\r\n";
            send(m_sock, act, (int)strlen(act), 0);
            Sleep(50);
            char buf[256] = {0};
            int r = recv(m_sock, buf, sizeof(buf)-1, 0);
            if (r > 0) {
                buf[r] = '\0';
                LogDebugA("MuChenLinker::Init recv: %s", buf);
            }
        }

        return m_available;
    }

    void Cleanup() {
        EnterCriticalSection(&m_cs);
        if (m_sock != INVALID_SOCKET) {
            closesocket(m_sock);
            m_sock = INVALID_SOCKET;
        }
        WSACleanup();
        m_available = false;
        LeaveCriticalSection(&m_cs);
    }

    bool IsAvailable() {
        return m_available && m_sock != INVALID_SOCKET;
    }

    // Returns true when file is UNSAFE, false when SAFE or other/equiv
    bool ScanA(const char* path) {
        if (!IsAvailable() || path == NULL) {
            OutputDebugStringA("MuChenLinker::ScanA - not available or null path\n");
            return false;
        }
        EnterCriticalSection(&m_cs);
        bool result = false;
        char dbg[1024];
            sprintf_s(dbg, "MuChenLinker::ScanA send: %s", path);
            LogDebugA(dbg);
        // send path as utf8/ansi, terminated
        int len = (int)strlen(path);
        int sent = send(m_sock, path, len, 0);
        if (sent == len) {
            // recv
            char buf[4096];
            // set receive timeout
            int timeout = 2000; // ms
            setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
            int r = recv(m_sock, buf, sizeof(buf)-1, 0);
            if (r > 0) {
                buf[r] = '\0';
                sprintf_s(dbg, "MuChenLinker::ScanA recv: %s", buf);
                LogDebugA(dbg);
                // If engine says it is not active, try to activate and retry once.
                if (strstr(buf, "No Active") != NULL || strstr(buf, "NoActive") != NULL) {
                    LogDebugA("MuChenLinker::ScanA engine not active, sending Active command and retrying");
                    const char* act = "Active\r\n";
                    send(m_sock, act, (int)strlen(act), 0);
                    Sleep(50);
                    // brief wait for response
                    char buf2[4096];
                    int r2 = recv(m_sock, buf2, sizeof(buf2)-1, 0);
                    if (r2 > 0) {
                        buf2[r2] = '\0';
                        LogDebugA("MuChenLinker::ScanA recv after Active: %s", buf2);
                    }
                    // resend the file path (with CRLF)
                    send(m_sock, path, len, 0);
                    send(m_sock, "\r\n", 2, 0);
                    int r3 = recv(m_sock, buf, sizeof(buf)-1, 0);
                    if (r3 > 0) {
                        r = r3;
                        buf[r] = '\0';
                        LogDebugA("MuChenLinker::ScanA recv after resend: %s", buf);
                    }
                }
                // parse until ';' or end
                char token[256] = {0};
                int i = 0;
                while (i < r && i < (int)sizeof(token)-1 && buf[i] != ';' && buf[i] != '\n' && buf[i] != '\r') {
                    token[i] = buf[i];
                    i++;
                }
                token[i] = '\0';
                // uppercase
                for (int k=0; token[k]; ++k) token[k] = (char)toupper((unsigned char)token[k]);
                sprintf_s(dbg, "MuChenLinker::ScanA token: %s", token);
                LogDebugA(dbg);
                if (strcmp(token, "UNSAFE") == 0) result = true;
                else result = false;
            }
        }
        LeaveCriticalSection(&m_cs);
        return result;
    }

    bool ScanW(const wchar_t* wpath) {
        if (!wpath) return false;
        // convert to UTF-8/ANSI for engine
        char buf[MAX_PATH*3];
        int n = WideCharToMultiByte(CP_UTF8, 0, wpath, -1, buf, (int)sizeof(buf), NULL, NULL);
        char dbg[1024];
        if (n > 0) {
            sprintf_s(dbg, "MuChenLinker::ScanW converted: %s", buf);
            LogDebugA(dbg);
        }
        if (n <= 0) return false;
        return ScanA(buf);
    }

private:
    SOCKET m_sock;
    bool m_available;
    int m_port;
    CRITICAL_SECTION m_cs;
};

static MuChenLinker g_scanner;

// Process protection
static CRITICAL_SECTION g_protect_cs;
static std::vector<DWORD> g_protectedPIDs;
static HANDLE g_hMapFile = NULL;
static DWORD* g_pSharedPIDs = NULL;
static const int MAX_SHARED_PIDS = 100;

static void InitProcessProtection() {
    InitializeCriticalSection(&g_protect_cs);
    
    g_hMapFile = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0, // dwMaximumSizeHigh
        sizeof(DWORD) * MAX_SHARED_PIDS, // dwMaximumSizeLow
        "XiguaSecurityProtectedPIDs"
    );
    
    if (g_hMapFile) {
        g_pSharedPIDs = (DWORD*)MapViewOfFile(
            g_hMapFile,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            sizeof(DWORD) * MAX_SHARED_PIDS
        );
        
        if (g_pSharedPIDs) {
            EnterCriticalSection(&g_protect_cs);
            for (int i = 0; i < MAX_SHARED_PIDS; i++) {
                if (g_pSharedPIDs[i] != 0) {
                    g_protectedPIDs.push_back(g_pSharedPIDs[i]);
                }
            }
            LeaveCriticalSection(&g_protect_cs);
            LogDebugA("Loaded %d protected PIDs from shared memory", (int)g_protectedPIDs.size());
        }
    }
}

static void CleanupProcessProtection() {
    EnterCriticalSection(&g_protect_cs);
    g_protectedPIDs.clear();
    LeaveCriticalSection(&g_protect_cs);
    
    if (g_pSharedPIDs) {
        UnmapViewOfFile(g_pSharedPIDs);
        g_pSharedPIDs = NULL;
    }
    
    if (g_hMapFile) {
        CloseHandle(g_hMapFile);
        g_hMapFile = NULL;
    }
    
    DeleteCriticalSection(&g_protect_cs);
}

static bool IsProcessProtected(DWORD pid) {
    EnterCriticalSection(&g_protect_cs);
    bool result = false;
    
    for (DWORD protectedPid : g_protectedPIDs) {
        if (protectedPid == pid) {
            result = true;
            break;
        }
    }
    
    if (!result && g_pSharedPIDs) {
        for (int i = 0; i < MAX_SHARED_PIDS; i++) {
            if (g_pSharedPIDs[i] == pid) {
                result = true;
                break;
            }
        }
    }
    
    LeaveCriticalSection(&g_protect_cs);
    
    if (result) {
        LogDebugA("IsProcessProtected: PID %d is PROTECTED", pid);
    }
    
    return result;
}

static bool AddProtectedProcess(DWORD pid) {
    if (!g_pSharedPIDs) return false;
    
    EnterCriticalSection(&g_protect_cs);
    
    bool found = false;
    for (int i = 0; i < MAX_SHARED_PIDS; i++) {
        if (g_pSharedPIDs[i] == pid) {
            found = true;
            break;
        }
        if (g_pSharedPIDs[i] == 0 && !found) {
            g_pSharedPIDs[i] = pid;
            g_protectedPIDs.push_back(pid);
            LogDebugA("Added protected PID: %d at index %d", pid, i);
            found = true;
            break;
        }
    }
    
    LeaveCriticalSection(&g_protect_cs);
    return found;
}

static bool RemoveProtectedProcess(DWORD pid) {
    if (!g_pSharedPIDs) return false;
    
    EnterCriticalSection(&g_protect_cs);
    
    bool found = false;
    for (int i = 0; i < MAX_SHARED_PIDS; i++) {
        if (g_pSharedPIDs[i] == pid) {
            g_pSharedPIDs[i] = 0;
            g_protectedPIDs.erase(
                std::remove(g_protectedPIDs.begin(), g_protectedPIDs.end(), pid),
                g_protectedPIDs.end()
            );
            LogDebugA("Removed protected PID: %d from index %d", pid, i);
            found = true;
            break;
        }
    }
    
    LeaveCriticalSection(&g_protect_cs);
    return found;
}

// Simple logging to OutputDebugString and a file in %TEMP%
static CRITICAL_SECTION g_log_cs;
static HANDLE g_logFile = INVALID_HANDLE_VALUE;

static void LogDebugA(const char* fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    OutputDebugStringA(buf);

    EnterCriticalSection(&g_log_cs);
    if (g_logFile == INVALID_HANDLE_VALUE) {
        char tmpPath[MAX_PATH];
        DWORD n = GetTempPathA(MAX_PATH, tmpPath);
        if (n && n < MAX_PATH) {
            strcat_s(tmpPath, "XIGUASecurityAntiVirus.log");
            g_logFile = CreateFileA(tmpPath, GENERIC_WRITE | FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, NULL);
        }
    }
    if (g_logFile != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        SetFilePointer(g_logFile, 0, NULL, FILE_END);
        WriteFile(g_logFile, buf, (DWORD)strlen(buf), &written, NULL);
        WriteFile(g_logFile, "\r\n", 2, &written, NULL);
    }
    LeaveCriticalSection(&g_log_cs);
}

extern "C" __declspec(dllexport) void InitScanner(int port) {
    g_scanner.Init(port);
}

extern "C" __declspec(dllexport) void CleanupScanner() {
    g_scanner.Cleanup();
}

// Thread routine to initialize the scanner outside of DllMain
static DWORD WINAPI ScannerInitThread(LPVOID) {
    g_scanner.Init(1145);
    return 0;
}

#ifndef SE_ERR_CANCELLED
#define SE_ERR_CANCELLED 1223
#endif

// 原始API函数指针
static BOOL (WINAPI *TrueCreateProcessA)(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) = CreateProcessA;

static BOOL (WINAPI *TrueCreateProcessW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) = CreateProcessW;

static HINSTANCE (WINAPI *TrueShellExecuteA)(
    HWND hwnd,
    LPCSTR lpOperation,
    LPCSTR lpFile,
    LPCSTR lpParameters,
    LPCSTR lpDirectory,
    INT nShowCmd
) = ShellExecuteA;

static HINSTANCE (WINAPI *TrueShellExecuteW)(
    HWND hwnd,
    LPCWSTR lpOperation,
    LPCWSTR lpFile,
    LPCWSTR lpParameters,
    LPCWSTR lpDirectory,
    INT nShowCmd
) = ShellExecuteW;

static BOOL (WINAPI *TrueShellExecuteExA)(
    LPSHELLEXECUTEINFOA lpExecInfo
) = ShellExecuteExA;

static BOOL (WINAPI *TrueShellExecuteExW)(
    LPSHELLEXECUTEINFOW lpExecInfo
) = ShellExecuteExW;

static BOOL (WINAPI *TrueTerminateProcess)(
    HANDLE hProcess,
    UINT uExitCode
) = TerminateProcess;

static HANDLE (WINAPI *TrueOpenProcess)(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId
) = OpenProcess;

// NtTerminateProcess function pointer (from ntdll.dll)
typedef NTSTATUS (NTAPI *NtTerminateProcess_t)(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
);
static NtTerminateProcess_t TrueNtTerminateProcess = NULL;

// Registry protection function pointers
static LSTATUS (WINAPI *TrueRegCreateKeyExA)(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD Reserved,
    LPSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult,
    LPDWORD lpdwDisposition
) = RegCreateKeyExA;

static LSTATUS (WINAPI *TrueRegCreateKeyExW)(
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD Reserved,
    LPWSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult,
    LPDWORD lpdwDisposition
) = RegCreateKeyExW;

static LSTATUS (WINAPI *TrueRegSetValueExA)(
    HKEY hKey,
    LPCSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE* lpData,
    DWORD cbData
) = RegSetValueExA;

static LSTATUS (WINAPI *TrueRegSetValueExW)(
    HKEY hKey,
    LPCWSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE* lpData,
    DWORD cbData
) = RegSetValueExW;

static LSTATUS (WINAPI *TrueRegDeleteKeyA)(
    HKEY hKey,
    LPCSTR lpSubKey
) = RegDeleteKeyA;

static LSTATUS (WINAPI *TrueRegDeleteKeyW)(
    HKEY hKey,
    LPCWSTR lpSubKey
) = RegDeleteKeyW;

static LSTATUS (WINAPI *TrueRegDeleteValueA)(
    HKEY hKey,
    LPCSTR lpValueName
) = RegDeleteValueA;

static LSTATUS (WINAPI *TrueRegDeleteValueW)(
    HKEY hKey,
    LPCWSTR lpValueName
) = RegDeleteValueW;

// NT Registry API function pointers (from ntdll.dll)
typedef NTSTATUS (NTAPI *NtCreateKey_t)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    PULONG Disposition
);
static NtCreateKey_t TrueNtCreateKey = NULL;

typedef NTSTATUS (NTAPI *NtSetValueKey_t)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize
);
static NtSetValueKey_t TrueNtSetValueKey = NULL;

typedef NTSTATUS (NTAPI *NtDeleteKey_t)(
    HANDLE KeyHandle
);
static NtDeleteKey_t TrueNtDeleteKey = NULL;

typedef NTSTATUS (NTAPI *NtDeleteValueKey_t)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName
);
static NtDeleteValueKey_t TrueNtDeleteValueKey = NULL;

// File system protection function pointers
static HANDLE (WINAPI *TrueCreateFileA)(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) = CreateFileA;

static HANDLE (WINAPI *TrueCreateFileW)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) = CreateFileW;

static BOOL (WINAPI *TrueWriteFile)(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
) = WriteFile;

static BOOL (WINAPI *TrueDeleteFileA)(
    LPCSTR lpFileName
) = DeleteFileA;

static BOOL (WINAPI *TrueDeleteFileW)(
    LPCWSTR lpFileName
) = DeleteFileW;

static BOOL (WINAPI *TrueCopyFileA)(
    LPCSTR lpExistingFileName,
    LPCSTR lpNewFileName,
    BOOL bFailIfExists
) = CopyFileA;

static BOOL (WINAPI *TrueCopyFileW)(
    LPCWSTR lpExistingFileName,
    LPCWSTR lpNewFileName,
    BOOL bFailIfExists
) = CopyFileW;

static BOOL (WINAPI *TrueMoveFileA)(
    LPCSTR lpExistingFileName,
    LPCSTR lpNewFileName
) = MoveFileA;

static BOOL (WINAPI *TrueMoveFileW)(
    LPCWSTR lpExistingFileName,
    LPCWSTR lpNewFileName
) = MoveFileW;

// 检查是否在白名单中
BOOL IsInWhitelist(LPCWSTR lpFileName)
{
    // 白名单：主程序本身
    const wchar_t* whitelist[] = {
        L"XIGUASecurityAntiVirusMain.exe"
    };
    
    int count = sizeof(whitelist) / sizeof(whitelist[0]);
    for (int i = 0; i < count; i++) {
        // 提取文件名部分进行比较
        LPCWSTR fileName = wcsrchr(lpFileName, L'\\');
        if (fileName) {
            fileName++;
        } else {
            fileName = lpFileName;
        }
        
        if (_wcsicmp(fileName, whitelist[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL IsInWhitelistA(LPCSTR lpFileName)
{
    // 白名单：主程序本身
    const char* whitelist[] = {
        "XIGUASecurityAntiVirusMain.exe"
    };
    
    int count = sizeof(whitelist) / sizeof(whitelist[0]);
    for (int i = 0; i < count; i++) {
        // 提取文件名部分进行比较
        LPCSTR fileName = strrchr(lpFileName, '\\');
        if (fileName) {
            fileName++;
        } else {
            fileName = lpFileName;
        }
        
        if (_stricmp(fileName, whitelist[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// 检查是否是主程序
BOOL IsMainProcess()
{
    // 获取当前进程的可执行文件路径
    wchar_t szExePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szExePath, MAX_PATH)) {
        // 检查是否是主程序
        if (IsInWhitelist(szExePath)) {
            return TRUE;
        }
    }
    return FALSE;
}

// 阻止应用程序启动的函数
BOOL WINAPI HookedCreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    // 检查是否是主程序
    if (IsMainProcess()) {
        return TrueCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }
    
    // 检查白名单
    if (lpApplicationName && IsInWhitelistA(lpApplicationName)) {
        return TrueCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    // 如果引擎可用，优先询问引擎；引擎返回 SAFE 时直接允许（不弹窗）
    if (g_scanner.IsAvailable()) {
        LogDebugA("HookedCreateProcessA: scanner available");
        char pathBuf[MAX_PATH] = {0};
        if (lpApplicationName && *lpApplicationName) {
            strncpy_s(pathBuf, lpApplicationName, _TRUNCATE);
        } else if (lpCommandLine && *lpCommandLine) {
            // 解析命令行首个可执行路径
            const char* p = lpCommandLine;
            if (*p == '"') {
                p++;
                const char* q = strchr(p, '"');
                if (q) strncpy_s(pathBuf, p, (size_t)(q - p));
                else strncpy_s(pathBuf, p, _TRUNCATE);
            } else {
                const char* q = strchr(p, ' ');
                if (q) strncpy_s(pathBuf, p, (size_t)(q - p));
                else strncpy_s(pathBuf, p, _TRUNCATE);
            }
        }

        if (pathBuf[0]) {
            LogDebugA("HookedCreateProcessA: probing path='%s'", pathBuf);
            int scanRes = g_scanner.ScanA(pathBuf);
            LogDebugA("HookedCreateProcessA: engine returned scanRes=%d", scanRes);
            if (scanRes == 0) {
                return TrueCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
            }
            else if (scanRes == 1) {
                char msg[512];
                sprintf_s(msg, "Warning: This file is detected as malicious!\n\nFile: %s\n\nDo you want to allow it to run?", pathBuf);
                int result = MessageBoxA(NULL, msg, "Security Protection - Malicious File Detected", MB_YESNO | MB_ICONWARNING);
                if (result == IDYES) {
                    return TrueCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
                }
                SetLastError(ERROR_VIRUS_INFECTED);
                return FALSE;
            }
            else {
                char msg[512];
                sprintf_s(msg, "Security scan timed out for: %s\n\nDo you want to allow it to run?", pathBuf);
                int result = MessageBoxA(NULL, msg, "Security Protection - Scan Timeout", MB_YESNO | MB_ICONWARNING);
                if (result == IDYES) {
                    return TrueCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
                }
                SetLastError(ERROR_VIRUS_INFECTED);
                return FALSE;
            }
        }
    }

    char szMessage[512];
    if (lpApplicationName)
        sprintf_s(szMessage, "Application launch request: %s", lpApplicationName);
    else if (lpCommandLine)
        sprintf_s(szMessage, "Application launch request: %s", lpCommandLine);
    else
        strcpy_s(szMessage, "Application launch request");

    int result = MessageBoxA(NULL, szMessage, "Security Protection", MB_YESNO | MB_ICONQUESTION);
    if (result == IDYES) {
        return TrueCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }
    return FALSE;
}

BOOL WINAPI HookedCreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    // 检查是否是主程序
    if (IsMainProcess()) {
        return TrueCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }
    
    // 检查白名单
    if (lpApplicationName && IsInWhitelist(lpApplicationName)) {
        return TrueCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    if (g_scanner.IsAvailable()) {
        LogDebugA("HookedCreateProcessW: scanner available");
        wchar_t pathBufW[MAX_PATH] = {0};
        if (lpApplicationName && *lpApplicationName) {
            wcsncpy_s(pathBufW, lpApplicationName, _TRUNCATE);
        } else if (lpCommandLine && *lpCommandLine) {
            const wchar_t* p = lpCommandLine;
            if (*p == L'"') {
                p++;
                const wchar_t* q = wcschr(p, L'"');
                if (q) wcsncpy_s(pathBufW, p, (size_t)(q - p));
                else wcsncpy_s(pathBufW, p, _TRUNCATE);
            } else {
                const wchar_t* q = wcschr(p, L' ');
                if (q) wcsncpy_s(pathBufW, p, (size_t)(q - p));
                else wcsncpy_s(pathBufW, p, _TRUNCATE);
            }
        }
        if (pathBufW[0]) {
            char pathBuf[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pathBufW, -1, pathBuf, sizeof(pathBuf), NULL, NULL);
            LogDebugA("HookedCreateProcessW: probing path='%s'", pathBuf);
            int scanRes = g_scanner.ScanA(pathBuf);
            LogDebugA("HookedCreateProcessW: engine returned scanRes=%d", scanRes);
            if (scanRes == 0) {
                return TrueCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
            }
            else if (scanRes == 1) {
                wchar_t wmsg[512];
                _snwprintf_s(wmsg, _countof(wmsg), _TRUNCATE, L"Warning: This file is detected as malicious!\n\nFile: %s\n\nDo you want to allow it to run?", pathBufW);
                int result = MessageBoxW(NULL, wmsg, L"Security Protection - Malicious File Detected", MB_YESNO | MB_ICONWARNING);
                if (result == IDYES) {
                    return TrueCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
                }
                SetLastError(ERROR_VIRUS_INFECTED);
                return FALSE;
            }
            else {
                wchar_t wmsg[512];
                _snwprintf_s(wmsg, _countof(wmsg), _TRUNCATE, L"Security scan timed out for: %s\n\nDo you want to allow it to run?", pathBufW);
                int result = MessageBoxW(NULL, wmsg, L"Security Protection - Scan Timeout", MB_YESNO | MB_ICONWARNING);
                if (result == IDYES) {
                    return TrueCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
                }
                SetLastError(ERROR_VIRUS_INFECTED);
                return FALSE;
            }
        }
    }

    wchar_t szMessage[512];
    if (lpApplicationName)
        swprintf_s(szMessage, L"Application launch request: %s", lpApplicationName);
    else if (lpCommandLine)
        swprintf_s(szMessage, L"Application launch request: %s", lpCommandLine);
    else
        wcscpy_s(szMessage, L"Application launch request");

    int result = MessageBoxW(NULL, szMessage, L"Security Protection", MB_YESNO | MB_ICONQUESTION);
    if (result == IDYES) {
        return TrueCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    SetLastError(ERROR_VIRUS_INFECTED);
    return FALSE;
}

HINSTANCE WINAPI HookedShellExecuteA(
    HWND hwnd,
    LPCSTR lpOperation,
    LPCSTR lpFile,
    LPCSTR lpParameters,
    LPCSTR lpDirectory,
    INT nShowCmd
)
{
    // 检查是否是主程序
    if (IsMainProcess()) {
        return TrueShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
    }
    
    // 检查白名单
    if (IsInWhitelistA(lpFile)) {
        return TrueShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
    }

    // 引擎判断
    if (g_scanner.IsAvailable() && lpFile) {
        LogDebugA("HookedShellExecuteA: probing path='%s'", lpFile);
        int scanRes = g_scanner.ScanA(lpFile);
        LogDebugA("HookedShellExecuteA: engine returned scanRes=%d", scanRes);
        if (scanRes == 0) {
            return TrueShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
        }
        else if (scanRes == 1) {
            char msg[512];
            sprintf_s(msg, "Warning: This file is detected as malicious!\n\nFile: %s\n\nDo you want to allow it to run?", lpFile);
            int result = MessageBoxA(NULL, msg, "Security Protection - Malicious File Detected", MB_YESNO | MB_ICONWARNING);
            if (result == IDYES) {
                return TrueShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
            }
            SetLastError(ERROR_VIRUS_INFECTED);
            return (HINSTANCE)SE_ERR_ACCESSDENIED;
        }
        else {
            char msg[512];
            sprintf_s(msg, "Security scan timed out for: %s\n\nDo you want to allow it to run?", lpFile);
            int result = MessageBoxA(NULL, msg, "Security Protection - Scan Timeout", MB_YESNO | MB_ICONWARNING);
            if (result == IDYES) {
                return TrueShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
            }
            SetLastError(ERROR_VIRUS_INFECTED);
            return (HINSTANCE)SE_ERR_ACCESSDENIED;
        }
    }

    char szMessage[512];
    sprintf_s(szMessage, "Application launch request: %s", lpFile);
    int result = MessageBoxA(NULL, szMessage, "Security Protection", MB_YESNO | MB_ICONQUESTION);
    if (result == IDYES) {
        return TrueShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
    }
    return (HINSTANCE)SE_ERR_FNF;
}

HINSTANCE WINAPI HookedShellExecuteW(
    HWND hwnd,
    LPCWSTR lpOperation,
    LPCWSTR lpFile,
    LPCWSTR lpParameters,
    LPCWSTR lpDirectory,
    INT nShowCmd
)
{
    // 检查是否是主程序
    if (IsMainProcess()) {
        return TrueShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
    }
    
    // 检查白名单
    if (IsInWhitelist(lpFile)) {
        return TrueShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
    }

    // 引擎判断
    if (g_scanner.IsAvailable() && lpFile) {
        char pathBuf[MAX_PATH*3];
        WideCharToMultiByte(CP_UTF8, 0, lpFile, -1, pathBuf, sizeof(pathBuf), NULL, NULL);
        LogDebugA("HookedShellExecuteW: probing path='%s'", pathBuf);
        int scanRes = g_scanner.ScanW(lpFile);
        LogDebugA("HookedShellExecuteW: engine returned scanRes=%d", scanRes);
        if (scanRes == 0) {
            return TrueShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
        }
        else if (scanRes == 1) {
            wchar_t wmsg[512];
            _snwprintf_s(wmsg, _countof(wmsg), _TRUNCATE, L"Warning: This file is detected as malicious!\n\nFile: %s\n\nDo you want to allow it to run?", lpFile);
            int result = MessageBoxW(NULL, wmsg, L"Security Protection - Malicious File Detected", MB_YESNO | MB_ICONWARNING);
            if (result == IDYES) {
                return TrueShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
            }
            SetLastError(ERROR_VIRUS_INFECTED);
            return (HINSTANCE)SE_ERR_ACCESSDENIED;
        }
        else {
            wchar_t wmsg[512];
            _snwprintf_s(wmsg, _countof(wmsg), _TRUNCATE, L"Security scan timed out for: %s\n\nDo you want to allow it to run?", lpFile);
            int result = MessageBoxW(NULL, wmsg, L"Security Protection - Scan Timeout", MB_YESNO | MB_ICONWARNING);
            if (result == IDYES) {
                return TrueShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
            }
            SetLastError(ERROR_VIRUS_INFECTED);
            return (HINSTANCE)SE_ERR_ACCESSDENIED;
        }
    }

    wchar_t szMessage[512];
    swprintf_s(szMessage, L"Application launch request: %s", lpFile);
    int result = MessageBoxW(NULL, szMessage, L"Security Protection", MB_YESNO | MB_ICONQUESTION);
    if (result == IDYES) {
        return TrueShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
    }
    return (HINSTANCE)SE_ERR_FNF;
}

BOOL WINAPI HookedShellExecuteExA(
    LPSHELLEXECUTEINFOA lpExecInfo
)
{
    // 检查是否是主程序
    if (IsMainProcess()) {
        return TrueShellExecuteExA(lpExecInfo);
    }
    
    // 检查白名单
    if (lpExecInfo->lpFile && IsInWhitelistA(lpExecInfo->lpFile)) {
        return TrueShellExecuteExA(lpExecInfo);
    }

    // 引擎判断
    if (g_scanner.IsAvailable() && lpExecInfo->lpFile) {
        int scanRes = g_scanner.ScanA(lpExecInfo->lpFile);
        if (scanRes == 0) {
            return TrueShellExecuteExA(lpExecInfo);
        }
        else if (scanRes == 1) {
            char msg[512];
            sprintf_s(msg, "Warning: This file is detected as malicious!\n\nFile: %s\n\nDo you want to allow it to run?", lpExecInfo->lpFile);
            int result = MessageBoxA(NULL, msg, "Security Protection - Malicious File Detected", MB_YESNO | MB_ICONWARNING);
            if (result == IDYES) {
                return TrueShellExecuteExA(lpExecInfo);
            }
            if (lpExecInfo) {
                lpExecInfo->hInstApp = (HINSTANCE)SE_ERR_ACCESSDENIED;
            }
            SetLastError(ERROR_VIRUS_INFECTED);
            return FALSE;
        }
        else {
            char msg[512];
            sprintf_s(msg, "Security scan timed out for: %s\n\nDo you want to allow it to run?", lpExecInfo->lpFile);
            int result = MessageBoxA(NULL, msg, "Security Protection - Scan Timeout", MB_YESNO | MB_ICONWARNING);
            if (result == IDYES) {
                return TrueShellExecuteExA(lpExecInfo);
            }
            if (lpExecInfo) {
                lpExecInfo->hInstApp = (HINSTANCE)SE_ERR_ACCESSDENIED;
            }
            SetLastError(ERROR_VIRUS_INFECTED);
            return FALSE;
        }
    }

    char szMessage[512];
    if (lpExecInfo->lpFile)
        sprintf_s(szMessage, "Application launch request: %s", lpExecInfo->lpFile);
    else
        strcpy_s(szMessage, "Application launch request");

    int result = MessageBoxA(NULL, szMessage, "Security Protection", MB_YESNO | MB_ICONQUESTION);
    if (result == IDYES) {
        return TrueShellExecuteExA(lpExecInfo);
    }

    // 设置错误码为找不到文件
    if (lpExecInfo) {
        lpExecInfo->hInstApp = (HINSTANCE)SE_ERR_FNF;
    }
    SetLastError(ERROR_VIRUS_INFECTED);
    return FALSE;
}

BOOL WINAPI HookedShellExecuteExW(
    LPSHELLEXECUTEINFOW lpExecInfo
)
{
    // 检查是否是主程序
    if (IsMainProcess()) {
        return TrueShellExecuteExW(lpExecInfo);
    }
    
    // 检查白名单
    if (lpExecInfo->lpFile && IsInWhitelist(lpExecInfo->lpFile)) {
        return TrueShellExecuteExW(lpExecInfo);
    }

    // 引擎判断
    if (g_scanner.IsAvailable() && lpExecInfo->lpFile) {
        int scanRes = g_scanner.ScanW(lpExecInfo->lpFile);
        if (scanRes == 0) {
            return TrueShellExecuteExW(lpExecInfo);
        }
        else if (scanRes == 1) {
            wchar_t wmsg[512];
            _snwprintf_s(wmsg, _countof(wmsg), _TRUNCATE, L"Warning: This file is detected as malicious!\n\nFile: %s\n\nDo you want to allow it to run?", lpExecInfo->lpFile);
            int result = MessageBoxW(NULL, wmsg, L"Security Protection - Malicious File Detected", MB_YESNO | MB_ICONWARNING);
            if (result == IDYES) {
                return TrueShellExecuteExW(lpExecInfo);
            }
            if (lpExecInfo) {
                lpExecInfo->hInstApp = (HINSTANCE)SE_ERR_ACCESSDENIED;
            }
            SetLastError(ERROR_VIRUS_INFECTED);
            return FALSE;
        }
        else {
            wchar_t wmsg[512];
            _snwprintf_s(wmsg, _countof(wmsg), _TRUNCATE, L"Security scan timed out for: %s\n\nDo you want to allow it to run?", lpExecInfo->lpFile);
            int result = MessageBoxW(NULL, wmsg, L"Security Protection - Scan Timeout", MB_YESNO | MB_ICONWARNING);
            if (result == IDYES) {
                return TrueShellExecuteExW(lpExecInfo);
            }
            if (lpExecInfo) {
                lpExecInfo->hInstApp = (HINSTANCE)SE_ERR_ACCESSDENIED;
            }
            SetLastError(ERROR_VIRUS_INFECTED);
            return FALSE;
        }
    }

    wchar_t szMessage[512];
    if (lpExecInfo->lpFile)
        swprintf_s(szMessage, L"Application launch request: %s", lpExecInfo->lpFile);
    else
        wcscpy_s(szMessage, L"Application launch request");

    int result = MessageBoxW(NULL, szMessage, L"Security Protection", MB_YESNO | MB_ICONQUESTION);
    if (result == IDYES) {
        return TrueShellExecuteExW(lpExecInfo);
    }

    // 设置错误码为找不到文件
    if (lpExecInfo) {
        lpExecInfo->hInstApp = (HINSTANCE)SE_ERR_FNF;
    }
    SetLastError(ERROR_VIRUS_INFECTED);
    return FALSE;
}

// Hook TerminateProcess to protect processes
BOOL WINAPI HookedTerminateProcess(
    HANDLE hProcess,
    UINT uExitCode
)
{
    DWORD pid = GetProcessId(hProcess);
    
    LogDebugA("HookedTerminateProcess: PID=%d", pid);
    
    if (IsProcessProtected(pid)) {
        LogDebugA("HookedTerminateProcess: PID %d is protected, denying termination", pid);
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    
    return TrueTerminateProcess(hProcess, uExitCode);
}

// Hook NtTerminateProcess to protect processes (used by task manager)
NTSTATUS NTAPI HookedNtTerminateProcess(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
)
{
    DWORD pid = GetProcessId(ProcessHandle);
    
    LogDebugA("HookedNtTerminateProcess: PID=%d, ExitStatus=%d", pid, ExitStatus);
    
    if (IsProcessProtected(pid)) {
        LogDebugA("HookedNtTerminateProcess: PID %d is protected, denying termination", pid);
        return STATUS_ACCESS_DENIED;
    }
    
    return TrueNtTerminateProcess(ProcessHandle, ExitStatus);
}

// Hook OpenProcess to protect processes
HANDLE WINAPI HookedOpenProcess(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId
)
{
    LogDebugA("HookedOpenProcess: PID=%d, Access=0x%X", dwProcessId, dwDesiredAccess);
    
    if (IsProcessProtected(dwProcessId)) {
        // 阻止任何对保护进程的访问（除了查询信息）
        if (dwDesiredAccess & PROCESS_TERMINATE || 
            dwDesiredAccess & PROCESS_VM_WRITE || 
            dwDesiredAccess & PROCESS_VM_OPERATION ||
            dwDesiredAccess & PROCESS_SUSPEND_RESUME) {
            LogDebugA("HookedOpenProcess: PID %d is protected, denying dangerous access", dwProcessId);
            SetLastError(ERROR_ACCESS_DENIED);
            return NULL;
        }
    }
    
    return TrueOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

// Registry protection - check if registry path is protected
static bool IsRegistryPathProtectedA(LPCSTR lpSubKey)
{
    if (!lpSubKey) return false;
    
    // Protected registry paths (startup locations and critical system settings)
    const char* protectedPaths[] = {
        // Startup locations
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load",
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run",
        "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        // System services
        "System\\CurrentControlSet\\Services",
        "System\\ControlSet",
        // Windows Explorer settings
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies",
        // Internet Explorer settings
        "Software\\Microsoft\\Internet Explorer",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        // Windows Defender
        "Software\\Microsoft\\Windows Defender",
        // UAC settings
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        // File associations
        "Software\\Classes\\",
        // Winlogon settings
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        // Shell settings
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
        // Driver settings
        "System\\CurrentControlSet\\Control\\Session Manager"
    };
    
    for (const char* path : protectedPaths) {
        if (_stricmp(lpSubKey, path) == 0 || 
            strstr(lpSubKey, path) != NULL) {
            LogDebugA("IsRegistryPathProtectedA: Path '%s' matches protected pattern '%s'", lpSubKey, path);
            return true;
        }
    }
    
    return false;
}

static bool IsRegistryPathProtectedW(LPCWSTR lpSubKey)
{
    if (!lpSubKey) return false;
    
    // Protected registry paths (startup locations and critical system settings)
    const wchar_t* protectedPaths[] = {
        // Startup locations
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load",
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run",
        L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        // System services
        L"System\\CurrentControlSet\\Services",
        L"System\\ControlSet",
        // Windows Explorer settings
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies",
        // Internet Explorer settings
        L"Software\\Microsoft\\Internet Explorer",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        // Windows Defender
        L"Software\\Microsoft\\Windows Defender",
        // UAC settings
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        // File associations
        L"Software\\Classes\\",
        // Winlogon settings
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        // Shell settings
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
        // Driver settings
        L"System\\CurrentControlSet\\Control\\Session Manager"
    };
    
    for (const wchar_t* path : protectedPaths) {
        if (_wcsicmp(lpSubKey, path) == 0 || 
            wcsstr(lpSubKey, path) != NULL) {
            LogDebugA("IsRegistryPathProtectedW: Path matches protected pattern");
            return true;
        }
    }
    
    return false;
}

// Helper function to get registry path from HKEY
static std::string GetRegPathFromHKEY(HKEY hKey)
{
    char name[256] = {0};
    DWORD nameSize = sizeof(name);
    
    // Try to get the key name
    if (RegQueryInfoKeyA(hKey, name, &nameSize, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        return std::string(name);
    }
    
    // Check for predefined keys
    if (hKey == HKEY_CLASSES_ROOT) return "HKEY_CLASSES_ROOT";
    if (hKey == HKEY_CURRENT_USER) return "HKEY_CURRENT_USER";
    if (hKey == HKEY_LOCAL_MACHINE) return "HKEY_LOCAL_MACHINE";
    if (hKey == HKEY_USERS) return "HKEY_USERS";
    if (hKey == HKEY_CURRENT_CONFIG) return "HKEY_CURRENT_CONFIG";
    
    return "Unknown";
}

// Hook RegCreateKeyExA
LSTATUS WINAPI HookedRegCreateKeyExA(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD Reserved,
    LPSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult,
    LPDWORD lpdwDisposition
)
{
    LogDebugA("HookedRegCreateKeyExA: hKey=%p, SubKey='%s'", hKey, lpSubKey ? lpSubKey : "(null)");
    
    if (IsRegistryPathProtectedA(lpSubKey)) {
        std::string fullPath = GetRegPathFromHKEY(hKey);
        if (lpSubKey) {
            fullPath += "\\";
            fullPath += lpSubKey;
        }
        
        char msg[512];
        sprintf_s(msg, "Warning: A program is trying to modify the startup registry!\n\nPath: %s\n\nDo you want to allow this operation?", fullPath.c_str());
        int result = MessageBoxA(NULL, msg, "Security Protection - Registry Modification", MB_YESNO | MB_ICONWARNING);
        
        if (result == IDNO) {
            LogDebugA("HookedRegCreateKeyExA: User denied access to protected registry path");
            return ERROR_ACCESS_DENIED;
        }
        
        LogDebugA("HookedRegCreateKeyExA: User allowed access to protected registry path");
    }
    
    return TrueRegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, 
                               lpSecurityAttributes, phkResult, lpdwDisposition);
}

// Hook RegCreateKeyExW
LSTATUS WINAPI HookedRegCreateKeyExW(
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD Reserved,
    LPWSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult,
    LPDWORD lpdwDisposition
)
{
    LogDebugA("HookedRegCreateKeyExW: hKey=%p", hKey);
    
    if (IsRegistryPathProtectedW(lpSubKey)) {
        char msg[512];
        sprintf_s(msg, "Warning: A program is trying to modify the startup registry!\n\nDo you want to allow this operation?");
        int result = MessageBoxA(NULL, msg, "Security Protection - Registry Modification", MB_YESNO | MB_ICONWARNING);
        
        if (result == IDNO) {
            LogDebugA("HookedRegCreateKeyExW: User denied access to protected registry path");
            return ERROR_ACCESS_DENIED;
        }
        
        LogDebugA("HookedRegCreateKeyExW: User allowed access to protected registry path");
    }
    
    return TrueRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, 
                               lpSecurityAttributes, phkResult, lpdwDisposition);
}

// Helper function to check if HKEY is a protected startup key
static bool IsStartupKey(HKEY hKey)
{
    // Check if this is a known startup key by querying its path
    char name[256] = {0};
    DWORD nameSize = sizeof(name);
    
    if (RegQueryInfoKeyA(hKey, name, &nameSize, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        std::string keyName(name);
        // Check if key path contains startup-related strings
        if (keyName.find("Run") != std::string::npos ||
            keyName.find("Startup") != std::string::npos ||
            keyName.find("Windows\\Load") != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

// Hook RegSetValueExA
LSTATUS WINAPI HookedRegSetValueExA(
    HKEY hKey,
    LPCSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE* lpData,
    DWORD cbData
)
{
    LogDebugA("HookedRegSetValueExA: hKey=%p, ValueName='%s'", hKey, lpValueName ? lpValueName : "(null)");
    
    // Check if this is a startup-related value in a startup key
    if (lpValueName && IsStartupKey(hKey)) {
        char msg[512];
        sprintf_s(msg, "Warning: A program is trying to modify the startup registry!\n\nKey: %s\nValue: %s\n\nDo you want to allow this operation?", 
                  GetRegPathFromHKEY(hKey).c_str(), lpValueName);
        int result = MessageBoxA(NULL, msg, "Security Protection - Registry Modification", MB_YESNO | MB_ICONWARNING);
        
        if (result == IDNO) {
            LogDebugA("HookedRegSetValueExA: User denied access to protected startup value");
            return ERROR_ACCESS_DENIED;
        }
        
        LogDebugA("HookedRegSetValueExA: User allowed access to protected startup value");
    }
    
    return TrueRegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

// Hook RegSetValueExW
LSTATUS WINAPI HookedRegSetValueExW(
    HKEY hKey,
    LPCWSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE* lpData,
    DWORD cbData
)
{
    LogDebugA("HookedRegSetValueExW: hKey=%p", hKey);
    
    // Check if this is a startup-related value in a startup key
    if (lpValueName && IsStartupKey(hKey)) {
        char msg[512];
        sprintf_s(msg, "Warning: A program is trying to modify the startup registry!\n\nKey: %s\n\nDo you want to allow this operation?", 
                  GetRegPathFromHKEY(hKey).c_str());
        int result = MessageBoxA(NULL, msg, "Security Protection - Registry Modification", MB_YESNO | MB_ICONWARNING);
        
        if (result == IDNO) {
            LogDebugA("HookedRegSetValueExW: User denied access to protected startup value");
            return ERROR_ACCESS_DENIED;
        }
        
        LogDebugA("HookedRegSetValueExW: User allowed access to protected startup value");
    }
    
    return TrueRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

// Hook RegDeleteKeyA
LSTATUS WINAPI HookedRegDeleteKeyA(
    HKEY hKey,
    LPCSTR lpSubKey
)
{
    LogDebugA("HookedRegDeleteKeyA: hKey=%p, SubKey='%s'", hKey, lpSubKey ? lpSubKey : "(null)");
    
    if (IsRegistryPathProtectedA(lpSubKey)) {
        std::string fullPath = GetRegPathFromHKEY(hKey);
        if (lpSubKey) {
            fullPath += "\\";
            fullPath += lpSubKey;
        }
        
        char msg[512];
        sprintf_s(msg, "Warning: A program is trying to delete a startup registry key!\n\nPath: %s\n\nDo you want to allow this operation?", fullPath.c_str());
        int result = MessageBoxA(NULL, msg, "Security Protection - Registry Deletion", MB_YESNO | MB_ICONWARNING);
        
        if (result == IDNO) {
            LogDebugA("HookedRegDeleteKeyA: User denied deletion of protected registry path");
            return ERROR_ACCESS_DENIED;
        }
        
        LogDebugA("HookedRegDeleteKeyA: User allowed deletion of protected registry path");
    }
    
    return TrueRegDeleteKeyA(hKey, lpSubKey);
}

// Hook RegDeleteKeyW
LSTATUS WINAPI HookedRegDeleteKeyW(
    HKEY hKey,
    LPCWSTR lpSubKey
)
{
    LogDebugA("HookedRegDeleteKeyW: hKey=%p", hKey);
    
    if (IsRegistryPathProtectedW(lpSubKey)) {
        char msg[512];
        sprintf_s(msg, "Warning: A program is trying to delete a startup registry key!\n\nDo you want to allow this operation?");
        int result = MessageBoxA(NULL, msg, "Security Protection - Registry Deletion", MB_YESNO | MB_ICONWARNING);
        
        if (result == IDNO) {
            LogDebugA("HookedRegDeleteKeyW: User denied deletion of protected registry path");
            return ERROR_ACCESS_DENIED;
        }
        
        LogDebugA("HookedRegDeleteKeyW: User allowed deletion of protected registry path");
    }
    
    return TrueRegDeleteKeyW(hKey, lpSubKey);
}

// Hook RegDeleteValueA
LSTATUS WINAPI HookedRegDeleteValueA(
    HKEY hKey,
    LPCSTR lpValueName
)
{
    LogDebugA("HookedRegDeleteValueA: hKey=%p, ValueName='%s'", hKey, lpValueName ? lpValueName : "(null)");
    
    // Check if this is a startup-related value in a startup key
    if (lpValueName && IsStartupKey(hKey)) {
        char msg[512];
        sprintf_s(msg, "Warning: A program is trying to delete a startup registry value!\n\nKey: %s\nValue: %s\n\nDo you want to allow this operation?", 
                  GetRegPathFromHKEY(hKey).c_str(), lpValueName);
        int result = MessageBoxA(NULL, msg, "Security Protection - Registry Deletion", MB_YESNO | MB_ICONWARNING);
        
        if (result == IDNO) {
            LogDebugA("HookedRegDeleteValueA: User denied deletion of protected startup value");
            return ERROR_ACCESS_DENIED;
        }
        
        LogDebugA("HookedRegDeleteValueA: User allowed deletion of protected startup value");
    }
    
    return TrueRegDeleteValueA(hKey, lpValueName);
}

// Hook RegDeleteValueW
LSTATUS WINAPI HookedRegDeleteValueW(
    HKEY hKey,
    LPCWSTR lpValueName
)
{
    LogDebugA("HookedRegDeleteValueW: hKey=%p", hKey);
    
    // Check if this is a startup-related value in a startup key
    if (lpValueName && IsStartupKey(hKey)) {
        char msg[512];
        sprintf_s(msg, "Warning: A program is trying to delete a startup registry value!\n\nKey: %s\n\nDo you want to allow this operation?", 
                  GetRegPathFromHKEY(hKey).c_str());
        int result = MessageBoxA(NULL, msg, "Security Protection - Registry Deletion", MB_YESNO | MB_ICONWARNING);
        
        if (result == IDNO) {
            LogDebugA("HookedRegDeleteValueW: User denied deletion of protected startup value");
            return ERROR_ACCESS_DENIED;
        }
        
        LogDebugA("HookedRegDeleteValueW: User allowed deletion of protected startup value");
    }
    
    return TrueRegDeleteValueW(hKey, lpValueName);
}

// Helper function to convert UNICODE_STRING to char*
static void UnicodeStringToChar(PUNICODE_STRING pUnicodeString, char* buffer, int bufferSize)
{
    if (!pUnicodeString || !pUnicodeString->Buffer || bufferSize <= 0) {
        if (buffer && bufferSize > 0) buffer[0] = '\0';
        return;
    }
    
    // UNICODE_STRING.Length is in bytes, so divide by sizeof(WCHAR) to get character count
    // Note: UNICODE_STRING may not be null-terminated, so we must use Length
    int charCount = pUnicodeString->Length / sizeof(WCHAR);
    if (charCount <= 0) {
        buffer[0] = '\0';
        return;
    }
    
    // Create a temporary null-terminated string
    wchar_t* tempBuffer = (wchar_t*)malloc((charCount + 1) * sizeof(wchar_t));
    if (!tempBuffer) {
        buffer[0] = '\0';
        return;
    }
    
    // Copy the string and null-terminate it
    memcpy(tempBuffer, pUnicodeString->Buffer, charCount * sizeof(wchar_t));
    tempBuffer[charCount] = L'\0';
    
    // Convert to ANSI
    WideCharToMultiByte(CP_ACP, 0, tempBuffer, -1, buffer, bufferSize - 1, NULL, NULL);
    buffer[bufferSize - 1] = '\0';
    
    free(tempBuffer);
}

// Helper function to get current process name
static void GetCurrentProcessName(char* buffer, int bufferSize)
{
    if (!buffer || bufferSize <= 0) return;
    
    buffer[0] = '\0';
    
    // Get current process ID
    DWORD pid = GetCurrentProcessId();
    
    // Open process to get name
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        char processName[MAX_PATH] = {0};
        DWORD size = sizeof(processName);
        
        // Try to get process image file name
        if (QueryFullProcessImageNameA(hProcess, 0, processName, &size)) {
            // Extract just the filename from the full path
            char* pLastSlash = strrchr(processName, '\\');
            if (pLastSlash) {
                strncpy_s(buffer, bufferSize, pLastSlash + 1, _TRUNCATE);
            } else {
                strncpy_s(buffer, bufferSize, processName, _TRUNCATE);
            }
        } else {
            // Fallback: use module name
            if (GetModuleFileNameA(NULL, processName, sizeof(processName))) {
                char* pLastSlash = strrchr(processName, '\\');
                if (pLastSlash) {
                    strncpy_s(buffer, bufferSize, pLastSlash + 1, _TRUNCATE);
                } else {
                    strncpy_s(buffer, bufferSize, processName, _TRUNCATE);
                }
            }
        }
        
        CloseHandle(hProcess);
    }
    
    // If still empty, use a default
    if (buffer[0] == '\0') {
        strncpy_s(buffer, bufferSize, "Unknown Process", _TRUNCATE);
    }
}

// Helper function to check if current process is whitelisted for registry operations
static bool IsRegistryOperationWhitelisted()
{
    char processName[256];
    GetCurrentProcessName(processName, sizeof(processName));
    
    // System critical processes that should not be intercepted
    const char* whitelistedProcesses[] = {
        "explorer.exe",
        "svchost.exe",
        "services.exe",
        "lsass.exe",
        "csrss.exe",
        "smss.exe",
        "wininit.exe",
        "winlogon.exe",
        "taskhostw.exe",
        "RuntimeBroker.exe",
        "SearchIndexer.exe",
        "dwm.exe",
        "fontdrvhost.exe",
        "dllhost.exe",
        "conhost.exe"
    };
    
    for (const char* whitelist : whitelistedProcesses) {
        if (_stricmp(processName, whitelist) == 0) {
            LogDebugA("IsRegistryOperationWhitelisted: Process '%s' is whitelisted", processName);
            return true;
        }
    }
    
    return false;
}

// Helper function to check if registry path is protected (for NT API)
static bool IsNTRegistryPathProtected(PUNICODE_STRING pObjectName)
{
    if (!pObjectName || !pObjectName->Buffer) return false;
    
    char path[512];
    UnicodeStringToChar(pObjectName, path, sizeof(path));
    
    // Check if path contains protected registry keywords
    // These include startup locations and other critical system settings
    const char* protectedPatterns[] = {
        // Startup locations
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "Microsoft\\Windows NT\\CurrentVersion\\Windows",
        "Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        // System services
        "System\\CurrentControlSet\\Services",
        "System\\ControlSet",
        // Windows Explorer settings
        "Microsoft\\Windows\\CurrentVersion\\Policies",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies",
        // Internet Explorer settings
        "Software\\Microsoft\\Internet Explorer",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        // Windows Defender
        "Software\\Microsoft\\Windows Defender",
        // UAC settings
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        // File associations
        "Software\\Classes\\",
        // Winlogon settings
        "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        // Shell settings
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
        // BCD settings
        "BCD00000000",
        // Driver settings
        "System\\CurrentControlSet\\Control\\Session Manager"
    };
    
    for (const char* pattern : protectedPatterns) {
        if (strstr(path, pattern) != NULL) {
            LogDebugA("IsNTRegistryPathProtected: Path '%s' matches protected pattern '%s'", path, pattern);
            return true;
        }
    }
    
    return false;
}

// Hook NtCreateKey
NTSTATUS NTAPI HookedNtCreateKey(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    PULONG Disposition
)
{
    LogDebugA("HookedNtCreateKey: Access=0x%X", DesiredAccess);
    
    // Check if process is whitelisted
    if (IsRegistryOperationWhitelisted()) {
        return TrueNtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
    }
    
    if (ObjectAttributes && ObjectAttributes->ObjectName && 
        IsNTRegistryPathProtected(ObjectAttributes->ObjectName)) {
        char path[512];
        UnicodeStringToChar(ObjectAttributes->ObjectName, path, sizeof(path));
        
        char processName[256];
        GetCurrentProcessName(processName, sizeof(processName));
        
        char msg[1024];
        sprintf_s(msg, "Warning: A program is trying to create/modify a protected registry key!\n\nProcess: %s\nPath: %s\n\nDo you want to allow this operation?", processName, path);
        int result = MessageBoxA(NULL, msg, "Security Protection - Registry Modification", MB_YESNO | MB_ICONWARNING);
        
        if (result == IDNO) {
            LogDebugA("HookedNtCreateKey: User denied access to protected registry path");
            return STATUS_ACCESS_DENIED;
        }
        
        LogDebugA("HookedNtCreateKey: User allowed access to protected registry path");
    }
    
    return TrueNtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
}

// Helper function to check if a key handle is in a startup path
static bool IsKeyInStartupPath(HKEY hKey)
{
    // Query the key name
    char name[512] = {0};
    DWORD nameSize = sizeof(name);
    
    // Try to get key information - this won't work for all handles but worth a try
    if (RegQueryInfoKeyA(hKey, name, &nameSize, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        // Check if the key name contains startup-related patterns
        const char* startupPatterns[] = {
            "Run",
            "RunOnce",
            "Windows\\Load",
            "Windows\\Run"
        };
        
        for (const char* pattern : startupPatterns) {
            if (strstr(name, pattern) != NULL) {
                LogDebugA("IsKeyInStartupPath: Key name '%s' matches startup pattern '%s'", name, pattern);
                return true;
            }
        }
    }
    
    // For NT handles, we can't easily get the path, so we'll be more permissive
    // and rely on the key creation being caught by NtCreateKey
    return false;
}

// Hook NtSetValueKey
NTSTATUS NTAPI HookedNtSetValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize
)
{
    LogDebugA("HookedNtSetValueKey: KeyHandle=%p", KeyHandle);
    
    // Check if process is whitelisted
    if (IsRegistryOperationWhitelisted()) {
        return TrueNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
    }
    
    // Check if this is in a startup-related key
    // For now, we'll check if the value name suggests it's a startup entry
    if (ValueName && ValueName->Buffer) {
        char valueName[256];
        UnicodeStringToChar(ValueName, valueName, sizeof(valueName));
        
        // Check if we're in a startup key by checking the value name
        // Most startup entries have meaningful names, so we'll check for common patterns
        // or just show a warning for any value set in what might be a startup key
        char processName[256];
        GetCurrentProcessName(processName, sizeof(processName));
        
        char msg[1024];
        sprintf_s(msg, "Warning: A program is trying to set a registry value!\n\nProcess: %s\nValue Name: %s\n\nDo you want to allow this operation?", processName, valueName);
        int result = MessageBoxA(NULL, msg, "Security Protection - Registry Modification", MB_YESNO | MB_ICONWARNING);
        
        if (result == IDNO) {
            LogDebugA("HookedNtSetValueKey: User denied setting registry value '%s'", valueName);
            return STATUS_ACCESS_DENIED;
        }
        
        LogDebugA("HookedNtSetValueKey: User allowed setting registry value '%s'", valueName);
    }
    
    return TrueNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
}

// Hook NtDeleteKey
NTSTATUS NTAPI HookedNtDeleteKey(
    HANDLE KeyHandle
)
{
    LogDebugA("HookedNtDeleteKey: KeyHandle=%p", KeyHandle);
    
    // Check if process is whitelisted
    if (IsRegistryOperationWhitelisted()) {
        return TrueNtDeleteKey(KeyHandle);
    }
    
    // For simplicity, we'll show a warning for all delete operations
    char processName[256];
    GetCurrentProcessName(processName, sizeof(processName));
    
    char msg[1024];
    sprintf_s(msg, "Warning: A program is trying to delete a registry key!\n\nProcess: %s\n\nDo you want to allow this operation?", processName);
    int result = MessageBoxA(NULL, msg, "Security Protection - Registry Deletion", MB_YESNO | MB_ICONWARNING);
    
    if (result == IDNO) {
        LogDebugA("HookedNtDeleteKey: User denied deletion of registry key");
        return STATUS_ACCESS_DENIED;
    }
    
    LogDebugA("HookedNtDeleteKey: User allowed deletion of registry key");
    return TrueNtDeleteKey(KeyHandle);
}

// Hook NtDeleteValueKey
NTSTATUS NTAPI HookedNtDeleteValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName
)
{
    LogDebugA("HookedNtDeleteValueKey: KeyHandle=%p", KeyHandle);
    
    // Check if process is whitelisted
    if (IsRegistryOperationWhitelisted()) {
        return TrueNtDeleteValueKey(KeyHandle, ValueName);
    }
    
    if (ValueName && ValueName->Buffer) {
        char valueName[256];
        UnicodeStringToChar(ValueName, valueName, sizeof(valueName));
        
        // Show warning for any registry value deletion
        char processName[256];
        GetCurrentProcessName(processName, sizeof(processName));
        
        char msg[1024];
        sprintf_s(msg, "Warning: A program is trying to delete a registry value!\n\nProcess: %s\nValue Name: %s\n\nDo you want to allow this operation?", processName, valueName);
        int result = MessageBoxA(NULL, msg, "Security Protection - Registry Deletion", MB_YESNO | MB_ICONWARNING);
        
        if (result == IDNO) {
            LogDebugA("HookedNtDeleteValueKey: User denied deletion of registry value '%s'", valueName);
            return STATUS_ACCESS_DENIED;
        }
        
        LogDebugA("HookedNtDeleteValueKey: User allowed deletion of registry value '%s'", valueName);
    }
    
    return TrueNtDeleteValueKey(KeyHandle, ValueName);
}

// Helper function to check if file path should be scanned
static bool ShouldScanFilePath(LPCSTR lpFileName)
{
    if (!lpFileName) return false;
    
    // Skip system directories to avoid too many prompts
    const char* systemPaths[] = {
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
        "C:\\Windows\\WinSxS",
        "C:\\Program Files",
        "C:\\ProgramData",
        "C:\\$Recycle.Bin"
    };
    
    for (const char* path : systemPaths) {
        if (_strnicmp(lpFileName, path, strlen(path)) == 0) {
            return false;
        }
    }
    
    // Check if it's an executable or script file
    const char* extensions[] = {
        ".exe", ".dll", ".sys", ".drv",
        ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".scr", ".com", ".pif"
    };
    
    const char* ext = strrchr(lpFileName, '.');
    if (ext) {
        for (const char* checkExt : extensions) {
            if (_stricmp(ext, checkExt) == 0) {
                return true;
            }
        }
    }
    
    return false;
}

static bool ShouldScanFilePathW(LPCWSTR lpFileName)
{
    if (!lpFileName) return false;
    
    char fileNameA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, fileNameA, sizeof(fileNameA), NULL, NULL);
    return ShouldScanFilePath(fileNameA);
}

// Helper function to scan file with engine
static int ScanFileWithEngine(LPCSTR lpFileName)
{
    if (!g_scanner.IsAvailable()) {
        return 0; // Not connected, allow by default
    }
    
    return g_scanner.ScanA(lpFileName);
}

// Hook CreateFileA
HANDLE WINAPI HookedCreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
)
{
    // Only scan when creating new files or writing to existing files
    bool isWriteOperation = (dwDesiredAccess & GENERIC_WRITE) || 
                            (dwDesiredAccess & FILE_WRITE_DATA) ||
                            (dwDesiredAccess & FILE_APPEND_DATA);
    
    bool isCreateOperation = (dwCreationDisposition == CREATE_NEW) ||
                             (dwCreationDisposition == CREATE_ALWAYS) ||
                             (dwCreationDisposition == OPEN_ALWAYS);
    
    if ((isWriteOperation || isCreateOperation) && ShouldScanFilePath(lpFileName)) {
        LogDebugA("HookedCreateFileA: Scanning file '%s'", lpFileName);
        
        int scanResult = ScanFileWithEngine(lpFileName);
        
        if (scanResult == 1) { // UNSAFE
            char processName[256];
            GetCurrentProcessName(processName, sizeof(processName));
            
            char msg[1024];
            sprintf_s(msg, "Warning: A program is trying to create/modify a potentially malicious file!\n\nProcess: %s\nFile: %s\n\nThe file was detected as UNSAFE by the security engine.\n\nDo you want to allow this operation?", processName, lpFileName);
            int result = MessageBoxA(NULL, msg, "Security Protection - File Operation", MB_YESNO | MB_ICONWARNING);
            
            if (result == IDNO) {
                LogDebugA("HookedCreateFileA: User denied file operation for '%s'", lpFileName);
                SetLastError(ERROR_ACCESS_DENIED);
                return INVALID_HANDLE_VALUE;
            }
            
            LogDebugA("HookedCreateFileA: User allowed file operation for '%s'", lpFileName);
        }
    }
    
    return TrueCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                           dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// Hook CreateFileW
HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
)
{
    // Convert to ANSI for scanning
    char fileNameA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, fileNameA, sizeof(fileNameA), NULL, NULL);
    
    // Only scan when creating new files or writing to existing files
    bool isWriteOperation = (dwDesiredAccess & GENERIC_WRITE) || 
                            (dwDesiredAccess & FILE_WRITE_DATA) ||
                            (dwDesiredAccess & FILE_APPEND_DATA);
    
    bool isCreateOperation = (dwCreationDisposition == CREATE_NEW) ||
                             (dwCreationDisposition == CREATE_ALWAYS) ||
                             (dwCreationDisposition == OPEN_ALWAYS);
    
    if ((isWriteOperation || isCreateOperation) && ShouldScanFilePath(fileNameA)) {
        LogDebugA("HookedCreateFileW: Scanning file '%s'", fileNameA);
        
        int scanResult = ScanFileWithEngine(fileNameA);
        
        if (scanResult == 1) { // UNSAFE
            char processName[256];
            GetCurrentProcessName(processName, sizeof(processName));
            
            char msg[1024];
            sprintf_s(msg, "Warning: A program is trying to create/modify a potentially malicious file!\n\nProcess: %s\nFile: %s\n\nThe file was detected as UNSAFE by the security engine.\n\nDo you want to allow this operation?", processName, fileNameA);
            int result = MessageBoxA(NULL, msg, "Security Protection - File Operation", MB_YESNO | MB_ICONWARNING);
            
            if (result == IDNO) {
                LogDebugA("HookedCreateFileW: User denied file operation for '%s'", fileNameA);
                SetLastError(ERROR_ACCESS_DENIED);
                return INVALID_HANDLE_VALUE;
            }
            
            LogDebugA("HookedCreateFileW: User allowed file operation for '%s'", fileNameA);
        }
    }
    
    return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                           dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// Hook CopyFileA
BOOL WINAPI HookedCopyFileA(
    LPCSTR lpExistingFileName,
    LPCSTR lpNewFileName,
    BOOL bFailIfExists
)
{
    // Scan the source file
    if (ShouldScanFilePath(lpExistingFileName)) {
        LogDebugA("HookedCopyFileA: Scanning source file '%s'", lpExistingFileName);
        
        int scanResult = ScanFileWithEngine(lpExistingFileName);
        
        if (scanResult == 1) { // UNSAFE
            char processName[256];
            GetCurrentProcessName(processName, sizeof(processName));
            
            char msg[1024];
            sprintf_s(msg, "Warning: A program is trying to copy a potentially malicious file!\n\nProcess: %s\nSource: %s\nDestination: %s\n\nThe file was detected as UNSAFE by the security engine.\n\nDo you want to allow this operation?", processName, lpExistingFileName, lpNewFileName);
            int result = MessageBoxA(NULL, msg, "Security Protection - File Copy", MB_YESNO | MB_ICONWARNING);
            
            if (result == IDNO) {
                LogDebugA("HookedCopyFileA: User denied copy operation");
                SetLastError(ERROR_ACCESS_DENIED);
                return FALSE;
            }
            
            LogDebugA("HookedCopyFileA: User allowed copy operation");
        }
    }
    
    return TrueCopyFileA(lpExistingFileName, lpNewFileName, bFailIfExists);
}

// Hook CopyFileW
BOOL WINAPI HookedCopyFileW(
    LPCWSTR lpExistingFileName,
    LPCWSTR lpNewFileName,
    BOOL bFailIfExists
)
{
    char existingFileA[MAX_PATH];
    char newFileA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, lpExistingFileName, -1, existingFileA, sizeof(existingFileA), NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, lpNewFileName, -1, newFileA, sizeof(newFileA), NULL, NULL);
    
    // Scan the source file
    if (ShouldScanFilePath(existingFileA)) {
        LogDebugA("HookedCopyFileW: Scanning source file '%s'", existingFileA);
        
        int scanResult = ScanFileWithEngine(existingFileA);
        
        if (scanResult == 1) { // UNSAFE
            char processName[256];
            GetCurrentProcessName(processName, sizeof(processName));
            
            char msg[1024];
            sprintf_s(msg, "Warning: A program is trying to copy a potentially malicious file!\n\nProcess: %s\nSource: %s\nDestination: %s\n\nThe file was detected as UNSAFE by the security engine.\n\nDo you want to allow this operation?", processName, existingFileA, newFileA);
            int result = MessageBoxA(NULL, msg, "Security Protection - File Copy", MB_YESNO | MB_ICONWARNING);
            
            if (result == IDNO) {
                LogDebugA("HookedCopyFileW: User denied copy operation");
                SetLastError(ERROR_ACCESS_DENIED);
                return FALSE;
            }
            
            LogDebugA("HookedCopyFileW: User allowed copy operation");
        }
    }
    
    return TrueCopyFileW(lpExistingFileName, lpNewFileName, bFailIfExists);
}

// Hook MoveFileA
BOOL WINAPI HookedMoveFileA(
    LPCSTR lpExistingFileName,
    LPCSTR lpNewFileName
)
{
    // Scan the source file
    if (ShouldScanFilePath(lpExistingFileName)) {
        LogDebugA("HookedMoveFileA: Scanning source file '%s'", lpExistingFileName);
        
        int scanResult = ScanFileWithEngine(lpExistingFileName);
        
        if (scanResult == 1) { // UNSAFE
            char processName[256];
            GetCurrentProcessName(processName, sizeof(processName));
            
            char msg[1024];
            sprintf_s(msg, "Warning: A program is trying to move a potentially malicious file!\n\nProcess: %s\nSource: %s\nDestination: %s\n\nThe file was detected as UNSAFE by the security engine.\n\nDo you want to allow this operation?", processName, lpExistingFileName, lpNewFileName);
            int result = MessageBoxA(NULL, msg, "Security Protection - File Move", MB_YESNO | MB_ICONWARNING);
            
            if (result == IDNO) {
                LogDebugA("HookedMoveFileA: User denied move operation");
                SetLastError(ERROR_ACCESS_DENIED);
                return FALSE;
            }
            
            LogDebugA("HookedMoveFileA: User allowed move operation");
        }
    }
    
    return TrueMoveFileA(lpExistingFileName, lpNewFileName);
}

// Hook MoveFileW
BOOL WINAPI HookedMoveFileW(
    LPCWSTR lpExistingFileName,
    LPCWSTR lpNewFileName
)
{
    char existingFileA[MAX_PATH];
    char newFileA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, lpExistingFileName, -1, existingFileA, sizeof(existingFileA), NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, lpNewFileName, -1, newFileA, sizeof(newFileA), NULL, NULL);
    
    // Scan the source file
    if (ShouldScanFilePath(existingFileA)) {
        LogDebugA("HookedMoveFileW: Scanning source file '%s'", existingFileA);
        
        int scanResult = ScanFileWithEngine(existingFileA);
        
        if (scanResult == 1) { // UNSAFE
            char processName[256];
            GetCurrentProcessName(processName, sizeof(processName));
            
            char msg[1024];
            sprintf_s(msg, "Warning: A program is trying to move a potentially malicious file!\n\nProcess: %s\nSource: %s\nDestination: %s\n\nThe file was detected as UNSAFE by the security engine.\n\nDo you want to allow this operation?", processName, existingFileA, newFileA);
            int result = MessageBoxA(NULL, msg, "Security Protection - File Move", MB_YESNO | MB_ICONWARNING);
            
            if (result == IDNO) {
                LogDebugA("HookedMoveFileW: User denied move operation");
                SetLastError(ERROR_ACCESS_DENIED);
                return FALSE;
            }
            
            LogDebugA("HookedMoveFileW: User allowed move operation");
        }
    }
    
    return TrueMoveFileW(lpExistingFileName, lpNewFileName);
}

// DllMain函数
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    LONG error;
    (void)hinstDLL;
    (void)lpvReserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (fdwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();

        // Initialize NT APIs from ntdll.dll
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            TrueNtTerminateProcess = (NtTerminateProcess_t)GetProcAddress(hNtdll, "NtTerminateProcess");
            TrueNtCreateKey = (NtCreateKey_t)GetProcAddress(hNtdll, "NtCreateKey");
            TrueNtSetValueKey = (NtSetValueKey_t)GetProcAddress(hNtdll, "NtSetValueKey");
            TrueNtDeleteKey = (NtDeleteKey_t)GetProcAddress(hNtdll, "NtDeleteKey");
            TrueNtDeleteValueKey = (NtDeleteValueKey_t)GetProcAddress(hNtdll, "NtDeleteValueKey");
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        
        // 挂钩所有启动应用程序的API
        DetourAttach(&(PVOID&)TrueCreateProcessA, HookedCreateProcessA);
        DetourAttach(&(PVOID&)TrueCreateProcessW, HookedCreateProcessW);
        DetourAttach(&(PVOID&)TrueShellExecuteA, HookedShellExecuteA);
        DetourAttach(&(PVOID&)TrueShellExecuteW, HookedShellExecuteW);
        DetourAttach(&(PVOID&)TrueShellExecuteExA, HookedShellExecuteExA);
        DetourAttach(&(PVOID&)TrueShellExecuteExW, HookedShellExecuteExW);
        
        // Hook process protection APIs
        DetourAttach(&(PVOID&)TrueTerminateProcess, HookedTerminateProcess);
        DetourAttach(&(PVOID&)TrueOpenProcess, HookedOpenProcess);
        
        // Hook NtTerminateProcess if available
        if (TrueNtTerminateProcess) {
            DetourAttach(&(PVOID&)TrueNtTerminateProcess, HookedNtTerminateProcess);
        }
        
        // Hook registry protection APIs (Win32)
        DetourAttach(&(PVOID&)TrueRegCreateKeyExA, HookedRegCreateKeyExA);
        DetourAttach(&(PVOID&)TrueRegCreateKeyExW, HookedRegCreateKeyExW);
        DetourAttach(&(PVOID&)TrueRegSetValueExA, HookedRegSetValueExA);
        DetourAttach(&(PVOID&)TrueRegSetValueExW, HookedRegSetValueExW);
        DetourAttach(&(PVOID&)TrueRegDeleteKeyA, HookedRegDeleteKeyA);
        DetourAttach(&(PVOID&)TrueRegDeleteKeyW, HookedRegDeleteKeyW);
        DetourAttach(&(PVOID&)TrueRegDeleteValueA, HookedRegDeleteValueA);
        DetourAttach(&(PVOID&)TrueRegDeleteValueW, HookedRegDeleteValueW);
        
        // Hook NT registry APIs if available
        if (TrueNtCreateKey) {
            DetourAttach(&(PVOID&)TrueNtCreateKey, HookedNtCreateKey);
        }
        if (TrueNtSetValueKey) {
            DetourAttach(&(PVOID&)TrueNtSetValueKey, HookedNtSetValueKey);
        }
        if (TrueNtDeleteKey) {
            DetourAttach(&(PVOID&)TrueNtDeleteKey, HookedNtDeleteKey);
        }
        if (TrueNtDeleteValueKey) {
            DetourAttach(&(PVOID&)TrueNtDeleteValueKey, HookedNtDeleteValueKey);
        }
        
        // Hook file system protection APIs
        DetourAttach(&(PVOID&)TrueCreateFileA, HookedCreateFileA);
        DetourAttach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
        DetourAttach(&(PVOID&)TrueCopyFileA, HookedCopyFileA);
        DetourAttach(&(PVOID&)TrueCopyFileW, HookedCopyFileW);
        DetourAttach(&(PVOID&)TrueMoveFileA, HookedMoveFileA);
        DetourAttach(&(PVOID&)TrueMoveFileW, HookedMoveFileW);
        
        error = DetourTransactionCommit();

        if (error == NO_ERROR) {
            OutputDebugStringA("XIGUASecurityAntiVirusHook: 成功挂钩应用程序启动API\n");
        }
        else {
            OutputDebugStringA("XIGUASecurityAntiVirusHook: 挂钩失败\n");
        }
        // 初始化日志互斥
        InitializeCriticalSection(&g_log_cs);
        // 初始化进程保护
        InitProcessProtection();
        // 初始化后台线程以连接扫描引擎（避免在 DllMain 中进行阻塞网络操作）
        HANDLE hThread = CreateThread(NULL, 0, ScannerInitThread, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        
        // 解除挂钩
        DetourDetach(&(PVOID&)TrueCreateProcessA, HookedCreateProcessA);
        DetourDetach(&(PVOID&)TrueCreateProcessW, HookedCreateProcessW);
        DetourDetach(&(PVOID&)TrueShellExecuteA, HookedShellExecuteA);
        DetourDetach(&(PVOID&)TrueShellExecuteW, HookedShellExecuteW);
        DetourDetach(&(PVOID&)TrueShellExecuteExA, HookedShellExecuteExA);
        DetourDetach(&(PVOID&)TrueShellExecuteExW, HookedShellExecuteExW);
        
        // Detach process protection APIs
        DetourDetach(&(PVOID&)TrueTerminateProcess, HookedTerminateProcess);
        DetourDetach(&(PVOID&)TrueOpenProcess, HookedOpenProcess);
        
        // Detach NtTerminateProcess if available
        if (TrueNtTerminateProcess) {
            DetourDetach(&(PVOID&)TrueNtTerminateProcess, HookedNtTerminateProcess);
        }
        
        // Detach registry protection APIs
        DetourDetach(&(PVOID&)TrueRegCreateKeyExA, HookedRegCreateKeyExA);
        DetourDetach(&(PVOID&)TrueRegCreateKeyExW, HookedRegCreateKeyExW);
        DetourDetach(&(PVOID&)TrueRegSetValueExA, HookedRegSetValueExA);
        DetourDetach(&(PVOID&)TrueRegSetValueExW, HookedRegSetValueExW);
        DetourDetach(&(PVOID&)TrueRegDeleteKeyA, HookedRegDeleteKeyA);
        DetourDetach(&(PVOID&)TrueRegDeleteKeyW, HookedRegDeleteKeyW);
        DetourDetach(&(PVOID&)TrueRegDeleteValueA, HookedRegDeleteValueA);
        DetourDetach(&(PVOID&)TrueRegDeleteValueW, HookedRegDeleteValueW);
        
        // Detach NT registry APIs if available
        if (TrueNtCreateKey) {
            DetourDetach(&(PVOID&)TrueNtCreateKey, HookedNtCreateKey);
        }
        if (TrueNtSetValueKey) {
            DetourDetach(&(PVOID&)TrueNtSetValueKey, HookedNtSetValueKey);
        }
        if (TrueNtDeleteKey) {
            DetourDetach(&(PVOID&)TrueNtDeleteKey, HookedNtDeleteKey);
        }
        if (TrueNtDeleteValueKey) {
            DetourDetach(&(PVOID&)TrueNtDeleteValueKey, HookedNtDeleteValueKey);
        }
        
        // Detach file system protection APIs
        DetourDetach(&(PVOID&)TrueCreateFileA, HookedCreateFileA);
        DetourDetach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
        DetourDetach(&(PVOID&)TrueCopyFileA, HookedCopyFileA);
        DetourDetach(&(PVOID&)TrueCopyFileW, HookedCopyFileW);
        DetourDetach(&(PVOID&)TrueMoveFileA, HookedMoveFileA);
        DetourDetach(&(PVOID&)TrueMoveFileW, HookedMoveFileW);
        
        error = DetourTransactionCommit();

        OutputDebugStringA("XIGUASecurityAntiVirusHook: 解除挂钩\n");
        
        CleanupProcessProtection();
    }
    return TRUE;
}

// Export function for SetWindowsHookEx global injection
// This function is called by SetWindowsHookEx when the hook is triggered
extern "C" __declspec(dllexport) LRESULT CALLBACK GlobalHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    // Just pass through - the real work is done in DllMain when the DLL is loaded
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}
