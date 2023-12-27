// SimpleHookH.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#define SIMPLE_HOOK_IMPLEMENTATION
#include "SimpleHookH.h"
#include <assert.h>
#include <stdio.h>

// TEST HOOKS
LONG WINAPI SleepHookTest(PEXCEPTION_POINTERS ExceptionInfo) {
    ExceptionInfo->ContextRecord->Rcx = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

LONG WINAPI MessageBeepHookTest(PEXCEPTION_POINTERS ExceptionInfo) {
    return EXCEPTION_CONTINUE_EXECUTION;
}

LONG WINAPI BeepHookTest(PEXCEPTION_POINTERS ExceptionInfo) {
    return EXCEPTION_CONTINUE_EXECUTION;
}

DWORD WINAPI SleepThreadTest(LPVOID lpParam) {
    UNREFERENCED_PARAMETER(lpParam);
    Sleep(1000000);
    Beep(1, 1);
    return 0;
}


// TESTS Functions
VOID SimplePGTest() {
    SHookInit(0);
    SHookRegisterPGHook((uint64_t)Sleep, SleepHookTest);
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    double interval;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    Sleep(5000);
    QueryPerformanceCounter(&end);
    interval = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;
    assert(interval < 5 && "[-] SimplePGTest ::: Failed To Hook Sleep With PG");
    SHookUninit();
    printf("[+] Passed SimplePGTest %f\n", interval);
}

VOID SimpleHWBPTest() {
    SHookInit(0);
    SHookRegisterHWBPAllThreads((DWORD64)Sleep, SleepHookTest, 0, TRUE);
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    double interval;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    Sleep(5000);
    QueryPerformanceCounter(&end);
    interval = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;
    assert(interval < 5 && "[-] SimpleHWBPTest ::: Failed To Hook Sleep With HWBP");
    SHookUninit();
    printf("[+] Passed SimpleHWBPTest %f\n", interval);
}

VOID SimpleHWBPAllRegTest() {
    SHookInit(0);
    SHookRegisterHWBPAllThreads((DWORD64)Sleep, SleepHookTest, 0, TRUE);
    SHookRegisterHWBPAllThreads((DWORD64)Beep, BeepHookTest, 1, TRUE);
    SHookRegisterHWBPAllThreads((DWORD64)MessageBeep, MessageBeepHookTest, 2, TRUE);

    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    double interval;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    Sleep(5000);
    Beep(1, 1);
    MessageBeep(MB_OK);
    Beep(1, 1);
    MessageBeep(MB_OK);
    QueryPerformanceCounter(&end);
    interval = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;
    assert(interval < 5 && "[-] SimpleHWBPAllRegTest ::: Failed To Hook Sleep With HWBP");
    SHookUninit();
    printf("[+] Passed SimpleHWBPAllRegTest %f\n", interval);
}

VOID NTCreateThreadPGReapplyTest() {
    SHookInit(0);
    SHookRegisterHWBPAllThreads((uintptr_t)Sleep, SleepHookTest, 0, TRUE);
    uintptr_t createThreadAddress = (uintptr_t)GetProcAddress(GetModuleHandleA("NTDLL.dll"), "NtCreateThreadEx");
    SHookRegisterPGHook(createThreadAddress, (SHHookHandler*)NtCreateThreadExHook_);
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    double interval;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    Sleep(100000);
    for (unsigned int i = 0; i < 2; ++i) {
        HANDLE t = CreateThread(NULL, 0, SleepThreadTest, NULL, 0, NULL);
        if (t) WaitForSingleObject(t, INFINITE);
    }
    QueryPerformanceCounter(&end);
    interval = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;
    assert(interval < 5 && "[-] NTCreateThreadPGReapplyTest ::: Failed To Reapply NtCreateThread PG");
    SHookUninit();
    printf("[+] Passed NTCreateThreadPGReapplyTest %f\n", interval);
}

VOID RemoveHooksTest() {
    SHookInit(0);
    SHookRegisterHWBPAllThreads((uintptr_t)Sleep, SleepHookTest, 0, TRUE);
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    double interval;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    // Remove HWHooks
    SHookRemoveHWBP();
    Sleep(2000);
    QueryPerformanceCounter(&end);
    interval = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;
    assert(interval < 3 && interval > 2 && "[-] RemoveHWHooksTest ::: Failed To Reapply remove hw bp");
    SHookUninit();
    printf("[+] Passed RemoveHWHooksTest %f\n", interval);
}


VOID RemovePGHooksTest() {
    SHookInit(0);
    SHookRegisterPGHook((uintptr_t)Sleep, (SHHookHandler*)SleepHookTest);
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    double interval;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    SHookRemovePGHook((uintptr_t)Sleep);
    Sleep(2000);
    QueryPerformanceCounter(&end);
    interval = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;
    assert(interval < 3 && interval > 2 && "[-] RemoveHWHooksTest ::: Failed To Reapply NtCreateThread PG");
    SHookUninit();
    printf("[+] Passed RemovePGHooksTest %f\n", interval);
}




VOID RunTests() {
    SimplePGTest();
    SimpleHWBPTest();
    SimpleHWBPAllRegTest();
    NTCreateThreadPGReapplyTest();
    RemoveHooksTest();
    RemovePGHooksTest();
    printf("OK\n");
}


int main()
{
    RunTests();
    return 0;
}

