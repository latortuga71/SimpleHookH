#pragma once

#ifndef SIMPLE_HOOK_H
#define SIMPLE_HOOK_H

#include <Windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <TlHelp32.h>

// Private Static Types
typedef LONG WINAPI SHHookHandler(PEXCEPTION_POINTERS ExceptionInfo);
typedef VOID WINAPI SHHookHandlerPG(PEXCEPTION_POINTERS ExceptionInfo);
static LONG WINAPI ExceptionHandlerMain_(PEXCEPTION_POINTERS ExceptionInfo);
// Private Static  consts
static const UINT MaxHWHooks_ = 3;

// Public Structs
typedef struct {
    uint64_t Address;
    SHHookHandler* Function;
} SHPageGuardHook;

typedef struct {
    uint64_t Address;
    SHHookHandler* Function;
} SHHWBPHook;

// This is dynamic because we can hook with guard pages infinitely
typedef struct {
    SHPageGuardHook* Hooks;
    int capacity;
    int count;
} SHPGHooksList;

// This is a static array because we only have 4 debug registers at once.
typedef struct {
    SHHWBPHook Hooks[2]; // Each Debug Register Corresponds To This Array, For Some Reason DR3 throws an unhandeled exception.
} SHHWHooksList;

typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer);

//  Globals 
SHPGHooksList* PGHooks = NULL;
SHHWHooksList HWHooks = { 0 };
PVOID handler_;
pfnNtCreateThreadEx SHNtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
VOID WINAPI NtCreateThreadExHook_(PEXCEPTION_POINTERS ExceptionInfo);

void SHookInit(int capacity);
void SHookUninit();
void SHookRegisterHWBPAllThreads(uintptr_t address, SHHookHandler* hookFunction, unsigned int position, bool init);
void SHookRegisterHWBP(HANDLE threadId, uintptr_t address, SHHookHandler* hookFunction, unsigned int position, bool init);
BOOL SHookRegisterPGHook(uint64_t address, SHHookHandler function);
void SHookRemovePGHook(uint64_t rip);
void SHookRemoveHWBP();









#endif


#ifdef SIMPLE_HOOK_IMPLEMENTATION

// static private
/*
static LONG WINAPI ExceptionHandlerMain_(PEXCEPTION_POINTERS ExceptionInfo);
static VOID WINAPI NtCreateThreadExHook_(PEXCEPTION_POINTERS ExceptionInfo);
static SHHookHandler* CheckIfHWHookExists_(DWORD64 rip);
static SHHookHandler* CheckIfPGHookExists_(DWORD64 rip);
static void RemoveHWHook_(uint64_t rip, UINT position);
static void RegisterHWHook_(uint64_t rip, SHHookHandler function, UINT position);
static uintptr_t FindRetGadget_(const uintptr_t function);
*/

// static
// Private
static void RegisterHWHook_(uint64_t rip, SHHookHandler function, UINT position) {
    if (position > MaxHWHooks_) {
        return;
    }
    HWHooks.Hooks[position].Address = rip;
    HWHooks.Hooks[position].Function = function;
}

// Private
static void RemoveHWHook_(uint64_t rip, UINT position) {
    HWHooks.Hooks[position].Address = 0;
    HWHooks.Hooks[position].Function = NULL;
}


static uintptr_t FindRetGadget_(const uintptr_t function) {
    BYTE stub[] = { 0xC3 };
    // cant we just read x bytes into a buffer then loop over it 
    // and return function plus offset.?
    for (unsigned int i = 0; i < (unsigned int)10000; i++) {
        if (memcmp((LPVOID)(function + i), stub, sizeof(stub)) == 0) {
            return (function + i);
        }
    }
    return 0;
}

// public api impl
void SHookInit(int capacity) {
    // Setup Page Guard Hooks List
    PGHooks = (SHPGHooksList*)malloc(sizeof(SHPGHooksList));
    memset(PGHooks, 0, sizeof(SHPGHooksList));
    if (capacity <= 0) {
        capacity = 1;
    }
    PGHooks->capacity = capacity;
    PGHooks->count = 0;
    PGHooks->Hooks = (SHPageGuardHook*)malloc(sizeof(SHPageGuardHook) * capacity);
    memset(PGHooks->Hooks, 0, sizeof(SHHWBPHook) * capacity);
    handler_ = AddVectoredExceptionHandler(1, &ExceptionHandlerMain_);
}

void SHookRemoveHWBP() {
    for (int position = 0; position < MaxHWHooks_; position++) {
        SHookRegisterHWBPAllThreads(HWHooks.Hooks[position].Address, NULL, position, FALSE);
    }
}


void SHookUninit() {
    DWORD oldprot = 0;
    // Remove Active Page Guards
    for (int idx = 0; idx < PGHooks->count; idx++) {
        if (PGHooks->Hooks[idx].Address != NULL) {
            VirtualProtect((LPVOID)PGHooks->Hooks[idx].Address, 1, PAGE_EXECUTE_READ, &oldprot);
        }
    }
    for (int position = 0; position < MaxHWHooks_; position++) {
        SHookRegisterHWBPAllThreads(HWHooks.Hooks[position].Address, NULL, position, FALSE);
    }
    free(PGHooks->Hooks);
    PGHooks->capacity = 0;
    PGHooks->count = 0;
    free(PGHooks);
    if (handler_)
        RemoveVectoredExceptionHandler(handler_);
}

// Public Sets HWBP On ALL Threads
void SHookRegisterHWBPAllThreads(uintptr_t address, SHHookHandler* hookFunction, unsigned int position, bool init) {
    DWORD pid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return;
    }
    THREADENTRY32 threadEntry = {};
    threadEntry.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hSnap, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID != pid)
                continue;
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
            if (hThread == INVALID_HANDLE_VALUE)
                continue;
            SHookRegisterHWBP(hThread, address, hookFunction, position, init);
            CloseHandle(hThread);
            threadEntry.dwSize = sizeof(threadEntry);
        } while (Thread32Next(hSnap, &threadEntry));
    }
    CloseHandle(hSnap);
}

// Public
void SHookRegisterHWBP(HANDLE threadId, uintptr_t address, SHHookHandler* hookFunction, unsigned int position, bool init) {
    if (position > MaxHWHooks_) {
        return;
    }
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(threadId, &context);
    if (init) {
        (&context.Dr0)[position] = address;
        context.Dr7 &= ~(3ull << (16 + 4 * position));
        context.Dr7 &= ~(3ull << (18 + 4 * position));
        context.Dr7 |= 1ull << (2 * position);
        RegisterHWHook_(address, hookFunction, position);
    }
    else {
        if ((&context.Dr0)[position] == address) {
            context.Dr7 &= ~(1ull << (2 * position));
            (&context.Dr7)[position] = NULL;
            RemoveHWHook_(address, position);
        }
    }
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(threadId, &context);
}

BOOL SHookRegisterPGHook(uint64_t address, SHHookHandler function) {
    if ((PGHooks->count + 1) > PGHooks->capacity) {
        // realloc PG List
        PGHooks->Hooks = (SHPageGuardHook*)realloc(PGHooks->Hooks, sizeof(SHHWBPHook) * (PGHooks->capacity * 2));
        PGHooks->capacity = PGHooks->capacity * 2;
    }
    PGHooks->Hooks[PGHooks->count].Function = function;
    PGHooks->Hooks[PGHooks->count].Address = address;
    PGHooks->count++;
    DWORD old = 0;
    return VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
}

void SHookRemovePGHook(uint64_t rip) {
    if (PGHooks->count == 0)
        return;
    int idx = 0;
    // TODO SHIFT ITEMS TO THE LEFT WHEN REMOVED
    DWORD old = 0;
    for (int i = 0; i < PGHooks->count; i++) {
        if (PGHooks->Hooks[i].Address == rip) {
            VirtualProtect((LPVOID)rip, 1, PAGE_EXECUTE_READ, &old);
            PGHooks->Hooks[i].Address = 0;
            PGHooks->Hooks[i].Function = NULL;
            idx = i;
        }
    }
}



//Static
static SHHookHandler* CheckIfPGHookExists_(DWORD64 rip) {
    for (int i = 0; i < PGHooks->count; i++) {
        if (rip == PGHooks->Hooks[i].Address) {
            return PGHooks->Hooks[i].Function;
        }
    }
    return NULL;
}

// Static
static SHHookHandler* CheckIfHWHookExists_(DWORD64 rip) {
    for (int i = 0; i < 3; i++) {
        if (HWHooks.Hooks[i].Address == rip) {
            return HWHooks.Hooks[i].Function;
        }
    }
    return NULL;
}

// Static NtCreateThreadHook?
static VOID WINAPI NtCreateThreadExHook_(PEXCEPTION_POINTERS ExceptionInfo) {
    //fprintf(stderr, "NtCreateThread RIP -> 0x%016llX\n", ExceptionInfo->ContextRecord->Rip);
    // Call Function But Suspend Thread
    LONG status = ((pfnNtCreateThreadEx)ExceptionInfo->ContextRecord->Rip)(
        (PHANDLE)ExceptionInfo->ContextRecord->Rcx,
        (ACCESS_MASK)ExceptionInfo->ContextRecord->Rdx,
        (PVOID)ExceptionInfo->ContextRecord->R8,
        (HANDLE)ExceptionInfo->ContextRecord->R9,
        (PVOID) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x28),
        (PVOID) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x30),
        (ULONG) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x38) | 0x1ull,
        (SIZE_T) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x40),
        (SIZE_T) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x48),
        (SIZE_T) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x50),
        (PVOID) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x58)
        );
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext((HANDLE)(*(PULONG64)ExceptionInfo->ContextRecord->Rcx), &context);
    // Loop Over Exisiting HardWareBreakPoints And Set Them 
    for (int position = 0; position < MaxHWHooks_; position++) {
        (&context.Dr0)[position] = HWHooks.Hooks[position].Address;
        context.Dr7 &= ~(3ull << (16 + 4 * position));
        context.Dr7 &= ~(3ull << (18 + 4 * position));
        context.Dr7 |= 1ull << (2 * position);
    }
    SetThreadContext((HANDLE)(*(PULONG64)ExceptionInfo->ContextRecord->Rcx), &context);
    ResumeThread((HANDLE)(*(PULONG64)ExceptionInfo->ContextRecord->Rcx));
    ExceptionInfo->ContextRecord->Rax = status;
    ExceptionInfo->ContextRecord->Rip = FindRetGadget_(ExceptionInfo->ContextRecord->Rip);
}


// Static Private Exception Handlers
static LONG WINAPI ExceptionHandlerMain_(PEXCEPTION_POINTERS ExceptionInfo) {
    //fprintf(stderr, "RIP -> 0x%016llX\n", ExceptionInfo->ContextRecord->Rip);
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        SHHookHandlerPG* PotentialFunction = (SHHookHandlerPG*)CheckIfPGHookExists_(ExceptionInfo->ContextRecord->Rip);
        if (PotentialFunction != NULL) {
            PotentialFunction(ExceptionInfo);
        }
        ExceptionInfo->ContextRecord->EFlags |= (1 << 8);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
        SHHookHandler* PotentialFunction = CheckIfHWHookExists_(ExceptionInfo->ContextRecord->Rip);
        if (PotentialFunction != NULL) {
            PotentialFunction(ExceptionInfo);
            ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        DWORD oldprot = 0;
        // Reapply Existing Page Guard Hooks
        for (int idx = 0; idx < PGHooks->count; idx++) {
            if (PGHooks->Hooks[idx].Address != NULL) {
                VirtualProtect((LPVOID)PGHooks->Hooks[idx].Address, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldprot);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}





#endif