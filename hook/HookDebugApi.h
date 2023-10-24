#pragma once
#include <ntifs.h>

void InitHook();
void DestoryHookAll();

ULONG64 GetNtCreateDebugObjectFunc();

ULONG64 GetNtDebugActiveProcessFunc();

ULONG64 GetNtDebugContinueFunc();

ULONG64 GetNtRemoveProcessDebugFunc();

ULONG64 GetNtWaitForDebugEventFunc();

ULONG64 GetNtProtectVirtualMemoryFunc();

ULONG64 GetNtWriteVirtualMemoryFunc();

ULONG64 GetNtReadVirtualMemoryFunc();

ULONG64 GetNtSetContextThreadFunc();

ULONG64 GetNtGetContextThreadFunc();