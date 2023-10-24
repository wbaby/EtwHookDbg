#pragma once
#include <ntifs.h>

NTSTATUS NTAPI HotGeNtProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
);

NTSTATUS NTAPI HotGeNtWriteVirtualMemory(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__in_bcount(BufferSize) CONST VOID *Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesWritten
);

NTSTATUS NTAPI HotGeNtReadVirtualMemory(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__out_bcount(BufferSize) PVOID Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesRead
);

NTSTATUS HotGeNtGetContextThread(
	__in HANDLE ThreadHandle,
	__inout PCONTEXT ThreadContext
);

NTSTATUS HotGeNtSetContextThread(
	__in HANDLE ThreadHandle,
	__in PCONTEXT ThreadContext
);