#pragma once
#include <ntifs.h>

NTSTATUS NTAPI NtTraceControl(
	_In_ ULONG FunctionCode,
	_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
	_In_ ULONG InBufferLen,
	_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
);

void __fastcall SyscallStub(
	_In_ unsigned int SystemCallIndex,
	_Inout_ void** SystemCallFunction);

typedef void (*SyscallCallbackProc)(
	_In_ unsigned int SystemCallIndex,
	_Inout_ void** SystemCallFunction);

NTSTATUS IfhOff();

NTSTATUS IfhOn(SyscallCallbackProc callback);

