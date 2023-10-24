#include "EtwControl.h"
#include "infinityhook.h"
#include "ntint.h"
#include "tools.h"


typedef NTSTATUS(NTAPI *ZwTraceControlProc) (
	_In_ ULONG FunctionCode,
	_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
	_In_ ULONG InBufferLen,
	_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
	);

SyscallCallbackProc gcallback = NULL;

WORK_QUEUE_ITEM gWorkItem = {0};
BOOLEAN gIsExitWorkItem = TRUE;

ULONG64 GetZwTraceControl()
{
	ULONG64 MZwTraceControl = NULL;
	if (MZwTraceControl) return (ULONG64)MZwTraceControl;

	UNICODE_STRING uName = { 0 };
	RtlInitUnicodeString(&uName, L"ZwTranslateFilePath");
	PUCHAR TranslateFilePath = (PUCHAR)MmGetSystemRoutineAddress(&uName);
	TranslateFilePath = TranslateFilePath - 0x30;
	for (int i = 0; i < 0x50; i++)
	{
		if (TranslateFilePath[i] == 0x48 &&
			TranslateFilePath[i + 1] == 0x8B &&
			TranslateFilePath[i + 2] == 0xC4)
		{
			MZwTraceControl = (ULONG64)(TranslateFilePath + i);
			break;
		}
	}

	return (ULONG64)MZwTraceControl;
}

NTSTATUS NTAPI NtTraceControl(
	_In_ ULONG FunctionCode,
	_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
	_In_ ULONG InBufferLen,
	_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
)
{
	ZwTraceControlProc func = (ZwTraceControlProc)GetZwTraceControl();
	if (func)
	{
		return func(FunctionCode, InBuffer, InBufferLen, OutBuffer, OutBufferLen, ReturnLength);
	}

	return STATUS_UNSUCCESSFUL;
}





NTSTATUS IfhOff()
{
	ULONG number = GetWindowsVersionNumberEtw();
	if (number < 2004)
	{
		gIsExitWorkItem = TRUE;
		LARGE_INTEGER inTime = { 0 };

		inTime.QuadPart = (-10000 * 6000ull);

		KeDelayExecutionThread(KernelMode, TRUE, &inTime);

		IfhRelease();
	}
	return STATUS_SUCCESS;
	
}


VOID LoopWorkEtwHook(PVOID context)
{
	LARGE_INTEGER inTime = {0};

	inTime.QuadPart = (-10000 * 3000ull);

	KeDelayExecutionThread(KernelMode, TRUE, &inTime);

	if (!gIsExitWorkItem)
	{
		IfhInitialize(SyscallStub);

		ExInitializeWorkItem(&gWorkItem, LoopWorkEtwHook, NULL);
		ExQueueWorkItem(&gWorkItem, DelayedWorkQueue);
	}
	
}


NTSTATUS IfhOn(SyscallCallbackProc callback)
{
	ULONG number = GetWindowsVersionNumberEtw();
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	gcallback = callback;
	if (number < 2004)
	{
		status = IfhInitialize(SyscallStub);
		if (NT_SUCCESS(status))
		{
			gIsExitWorkItem = FALSE;
			ExInitializeWorkItem(&gWorkItem, LoopWorkEtwHook, NULL);
			ExQueueWorkItem(&gWorkItem, DelayedWorkQueue);
		}
	}
	
	
	return status;
	
}



void __fastcall SyscallStub(_In_ unsigned int SystemCallIndex,_Inout_ void** SystemCallFunction)
{
	if (gcallback) gcallback(SystemCallIndex, SystemCallFunction);
}


