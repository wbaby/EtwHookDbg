#pragma once
#include <ntifs.h>
#include "Struct.h"

typedef struct _SYSTEM_DLL_ENTRY
{
	
	ULONG64 type;
	UNICODE_STRING FullName;
	PVOID ImageBase;
	PWCHAR BaseName;
	PWCHAR StaticUnicodeBuffer;
}SYSTEM_DLL_ENTRY, *PSYSTEM_DLL_ENTRY;

typedef struct _SYSTEM_DLL_INFO 
{
	PVOID Section;
	ULONG64 Un1;
	SYSTEM_DLL_ENTRY entry;

}SYSTEM_DLL_INFO,*PSYSTEM_DLL_INFO;



void initSearchFunc();

PETHREAD PsGetNextProcessThread(PEPROCESS Process, PETHREAD Thread);
NTSTATUS PsSuspendThread(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);

NTSTATUS PsResumeThread(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);

PSYSTEM_DLL_ENTRY PsQuerySystemDllInfo(ULONG index);

VOID KeFreezeAllThreads(VOID);

VOID KeThawAllThreads(VOID);

VOID PsSynchronizeWithThreadInsertion(PETHREAD thread, PETHREAD curThread);

NTSTATUS MmGetFileNameForAddress(
	IN PVOID ProcessVa,
	OUT PUNICODE_STRING FileName
);

PSYSTEM_DLL_INFO GetPspSystemDlls();

NTSTATUS ObDuplicateObject(
	IN PEPROCESS SourceProcess,
	IN HANDLE SourceHandle,
	IN PEPROCESS TargetProcess OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options,
	IN KPROCESSOR_MODE PreviousMode
);

NTSTATUS DbgkpSendErrorMessage(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN ULONG Falge,
	IN PVOID	DbgApiMsg);

NTSTATUS DbgkpSendApiMessageLpc(
	IN OUT PVOID ApiMsg,
	IN PVOID Port,
	IN BOOLEAN SuspendProcess
);


PVOID ObFastReferenceObject(
	IN PEX_FAST_REF FastRef
);

/*
NTSTATUS DbgkpPostModuleMessages(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN PVOID DebugObject);

	*/