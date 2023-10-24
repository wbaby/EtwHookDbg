#include <intrin.h>
#include "Dbg.h"
#include "comm\SystemExportFunc.h"
#include "comm\ObjectType.h"
#include "comm\DbgStruct.h"
#include "Dbgkp.h"
#include "Peb.h"
#include "Struct.h"
#include "SearchFunc.h"

FAST_MUTEX DbgkpProcessDebugPortMutex;
POBJECT_TYPE g_HotGeDebugObject;
ULONG g_DbgkpMaxModuleMsgs;

int ExSystemExceptionFilter(VOID)
{
	return(ExGetPreviousMode() != KernelMode ? EXCEPTION_EXECUTE_HANDLER: EXCEPTION_CONTINUE_SEARCH);
}

FORCEINLINE VOID ProbeForWriteSmallStructure(
	IN PVOID Address,
	IN SIZE_T Size,
	IN ULONG Alignment
)
{

	ASSERT((Alignment == 1) || (Alignment == 2) ||
		(Alignment == 4) || (Alignment == 8) ||
		(Alignment == 16));

	
	if ((Size == 0) || (Size >= PAGE_SIZE)) {
		ASSERT(0);
		ProbeForWrite(Address, Size, Alignment);

	}
	else
	{
		if (((ULONG_PTR)(Address) & (Alignment - 1)) != 0) {
			ExRaiseDatatypeMisalignment();
		}

		if ((ULONG_PTR)(Address) >= (ULONG_PTR)MM_USER_PROBE_ADDRESS) {
			Address = (UCHAR * const)MM_USER_PROBE_ADDRESS;
		}

		((volatile UCHAR *)(Address))[0] = ((volatile UCHAR *)(Address))[0];
		((volatile UCHAR *)(Address))[Size - 1] = ((volatile UCHAR *)(Address))[Size - 1];

	}
}

FORCEINLINE VOID ProbeForReadSmallStructure(IN PVOID Address, IN SIZE_T Size, IN ULONG Alignment)
{
	ASSERT((Alignment == 1) || (Alignment == 2) ||
		(Alignment == 4) || (Alignment == 8) ||
		(Alignment == 16));

	if ((Size == 0) || (Size >= 0x10000)) {

		ASSERT(0);
		ProbeForRead(Address, Size, Alignment);

	}
	else {
		if (((ULONG_PTR)Address & (Alignment - 1)) != 0) {
			ExRaiseDatatypeMisalignment();
		}

		if ((PUCHAR)Address >= (UCHAR * const)MM_USER_PROBE_ADDRESS) {
			Address = (UCHAR * const)MM_USER_PROBE_ADDRESS;
		}

		_ReadWriteBarrier();
		*(volatile UCHAR *)Address;
	}
}

BOOLEAN IsProcessProtected(PEPROCESS eprocess)
{
	ULONG flags = *(PULONG)((PUCHAR)eprocess + 0x43c);
	return (flags >> 0xb) & 1;
}

NTSTATUS HotGeNtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
)
{
	NTSTATUS status = STATUS_SUCCESS;
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	if (Flags & ~DEBUG_KILL_ON_CLOSE)
	{
		return STATUS_INVALID_PARAMETER;
	}

	PDEBUG_OBJECT pDebug = NULL;
	status = ObCreateObject(PreviousMode, g_HotGeDebugObject, ObjectAttributes, PreviousMode, NULL, sizeof(DEBUG_OBJECT), 0, 0, &pDebug);

	if (!NT_SUCCESS(status))
	{
		return status;
	} 

	ExInitializeFastMutex(&pDebug->Mutex);
	InitializeListHead(&pDebug->EventList);
	KeInitializeEvent(&pDebug->EventsPresent, NotificationEvent, FALSE);

	pDebug->Flags = 0;
	PPEB32 peb = PsGetProcessWow64Process(PsGetCurrentProcess());

	if (peb)
	{
		pDebug->Flags = DEBUG_WOW64_PROCESS;
	}
	
	HANDLE DebugObjectHanndle = NULL;
	status = ObInsertObject(pDebug, NULL, DesiredAccess, 0, NULL, &DebugObjectHanndle);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	*DebugObjectHandle = DebugObjectHanndle;

	return status;
}

NTSTATUS HotGeNtDebugActiveProcess(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle
)
{
	//DbgBreakPoint();
	
	NTSTATUS status = STATUS_SUCCESS;
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	PEPROCESS Process = NULL;
	PEPROCESS CurProcess = PsGetCurrentProcess();
	PETHREAD pThread = NULL;

	status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_SET_PORT, *PsProcessType, PreviousMode, &Process, NULL);
	do 
	{
		if (!NT_SUCCESS(status))
		{
			break;
		}

		if (Process == CurProcess || Process == (PVOID)PsInitialSystemProcess)
		{
			status = STATUS_ACCESS_DENIED;
			break;
		}

		/*
		if (PreviousMode == UserMode && !IsProcessProtected(CurProcess))
		{
			if (IsProcessProtected(Process))
			{
				status = STATUS_PROCESS_IS_PROTECTED;
				break;
			}
		}
		*/
		//如果调试进程是x86进程，但是被调试程序是64位进程
		if (PsGetProcessWow64Process(CurProcess) && !PsGetProcessWow64Process(Process))
		{
			status = STATUS_NOT_SUPPORTED;
			break;
		}

		PDEBUG_OBJECT debugObject = NULL;
		status = ObReferenceObjectByHandle(DebugObjectHandle, DEBUG_PROCESS_ASSIGN, g_HotGeDebugObject, PreviousMode, &debugObject, NULL);
		
		if (!NT_SUCCESS(status))
		{
			break;
		}
		
		if (!EntryAcquireRundownProtectionByProcess(Process))
		{
			status = STATUS_PROCESS_IS_TERMINATING;
			ObDereferenceObject(debugObject);
			break;
		}

		status = DbgkpPostFakeProcessCreateMessages(Process, debugObject,&pThread);
		status = DbgkpSetProcessDebugObject(Process, debugObject, status, pThread);
		ExitReleaseRundownProtectionByProcess(Process);
		ObDereferenceObject(debugObject);
	} while (0);
	
	if (Process) ObDereferenceObject(Process);
	return status;
}

NTSTATUS HotGeNtRemoveProcessDebug(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle
)
{
	//DbgBreakPoint();
	NTSTATUS status = STATUS_SUCCESS;
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	PEPROCESS Process = NULL;
	PEPROCESS CurProcess = PsGetCurrentProcess();

	status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_SET_PORT, *PsProcessType, PreviousMode, &Process, NULL);
	
	do 
	{
		if (!NT_SUCCESS(status))
		{
			break;
		}

		/*
		if (!IsProcessProtected(CurProcess) && IsProcessProtected(Process))
		{
			status = STATUS_PROCESS_IS_PROTECTED;
			break;
		}
		*/
		PDEBUG_OBJECT debugObject = NULL;
		status = ObReferenceObjectByHandle(DebugObjectHandle, DEBUG_PROCESS_ASSIGN, g_HotGeDebugObject, PreviousMode, &debugObject, NULL);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		status=DbgkClearProcessDebugObject(Process, debugObject);
		ObDereferenceObject(debugObject);

	} while (0);
	
	if (Process) ObDereferenceObject(Process);
	return status;
	
}

NTSTATUS HotGetDbgkInitialize(VOID)
{
	//DbgBreakPoint();
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	ExInitializeFastMutex(&DbgkpProcessDebugPortMutex);
	g_HotGeDebugObject = GetHotGetType();
	g_DbgkpMaxModuleMsgs = 500;

	//初始化
	initSearchFunc();
	
	if (!g_HotGeDebugObject)
	{
		UNICODE_STRING Name;
		OBJECT_TYPE_INITIALIZER oti = { 0 };
		GENERIC_MAPPING GenericMapping = { STANDARD_RIGHTS_READ | DEBUG_READ_EVENT,
			STANDARD_RIGHTS_WRITE | DEBUG_PROCESS_ASSIGN,
			STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
			DEBUG_ALL_ACCESS };

		//RtlInitUnicodeString(&Name, L"HotGeObject");
		RtlInitUnicodeString(&Name, L"DebugObject");

		oti.Length = sizeof(oti);
		oti.SecurityRequired = TRUE;
		oti.InvalidAttributes = 0;
		oti.PoolType = NonPagedPool;
		oti.DeleteProcedure = NULL;
		oti.CloseProcedure = NULL;
		oti.ValidAccessMask = DEBUG_ALL_ACCESS;
		oti.GenericMapping = GenericMapping;
		oti.DefaultPagedPoolCharge = 0;
		oti.DefaultNonPagedPoolCharge = 0;
		oti.ObjectTypeFlags = 8;

		Status = ObCreateObjectType(&Name, &oti, NULL, &g_HotGeDebugObject);
		
	}

	return g_HotGeDebugObject ? STATUS_SUCCESS : Status;
}

NTSTATUS HotGeNtWaitForDebugEvent(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange
)
{

	//DbgBreakPoint();
	DBGUI_WAIT_STATE_CHANGE newStateChange = {0};
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	LARGE_INTEGER MTimeout = { 0 };
	PDEBUG_OBJECT DebugObject =NULL;
	LARGE_INTEGER StartTime = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	PLIST_ENTRY Entry, Entry2;
	PDEBUG_EVENT DebugEvent, DebugEvent2;
	BOOLEAN GotEvent;

	PEPROCESS Process = NULL;
	PETHREAD Thread = NULL;

	__try{
		if (ARGUMENT_PRESENT(Timeout)) {
			if (PreviousMode != KernelMode) {
				ProbeForRead(Timeout, sizeof(*Timeout), sizeof(UCHAR));
			}
			MTimeout = *Timeout;
			Timeout = &MTimeout;
			KeQuerySystemTime(&StartTime);
		}

		if (PreviousMode != KernelMode) {
			ProbeForWrite(WaitStateChange, sizeof(*WaitStateChange), sizeof(UCHAR));
		}

	} __except(ExSystemExceptionFilter()) {
		return GetExceptionCode();
	}

	status = ObReferenceObjectByHandle(DebugObjectHandle,
		DEBUG_READ_EVENT,
		g_HotGeDebugObject,
		PreviousMode,
		&DebugObject,
		NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}


	while (TRUE)
	{
		status = KeWaitForSingleObject(&DebugObject->EventsPresent, Executive, PreviousMode, Alertable, Timeout);

		if (!NT_SUCCESS(status) || status == STATUS_TIMEOUT || status == STATUS_ALERTED || status == STATUS_USER_APC) {
			break;
		}

		GotEvent = FALSE;
		DebugEvent = NULL;

		ExAcquireFastMutex(&DebugObject->Mutex);
		
		if ((DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) == 0) {

			for (Entry = DebugObject->EventList.Flink; Entry != &DebugObject->EventList; Entry = Entry->Flink) {

				DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);

				if ((DebugEvent->Flags & (DEBUG_EVENT_READ | DEBUG_EVENT_INACTIVE)) == 0) {
					GotEvent = TRUE;

					for (Entry2 = DebugObject->EventList.Flink; Entry2 != Entry; Entry2 = Entry2->Flink) {
						DebugEvent2 = CONTAINING_RECORD(Entry2, DEBUG_EVENT, EventList);

						if (DebugEvent->ClientId.UniqueProcess == DebugEvent2->ClientId.UniqueProcess) {
							
							DebugEvent->Flags |= DEBUG_EVENT_INACTIVE;
							DebugEvent->BackoutThread = NULL;
							GotEvent = FALSE;
							break;
						}
					}

					if (GotEvent) {
						break;
					}

				}

			}

			if (GotEvent) {
				Process = DebugEvent->Process;
				Thread = DebugEvent->Thread;
				ObReferenceObject(Thread);
				ObReferenceObject(Process);
				DbgkpConvertKernelToUserStateChange(&newStateChange, DebugEvent);
				DebugEvent->Flags |= DEBUG_EVENT_READ;
			}
			else {

				KeClearEvent(&DebugObject->EventsPresent);
			}

			status = STATUS_SUCCESS;
		}
		else {
			status = STATUS_DEBUGGER_INACTIVE;
		}

		ExReleaseFastMutex(&DebugObject->Mutex);

		if (!NT_SUCCESS(status))
		{
			break;
		}

		if (GotEvent) {
			DbgkpOpenHandles(&newStateChange, Process, Thread);
			ObDereferenceObject(Thread);
			ObDereferenceObject(Process);
			break;
			
		}

		if (MTimeout.QuadPart < 0) {
			LARGE_INTEGER NewTime;
			KeQuerySystemTime(&NewTime);
			MTimeout.QuadPart = MTimeout.QuadPart + (NewTime.QuadPart - StartTime.QuadPart);
			StartTime = NewTime;
			if (MTimeout.QuadPart >= 0) {
				status = STATUS_TIMEOUT;
				break;
			}
		}

	}

	ObDereferenceObject(DebugObject);

	try {
		*WaitStateChange = newStateChange;
	} except(ExSystemExceptionFilter()) { // If previous mode is kernel then don't handle the exception
		status = GetExceptionCode();
	}
	return status;

}


NTSTATUS HotGeNtDebugContinue(IN HANDLE DebugObjectHandle,IN PCLIENT_ID ClientId,IN NTSTATUS ContinueStatus)
{
	//DbgBreakPoint();
	NTSTATUS Status;
	PDEBUG_OBJECT DebugObject;
	PDEBUG_EVENT DebugEvent, FoundDebugEvent;
	KPROCESSOR_MODE PreviousMode;
	CLIENT_ID Clid;
	PLIST_ENTRY Entry;
	BOOLEAN GotEvent;

	PreviousMode = ExGetPreviousMode();

	try {
		if (PreviousMode != KernelMode) {
			ProbeForReadSmallStructure(ClientId, sizeof(*ClientId), sizeof(UCHAR));
		}
		Clid = *ClientId;

	} except(ExSystemExceptionFilter()) { // If previous mode is kernel then don't handle the exception
		return GetExceptionCode();
	}

	switch (ContinueStatus) {
	case DBG_EXCEPTION_HANDLED:
	case DBG_EXCEPTION_NOT_HANDLED:
	case DBG_TERMINATE_THREAD:
	case DBG_TERMINATE_PROCESS:
	case DBG_CONTINUE:
		break;
	default:
		return STATUS_INVALID_PARAMETER;
	}

	Status = ObReferenceObjectByHandle(DebugObjectHandle,
		DEBUG_READ_EVENT,
		g_HotGeDebugObject,
		PreviousMode,
		&DebugObject,
		NULL);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	GotEvent = FALSE;
	FoundDebugEvent = NULL;

	ExAcquireFastMutex(&DebugObject->Mutex);

	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		Entry = Entry->Flink) {

		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);

		//
		// Make sure the client ID matches and that the debugger saw all the events.
		// We don't allow the caller to start a thread that it never saw a message for.
		//
		if (DebugEvent->ClientId.UniqueProcess == Clid.UniqueProcess) {
			if (!GotEvent) {
				if (DebugEvent->ClientId.UniqueThread == Clid.UniqueThread &&
					(DebugEvent->Flags&DEBUG_EVENT_READ) != 0) {
					RemoveEntryList(Entry);
					FoundDebugEvent = DebugEvent;
					GotEvent = TRUE;
				}
			}
			else {
				
				DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
				KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
				break;
			}
		}
	}

	ExReleaseFastMutex(&DebugObject->Mutex);


	ObDereferenceObject(DebugObject);

	if (GotEvent) {
		FoundDebugEvent->ApiMsg.ReturnedStatus = ContinueStatus;
		FoundDebugEvent->Status = STATUS_SUCCESS;
		DbgkpWakeTarget(FoundDebugEvent);
	}
	else {
		Status = STATUS_INVALID_PARAMETER;
	}

	return Status;
}