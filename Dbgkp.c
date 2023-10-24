#include "Dbgkp.h"
#include <intrin.h>
#include "comm\SystemExportFunc.h"
#include "Struct.h"
#include "Peb.h"
#include "Dbg.h"
#include "comm\DbgStruct.h"
#include "SearchFunc.h"
#include <ntimage.h>

#include "tools\Module.h"

FAST_MUTEX DbgkpProcessDebugPortMutex;
POBJECT_TYPE g_HotGeDebugObject;
LONG g_DbgkpMaxModuleMsgs;

PEPROCESS PsGetThreadToAPCProcess(PETHREAD thread)
{
	PETHREADWIN7 ethread = (PETHREADWIN7)thread;
	return ethread->Tcb.ApcState.Process;
}

PVOID PsGetThreadWin32Address(PETHREAD thread)
{
	PETHREADWIN7 ethread = (PETHREADWIN7)thread;
	return ethread->Win32StartAddress;
}

PVOID PsGetThreadStartAddress(PETHREAD thread)
{
	PETHREADWIN7 ethread = (PETHREADWIN7)thread;
	return ethread->StartAddress;
}

BOOLEAN IsThreadSystem(PETHREAD thread)
{
	PETHREADWIN7 ethread = (PETHREADWIN7)thread;
	return (ethread->Tcb.MiscFlags >> 0xD) & 1;
}

ULONG GetThreadApcIndex(PETHREAD thread)
{
	PETHREADWIN7 ethread = (PETHREADWIN7)thread;
	return ethread->Tcb.ApcStateIndex;
}

BOOLEAN IsThreadInserted(PETHREAD thread)
{
	PETHREADWIN7 ethread = (PETHREADWIN7)thread;
	return (ethread->CrossThreadFlags >> 1) & 1;
}

BOOLEAN IsThreadSkipCreationMsg(PETHREAD thread)
{
	PETHREADWIN7 ethread = (PETHREADWIN7)thread;
	return (ethread->CrossThreadFlags >> 7) & 1;
}

BOOLEAN IsThreadHideFromDebugger(PETHREAD thread)
{
	PETHREADWIN7 ethread = (PETHREADWIN7)thread;
	return (ethread->CrossThreadFlags >> 2) & 1;
}

BOOLEAN IsThreadSkipTerminationMsg(PETHREAD thread)
{
	PETHREADWIN7 ethread = (PETHREADWIN7)thread;
	return (ethread->CrossThreadFlags >> 8) & 1;
}

CLIENT_ID GetThreadClientId(PETHREAD thread)
{
	PETHREADWIN7 ethread = (PETHREADWIN7)thread;
	return ethread->Cid;
}

VOID SetThreadCrossThreadFlags(PETHREAD thread, ULONG f)
{
	PETHREADWIN7 ethread = (PETHREADWIN7)thread;
	ethread->CrossThreadFlags |= f;
}

ULONG SetProcessFlags(PEPROCESS Process,ULONG Flags)
{
	PEPROCESSWIN7 ProcessWin7 = (PEPROCESSWIN7)Process;
	ULONG flags = ProcessWin7->Flags;
	ProcessWin7->Flags |= Flags;
	return flags;
}





PULONG_PTR GetProcessExPush(PEPROCESS Process)
{
	PEPROCESSWIN7 ProcessWin7 = (PEPROCESSWIN7)Process;
	
	return (PULONG_PTR)&ProcessWin7->ProcessLock;
}

PVOID GetSectionObject(PEPROCESS Process)
{
	UNICODE_STRING uni = { 0 };

	RtlInitUnicodeString(&uni, L"PsGetProcessSectionBaseAddress");
	PUCHAR p = (PUCHAR)MmGetSystemRoutineAddress(&uni);
	ULONG offset = *(PULONG)(p + 3);
	if (offset)
	{
		offset -= 8;
	}
	return (PVOID)*(PULONG64)((ULONG64)Process + offset);
}

PVOID GeExceptionPort(PEPROCESS Process)
{
	UNICODE_STRING uni = { 0 };

	RtlInitUnicodeString(&uni, L"PsGetProcessDebugPort");
	PUCHAR p = (PUCHAR)MmGetSystemRoutineAddress(&uni);
	ULONG offset = *(PULONG)(p + 3);
	if (offset)
	{
		offset += 8;
	}
	ULONG64 value = *(PULONG64)((ULONG64)Process + offset);
	return (PVOID)value;
}



//定义内联函数
BOOLEAN EntryAcquireRundownProtectionByProcess(PEPROCESS eprocess)
{
	
	PEPROCESSWIN7 eprocessWin7 = (PEPROCESSWIN7)(eprocess);
	/*
	_m_prefetchw(&eprocessWin7->RundownProtect);

	ULONG64 value = (eprocessWin7->RundownProtect.Count & (~1I64));

	if (InterlockedCompareExchange64(&eprocessWin7->RundownProtect, value + 2, value) == value)
	{
		return TRUE;
	}

	if (ExAcquireRundownProtection(&eprocessWin7->RundownProtect)) return TRUE;
	*/
	return ExAcquireRundownProtection(&eprocessWin7->RundownProtect);

}

VOID ExitReleaseRundownProtectionByProcess(PEPROCESS eprocess)
{

	PEPROCESSWIN7 eprocessWin7 = (PEPROCESSWIN7)(eprocess);
	/*
	_m_prefetchw(&eprocessWin7->RundownProtect);

	ULONG64 value = (eprocessWin7->RundownProtect.Count & (~1I64));
	if (InterlockedCompareExchange64(&eprocessWin7->RundownProtect, value - 2, value) == value)
	{
		return;
	}
	*/
	ExReleaseRundownProtection(&eprocessWin7->RundownProtect);
}

FORCEINLINE BOOLEAN EntryAcquireRundownProtectionByThread(PETHREAD thread)
{

	PETHREADWIN7 threadWin7 = (PETHREADWIN7)(thread);
	return ExAcquireRundownProtection(&threadWin7->RundownProtect);

}

FORCEINLINE VOID ExitReleaseRundownProtectionByThread(PETHREAD thread)
{
	PETHREADWIN7 threadWin7 = (PETHREADWIN7)(thread);
	ExReleaseRundownProtection(&threadWin7->RundownProtect);
}




ULONG GetProcessExitTimeOffset()
{
	static ULONG offset = 0;
	if (offset) return offset;

	wchar_t wa_PsGetProcessExitTime[] = { 0xE3B3, 0xE390, 0xE3A4, 0xE386, 0xE397, 0xE3B3, 0xE391, 0xE38C, 0xE380, 0xE386, 0xE390, 0xE390, 0xE3A6, 0xE39B, 0xE38A, 0xE397, 0xE3B7, 0xE38A, 0xE38E, 0xE386, 0xE3E3, 0xE3E3 };

	for (int i = 0; i < 22; i++)
	{
		wa_PsGetProcessExitTime[i] ^= 0x6D6D;
		wa_PsGetProcessExitTime[i] ^= 0x8E8E;
	};

	UNICODE_STRING unFuncNamePsGetProcessExitTime = { 0 };
	RtlInitUnicodeString(&unFuncNamePsGetProcessExitTime, wa_PsGetProcessExitTime);
	PUCHAR funcPsGetProcessExitTime = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNamePsGetProcessExitTime);

	for (int i = 0; i < 100; i++)
	{
		if (funcPsGetProcessExitTime[i] == 0xc3 && (funcPsGetProcessExitTime[i + 1] == 0xcc || funcPsGetProcessExitTime[i + 1] == 0x90))
		{
			offset = *(PULONG)(funcPsGetProcessExitTime + i - 4);
			break;
		}
	}
	
	return offset;
}

PDEBUG_OBJECT HotGePsGetProcessDebugPort(PEPROCESS Process)
{
	//PEPROCESSWIN7 pro = Process;
	//return pro->DebugPort;

	ULONG offset = GetProcessExitTimeOffset();

	PDEBUG_OBJECT debug = (PDEBUG_OBJECT)*(PULONG64)((PUCHAR)Process + offset);

	return debug;
}

VOID HotGePsSetProcessDebugPort(PEPROCESS Process,PDEBUG_OBJECT debugObject)
{
	
	ULONG offset = GetProcessExitTimeOffset();

	*(PULONG64)((PUCHAR)Process + offset) = debugObject;

}


NTSTATUS DbgkClearProcessDebugObject(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT SourceDebugObject
)
{
	NTSTATUS status = STATUS_SUCCESS;
	LIST_ENTRY TempList = {0};
	PDEBUG_EVENT Entry = NULL;

	ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);
	
	PDEBUG_OBJECT targerDebugObject = HotGePsGetProcessDebugPort(Process);
	if (!targerDebugObject || (SourceDebugObject && SourceDebugObject != targerDebugObject))
	{
		status = STATUS_PORT_NOT_SET;
		targerDebugObject = NULL;
	}
	else 
	{
		HotGePsSetProcessDebugPort(Process,NULL);
		status = STATUS_SUCCESS;
	}

	
	ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);

	if (NT_SUCCESS(status))
	{
		//DbgkpMarkProcessPeb(Process);
	}
		
	if (!targerDebugObject) return status;

	InitializeListHead(&TempList);

	ExAcquireFastMutex(&targerDebugObject->Mutex);
	

	PLIST_ENTRY list = targerDebugObject->EventList.Flink;
	while (list != &targerDebugObject->EventList)
	{
		Entry = (PDEBUG_EVENT)list;
		list = list->Flink;

		if (Entry->Process == Process) {
			RemoveEntryList(&Entry->EventList);
			InsertTailList(&TempList, &Entry->EventList);
		}
	}

	ExReleaseFastMutex(&targerDebugObject->Mutex);
	ObfDereferenceObject(targerDebugObject);

	while (!IsListEmpty(&TempList)) {
		PLIST_ENTRY Entry1 = RemoveHeadList(&TempList);
		PDEBUG_EVENT DebugEvent = CONTAINING_RECORD(Entry1, DEBUG_EVENT, EventList);
		DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
		DbgkpWakeTarget(DebugEvent);
	}


	return status;
}

VOID DbgkpMarkProcessPeb(PEPROCESS Process)
{
	
	if (!EntryAcquireRundownProtectionByProcess(Process))
	{
		return;
	}
	
	KAPC_STATE kapc = {0};
	
	PEPROCESSWIN7 ProcessWin7 = (PEPROCESSWIN7)Process;
	PMPEB peb = (PMPEB)ProcessWin7->Peb;
	
	if (peb)
	{
		KeStackAttachProcess(Process, &kapc);
		ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);
		peb->BeingDebugged = HotGePsGetProcessDebugPort(Process) != NULL;
		if (PsGetProcessWow64Process(Process))
		{
			PsGetProcessWow64Process(Process)->BeingDebugged = peb->BeingDebugged;
		}
		ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
	
	
	
		KeUnstackDetachProcess(&kapc);
	}
	
	ExitReleaseRundownProtectionByProcess(Process);



}

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(unsigned __int64 *)(name)
#define DEREF_32( name )*(unsigned long *)(name)
#define DEREF_16( name )*(unsigned short *)(name)
#define DEREF_8( name )*(UCHAR *)(name)
ULONG_PTR GetProcAddressR(ULONG_PTR hModule, const char* lpProcName, BOOLEAN x64Module)
{
	UINT_PTR uiLibraryAddress = 0;
	ULONG_PTR fpResult = NULL;

	if (hModule == NULL)
		return NULL;

	// a module handle is really its base address
	uiLibraryAddress = (UINT_PTR)hModule;

	__try
	{
		UINT_PTR uiAddressArray = 0;
		UINT_PTR uiNameArray = 0;
		UINT_PTR uiNameOrdinals = 0;
		PIMAGE_NT_HEADERS32 pNtHeaders32 = NULL;
		PIMAGE_NT_HEADERS64 pNtHeaders64 = NULL;
		PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

		// get the VA of the modules NT Header
		pNtHeaders32 = (PIMAGE_NT_HEADERS32)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
		pNtHeaders64 = (PIMAGE_NT_HEADERS64)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
		if (x64Module)
		{
			pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		}
		else
		{
			pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		}


		// get the VA of the export directory
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

		// get the VA for the array of addresses
		uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

		// get the VA for the array of name pointers
		uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

		// get the VA for the array of name ordinals
		uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

		// test if we are importing by name or by ordinal...
		if ((PtrToUlong(lpProcName) & 0xFFFF0000) == 0x00000000)
		{
			// import by ordinal...

			// use the import ordinal (- export ordinal base) as an index into the array of addresses
			uiAddressArray += ((IMAGE_ORDINAL(PtrToUlong(lpProcName)) - pExportDirectory->Base) * sizeof(unsigned long));

			// resolve the address for this imported function
			fpResult = (ULONG_PTR)(uiLibraryAddress + DEREF_32(uiAddressArray));
		}
		else
		{
			// import by name...
			unsigned long dwCounter = pExportDirectory->NumberOfNames;
			while (dwCounter--)
			{
				char * cpExportedFunctionName = (char *)(uiLibraryAddress + DEREF_32(uiNameArray));

				// test if we have a match...
				if (strcmp(cpExportedFunctionName, lpProcName) == 0)
				{
					// use the functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(unsigned long));

					// calculate the virtual address for the function
					fpResult = (ULONG_PTR)(uiLibraryAddress + DEREF_32(uiAddressArray));

					// finish...
					break;
				}

				// get the next exported function name
				uiNameArray += sizeof(unsigned long);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(unsigned short);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		fpResult = NULL;
	}

	return fpResult;
}


static NTSTATUS NTAPI ZwProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
)
{

	typedef NTSTATUS(NTAPI *ZwProtectVirtualMemoryProc)(
		__in HANDLE ProcessHandle,
		__inout PVOID *BaseAddress,
		__inout PSIZE_T RegionSize,
		__in ULONG NewProtect,
		__out PULONG OldProtect
		);

	static ZwProtectVirtualMemoryProc ZwProtectVirtualMemoryFunc = NULL;
	if (!ZwProtectVirtualMemoryFunc)
	{
		UNICODE_STRING uNname = { 0 };
		RtlInitUnicodeString(&uNname, L"ZwIsProcessInJob");
		PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&uNname);

		if (func)
		{
			func += 20;
			for (int i = 0; i < 0x100; i++)
			{
				if (func[i] == 0x48 && func[i + 1] == 0x8b && func[i + 2] == 0xc4)
				{
					ZwProtectVirtualMemoryFunc = (ZwProtectVirtualMemoryProc)(func + i);
					break;
				}
			}
		}


	}

	if (ZwProtectVirtualMemoryFunc)
	{
		return ZwProtectVirtualMemoryFunc(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
	}

	return STATUS_NOT_IMPLEMENTED;
}

VOID DbgkpHandlerFirstInt3()
{
	ULONG64 module = GetModuleR3(PsGetCurrentProcessId(), "ntdll.dll", NULL);

	PPEB32 peb32 = (PPEB32)PsGetProcessWow64Process(IoGetCurrentProcess());

	if (peb32)
	{
		//ULONG64 DbgUiRemoteBreakin = GetProcAddressR(module, "DbgUiRemoteBreakin", FALSE);
		ULONG64 DbgBreakPoint1 = GetProcAddressR(module, "DbgBreakPoint", FALSE);
		ULONG64 DbgUiIssueRemoteBreakin  = GetProcAddressR(module, "DbgUiIssueRemoteBreakin", FALSE);

		ULONG64 temp = DbgUiIssueRemoteBreakin;
		SIZE_T tempSize = 0x200;
		ULONG pro = 0;
		//
		NTSTATUS st = ZwProtectVirtualMemory(NtCurrentProcess(), &temp, &tempSize, PAGE_EXECUTE_READWRITE, &pro);

		if (NT_SUCCESS(st))
		{
			PUCHAR tempC = DbgUiIssueRemoteBreakin;
			for (int i = 0; i < 100; i++)
			{
				if (tempC[i] == 0x68)
				{
					*(PULONG)&tempC[i + 1] = DbgBreakPoint1;
					DbgPrintEx(77, 0, "[db]:x86 replace flish\r\n");
					break;
				}
			}


			ZwProtectVirtualMemory(NtCurrentProcess(), &temp, &tempSize, pro, &pro);
		}

	}
	else 
	{
		ULONG64 DbgBreakPoint1 = GetProcAddressR(module, "DbgBreakPoint", TRUE);
		ULONG64 DbgUiIssueRemoteBreakin = GetProcAddressR(module, "DbgUiIssueRemoteBreakin", TRUE);

		ULONG64 temp = DbgUiIssueRemoteBreakin;
		SIZE_T tempSize = 0x200;
		ULONG pro = 0;
		//
		NTSTATUS st = ZwProtectVirtualMemory(NtCurrentProcess(), &temp, &tempSize, PAGE_EXECUTE_READWRITE, &pro);

		if (NT_SUCCESS(st))
		{
			PUCHAR tempC = DbgUiIssueRemoteBreakin;
			for (int i = 0; i < 100; i++)
			{
				if (tempC[i] == 0x48 && tempC[i + 1] == 0x8d && tempC[i + 2] == 0x5)
				{
					ULONG64 next = (ULONG64)(tempC + i + 7);
					ULONG64 offset = DbgBreakPoint1 - next;
					*(PLONG)&tempC[i + 3] = offset;
					DbgPrintEx(77, 0, "[db]:replace flish\r\n");
					break;
				}
			}


			ZwProtectVirtualMemory(NtCurrentProcess(), &temp, &tempSize, pro, &pro);
		}

	}

	


}



VOID DbgkpFreeDebugEvent(IN PDEBUG_EVENT DebugEvent)
{
	NTSTATUS Status;

	switch (DebugEvent->ApiMsg.ApiNumber) {
	case DbgKmCreateProcessApi:
		if (DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle != NULL) {
			Status = ObCloseHandle(DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
		}
		break;

	case DbgKmLoadDllApi:
		if (DebugEvent->ApiMsg.u.LoadDll.FileHandle != NULL) {
			Status = ObCloseHandle(DebugEvent->ApiMsg.u.LoadDll.FileHandle, KernelMode);
		}
		break;

	}

	ObDereferenceObject(DebugEvent->Process);
	ObDereferenceObject(DebugEvent->Thread);
	ExFreePool(DebugEvent);
}

VOID DbgkpWakeTarget(IN PDEBUG_EVENT DebugEvent)
{
	PETHREADWIN7 Thread = (PETHREADWIN7)DebugEvent->Thread;

	if ((DebugEvent->Flags&DEBUG_EVENT_SUSPEND) != 0) {
		PsResumeThread(DebugEvent->Thread, NULL);
	}

	if (DebugEvent->Flags & DEBUG_EVENT_RELEASE) {
		ExReleaseRundownProtection(&Thread->RundownProtect);
	}

	if ((DebugEvent->Flags&DEBUG_EVENT_NOWAIT) == 0) {
		KeSetEvent(&DebugEvent->ContinueEvent, 0, FALSE); // Wake up waiting process
	}
	else {
		DbgkpFreeDebugEvent(DebugEvent);
	}

}


NTSTATUS DbgkpPostModuleMessages(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN PDEBUG_OBJECT DebugObject)
{
	PMPEB peb = (PMPEB)PsGetProcessPeb(Process);
	DBGKM_APIMSG apiMsg;
	NTSTATUS status = STATUS_UNSUCCESSFUL;


	PLDR_DATA_TABLE_ENTRY list =(PLDR_DATA_TABLE_ENTRY)&peb->Ldr->InLoadOrderModuleList;
	if ((ULONG64)list >= MmUserProbeAddress)
	{
		return STATUS_UNSUCCESSFUL;
	}
	PLDR_DATA_TABLE_ENTRY listEntry = list;
	PLDR_DATA_TABLE_ENTRY listNext= (PLDR_DATA_TABLE_ENTRY)list->InLoadOrderLinks.Flink;
	ULONG count = 0;

	while (listEntry != listNext && count < g_DbgkpMaxModuleMsgs)
	{
		if (count > 1)
		{
			memset(&apiMsg, 0, sizeof(apiMsg));
			apiMsg.ApiNumber = DbgKmLoadDllApi;
			apiMsg.u.LoadDll.BaseOfDll = listNext->DllBase;
			PIMAGE_NT_HEADERS pNts =  RtlImageNtHeader(apiMsg.u.LoadDll.BaseOfDll);
			if (pNts)
			{
				apiMsg.u.LoadDll.DebugInfoFileOffset = pNts->FileHeader.PointerToSymbolTable;
				apiMsg.u.LoadDll.DebugInfoSize = pNts->FileHeader.NumberOfSymbols;
				
			}

			UNICODE_STRING unName = {0};
			status = MmGetFileNameForAddress(apiMsg.u.LoadDll.BaseOfDll, &unName);
			if (NT_SUCCESS(status))
			{
				OBJECT_ATTRIBUTES ObjectAttributes;
				InitializeObjectAttributes(&ObjectAttributes, &unName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_FORCE_ACCESS_CHECK, NULL, NULL);
				IO_STATUS_BLOCK IoStatusBlock = {0};
				status = ZwOpenFile(&apiMsg.u.LoadDll.FileHandle, GENERIC_READ | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_VALID_FLAGS, FILE_SYNCHRONOUS_IO_NONALERT);
				if (!NT_SUCCESS(status)) {
					apiMsg.u.LoadDll.FileHandle = NULL;
				}

				ExFreePoolWithTag(unName.Buffer, 0);
			}

			if (DebugObject)
			{
				status = DbgkpQueueMessage(Process, Thread, &apiMsg, DEBUG_EVENT_NOWAIT, DebugObject);
			}
			else
			{
				DbgkpSendApiMessage(DEBUG_EVENT_NOWAIT | DEBUG_READ_EVENT, &apiMsg);
				status = STATUS_UNSUCCESSFUL;
			}

			if (!NT_SUCCESS(status) && apiMsg.u.LoadDll.FileHandle)
			{
				ObCloseHandle(apiMsg.u.LoadDll.FileHandle, KernelMode);
				apiMsg.u.LoadDll.FileHandle = NULL;
			}
		}

		
		listNext = (PLDR_DATA_TABLE_ENTRY)listNext->InLoadOrderLinks.Flink;
		count++;
	}

	//在判断是不是wow64进程
	PPEB32 peb32 = PsGetProcessWow64Process(Process);
	if (!peb32) return STATUS_SUCCESS;

	PEB_LDR_DATA32 * ldr32 = (PEB_LDR_DATA32 *)ULongToPtr(peb32->Ldr);
	LDR_DATA_TABLE_ENTRY32 *list32 = (LDR_DATA_TABLE_ENTRY32 *)&ldr32->InLoadOrderModuleList;
	LDR_DATA_TABLE_ENTRY32 *list32Next = (LDR_DATA_TABLE_ENTRY32 *)list32->InLoadOrderLinks.Flink;
	
	count = 0;
	while (list32Next != list32 && count < g_DbgkpMaxModuleMsgs)
	{
		if (count > 1)
		{
			memset(&apiMsg, 0, sizeof(apiMsg));
			apiMsg.ApiNumber = DbgKmLoadDllApi;
			apiMsg.u.LoadDll.BaseOfDll = (PVOID)list32Next->DllBase;
			PIMAGE_NT_HEADERS pNts = RtlImageNtHeader(apiMsg.u.LoadDll.BaseOfDll);
			if (pNts)
			{
				apiMsg.u.LoadDll.DebugInfoFileOffset = pNts->FileHeader.PointerToSymbolTable;
				apiMsg.u.LoadDll.DebugInfoSize = pNts->FileHeader.NumberOfSymbols;

			}

			UNICODE_STRING unName = { 0 };
			status = MmGetFileNameForAddress(apiMsg.u.LoadDll.BaseOfDll, &unName);
			if (NT_SUCCESS(status))
			{
				PWCHAR findStr = wcsstr(unName.Buffer, L"\\SYSTEM32\\");
				if (findStr)
				{
					wcscpy(findStr + 1, L"SysWOW64");
				}
				OBJECT_ATTRIBUTES ObjectAttributes;
				InitializeObjectAttributes(&ObjectAttributes, &unName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_FORCE_ACCESS_CHECK, NULL, NULL);
				IO_STATUS_BLOCK IoStatusBlock = { 0 };
				status = ZwOpenFile(&apiMsg.u.LoadDll.FileHandle, GENERIC_READ | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_VALID_FLAGS, FILE_SYNCHRONOUS_IO_NONALERT);
				if (!NT_SUCCESS(status)) {
					apiMsg.u.LoadDll.FileHandle = NULL;
				}

				ExFreePoolWithTag(unName.Buffer, 0);
			}

			if (DebugObject)
			{
				status = DbgkpQueueMessage(Process, Thread, &apiMsg, DEBUG_EVENT_NOWAIT, DebugObject);
			}
			else
			{
				DbgkpSendApiMessage(DEBUG_EVENT_NOWAIT | DEBUG_READ_EVENT, &apiMsg);
				status = STATUS_UNSUCCESSFUL;
			}

			if (!NT_SUCCESS(status) && apiMsg.u.LoadDll.FileHandle)
			{
				ObCloseHandle(apiMsg.u.LoadDll.FileHandle, KernelMode);
				apiMsg.u.LoadDll.FileHandle = NULL;
			}
		}

		count++;
		list32Next = (LDR_DATA_TABLE_ENTRY32 *)list32Next->InLoadOrderLinks.Flink;
	}


	return count;
}

NTSTATUS DbgkpQueueMessage(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject
)
{
	//DbgBreakPoint();
	PDEBUG_OBJECT pDebugObject = NULL;
	PDEBUG_EVENT pDebugEvent = { 0 };
	DEBUG_EVENT mDebugEvent = {0};
	BOOLEAN isThreadSkipCreationMsg = FALSE;
	ULONG mFlags = Flags;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	//PDBGKM_APIMSG SaveApiMsg = NULL;

	if (mFlags & DEBUG_EVENT_NOWAIT)
	{
		pDebugEvent = (PDEBUG_EVENT)ExAllocatePoolWithQuotaTag(POOL_QUOTA_FAIL_INSTEAD_OF_RAISE, sizeof(DEBUG_EVENT), 'EgbD');
		if (!pDebugEvent) return STATUS_INSUFFICIENT_RESOURCES;

		pDebugEvent->Flags = mFlags | DEBUG_EVENT_INACTIVE;

		ObReferenceObject(Process);
		ObReferenceObject(Thread);
		pDebugObject = TargetDebugObject;
		pDebugEvent->BackoutThread = KeGetCurrentThread();
	}
	else 
	{
		pDebugEvent = &mDebugEvent;
		mDebugEvent.Flags = mFlags;
		ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);
		DBGKM_APINUMBER apiNumber = ApiMsg->ApiNumber;
		pDebugObject = HotGePsGetProcessDebugPort(Process);

		if ((apiNumber == DbgKmCreateThreadApi || apiNumber == DbgKmCreateProcessApi))
		{
			isThreadSkipCreationMsg = IsThreadSkipCreationMsg(Thread);
			if (isThreadSkipCreationMsg)
			{
				pDebugObject = NULL;
			}
		}

		if ((apiNumber == DbgKmLoadDllApi) && IsThreadSkipCreationMsg(Thread) && (mFlags & 0x40))
		{
			pDebugObject = NULL;
		}

		if ((apiNumber == DbgKmExitThreadApi || apiNumber == DbgKmExitProcessApi) && IsThreadSkipTerminationMsg(Thread))
		{
			pDebugObject = NULL;
		}

		KeInitializeEvent(&mDebugEvent.ContinueEvent, SynchronizationEvent, 0);
	}

	//SaveApiMsg = &pDebugEvent->ApiMsg;
	pDebugEvent->Process = Process;
	pDebugEvent->Thread = Thread;
	memcpy(&pDebugEvent->ApiMsg, ApiMsg, sizeof(DBGKM_APIMSG));
	pDebugEvent->ClientId = GetThreadClientId(Thread);
	//pDebugEvent->ClientId.UniqueProcess = PsGetProcessId(Process);
	//pDebugEvent->ClientId.UniqueThread = PsGetThreadId(Thread);
	if (pDebugObject)
	{
		ExAcquireFastMutex(&pDebugObject->Mutex);
		if (pDebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING)
		{
			status = STATUS_DEBUGGER_INACTIVE;
		}
		else 
		{
			InsertTailList(&pDebugObject->EventList, &pDebugEvent->EventList);
			if ((mFlags & DEBUG_EVENT_NOWAIT) == 0)
			{
				KeSetEvent(&pDebugObject->EventsPresent, 0, 0);
			}

			status = STATUS_SUCCESS;
		}

		ExReleaseFastMutex(&pDebugObject->Mutex);
		//SaveApiMsg = &pDebugEvent->ApiMsg;
	}
	else
	{
		status = STATUS_PORT_NOT_SET;
	}

	if ((mFlags & DEBUG_EVENT_NOWAIT))
	{
		if (!NT_SUCCESS(status))
		{
			ObDereferenceObject(Process);
			ObDereferenceObject(Thread);
			ExFreePoolWithTag(pDebugEvent, 0);
		}
	}
	else 
	{
		ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
		if (NT_SUCCESS(status))
		{
			KeWaitForSingleObject(&pDebugEvent->ContinueEvent, Executive, KernelMode, FALSE,NULL);
			status = pDebugEvent->Status;
			RtlCopyMemory(ApiMsg, &pDebugEvent->ApiMsg, sizeof(DBGKM_APIMSG));
		}
	}

	return status;
}

NTSTATUS DbgkpPostFakeThreadMessages(
	PEPROCESS Process,
	PDEBUG_OBJECT DebugObject,
	PETHREAD	StartThread,
	PETHREAD* pFirstThread,
	PETHREAD* pLastThread)
{

	NTSTATUS status;
	PETHREAD Thread, FirstThread, LastThread, CurrentThread;
	DBGKM_APIMSG ApiMsg;
	BOOLEAN First = TRUE;
	BOOLEAN IsFirstThread;
	PIMAGE_NT_HEADERS NtHeaders;
	ULONG Flags;
	KAPC_STATE ApcState;

	status = STATUS_UNSUCCESSFUL;

	LastThread = FirstThread = NULL;

	CurrentThread = (PETHREAD)PsGetCurrentThread();

	if (StartThread == 0)
	{
		StartThread = (PETHREAD)PsGetNextProcessThread((PEPROCESS)Process, 0);
		First = TRUE;
	}
	else {
		First = FALSE;
		FirstThread = StartThread;
		ObReferenceObject(StartThread);
	}

	for (Thread = StartThread;
		Thread != NULL;
		Thread = (PETHREAD)PsGetNextProcessThread((PEPROCESS)Process, (PETHREAD)Thread))
	{

		Flags = DEBUG_EVENT_NOWAIT;

		if (LastThread != 0)
		{
			ObDereferenceObject(LastThread);
		}

		LastThread = Thread;
		ObReferenceObject(LastThread);
		if (IsThreadSystem(Thread))
		{
			continue;
		}


		if (!IsThreadInserted(Thread))//这里要注意下位操作
		{
			//这个涉及的内容也比较多，而且一般也不会进入这里，所以为了简单注释掉好了
			PsSynchronizeWithThreadInsertion(Thread,CurrentThread);
			if (!IsThreadInserted(Thread))
			{
				continue;
			}
		}
		
		if (EntryAcquireRundownProtectionByThread(Thread))
		{
			Flags |= DEBUG_EVENT_RELEASE;
			status = PsSuspendThread((PETHREAD)Thread, 0);
			if (NT_SUCCESS(status))
			{
				Flags |= DEBUG_EVENT_SUSPEND;
			}
		}
		else {
			Flags |= DEBUG_EVENT_PROTECT_FAILED;
		}

		//每次构造一个DBGKM_APIMSG结构
		memset(&ApiMsg, 0, sizeof(DBGKM_APIMSG));

		if (First && (Flags & DEBUG_EVENT_PROTECT_FAILED) == 0)
		{
			//进程的第一个线程才会到这里
			IsFirstThread = TRUE;
			ApiMsg.ApiNumber = DbgKmCreateProcessApi;
			PVOID pSection = GetSectionObject(Process);
			if (pSection)
			{
				ApiMsg.u.CreateProcessInfo.FileHandle = DbgkpProcessToFileHandle(Process);
			}
			else {
				ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
			}
			ApiMsg.u.CreateProcessInfo.BaseOfImage = PsGetProcessSectionBaseAddress(Process);

			KeStackAttachProcess((PRKPROCESS)Process, &ApcState);

			__try {
				NtHeaders = RtlImageNtHeader(ApiMsg.u.CreateProcessInfo.BaseOfImage);
				if (NtHeaders)
				{
					ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL;
					ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg.u.CreateProcessInfo.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
			}_except(EXCEPTION_EXECUTE_HANDLER) {
				ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL;
				ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = 0;
				ApiMsg.u.CreateProcessInfo.DebugInfoSize = 0;
			}

			KeUnstackDetachProcess(&ApcState);
		}
		else {
			IsFirstThread = FALSE;
			ApiMsg.ApiNumber = DbgKmCreateThreadApi;
			ApiMsg.u.CreateThread.StartAddress = PsGetThreadStartAddress(Thread);//注意偏移
		}

		status = DbgkpQueueMessage(
			Process,
			Thread,
			&ApiMsg,
			Flags,
			DebugObject);

		if (!NT_SUCCESS(status))
		{
			if (Flags & DEBUG_EVENT_SUSPEND)
			{
				PsResumeThread((PETHREAD)Thread,NULL);
			}

			if (Flags & DEBUG_EVENT_RELEASE)
			{
				ExitReleaseRundownProtectionByThread(Thread);
				
			}

			if (ApiMsg.ApiNumber == DbgKmCreateProcessApi && ApiMsg.u.CreateProcessInfo.FileHandle != NULL)
			{
				ObCloseHandle(ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
			}

			ObDereferenceObject(Thread);
			break;

		}
		else if (IsFirstThread) {
			First = FALSE;
			ObReferenceObject(Thread);
			FirstThread = Thread;

			DbgkSendSystemDllMessages(Thread, DebugObject, &ApiMsg);
		}
	}

	if (!NT_SUCCESS(status)) {
		if (FirstThread)
		{
			ObDereferenceObject(FirstThread);
		}
		if (LastThread != NULL)
		{
			ObDereferenceObject(LastThread);
		}
	}
	else {
		if (FirstThread) {
			*pFirstThread = FirstThread;
			*pLastThread = LastThread;
		}
		else {

			if (LastThread != NULL)
			{
				ObDereferenceObject(LastThread);
			}
			status = STATUS_UNSUCCESSFUL;
		}
	}
	return status;
}



VOID  DbgkSendSystemDllMessages(IN PETHREAD thread, IN PDEBUG_OBJECT TargetDebugObject, DBGKM_APIMSG * apiMsg)
{
	PEPROCESS eprocess = NULL;
	BOOLEAN isAttach = 0;
	KAPC_STATE kApcState = {0};
	PTEB teb = NULL;

	if (thread)
	{
		
		 eprocess = PsGetThreadToAPCProcess(thread);
	}
	else 
	{
		eprocess = PsGetCurrentProcess();
	}



	PSYSTEM_DLL_ENTRY dllEntry = NULL;
	for (int i = 0; i < 2; i++)
	{
		dllEntry = PsQuerySystemDllInfo(i);

		if (dllEntry && (i != 1 || PsGetProcessWow64Process(eprocess)))
		{
			//这个地方可能有问题
			memset(&apiMsg->u.LoadDll, 0, sizeof(DBGKM_LOAD_DLL));
			PVOID ImageBase = dllEntry->ImageBase;
			apiMsg->u.LoadDll.BaseOfDll = ImageBase;
			if (thread && i)
			{
				isAttach = TRUE;
				KeStackAttachProcess(eprocess, &kApcState);
			}
			else 
			{
				isAttach = FALSE;
			}

			PIMAGE_NT_HEADERS pNt = RtlImageNtHeader(ImageBase);
			if (pNt)
			{
				apiMsg->u.LoadDll.DebugInfoFileOffset = pNt->FileHeader.PointerToSymbolTable;
				apiMsg->u.LoadDll.DebugInfoSize = pNt->FileHeader.NumberOfSymbols;
			}
			
			if (thread)
			{
				teb = NULL;
			}
			else 
			{
				PETHREAD CurThread = PsGetCurrentThread();
				if (IsThreadSystem(CurThread) || GetThreadApcIndex(CurThread) == 1)
				{
					teb = NULL;
				}
				else 
				{
					teb = ((PETHREADWIN7)CurThread)->Tcb.Teb;
				}

				if (teb)
				{
					RtlMoveMemory(teb->StaticUnicodeBuffer, dllEntry->StaticUnicodeBuffer, 0x20A);
					teb->NtTib.ArbitraryUserPointer = teb->StaticUnicodeBuffer;
					apiMsg->u.LoadDll.NamePointer = teb->NtTib.ArbitraryUserPointer;

				}
			}

			if (isAttach)
			{
				KeUnstackDetachProcess(&kApcState);
			}

			OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
			IO_STATUS_BLOCK IoStatusBlock = {0};
			InitializeObjectAttributes(&ObjectAttributes,NULL, OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,NULL,NULL);
			
			NTSTATUS status = ZwOpenFile((PHANDLE)&apiMsg->u.LoadDll.FileHandle, GENERIC_READ | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_VALID_FLAGS, FILE_SYNCHRONOUS_IO_NONALERT);
			if (!NT_SUCCESS(status))
			{
				apiMsg->u.LoadDll.FileHandle = NULL;
			}

			apiMsg->h.u1.Length = 0x500028;
			apiMsg->h.u2.ZeroInit = 8;
			apiMsg->ApiNumber = DbgKmLoadDllApi;
			if (thread)
			{
				status = DbgkpQueueMessage(eprocess, thread, apiMsg, DEBUG_EVENT_NOWAIT, TargetDebugObject);
				if (!NT_SUCCESS(status) && apiMsg->u.LoadDll.FileHandle)
				{
					ObCloseHandle(apiMsg->u.LoadDll.FileHandle, 0i64);
				}
			}
			else 
			{
				DbgkpSendApiMessage(DEBUG_EVENT_NOWAIT | DEBUG_EVENT_READ, apiMsg);
				if (apiMsg->u.LoadDll.FileHandle)
					ObCloseHandle(apiMsg->u.LoadDll.FileHandle, 0i64);
				if (teb)
					teb->NtTib.ArbitraryUserPointer = NULL;
			}
		}
	}

	return ;
}

BOOLEAN DbgkpSuspendProcess(VOID)
{
	PEPROCESSWIN7 eprocess = (PEPROCESSWIN7) PsGetCurrentProcess();
	if (eprocess->Flags & 8) //判断进程是否删除
	{
		return FALSE;
	}

	KeFreezeAllThreads();

	return TRUE;
}

NTSTATUS DbgkpSendApiMessage(
	ULONG Flags,
	PDBGKM_APIMSG apiMsg
)
{
	BOOLEAN isSuspend = FALSE;
	if (Flags & 1)
	{
		isSuspend = DbgkpSuspendProcess();
	}

	apiMsg->ReturnedStatus = STATUS_PENDING;

	ULONG eventFlags = (Flags & DEBUG_EVENT_NOWAIT) << 5; //挂起
	NTSTATUS status = DbgkpQueueMessage(PsGetCurrentProcess(), PsGetCurrentThread(), apiMsg, eventFlags,NULL);
	ZwFlushInstructionCache(NtCurrentProcess(), NULL, 0);

	if (isSuspend)
	{
		KeThawAllThreads();
	}

	return status;
}

HANDLE DbgkpProcessToFileHandle(
	IN PVOID SectionObject
)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES Obja;
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE Handle;
	POBJECT_NAME_INFORMATION FileNameInfo;

	PAGED_CODE();

	Status = MmGetFileNameForProcess(SectionObject, &FileNameInfo);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}

	InitializeObjectAttributes(
		&Obja,
		&FileNameInfo->Name,
		OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);

	Status = ZwOpenFile(
		&Handle,
		(ACCESS_MASK)(GENERIC_READ | SYNCHRONIZE),
		&Obja,
		&IoStatusBlock,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SYNCHRONOUS_IO_NONALERT
	);
	ExFreePool(FileNameInfo);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}
	else {
		return Handle;
	}
}



NTSTATUS DbgkpSetProcessDebugObject(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PETHREAD LastThread)
{
	NTSTATUS Status;
	PETHREAD ThisThread;
	LIST_ENTRY TempList;
	PLIST_ENTRY Entry;
	PDEBUG_EVENT DebugEvent;
	BOOLEAN First;
	PETHREAD Thread;
	BOOLEAN GlobalHeld;
	PETHREAD FirstThread;

	PAGED_CODE();

	ThisThread = (PETHREAD)PsGetCurrentThread();

	//初始化链表，这个之后储存消息
	InitializeListHead(&TempList);

	First = TRUE;
	GlobalHeld = FALSE;

	if (!NT_SUCCESS(MsgStatus)) {
		LastThread = NULL;
		Status = MsgStatus;
	}
	else {
		Status = STATUS_SUCCESS;
	}


	if (NT_SUCCESS(Status)) {

		while (1) {

			GlobalHeld = TRUE;

			ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);

			//如果被调试进程的debugport已经设置，那么跳出循环
			
			if (HotGePsGetProcessDebugPort(Process)) {
				Status = STATUS_PORT_ALREADY_SET;
				break;
			}

			//没有设置debugport，在这里设置
			HotGePsSetProcessDebugPort(Process, DebugObject);

			//增加被调试进程最后一个线程的引用
			ObfReferenceObject(LastThread);

			//这里如果返回有值，说明在这之间还有线程被创建了，这里也要加入调试消息链表
			Thread = (PETHREAD)PsGetNextProcessThread((PEPROCESS)Process, (PETHREAD)LastThread);
			if (Thread != NULL) {

				HotGePsSetProcessDebugPort(Process, NULL);

				ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);

				GlobalHeld = FALSE;

				ObfDereferenceObject(LastThread);
				//通知线程创建消息
				Status = DbgkpPostFakeThreadMessages(
					Process,
					DebugObject,
					Thread,
					&FirstThread,
					&LastThread);
				if (!NT_SUCCESS(Status)) {
					LastThread = NULL;
					break;
				}
				ObfDereferenceObject(FirstThread);
			}
			else {
				break;
			}
		}
	}

	ExAcquireFastMutex(&DebugObject->Mutex);

	if (NT_SUCCESS(Status)) {
		//看看调试对象是否要求删除
		if ((DebugObject->Flags & DEBUG_EVENT_READ) == 0) {
			SetProcessFlags(Process, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT | PS_PROCESS_FLAGS_CREATE_REPORTED);
			//RtlInterlockedSetBitsDiscardReturn(&Process->Flags, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT | PS_PROCESS_FLAGS_CREATE_REPORTED);
			ObfReferenceObject(DebugObject);
		}
		else {
			HotGePsSetProcessDebugPort(Process, NULL);
			Status = STATUS_DEBUGGER_INACTIVE;
		}
	}

	//通过上面的操作，调试对象的消息链表装满了线程创建的消息(同时也包含模块加载的消息)
	//
	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		) {
		//取出调试事件
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		Entry = Entry->Flink;

		//看看调试事件是否急于处理，如果不是急于处理的，说明在DbgkpQueueMessage函数里面没有得到处理，
		//那么我们就在这里想办法处理吧(急于处理的已经在DbgkpQueueMessage函数中处理过了，所以这里无需担心)。
		//并且看看是否是本线程负责通知完成此消息
		if ((DebugEvent->Flags & 0x4) != 0 && DebugEvent->BackoutThread == (PETHREAD)ThisThread) {
			Thread = DebugEvent->Thread;

			if (NT_SUCCESS(Status)) {
				//这里判断之前对线程申请的停止保护是否失败
				if ((DebugEvent->Flags & DEBUG_EVENT_PROTECT_FAILED) != 0) {
					SetThreadCrossThreadFlags(Thread, PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG);
					//RtlInterlockedSetBitsDiscardReturn(&Thread->CrossThreadFlags,
					//	0x100);
					RemoveEntryList(&DebugEvent->EventList);
					InsertTailList(&TempList, &DebugEvent->EventList);
				}
				else {
					//这里极有可能是判断是否主线程的创建消息，是主线程的话完成消息
					if (First) {
						DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
						KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
						First = FALSE;
					}
					//到这里设置跳过线程创建消息
					DebugEvent->BackoutThread = NULL;
					SetThreadCrossThreadFlags(Thread, PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);
					//RtlInterlockedSetBitsDiscardReturn(&Thread->CrossThreadFlags,0x80);

				}
			}
			else {
				//很移除消息，并且加入临时链表中
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}
			//这里看看是够请求过线程停止保护，是的话释放请求
			if (DebugEvent->Flags & DEBUG_EVENT_RELEASE) {
				DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;
				ExitReleaseRundownProtectionByThread(Thread);
			}

		}
	}

	ExReleaseFastMutex(&DebugObject->Mutex);

	if (GlobalHeld) {
		ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
	}

	if (LastThread != NULL) {
		ObDereferenceObject(LastThread);
	}

	//这里读取临时链表，并且处理里面的每个消息
	while (!IsListEmpty(&TempList)) {
		Entry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		DbgkpWakeTarget(DebugEvent);
	}

	if (NT_SUCCESS(Status)) {
		//DbgkpMarkProcessPeb(Process);
		DbgkpHandlerFirstInt3();
	}

	return Status;
}

NTSTATUS DbgkpPostFakeProcessCreateMessages(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD *pLastThread)
{
	KAPC_STATE kApc = {0};
	PETHREAD pFisrtThread = NULL;
	PETHREAD pMLastThread = NULL;
	NTSTATUS status = DbgkpPostFakeThreadMessages(Process, DebugObject, NULL, &pFisrtThread, &pMLastThread);
	if (NT_SUCCESS(status))
	{
		KeStackAttachProcess(Process,&kApc);
		DbgkpPostModuleMessages(Process, pFisrtThread, DebugObject);
		KeUnstackDetachProcess(&kApc);
		ObfDereferenceObject(pFisrtThread);
		status = STATUS_SUCCESS;
	}

	*pLastThread = pMLastThread;
	return status;
}


PVOID ObFastReferenceObjectLocked(PEX_PUSH_LOCK lock)
{
	ULONG64 Object = *lock & (~0xFi64);
	if (Object)
		ObfReferenceObjectWithTag(*(PULONG64)Object & (~0xFi64), 'tlfD');
	return (PVOID)Object;
}

EX_PUSH_LOCK MiChangeControlAreaFileLock;
PFILE_OBJECT MiReferenceControlAreaFile(
	PCONTROL_AREA CtrlArea)
{

	PKTHREAD	CurrentThread;
	PFILE_OBJECT FileObject;

	CurrentThread = (PKTHREAD)PsGetCurrentThread();
	KeEnterCriticalRegion();

	ExfAcquirePushLockShared((ULONG_PTR)&MiChangeControlAreaFileLock);

	((PETHREADWIN7)CurrentThread)->OwnsChangeControlAreaShared = TRUE;
	FileObject = (PFILE_OBJECT)ObFastReferenceObjectLocked(&CtrlArea->FilePointer);
	((PETHREADWIN7)CurrentThread)->OwnsChangeControlAreaShared = FALSE;

	ExfReleasePushLockShared((ULONG_PTR)&MiChangeControlAreaFileLock);

	KeLeaveCriticalRegion();

	return FileObject;
}

NTSTATUS MmGetFileNameForSection(
	PSECTION  SectionObject,
	OUT POBJECT_NAME_INFORMATION *FileNameInfo
)
{
	ULONG NumberOfBytes;
	ULONG AdditionalLengthNeeded;
	NTSTATUS Status;
	PFILE_OBJECT FileObject;

	NumberOfBytes = 1024;

	*FileNameInfo = NULL;


	
	if (SectionObject->u.Flags.Image == 0) {
		return STATUS_SECTION_NOT_IMAGE;
	}

	*FileNameInfo = ExAllocatePoolWithTag(PagedPool, NumberOfBytes, '  mM');

	if (*FileNameInfo == NULL) {
		return STATUS_NO_MEMORY;
	}

	FileObject = (PFILE_OBJECT)ObFastReferenceObject(&SectionObject->Segment->ControlArea->FilePointer);
	if (FileObject == 0)
	{
		FileObject = MiReferenceControlAreaFile(SectionObject->Segment->ControlArea);
	}

	Status = ObQueryNameString(FileObject,
		*FileNameInfo,
		NumberOfBytes,
		&AdditionalLengthNeeded);

	if (!NT_SUCCESS(Status)) {

		if (Status == STATUS_INFO_LENGTH_MISMATCH) {

			//
			// Our buffer was not large enough, retry just once with a larger
			// one (as specified by ObQuery).  Don't try more than once to
			// prevent broken parse procedures which give back wrong
			// AdditionalLengthNeeded values from causing problems.
			//

			ExFreePool(*FileNameInfo);

			NumberOfBytes += AdditionalLengthNeeded;

			*FileNameInfo = ExAllocatePoolWithTag(PagedPool,
				NumberOfBytes,
				'  mM');

			if (*FileNameInfo == NULL) {
				return STATUS_NO_MEMORY;
			}

			Status = ObQueryNameString(FileObject,
				*FileNameInfo,
				NumberOfBytes,
				&AdditionalLengthNeeded);

			if (NT_SUCCESS(Status)) {
				return STATUS_SUCCESS;
			}
		}

		ExFreePool(*FileNameInfo);
		*FileNameInfo = NULL;
		return Status;
	}

	return STATUS_SUCCESS;
}


NTSTATUS MmGetFileNameForProcess(
	PEPROCESS eprocess,
	OUT POBJECT_NAME_INFORMATION *FileNameInfo
)
{
	ULONG NumberOfBytes;
	ULONG AdditionalLengthNeeded;
	NTSTATUS Status;
	PFILE_OBJECT FileObject;

	NumberOfBytes = 1024;

	*FileNameInfo = ExAllocatePoolWithTag(PagedPool, NumberOfBytes, '  mM');

	if (*FileNameInfo == NULL) {
		return STATUS_NO_MEMORY;
	}

	Status = PsReferenceProcessFilePointer(eprocess,&FileObject);
	if (!NT_SUCCESS(Status))
	{
		return STATUS_NOT_FOUND;
	}


	Status = ObQueryNameString(FileObject,
		*FileNameInfo,
		NumberOfBytes,
		&AdditionalLengthNeeded);

	ObDereferenceObject(FileObject);

	if (!NT_SUCCESS(Status)) {

		if (Status == STATUS_INFO_LENGTH_MISMATCH) {

			ExFreePool(*FileNameInfo);

			NumberOfBytes += AdditionalLengthNeeded;

			*FileNameInfo = ExAllocatePoolWithTag(PagedPool,NumberOfBytes,'mM');

			if (*FileNameInfo == NULL) {
				return STATUS_NO_MEMORY;
			}

			Status = ObQueryNameString(FileObject,
				*FileNameInfo,
				NumberOfBytes,
				&AdditionalLengthNeeded);

			if (NT_SUCCESS(Status)) {
				return STATUS_SUCCESS;
			}
		}

		ExFreePool(*FileNameInfo);
		*FileNameInfo = NULL;
		return Status;
	}

	return Status;
}

VOID DbgkpOpenHandles(PDBGUI_WAIT_STATE_CHANGE WaitStateChange,PEPROCESS Process,PETHREAD Thread)
{
	NTSTATUS Status;
	PEPROCESS CurrentProcess;
	HANDLE OldHandle;

	switch (WaitStateChange->NewState) {
	case DbgCreateThreadStateChange:
		Status = ObOpenObjectByPointer(Thread,
			0,
			NULL,
			THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | \
			THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION | THREAD_TERMINATE |
			READ_CONTROL | SYNCHRONIZE,
			*PsThreadType,
			KernelMode,
			&WaitStateChange->StateInfo.CreateThread.HandleToThread);
		if (!NT_SUCCESS(Status)) {
			WaitStateChange->StateInfo.CreateThread.HandleToThread = NULL;
		}
		break;

	case DbgCreateProcessStateChange:

		Status = ObOpenObjectByPointer(Thread,
			0,
			NULL,
			THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | \
			THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION | THREAD_TERMINATE |
			READ_CONTROL | SYNCHRONIZE,
			*PsThreadType,
			KernelMode,
			&WaitStateChange->StateInfo.CreateProcessInfo.HandleToThread);
		if (!NT_SUCCESS(Status)) {
			WaitStateChange->StateInfo.CreateProcessInfo.HandleToThread = NULL;
		}
		Status = ObOpenObjectByPointer(Process,
			0,
			NULL,
			PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
			PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION |
			PROCESS_CREATE_THREAD | PROCESS_TERMINATE |
			READ_CONTROL | SYNCHRONIZE,
			*PsProcessType,
			KernelMode,
			&WaitStateChange->StateInfo.CreateProcessInfo.HandleToProcess);
		if (!NT_SUCCESS(Status)) {
			WaitStateChange->StateInfo.CreateProcessInfo.HandleToProcess = NULL;
		}

		OldHandle = WaitStateChange->StateInfo.CreateProcessInfo.NewProcess.FileHandle;
		if (OldHandle != NULL) {
			CurrentProcess = (PEPROCESS)PsGetCurrentProcess();
			Status = ObDuplicateObject((PEPROCESS)CurrentProcess,
				OldHandle,
				(PEPROCESS)CurrentProcess,
				&WaitStateChange->StateInfo.CreateProcessInfo.NewProcess.FileHandle,
				0,
				0,
				DUPLICATE_SAME_ACCESS,
				KernelMode);
			if (!NT_SUCCESS(Status)) {
				WaitStateChange->StateInfo.CreateProcessInfo.NewProcess.FileHandle = NULL;
			}
			if (Status != STATUS_INVALID_HANDLE)
			{
				ObCloseHandle(OldHandle, KernelMode);
			}
		}
		break;

	case DbgLoadDllStateChange:

		//DbgBreakPoint();
		OldHandle = WaitStateChange->StateInfo.LoadDll.FileHandle;
		if (OldHandle != NULL) {
			CurrentProcess = (PEPROCESS)PsGetCurrentProcess();
			Status = ObDuplicateObject((PEPROCESS)CurrentProcess,
				OldHandle,
				(PEPROCESS)CurrentProcess,
				&WaitStateChange->StateInfo.LoadDll.FileHandle,
				0,
				0,
				DUPLICATE_SAME_ACCESS,
				KernelMode);
			if (!NT_SUCCESS(Status)) {
				WaitStateChange->StateInfo.LoadDll.FileHandle = NULL;
			}
			
			if (Status != STATUS_INVALID_HANDLE)
			{
				ObCloseHandle(OldHandle, KernelMode);
			}
			
		}

		break;

	default:
		break;
	}
}

VOID DbgkpConvertKernelToUserStateChange(PDBGUI_WAIT_STATE_CHANGE WaitStateChange,PDEBUG_EVENT DebugEvent)
{
	WaitStateChange->AppClientId = DebugEvent->ClientId;
	switch (DebugEvent->ApiMsg.ApiNumber) {
	case DbgKmExceptionApi:
		switch (DebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionCode) {
		case STATUS_BREAKPOINT:
			WaitStateChange->NewState = DbgBreakpointStateChange;
			break;

		case STATUS_SINGLE_STEP:
			WaitStateChange->NewState = DbgSingleStepStateChange;
			break;

		default:
			WaitStateChange->NewState = DbgExceptionStateChange;
			break;
		}
		WaitStateChange->StateInfo.Exception = DebugEvent->ApiMsg.u.Exception;
		break;

	case DbgKmCreateThreadApi:
		WaitStateChange->NewState = DbgCreateThreadStateChange;
		WaitStateChange->StateInfo.CreateThread.NewThread = DebugEvent->ApiMsg.u.CreateThread;
		break;

	case DbgKmCreateProcessApi:
		WaitStateChange->NewState = DbgCreateProcessStateChange;
		WaitStateChange->StateInfo.CreateProcessInfo.NewProcess = DebugEvent->ApiMsg.u.CreateProcessInfo;
		DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
		break;

	case DbgKmExitThreadApi:
		WaitStateChange->NewState = DbgExitThreadStateChange;
		WaitStateChange->StateInfo.ExitThread = DebugEvent->ApiMsg.u.ExitThread;
		break;

	case DbgKmExitProcessApi:
		WaitStateChange->NewState = DbgExitProcessStateChange;
		WaitStateChange->StateInfo.ExitProcess = DebugEvent->ApiMsg.u.ExitProcess;
		break;

	case DbgKmLoadDllApi:
		WaitStateChange->NewState = DbgLoadDllStateChange;
		WaitStateChange->StateInfo.LoadDll = DebugEvent->ApiMsg.u.LoadDll;
		DebugEvent->ApiMsg.u.LoadDll.FileHandle = NULL;
		break;

	case DbgKmUnloadDllApi:
		WaitStateChange->NewState = DbgUnloadDllStateChange;
		WaitStateChange->StateInfo.UnloadDll = DebugEvent->ApiMsg.u.UnloadDll;
		break;

	default:
		ASSERT(FALSE);
	}
}


VOID DbgkCreateThread(PETHREAD Thread)
{
	PEPROCESS Process = PsGetThreadToAPCProcess(Thread);
	//PPEB32 peb32 = PsGetProcessWow64Process(Process);
	ULONG OldFlags = SetProcessFlags(Process, PS_PROCESS_FLAGS_CREATE_REPORTED | PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE);

	DBGKM_APIMSG m;
	PDBGKM_CREATE_THREAD CreateThreadArgs;
	PDBGKM_CREATE_PROCESS CreateProcessArgs;
	//if((OldFlags & PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE)== 0 && )
	
	DEBUG_OBJECT * debugPort = (DEBUG_OBJECT *)HotGePsGetProcessDebugPort(Process);
	if (!debugPort) return;

	if ((OldFlags & PS_PROCESS_FLAGS_CREATE_REPORTED))
	{
		CreateThreadArgs = &m.u.CreateThread;
		CreateThreadArgs->SubSystemKey = 0;
		CreateThreadArgs->StartAddress = PsGetThreadWin32Address(Thread);

		DBGKM_FORMAT_API_MSG(m, DbgKmCreateThreadApi, sizeof(*CreateThreadArgs));
		DbgkpSendApiMessage(TRUE,&m);
	}
	else 
	{
		//创建进程逻辑说
		CreateThreadArgs = &m.u.CreateProcessInfo.InitialThread;
		CreateThreadArgs->SubSystemKey = 0;

		CreateProcessArgs = &m.u.CreateProcessInfo;
		CreateProcessArgs->SubSystemKey = 0;
		CreateProcessArgs->FileHandle = DbgkpProcessToFileHandle(Process);

		CreateProcessArgs->BaseOfImage = PsGetProcessSectionBaseAddress(Process);
		CreateThreadArgs->StartAddress = NULL;
		CreateProcessArgs->DebugInfoFileOffset = 0;
		CreateProcessArgs->DebugInfoSize = 0;

		try{

			PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(CreateProcessArgs->BaseOfImage);

			if (NtHeaders) {
				CreateThreadArgs->StartAddress = (PVOID)(NtHeaders->OptionalHeader.ImageBase + NtHeaders->OptionalHeader.AddressOfEntryPoint);

				CreateProcessArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
				CreateProcessArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
			}
		} except(EXCEPTION_EXECUTE_HANDLER) {
			CreateThreadArgs->StartAddress = NULL;
			CreateProcessArgs->DebugInfoFileOffset = 0;
			CreateProcessArgs->DebugInfoSize = 0;
		}

		DBGKM_FORMAT_API_MSG(m, DbgKmCreateProcessApi, sizeof(*CreateProcessArgs));

		DbgkpSendApiMessage(FALSE,&m);

		if (CreateProcessArgs->FileHandle != NULL) {
			ObCloseHandle(CreateProcessArgs->FileHandle, KernelMode);
		}

		DbgkSendSystemDllMessages(NULL,NULL,&m);
	}
}

BOOLEAN DbgkpSuppressDbgMsg(
	IN PTEB Teb)
{
	BOOLEAN bSuppress;
	try{
		bSuppress = Teb->SuppressDebugMsg;
		if (bSuppress) return bSuppress;
		if (PsGetProcessWow64Process(PsGetCurrentProcess()))
		{
			PTEB32 teb32 = (PTEB32)((ULONG64)Teb + 0x2000);
			bSuppress= teb32->SuppressDebugMsg;
		}
		
	}except(EXCEPTION_EXECUTE_HANDLER) {
		bSuppress = FALSE;
	}
	return bSuppress;
};

VOID DbgkMapViewOfSection(
	IN PEPROCESS	Process,
	IN PVOID SectionObject,
	IN PVOID BaseAddress

)
{
	PVOID Port;
	DBGKM_APIMSG m;
	PDBGKM_LOAD_DLL LoadDllArgs;
	PEPROCESS CurrentProcess;
	PIMAGE_NT_HEADERS NtHeaders = NULL;
	PETHREAD CurrentThread = (PETHREAD)PsGetCurrentThread();
	PTEB Teb = NULL;
	DBGKM_APIMSG ApiMsg;
	HANDLE	hFile;

	if (ExGetPreviousMode() == KernelMode) {
		return;
	}

	CurrentProcess = PsGetCurrentProcess();
	Port = HotGePsGetProcessDebugPort(Process);
	/*
	if (PsGetCurrentThread()->CrossThreadFlags &  PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) {
		Port = NULL;
	}
	else {
		Port = Process->DebugPort;
	}
	*/
	if (!Port) {
		return;
	}

	LoadDllArgs = &m.u.LoadDll;
	LoadDllArgs->FileHandle = DbgkpSectionToFileHandle(SectionObject);
	LoadDllArgs->BaseOfDll = BaseAddress;
	LoadDllArgs->DebugInfoFileOffset = 0;
	LoadDllArgs->DebugInfoSize = 0;

	if (IsThreadSystem(CurrentThread) != TRUE &&GetThreadApcIndex(CurrentThread) != 0x1)
	{
		
		Teb = PsGetCurrentThreadTeb();
	}
	else
	{
		Teb = NULL;
	}

	if (Teb != NULL && Process == CurrentProcess)
	{
		if (!DbgkpSuppressDbgMsg(Teb))
		{
			ApiMsg.u.LoadDll.NamePointer = Teb->NtTib.ArbitraryUserPointer;
		}
		else {
			//暂停调试消息的话就退出
			return;
		}
	}
	else {
		ApiMsg.u.LoadDll.NamePointer = NULL;
	}

	hFile = DbgkpSectionToFileHandle(SectionObject);
	ApiMsg.u.LoadDll.FileHandle = hFile;
	ApiMsg.u.LoadDll.BaseOfDll = BaseAddress;
	ApiMsg.u.LoadDll.DebugInfoFileOffset = 0;
	ApiMsg.u.LoadDll.DebugInfoSize = 0;

	try{
		PIMAGE_NT_HEADERS pImageHeader = RtlImageNtHeader(BaseAddress);
		if (pImageHeader != NULL)
		{
			ApiMsg.u.LoadDll.DebugInfoFileOffset = pImageHeader->FileHeader.PointerToSymbolTable;
			ApiMsg.u.LoadDll.DebugInfoSize = pImageHeader->FileHeader.NumberOfSymbols;
		}
	}except(EXCEPTION_EXECUTE_HANDLER) {
		ApiMsg.u.LoadDll.DebugInfoFileOffset = 0;
		ApiMsg.u.LoadDll.DebugInfoSize = 0;
		ApiMsg.u.LoadDll.NamePointer = NULL;
	}

	ApiMsg.h.u1.Length = 0x500028;
	ApiMsg.h.u2.ZeroInit = 8;
	ApiMsg.ApiNumber = DbgKmLoadDllApi;

	DbgkpSendApiMessage(0x1, &ApiMsg);

	if (ApiMsg.u.LoadDll.FileHandle != NULL)
	{
		ObCloseHandle(ApiMsg.u.LoadDll.FileHandle, KernelMode);
	}
}


HANDLE DbgkpSectionToFileHandle(IN PVOID SectionObject)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES Obja;
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE Handle;
	POBJECT_NAME_INFORMATION FileNameInfo;

	Status = MmGetFileNameForSection((PSEGMENT_OBJECT)SectionObject, &FileNameInfo);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}

	InitializeObjectAttributes(
		&Obja,
		&FileNameInfo->Name,
		OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);

	Status = ZwOpenFile(
		&Handle,
		(ACCESS_MASK)(GENERIC_READ | SYNCHRONIZE),
		&Obja,
		&IoStatusBlock,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SYNCHRONOUS_IO_NONALERT
	);
	ExFreePool(FileNameInfo);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}
	else {
		return Handle;
	}
}

VOID DbgkUnMapViewOfSection(
	IN PEPROCESS	Process,
	IN PVOID	BaseAddress)
{
	PTEB	Teb;
	DBGKM_APIMSG ApiMsg;
	PEPROCESS CurrentProcess;
	PETHREAD	CurrentThread;

	CurrentProcess = (PEPROCESS)PsGetCurrentProcess();
	CurrentThread = (PETHREAD)PsGetCurrentThread();

	if (ExGetPreviousMode() == KernelMode || HotGePsGetProcessDebugPort(Process))
	{
		return;
	}

	if (IsThreadSystem(CurrentThread) != TRUE &&GetThreadApcIndex(CurrentThread) != 0x1)
	{

		Teb = PsGetCurrentThreadTeb();
	}
	else
	{
		Teb = NULL;
	}

	if (Teb != NULL && Process == CurrentProcess)
	{
		if (DbgkpSuppressDbgMsg(Teb))
		{
			return;
		}
	}
	ApiMsg.u.UnloadDll.BaseAddress = BaseAddress;
	ApiMsg.h.u1.Length = 0x380010;
	ApiMsg.h.u2.ZeroInit = 8;
	ApiMsg.ApiNumber = DbgKmUnloadDllApi;
	DbgkpSendApiMessage(0x1, &ApiMsg);
}

VOID  DbgkExitProcess(NTSTATUS ExitStatus)
{
	PEPROCESS Process = PsGetCurrentProcess();
	//PETHREAD Thread = PsGetCurrentThread();
	DBGKM_APIMSG ApiMsg = {0};
	//隐藏对我无效
	/*
	if (IsThreadHideFromDebugger(Thread))
	{
		return;
	}
	*/

	if (!HotGePsGetProcessDebugPort(Process))
	{
		return;
	}


	KeQuerySystemTime(&((PEPROCESSWIN7)Process)->ExitTime);
	ApiMsg.u.ExitProcess.ExitStatus = ExitStatus;
	ApiMsg.h.u1.Length = 0x34000C;
	ApiMsg.h.u2.ZeroInit = 8;
	ApiMsg.ApiNumber = DbgKmExitProcessApi;
	DbgkpSendApiMessage(FALSE, &ApiMsg);
}

VOID  DbgkExitThread(NTSTATUS ExitStatus)
{
	DBGKM_APIMSG ApiMsg;
	PEPROCESS	Process = PsGetCurrentProcess();
	//PETHREAD	CurrentThread = PsGetCurrentThread();

	//隐藏对我无效
	/*
	if (IsThreadHideFromDebugger(Thread))
	{
	return;
	}
	*/

	if (!HotGePsGetProcessDebugPort(Process))
	{
		return;
	}

	ApiMsg.u.ExitThread.ExitStatus = ExitStatus;
	ApiMsg.h.u1.Length = 0x34000C;
	ApiMsg.h.u2.ZeroInit = 8;
	ApiMsg.ApiNumber = DbgKmExitThreadApi;
	DbgkpSendApiMessage(0x1, &ApiMsg);
}


PVOID PsCaptureExceptionPort(IN PEPROCESS Process)
{
	//PKTHREAD	Thread;
	PVOID		ExceptionPort;

	ExceptionPort = GeExceptionPort(Process);
	if (ExceptionPort != NULL)
	{
		KeEnterCriticalRegion();
		ExfAcquirePushLockShared(GetProcessExPush(Process));
		ExceptionPort = (PVOID)((ULONG_PTR)ExceptionPort & ~0x7);
		ObfReferenceObject(ExceptionPort);
		ExfReleasePushLockShared(GetProcessExPush(Process));
		KeLeaveCriticalRegion();
		
	}

	return ExceptionPort;
}


BOOLEAN  DbgkForwardException(PEXCEPTION_RECORD ExceptionRecord,BOOLEAN DebugException, BOOLEAN SecondChance)
{
	DBGKM_APIMSG apiMsg = {0};
	PEPROCESS Process =PsGetCurrentProcess();
	PDEBUG_OBJECT pDebugObject = NULL;
	BOOLEAN bLpcPort = FALSE;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID ExceptionPort = NULL;

	apiMsg.h.u1.Length = 0xD000A8;
	apiMsg.h.u2.ZeroInit = 8;
	apiMsg.ApiNumber = DbgKmExceptionApi;
	//__debugbreak();
	DbgPrintEx(77,0,"---------------------------%p\r\n", DbgkForwardException);
	if (DebugException)
	{

		
		pDebugObject = (PDEBUG_OBJECT)HotGePsGetProcessDebugPort(Process);
	}
	else 
	{
		ExceptionPort = (PDEBUG_OBJECT)PsCaptureExceptionPort(Process);
		apiMsg.h.u2.ZeroInit = 0x7;
		bLpcPort = TRUE;
	}


	if (pDebugObject == NULL &&DebugException == TRUE && ExceptionPort == NULL)
	{
		return FALSE;
	}

	apiMsg.u.Exception.ExceptionRecord = *ExceptionRecord; 
	apiMsg.u.Exception.FirstChance = !SecondChance;

	if (!bLpcPort)
	{
		status = DbgkpSendApiMessage(DebugException, &apiMsg);
	}
	else if(ExceptionPort)
	{
		status = DbgkpSendApiMessageLpc(&apiMsg, ExceptionPort, DebugException);
		ObDereferenceObject(ExceptionPort);
	}
	else 
	{
		apiMsg.ReturnedStatus = DBG_EXCEPTION_NOT_HANDLED;
		status = STATUS_SUCCESS;
	}

	if (NT_SUCCESS(status))
	{
		status = apiMsg.ReturnedStatus;

		if (apiMsg.ReturnedStatus == DBG_EXCEPTION_NOT_HANDLED)
		{
			if (DebugException == TRUE)
			{
				return FALSE;
			}

			status = DbgkpSendErrorMessage(ExceptionRecord, 0, &apiMsg);
		}
	}

	return NT_SUCCESS(status);
}