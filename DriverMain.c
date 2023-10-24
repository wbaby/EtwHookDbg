
#include<ntifs.h>
#include "Dbg.h"
#include "SearchFunc.h"
#include "hook\HookDebugApi.h"
#include "hook\Function.h"
#include "BEPatchDebug/etw/EtwControl.h"
#include "Pg\DisPg.h"


void SyscallCallback(_In_ unsigned int SystemCallIndex, _Inout_ void** SystemCallFunction)
{
	if (GetNtCreateDebugObjectFunc() == *SystemCallFunction)
	{
		*SystemCallFunction = HotGeNtCreateDebugObject;
	}
	else if (GetNtDebugActiveProcessFunc() == *SystemCallFunction)
	{
		*SystemCallFunction = HotGeNtDebugActiveProcess;
	}
	else if (GetNtDebugContinueFunc() == *SystemCallFunction)
	{
		*SystemCallFunction = HotGeNtDebugContinue;
	}
	else if (GetNtRemoveProcessDebugFunc() == *SystemCallFunction)
	{
		*SystemCallFunction = HotGeNtRemoveProcessDebug;
	}
	else if (GetNtWaitForDebugEventFunc() == *SystemCallFunction)
	{
		*SystemCallFunction = HotGeNtWaitForDebugEvent;
	}
	else if (GetNtReadVirtualMemoryFunc() == *SystemCallFunction)
	{
		*SystemCallFunction = HotGeNtReadVirtualMemory;
	}
	else if (GetNtWriteVirtualMemoryFunc() == *SystemCallFunction)
	{
		*SystemCallFunction = HotGeNtWriteVirtualMemory;
	}
	else if (GetNtProtectVirtualMemoryFunc() == *SystemCallFunction)
	{
		*SystemCallFunction = HotGeNtProtectVirtualMemory;
	}

	else if (GetNtSetContextThreadFunc() == *SystemCallFunction)
	{
		*SystemCallFunction = HotGeNtSetContextThread;
	}

	else if (GetNtGetContextThreadFunc() == *SystemCallFunction)
	{
		*SystemCallFunction = HotGeNtGetContextThread;
	}
}


VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	KdPrint(("DriverUnload\r\n"));
	DestoryHookAll();
	IfhOff();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	GetKiRetireDpcList();

	HotGetDbgkInitialize();
	InitHook();
	IfhOn(SyscallCallback);

	pDriver->DriverUnload = DriverUnload;
	KdPrint(("DriverEntry\r\n"));
	
	return 0;
}

