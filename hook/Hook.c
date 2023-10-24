#include "Hook.h"
#include "../tools/AsmCode.h"



HOOK g_HOOKList;

PHOOK FindHOOK(ULONG64 FunctionAddr)
{
	BOOLEAN result = TRUE;

	
	PLIST_ENTRY	head = &g_HOOKList.list;
	PHOOK next = (PHOOK)g_HOOKList.list.Flink;
	PHOOK findList = 0;
	while (head != (PLIST_ENTRY)next)
	{
		if (next->oldFunction == FunctionAddr || next->newFunction == FunctionAddr)
		{
			findList = next;
			break;
		}

		next = (PHOOK)(next->list.Flink);
	}



	return findList;
}

BOOLEAN AddHeadHook(ULONG64 FunctionAddr, ULONG64 newFunctionAddr)
{
	BOOLEAN isRet = FALSE;
	PHOOK hook = FindHOOK(FunctionAddr);
	if (hook) return FALSE;


	hook = (PHOOK)ExAllocatePool(PagedPool,sizeof(HOOK));

	if (hook == NULL)
	{
		return FALSE;
	}

	hook->newFunction = newFunctionAddr;
	hook->oldFunction = FunctionAddr;
	InitializeListHead(&hook->list);
	
	//第一步 计算HOOK的长度
	char shellCode[14] = 
	{
		0xFF,0x25,0,0,0,0,
	};


	*(PULONG64)&shellCode[6] = newFunctionAddr;

	//获取合适长度
	int len = 0;
	PCHAR pTemp = (PCHAR)FunctionAddr;
	while (1)
	{
		int ilen = insn_len_x86_64(pTemp);
		len += ilen;
		pTemp += ilen;
		if (len >= 14)
		{
			break;
		}

	}
	
	hook->retAddr = (ULONG64)pTemp;
	hook->oldSaveLen = len;
	memcpy(hook->oldCode, (PCHAR)FunctionAddr,hook->oldSaveLen);


	char shellCode2[14] =
	{
		0xFF,0x25,0,0,0,0,0,0,0,0,0,0,0,0
	};
	*(PULONG64)&shellCode2[6] = hook->retAddr;
	//申请页
	PCHAR resetAddr = (PCHAR)ExAllocatePool(NonPagedPool, 60);
	memcpy(resetAddr, hook->oldCode, hook->oldSaveLen);
	hook->OldCallAddr = (ULONG64)resetAddr;
	resetAddr += hook->oldSaveLen;
	memcpy(resetAddr, shellCode2, sizeof(shellCode2));
	
	//开始HOOK
	PHYSICAL_ADDRESS ppte = MmGetPhysicalAddress(FunctionAddr);
	ppte.QuadPart = ppte.QuadPart & 0xFFFFFFFFFFFF;
	
	PVOID mem = MmMapIoSpace(ppte, 0x40,MmNonCached);
	if (!mem)
	{
		ExFreePool((PVOID)hook->OldCallAddr);
		isRet = FALSE;
		ExFreePool(hook);
	}
	else
	{
		memcpy(mem, shellCode,sizeof(shellCode));
		MmUnmapIoSpace(mem, 0x40);
		hook->isHook = TRUE;
		isRet = TRUE;
		InsertTailList(&g_HOOKList.list, &hook->list);
	}


	return isRet;
}

BOOLEAN RemoveHeadHook(ULONG64 FunctionAddr)
{
	PHOOK hook = FindHOOK(FunctionAddr);
	BOOLEAN isRet = FALSE;
	if (hook)
	{

		if (hook->isHook)
		{
			PVOID mem = MmMapIoSpace(MmGetPhysicalAddress(hook->oldFunction), 0x40, MmNonCached);
			isRet = TRUE;
			if (mem)
			{
				memcpy(mem, hook->oldCode, hook->oldSaveLen);
				MmUnmapIoSpace(mem, 0x40);
			}
		}

		RemoveEntryList(&hook->list);
		ExFreePool((PVOID)hook->OldCallAddr);
		ExFreePool(hook);
		
	}

	return isRet;
}

VOID RemoveAllHook()
{
	PLIST_ENTRY	head = &g_HOOKList.list;
	PHOOK next = (PHOOK)g_HOOKList.list.Flink;

	while (head != (PLIST_ENTRY)next)
	{
		PHOOK hook = next;
		next = (PHOOK)next->list.Flink;
		

		if (hook->isHook)
		{
			PVOID mem = MmMapIoSpace(MmGetPhysicalAddress(hook->oldFunction), 0x40, MmNonCached);
			
			if (mem)
			{
				memcpy(mem, hook->oldCode, hook->oldSaveLen);
				MmUnmapIoSpace(mem, 0x40);
			}
		}
		RemoveEntryList(&hook->list);
		ExFreePool((PVOID)hook->OldCallAddr);
		ExFreePool(&hook->list);
	}
	
}



void InitHookObjectManager()
{
	InitializeListHead(&g_HOOKList.list);
}

void DestoryHookObjectManager()
{
	
	RemoveAllHook();
}