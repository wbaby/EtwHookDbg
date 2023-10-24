#include "HookDebugApi.h"
#include "../tools/AsmCode.h"
#include "../tools/ssdt.h"
#include "Hook.h"
#include "../Dbg.h"
#include "../tools/SearchCode.h"
#include "../Dbgkp.h"


ULONG64 FindDbgkpQueueMessage()
{
	static ULONG64 Func = NULL;
	if (Func) return Func;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("B8****E9****83**498BCF8968*E8****498BCCE8****65********488B******4C89**E9****488D***4489***44***44***F0********72*48******E8****B9****65", -0x5cL);
	}

	Func = (ULONG64)searchResult;

	return Func;
}

ULONG64 FindDbgkUnMapViewOfSection()
{
	static ULONG64 Func = NULL;
	if (Func) return Func;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
										
		searchResult = SearchNtCodeHead("40534881ec****65488b******80b8*****74*654c8b******41", 0);
	}

	Func = (ULONG64)searchResult;

	return Func;
}

ULONG64 FindDbgkCreateThread()
{
	static ULONG64 Func = NULL;
	if (Func) return Func;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("488B**4889***4C8B*****4C89******0F******8B87****8BD081*****F00F******75*8984*****0F***73*BE****33DB4839", -0x1a);
	}

	Func = (ULONG64)searchResult;

	return Func;
}

ULONG64 FindDbgkMapViewOfSection()
{
	static ULONG64 Func = NULL;
	if (Func) return Func;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("415448******498BF04C8BE24C8BD165********80B8*****74*65********41F6******75*4883******0F*****4C8D******498B**498B**498BE3415CC3", -0xa);
	}

	Func = (ULONG64)searchResult;

	return Func;
}

ULONG64 FindDbgkExitProcess()
{
	static ULONG64 Func = NULL;
	if (Func) return Func;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("65********65********4C8B**8B82****A8*75*4983******74*A8*74*48*********894C**488D***33C9C744******C744******4989*****C744******E8****48******C3", -0x7L);
	}

	Func = (ULONG64)searchResult;

	return Func;
}

ULONG64 FindDbgkExitThread()
{
	static ULONG64 Func = NULL;
	if (Func) return Func;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("65********448B*****41***75*65********488B**4883******74*41***74*894C**488D***B9****C744******C744******C744******E8****48******C3", -0x7L);
	}

	Func = (ULONG64)searchResult;

	return Func;
}

ULONG64 FindDbgkForwardException()
{
	
	static ULONG64 Func = NULL;
	if (Func) return Func;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtFuncHead("C744******C744******65");
	}

	Func = (ULONG64)searchResult;
	
	return Func;
}

PUCHAR FindKdIgnoreUmExceptions()
{

	static ULONG64 Func = NULL;
	if (Func) return Func;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("803d*****74*413ac0",0);

		if (searchResult)
		{
			LONG64 offset = *(PLONG)(searchResult + 2);

			PUCHAR addr = (PUCHAR)(searchResult + 7 + offset);

			searchResult = addr;
		}
	}

	Func = (ULONG64)searchResult;
	//
	return Func;
}

ULONG GetNtCreateDebugObjectIndex()
{
	wchar_t wa_ZwConnectPort[] = { 0xE3B9, 0xE394, 0xE3A0, 0xE38C, 0xE38D, 0xE38D, 0xE386, 0xE380, 0xE397, 0xE3B3, 0xE38C, 0xE391, 0xE397, 0xE3E3, 0xE3E3 };

	for (int i = 0; i < 15; i++)
	{
		wa_ZwConnectPort[i] ^= 0x6D6D;
		wa_ZwConnectPort[i] ^= 0x8E8E;
	};

	UNICODE_STRING unFuncNameZwConnectPort = { 0 };
	RtlInitUnicodeString(&unFuncNameZwConnectPort, wa_ZwConnectPort);
	PUCHAR funcZwConnectPort = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNameZwConnectPort);

	funcZwConnectPort += 0x21;
	ULONG index = 0;
	for (int i = 0; i < 0x30; i++)
	{
		if (funcZwConnectPort[i] == 0xb8)
		{
			index = *(PLONG)(funcZwConnectPort + i + 1);
			break;
		}

	}

	return index;
}

ULONG GetNtDebugActiveProcessIndex()
{
	wchar_t wa_ZwCreateTransactionManager[] = { 0xE3B9, 0xE394, 0xE3A0, 0xE391, 0xE386, 0xE382, 0xE397, 0xE386, 0xE3B7, 0xE391, 0xE382, 0xE38D, 0xE390, 0xE382, 0xE380, 0xE397, 0xE38A, 0xE38C, 0xE38D, 0xE3AE, 0xE382, 0xE38D, 0xE382, 0xE384, 0xE386, 0xE391, 0xE3E3, 0xE3E3 };

	for (int i = 0; i < 28; i++)
	{
		wa_ZwCreateTransactionManager[i] ^= 0x6D6D;
		wa_ZwCreateTransactionManager[i] ^= 0x8E8E;
	};

	UNICODE_STRING unFuncNameZwCreateTransactionManager = { 0 };
	RtlInitUnicodeString(&unFuncNameZwCreateTransactionManager, wa_ZwCreateTransactionManager);
	PUCHAR funcZwCreateTransactionManager = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNameZwCreateTransactionManager);


	funcZwCreateTransactionManager += 0x80;
	ULONG index = 0;
	for (int i = 0; i < 0x30; i++)
	{
		if (funcZwCreateTransactionManager[i] == 0xb8)
		{
			index = *(PLONG)(funcZwCreateTransactionManager + i + 1);
			break;
		}

	}

	return index;
}

ULONG GetNtDebugContinueIndex()
{
	wchar_t wa_ZwCreateTransactionManager[] = { 0xE3B9, 0xE394, 0xE3A0, 0xE391, 0xE386, 0xE382, 0xE397, 0xE386, 0xE3B7, 0xE391, 0xE382, 0xE38D, 0xE390, 0xE382, 0xE380, 0xE397, 0xE38A, 0xE38C, 0xE38D, 0xE3AE, 0xE382, 0xE38D, 0xE382, 0xE384, 0xE386, 0xE391, 0xE3E3, 0xE3E3 };

	for (int i = 0; i < 28; i++)
	{
		wa_ZwCreateTransactionManager[i] ^= 0x6D6D;
		wa_ZwCreateTransactionManager[i] ^= 0x8E8E;
	};

	UNICODE_STRING unFuncNameZwCreateTransactionManager = { 0 };
	RtlInitUnicodeString(&unFuncNameZwCreateTransactionManager, wa_ZwCreateTransactionManager);
	PUCHAR funcZwCreateTransactionManager = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNameZwCreateTransactionManager);


	funcZwCreateTransactionManager += 0xA0;
	ULONG index = 0;
	for (int i = 0; i < 0x30; i++)
	{
		if (funcZwCreateTransactionManager[i] == 0xb8)
		{
			index = *(PLONG)(funcZwCreateTransactionManager + i + 1);
			break;
		}

	}

	return index;
}

ULONG GetNtRemoveProcessDebugIndex()
{
	wchar_t wa_ZwRemoveIoCompletionEx[] = { 0xE3B9, 0xE394, 0xE3B1, 0xE386, 0xE38E, 0xE38C, 0xE395, 0xE386, 0xE3AA, 0xE38C, 0xE3A0, 0xE38C, 0xE38E, 0xE393, 0xE38F, 0xE386, 0xE397, 0xE38A, 0xE38C, 0xE38D, 0xE3A6, 0xE39B, 0xE3E3, 0xE3E3 };

	for (int i = 0; i < 24; i++)
	{
		wa_ZwRemoveIoCompletionEx[i] ^= 0x6D6D;
		wa_ZwRemoveIoCompletionEx[i] ^= 0x8E8E;
	};

	UNICODE_STRING unFuncNameZwRemoveIoCompletionEx = { 0 };
	RtlInitUnicodeString(&unFuncNameZwRemoveIoCompletionEx, wa_ZwRemoveIoCompletionEx);
	PUCHAR funcZwRemoveIoCompletionEx = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNameZwRemoveIoCompletionEx);



	funcZwRemoveIoCompletionEx += 0x20;
	ULONG index = 0;
	for (int i = 0; i < 0x30; i++)
	{
		if (funcZwRemoveIoCompletionEx[i] == 0xb8)
		{
			index = *(PLONG)(funcZwRemoveIoCompletionEx + i + 1);
			break;
		}

	}

	return index;
}

ULONG GetNtNtWaitForDebugEventIndex()
{
	wchar_t wa_ZwUnlockFile[] = { 0xE3B9, 0xE394, 0xE3B6, 0xE38D, 0xE38F, 0xE38C, 0xE380, 0xE388, 0xE3A5, 0xE38A, 0xE38F, 0xE386, 0xE3E3, 0xE3E3 };

	for (int i = 0; i < 14; i++)
	{
		wa_ZwUnlockFile[i] ^= 0x6D6D;
		wa_ZwUnlockFile[i] ^= 0x8E8E;
	};

	UNICODE_STRING unFuncNameZwUnlockFile = { 0 };
	RtlInitUnicodeString(&unFuncNameZwUnlockFile, wa_ZwUnlockFile);
	PUCHAR funcZwUnlockFile = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNameZwUnlockFile);




	funcZwUnlockFile += 0x60;
	ULONG index = 0;
	for (int i = 0; i < 0x30; i++)
	{
		if (funcZwUnlockFile[i] == 0xb8)
		{
			index = *(PLONG)(funcZwUnlockFile + i + 1);
			break;
		}

	}

	return index;
}

ULONG GetReadVirtualMemoryIndex()
{
	wchar_t wa_ZwClearEvent[] = { 0xE3B9, 0xE394, 0xE3A0, 0xE38F, 0xE386, 0xE382, 0xE391, 0xE3A6, 0xE395, 0xE386, 0xE38D, 0xE397, 0xE3E3, 0xE3E3 };

	for (int i = 0; i < 14; i++)
	{
		wa_ZwClearEvent[i] ^= 0x6D6D;
		wa_ZwClearEvent[i] ^= 0x8E8E;
	};

	UNICODE_STRING unFuncNameZwClearEvent = { 0 };
	RtlInitUnicodeString(&unFuncNameZwClearEvent, wa_ZwClearEvent);
	PUCHAR funcZwClearEvent = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNameZwClearEvent);

	funcZwClearEvent += 0x20;
	ULONG index = 0;
	for (int i = 0; i < 0x30; i++)
	{
		if (funcZwClearEvent[i] == 0xb8)
		{
			index = *(PLONG)(funcZwClearEvent + i + 1);
			break;
		}

	}

	return index;
}

ULONG GetWriteVirtualMemoryIndex()
{
	wchar_t wa_ZwFsControlFile[] = { 0xE3B9, 0xE394, 0xE3A5, 0xE390, 0xE3A0, 0xE38C, 0xE38D, 0xE397, 0xE391, 0xE38C, 0xE38F, 0xE3A5, 0xE38A, 0xE38F, 0xE386, 0xE3E3, 0xE3E3 };

	for (int i = 0; i < 17; i++)
	{
		wa_ZwFsControlFile[i] ^= 0x6D6D;
		wa_ZwFsControlFile[i] ^= 0x8E8E;
	};

	UNICODE_STRING unFuncNameZwFsControlFile = { 0 };
	RtlInitUnicodeString(&unFuncNameZwFsControlFile, wa_ZwFsControlFile);
	PUCHAR funcZwFsControlFile = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNameZwFsControlFile);


	funcZwFsControlFile += 0x20;
	ULONG index = 0;
	for (int i = 0; i < 0x30; i++)
	{
		if (funcZwFsControlFile[i] == 0xb8)
		{
			index = *(PLONG)(funcZwFsControlFile + i + 1);
			break;
		}

	}

	return index;
}

ULONG GetProtectVirtualMemoryIndex()
{
	wchar_t wa_ZwIsProcessInJob[] = { 0xE3B9, 0xE394, 0xE3AA, 0xE390, 0xE3B3, 0xE391, 0xE38C, 0xE380, 0xE386, 0xE390, 0xE390, 0xE3AA, 0xE38D, 0xE3A9, 0xE38C, 0xE381, 0xE3E3, 0xE3E3 };

	for (int i = 0; i < 18; i++)
	{
		wa_ZwIsProcessInJob[i] ^= 0x6D6D;
		wa_ZwIsProcessInJob[i] ^= 0x8E8E;
	};

	UNICODE_STRING unFuncNameZwIsProcessInJob = { 0 };
	RtlInitUnicodeString(&unFuncNameZwIsProcessInJob, wa_ZwIsProcessInJob);
	PUCHAR funcZwIsProcessInJob = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNameZwIsProcessInJob);

	funcZwIsProcessInJob += 0x20;
	ULONG index = 0;
	for (int i = 0; i < 0x30; i++)
	{
		if (funcZwIsProcessInJob[i] == 0xb8)
		{
			index = *(PLONG)(funcZwIsProcessInJob + i + 1);
			break;
		}

	}

	return index;
}

ULONG GetNtGetContextThreadIndex()
{
	wchar_t wa_ZwFlushVirtualMemory[] = { 0xE3B9, 0xE394, 0xE3A5, 0xE38F, 0xE396, 0xE390, 0xE38B, 0xE3B5, 0xE38A, 0xE391, 0xE397, 0xE396, 0xE382, 0xE38F, 0xE3AE, 0xE386, 0xE38E, 0xE38C, 0xE391, 0xE39A, 0xE3E3, 0xE3E3 };

	for (int i = 0; i < 22; i++)
	{
		wa_ZwFlushVirtualMemory[i] ^= 0x6D6D;
		wa_ZwFlushVirtualMemory[i] ^= 0x8E8E;
	};

	UNICODE_STRING unFuncNameZwFlushVirtualMemory = { 0 };
	RtlInitUnicodeString(&unFuncNameZwFlushVirtualMemory, wa_ZwFlushVirtualMemory);
	PUCHAR funcZwFlushVirtualMemory = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNameZwFlushVirtualMemory);


	funcZwFlushVirtualMemory += 0xA0;
	ULONG index = 0;
	for (int i = 0; i < 0x30; i++)
	{
		if (funcZwFlushVirtualMemory[i] == 0xb8)
		{
			index = *(PLONG)(funcZwFlushVirtualMemory + i + 1);
			break;
		}

	}

	return index;
}


ULONG GetNtSetContextThreadIndex()
{
	wchar_t wa_ZwSetBootOptions[] = { 0xE3B9, 0xE394, 0xE3B0, 0xE386, 0xE397, 0xE3A1, 0xE38C, 0xE38C, 0xE397, 0xE3AC, 0xE393, 0xE397, 0xE38A, 0xE38C, 0xE38D, 0xE390, 0xE3E3, 0xE3E3 };

	for (int i = 0; i < 18; i++)
	{
		wa_ZwSetBootOptions[i] ^= 0x6D6D;
		wa_ZwSetBootOptions[i] ^= 0x8E8E;
	};

	UNICODE_STRING unFuncNameZwSetBootOptions = { 0 };
	RtlInitUnicodeString(&unFuncNameZwSetBootOptions, wa_ZwSetBootOptions);
	PUCHAR funcZwSetBootOptions = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNameZwSetBootOptions);



	funcZwSetBootOptions += 0x20;
	ULONG index = 0;
	for (int i = 0; i < 0x30; i++)
	{
		if (funcZwSetBootOptions[i] == 0xb8)
		{
			index = *(PLONG)(funcZwSetBootOptions + i + 1);
			break;
		}

	}

	return index;
}

//-----------------------------------------------------------------

ULONG64 GetNtCreateDebugObjectFunc()
{
	static ULONG64 func = 0;
	if (func) return func;
	func = GetSSDTFunc(GetNtCreateDebugObjectIndex());

	return func;
}


ULONG64 GetNtDebugActiveProcessFunc()
{
	static ULONG64 func = 0;
	if (func) return func;
	func = GetSSDTFunc(GetNtDebugActiveProcessIndex());

	return func;
}

ULONG64 GetNtDebugContinueFunc()
{
	static ULONG64 func = 0;
	if (func) return func;
	func = GetSSDTFunc(GetNtDebugContinueIndex());

	return func;
}

ULONG64 GetNtRemoveProcessDebugFunc()
{
	static ULONG64 func = 0;
	if (func) return func;
	func = GetSSDTFunc(GetNtRemoveProcessDebugIndex());

	return func;
}


ULONG64 GetNtWaitForDebugEventFunc()
{
	static ULONG64 func = 0;
	if (func) return func;
	func = GetSSDTFunc(GetNtNtWaitForDebugEventIndex());

	return func;
}

ULONG64 GetNtProtectVirtualMemoryFunc()
{
	static ULONG64 func = 0;
	if (func) return func;
	func = GetSSDTFunc(GetProtectVirtualMemoryIndex());

	return func;
}

ULONG64 GetNtWriteVirtualMemoryFunc()
{
	static ULONG64 func = 0;
	if (func) return func;
	func = GetSSDTFunc(GetWriteVirtualMemoryIndex());

	return func;
}

ULONG64 GetNtReadVirtualMemoryFunc()
{
	static ULONG64 func = 0;
	if (func) return func;
	func = GetSSDTFunc(GetReadVirtualMemoryIndex());

	return func;
}

ULONG64 GetNtGetContextThreadFunc()
{
	static ULONG64 func = 0;
	if (func) return func;
	func = GetSSDTFunc(GetNtGetContextThreadIndex());

	return func;
}

ULONG64 GetNtSetContextThreadFunc()
{
	static ULONG64 func = 0;
	if (func) return func;
	func = GetSSDTFunc(GetNtSetContextThreadIndex());

	return func;
}

void InitHook()
{

	GetNtCreateDebugObjectFunc();
	GetNtDebugActiveProcessFunc();
	GetNtDebugContinueFunc();
	GetNtRemoveProcessDebugFunc();
	GetNtWaitForDebugEventFunc();

	GetNtProtectVirtualMemoryFunc();
	GetNtWriteVirtualMemoryFunc();

	GetNtReadVirtualMemoryFunc();

	GetNtGetContextThreadFunc();

	GetNtSetContextThreadFunc();


	InitHookObjectManager();

	ULONG64 func = FindDbgkMapViewOfSection();
	if (func)
	{
		AddHeadHook(func, (ULONG64)DbgkMapViewOfSection);
	}

	func = FindDbgkCreateThread();
	if (func)
	{
		AddHeadHook(func, (ULONG64)DbgkCreateThread);

	}

	func = FindDbgkUnMapViewOfSection();
	if (func)
	{
		AddHeadHook(func, (ULONG64)DbgkUnMapViewOfSection);
	}

	func = FindDbgkExitProcess();
	if (func)
	{
		AddHeadHook(func, (ULONG64)DbgkExitProcess);
	}

	func = FindDbgkExitThread();
	if (func)
	{
		AddHeadHook(func, (ULONG64)DbgkExitThread);
	}

	func = FindDbgkForwardException(); 
	if (func)
	{
		AddHeadHook(func, (ULONG64)DbgkForwardException);
	}

	
	PUCHAR excep = FindKdIgnoreUmExceptions();

	if (excep)
	{
		*excep = 1;
	}
}

void DestoryHookAll()
{
	DestoryHookObjectManager();
}