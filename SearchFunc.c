#include "SearchFunc.h"
#include "tools\SearchCode.h"

typedef NTSTATUS(*PsResumeThreadProc)(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
typedef NTSTATUS(*PsSuspendThreadProc)(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
typedef PETHREAD(NTAPI *PsGetNextProcessThreadProc)(
	IN PEPROCESS Process,
	IN PETHREAD Thread);

typedef PVOID(*PsQuerySystemDllInfoProc)(ULONG index);

typedef VOID (*KeFreezeAllThreadsProc)(VOID);
typedef VOID (*KeThawAllThreadsProc)(VOID);
typedef VOID (*PsSynchronizeWithThreadInsertionProc)(PETHREAD thread, PETHREAD curThread);
typedef NTSTATUS(*DbgkpSendErrorMessageProc)(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN ULONG Falge,
	IN PVOID	DbgApiMsg);

typedef NTSTATUS (*DbgkpSendApiMessageLpcProc)(
	IN OUT PVOID ApiMsg,
	IN PVOID Port,
	IN BOOLEAN SuspendProcess
);
typedef PVOID(*ObFastReferenceObjectProc)(IN PEX_FAST_REF FastRef);

typedef NTSTATUS (*ObDuplicateObjectProc)(
	IN PEPROCESS SourceProcess,
	IN HANDLE SourceHandle,
	IN PEPROCESS TargetProcess OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options,
	IN KPROCESSOR_MODE PreviousMode
);

typedef NTSTATUS (*MmGetFileNameForAddressProc)(
	IN PVOID ProcessVa,
	OUT PUNICODE_STRING FileName
);

typedef NTSTATUS (*DbgkpPostModuleMessagesProcs)(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN PVOID DebugObject);

PsSuspendThreadProc PsSuspendThreadFunc = NULL;
PsResumeThreadProc PsResumeThreadFunc = NULL;
PsGetNextProcessThreadProc PsGetNextProcessThreadFunc = NULL;



ULONG64 FindPsResumeThread()
{
	if (PsResumeThreadFunc) return (ULONG64)PsResumeThreadFunc;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCode("405348***488BDAE8****4885DB74*890333C048***5BC3");
		if (!searchResult)
		{
			searchResult = SearchNtCode("FFF34883EC*488BDAE8****4885DB74*890333C04883C4*5BC3");
		}
	}
	else if (version.dwMajorVersion == 10)
	{
		ULONG number = GetWindowsVersionNumber();

		if (number == 1607 || number == 1507 || number == 1511 || number == 1703 || number == 1709)
		{
			searchResult = SearchNtCodeHead("488BDA488BF9E8****4533C08BD083**75*488B*****0F******488B*****4885C074*A8*75*F04C*******75*4885DB74*891333C0488B***48***5FC3", -0xA);
		}
		else if (number == 1803)
		{
			searchResult = SearchNtCodeHead("488BDA488BF9E8****83**75*488B*****41*****4485*****74*4885DB74*890333C0488B***48***5FC3", -0xA);
		}
		else if (number == 1809 || number == 1903 || number == 1909 || number == 2004)
		{
			searchResult = SearchNtCodeHead("488BDA488BF9E8****65********8BF083**75*4C8B*****B8****418B*****85C874*0F***0F*****4885DB74*8933488B***33C0488B***48***5FC3", -0xF);
		}
	}

	if (!searchResult) return 0;

	PsResumeThreadFunc = (PsResumeThreadProc)searchResult;
	return (ULONG64)PsResumeThreadFunc;
}


ULONG64 FindPsSuspendThread()
{
	if (PsSuspendThreadFunc) return (ULONG64)PsSuspendThreadFunc;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("4C8BEA488BF133FF897C**65********4C89******6641*******48******0F**488B0148***488D**F0480FB1110F*****8B86****A8*0F*****488BCEE8****8944**897C**EB*8944", -0x15);

	}
	else if (version.dwMajorVersion == 10)
	{
		ULONG number = GetWindowsVersionNumber();

		if (number == 1607 || number == 1507 || number == 1511 || number == 1703)
		{
			searchResult = SearchNtCodeHead("488BF2488BF98360**65********4C89***6641******48******E8****84C00F*****8B87****A8*0F*****488BCFE8****8944**33DB895C**EB*8BD88944", -0x17);
		}
		else if (number == 1709 || number == 1803)
		{
			searchResult = SearchNtCodeHead("488BFA488BD98364***65********4889***66FF*****4C8D*****4C89***498BCEE8****84C00F*****8B83****A8*0F*****488BCBE8****8944**33DB895C**EB*8BD88944**488B***488B***4C8B", -0x12);
		}
		else if (number == 1809 || number == 1903 || number == 1909 || number == 2004)
		{
			searchResult = SearchNtCodeHead("4C8BF2488BF98364***65********4889***66FF*****4C8D*****4C89***498BCFE8****84C00F*****8B87****A8*0F*****488BCFE8****8944**33DB895C**EB*8BD88944**4C8B***488B***488B***4C8B", -0x15);
		}
	}

	if (!searchResult) return 0;

	PsSuspendThreadFunc = (PsSuspendThreadProc)searchResult;
	return PsSuspendThreadFunc;
}

NTSTATUS PsSuspendThread(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL)
{
	//if (PsSuspendThreadFunc) return PsSuspendThreadFunc(Thread, &PreviousSuspendCount);

	PsSuspendThreadFunc = (PsSuspendThreadProc)FindPsSuspendThread();

	if (PsSuspendThreadFunc)
	{
		return PsSuspendThreadFunc(Thread, PreviousSuspendCount);
	}

	return STATUS_NOT_FOUND;

}


NTSTATUS PsResumeThread(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL)
{
	//if (PsResumeThreadFunc) return PsResumeThreadFunc(Thread, &PreviousSuspendCount);


	PsResumeThreadFunc = (PsResumeThreadProc)FindPsResumeThread();

	if (PsResumeThreadFunc)
	{
		return PsResumeThreadFunc(Thread, PreviousSuspendCount);
	}

	return STATUS_NOT_FOUND;
}

ULONG64 FindPsGetNextProcessThread()
{
	if (PsGetNextProcessThreadFunc) return (ULONG64)PsGetNextProcessThreadFunc;

	FindCode findCodes[1] = { 0 };

	RTL_OSVERSIONINFOW version = { 0 };
	RtlGetVersion(&version);
	
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		PsGetNextProcessThreadFunc = (PsGetNextProcessThreadProc)SearchNtCodeHead("418BEF4C8D*****33C0418D**F049****0F*****493BF775*498B1C24493BDC", -0x3cL);

	}
	else if (version.dwMajorVersion == 10)
	{
		PsGetNextProcessThreadFunc = (PsGetNextProcessThreadProc)SearchNtCodeHead("33D2488BCDE8****4885FF0F*****488B*****493BF574*4C8D*****BA****498BCFE8****84C074", -0x47L);
	}

	return (ULONG64)PsGetNextProcessThreadFunc;
}

PETHREAD PsGetNextProcessThread(PEPROCESS Process, PETHREAD Thread)
{
	PsGetNextProcessThreadProc func = FindPsGetNextProcessThread();
	if (func)
	{
		PETHREAD hThread = func(Process, Thread);
		return hThread;
	}

	return NULL;
}

PsQuerySystemDllInfoProc FindPsQuerySystemDllInfo()
{
	static PsQuerySystemDllInfoProc PsQuerySystemDllInfoFunc = NULL;
	if (PsQuerySystemDllInfoFunc) return PsQuerySystemDllInfoFunc;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("4863C148******488B04C14885C074*4883***74*48***C333C0C3",0);
	}

	PsQuerySystemDllInfoFunc = (PsQuerySystemDllInfoProc)searchResult;

	return PsQuerySystemDllInfoFunc;
}

PSYSTEM_DLL_ENTRY PsQuerySystemDllInfo(ULONG index)
{
	PsQuerySystemDllInfoProc PsQuerySystemDllInfoFunc = FindPsQuerySystemDllInfo();
	if (PsQuerySystemDllInfoFunc)
	{
		return PsQuerySystemDllInfoFunc(index);
	}

	return NULL;
}


PSYSTEM_DLL_INFO GetPspSystemDlls()
{
	PsQuerySystemDllInfoProc PsQuerySystemDllInfoFunc = FindPsQuerySystemDllInfo();
	PSYSTEM_DLL_INFO info = 0;
	LARGE_INTEGER in = { 0 };

	if (PsQuerySystemDllInfoFunc)
	{
		RTL_OSVERSIONINFOEXW version = { 0 };
		RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
		if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
		{
			ULONG offset = *(PULONG)((ULONG64)PsQuerySystemDllInfoFunc + 6);
			in.QuadPart = ((ULONG64)PsQuerySystemDllInfoFunc + 10);
			in.LowPart += offset;
			
		}
		
	}

	info = (PSYSTEM_DLL_INFO)in.QuadPart;

	return info;
}

KeFreezeAllThreadsProc FindKeFreezeAllThreads()
{
	static KeFreezeAllThreadsProc KeFreezeAllThreadsFunc = NULL;
	if (KeFreezeAllThreadsFunc) return KeFreezeAllThreadsFunc;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("EB*F3*488B**4885C075*F048*****72*EB*F048****410FB6C744***44***44***65********448AF833DBEB", -0x5D);
	}

	KeFreezeAllThreadsFunc = (KeFreezeAllThreadsProc)searchResult;

	return KeFreezeAllThreadsFunc;
}


VOID KeFreezeAllThreads(VOID)
{
	KeFreezeAllThreadsProc KeFreezeAllThreadsFunc = FindKeFreezeAllThreads();
	if (KeFreezeAllThreadsFunc)
	{
		KeFreezeAllThreadsFunc();
	}

}

KeThawAllThreadsProc FindKeThawAllThreads()
{
	//EB*F3*488B**4885C075*F048*****72*EB*F048****410FB6C744***44***44***65********448AF833DBEB
	static KeThawAllThreadsProc KeThawAllThreadsFunc = NULL;
	if (KeThawAllThreadsFunc) return KeThawAllThreadsFunc;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("8D48*8BDFEB*03D985*****75*F6******74*8BCBE8****B9****EB*F3*498B***483BC775*F049******72*498B**EB", -0x46);
	}

	KeThawAllThreadsFunc = (KeThawAllThreadsProc)searchResult;

	return KeThawAllThreadsFunc;
}

PsSynchronizeWithThreadInsertionProc FindPsSynchronizeWithThreadInsertion()
{
	static PsSynchronizeWithThreadInsertionProc PsSynchronizeWithThreadInsertionFunc = NULL;
	if (PsSynchronizeWithThreadInsertionFunc) return PsSynchronizeWithThreadInsertionFunc;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("F00934240F**8B078D6E*4823C5F00934240F**483BC674*488BCFE8****488BCFE8****6601*****75*488D**48390074*6639*****75*E8", -0x27);
	}

	PsSynchronizeWithThreadInsertionFunc = (PsSynchronizeWithThreadInsertionProc)searchResult;

	return PsSynchronizeWithThreadInsertionFunc;
}

VOID PsSynchronizeWithThreadInsertion(PETHREAD thread, PETHREAD curThread)
{
	PsSynchronizeWithThreadInsertionProc PsSynchronizeWithThreadInsertionFunc = FindPsSynchronizeWithThreadInsertion();
	if (PsSynchronizeWithThreadInsertionFunc)
	{
		PsSynchronizeWithThreadInsertionFunc(thread, curThread);
	}
}

VOID KeThawAllThreads(VOID) 
{
	KeThawAllThreadsProc KeThawAllThreadsFunc = FindKeThawAllThreads();
	if (KeThawAllThreadsFunc)
	{
		KeThawAllThreadsFunc();
	}
}

MmGetFileNameForAddressProc FindMmGetFileNameForAddress()
{
	static MmGetFileNameForAddressProc MmGetFileNameForAddressFunc = NULL;
	if (MmGetFileNameForAddressFunc) return MmGetFileNameForAddressFunc;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("448D**F04C0FB13E74*488BCEE8****808B*****488BCFE8****4533ED41*****4C8BC0493BC575*BF****EB*488B**48***413AC674*498B**488B38493BFD74", -0x3F);
	}

	MmGetFileNameForAddressFunc = (MmGetFileNameForAddressProc)searchResult;

	return MmGetFileNameForAddressFunc;
}

ObDuplicateObjectProc FindObDuplicateObject()
{
	static ObDuplicateObjectProc ObDuplicateObjectFunc = NULL;
	if (ObDuplicateObjectFunc) return ObDuplicateObjectFunc;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("0F***4D85C974*4D8939448B******418BFE83**0F*****4889******488D*****0F***488B**48***488D**F048****0F*****4D8B", -0x63);
	}

	ObDuplicateObjectFunc = (ObDuplicateObjectProc)searchResult;

	return ObDuplicateObjectFunc;
}

NTSTATUS ObDuplicateObject(
	IN PEPROCESS SourceProcess,
	IN HANDLE SourceHandle,
	IN PEPROCESS TargetProcess OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options,
	IN KPROCESSOR_MODE PreviousMode
)
{
	ObDuplicateObjectProc ObDuplicateObjectFunc = FindObDuplicateObject();
	if (ObDuplicateObjectFunc)
	{
		return ObDuplicateObjectFunc(SourceProcess,SourceHandle,
									TargetProcess ,
									TargetHandle ,
									DesiredAccess,
									HandleAttributes,
									Options,
									PreviousMode);
	}

	return STATUS_SUCCESS;
}

NTSTATUS MmGetFileNameForAddress(
	IN PVOID ProcessVa,
	OUT PUNICODE_STRING FileName
)
{
	MmGetFileNameForAddressProc MmGetFileNameForAddressFunc = FindMmGetFileNameForAddress();
	if (MmGetFileNameForAddressFunc)
	{
		return MmGetFileNameForAddressFunc(ProcessVa, FileName);
	}

	return STATUS_NOT_FOUND;
}

DbgkpSendErrorMessageProc FindDbgkpSendErrorMessage()
{
	static DbgkpSendErrorMessageProc DbgkpSendErrorMessageFunc = NULL;
	if (DbgkpSendErrorMessageFunc) return DbgkpSendErrorMessageFunc;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("33D248C7*******4889***E8****3D****0F*****4C******0F*****488B*****48***418BDF6601*****498BFF4D8BE78D48*33C0F0********74*48******E8****48******483BE875*BB****EB", -0x5bL);
	}

	DbgkpSendErrorMessageFunc = (DbgkpSendErrorMessageProc)searchResult;

	return DbgkpSendErrorMessageFunc;
}

NTSTATUS DbgkpSendErrorMessage(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN ULONG Falge,
	IN PVOID	DbgApiMsg)
{
	DbgkpSendErrorMessageProc DbgkpSendErrorMessageFunc = FindDbgkpSendErrorMessage();
	if (DbgkpSendErrorMessageFunc)
	{
		return DbgkpSendErrorMessageFunc(ExceptionRecord, Falge, DbgApiMsg);
	}

	return STATUS_NOT_FOUND;
}


DbgkpSendApiMessageLpcProc FindDbgkpSendApiMessageLpc()
{
	static DbgkpSendApiMessageLpcProc FindDbgkpSendApiMessageLpcFunc = NULL;
	if (FindDbgkpSendApiMessageLpcFunc) return FindDbgkpSendApiMessageLpcFunc;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("74*E8****408AF84C8D***488BD6488BCBC746*****E8****4533C033D248***8BD8E8****81*****75*BB****EB*85DB78", -0x1eL);
	}

	FindDbgkpSendApiMessageLpcFunc = (DbgkpSendApiMessageLpcProc)searchResult;

	return FindDbgkpSendApiMessageLpcFunc;
}

ObFastReferenceObjectProc FindObFastReferenceObject()
{
	static ObFastReferenceObjectProc ObFastReferenceObjectFunc = NULL;
	if (ObFastReferenceObjectFunc) return ObFastReferenceObjectFunc;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("488BF90F**4C8B0141***74*498D**498BC0F0480FB1110F*****498BD841***48***41***76*488BC3488B***48", -0xaL);
	}

	ObFastReferenceObjectFunc = (ObFastReferenceObjectProc)searchResult;

	return ObFastReferenceObjectFunc;
}

PVOID ObFastReferenceObject(IN PEX_FAST_REF FastRef)
{
	ObFastReferenceObjectProc ObFastReferenceObjectFunc = FindObFastReferenceObject();
	if (ObFastReferenceObjectFunc)
	{
		return ObFastReferenceObjectFunc(FastRef);
	}
	return NULL;
}


NTSTATUS DbgkpSendApiMessageLpc(
	IN OUT PVOID ApiMsg,
	IN PVOID Port,
	IN BOOLEAN SuspendProcess
)
{
	DbgkpSendApiMessageLpcProc FindDbgkpSendApiMessageLpcFunc = FindDbgkpSendApiMessageLpc();
	if (FindDbgkpSendApiMessageLpcFunc)
	{
		return FindDbgkpSendApiMessageLpcFunc(ApiMsg, Port, SuspendProcess);
	}

	return STATUS_NOT_FOUND;
}

DbgkpPostModuleMessagesProcs FindDbgkpPostModuleMessages()
{
	static DbgkpPostModuleMessagesProcs DbgkpPostModuleMessagesFunc = NULL;
	if (DbgkpPostModuleMessagesFunc) return DbgkpPostModuleMessagesFunc;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	ULONG64 searchResult = 0;
	if (version.dwMajorVersion == 6 && version.dwMinorVersion == 1)
	{
		searchResult = SearchNtCodeHead("483BF90F*****3B*****0F*****83**0F*****33D241*****488D******E8****48******483BF8480F43F88A07C784*********488B***488B**4889******48******483BC8480F43C88A01488B", -0x62L);
	}

	DbgkpPostModuleMessagesFunc = (DbgkpPostModuleMessagesProcs)searchResult;

	return DbgkpPostModuleMessagesFunc;
}

/*
NTSTATUS DbgkpPostModuleMessages(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN PVOID DebugObject)
{
	DbgkpPostModuleMessagesProcs DbgkpPostModuleMessagesFunc = FindDbgkpPostModuleMessages();
	if (DbgkpPostModuleMessagesFunc)
	{
		return DbgkpPostModuleMessagesFunc(Process, Thread, DebugObject);
	}

	return STATUS_NOT_FOUND;
}
*/


void initSearchFunc()
{
	PVOID func = NULL;
	func = FindPsGetNextProcessThread();
	KdPrint(("FindPsGetNextProcessThread %p\r\n", func));

	func = FindPsResumeThread();
	KdPrint(("FindPsResumeThread %p\r\n", func));
	
	func = FindPsSuspendThread();
	KdPrint(("FindPsSuspendThread %p\r\n", func));

	func = FindPsQuerySystemDllInfo();
	KdPrint(("FindPsQuerySystemDllInfo %p\r\n", func));

	
	func = FindKeFreezeAllThreads();
	KdPrint(("FindKeFreezeAllThreads %p\r\n", func));


	func = FindKeThawAllThreads();
	KdPrint(("FindKeThawAllThreads %p\r\n", func));


	func = FindPsSynchronizeWithThreadInsertion();
	KdPrint(("FindPsSynchronizeWithThreadInsertion %p\r\n", func));


	func = FindMmGetFileNameForAddress();
	KdPrint(("FindMmGetFileNameForAddress %p\r\n", func));


	func = FindObDuplicateObject();
	KdPrint(("FindObDuplicateObject %p\r\n", func));

	func = FindDbgkpSendApiMessageLpc();
	KdPrint(("FindDbgkpSendApiMessageLpc %p\r\n", func));

	func = FindObFastReferenceObject();
	KdPrint(("FindObFastReferenceObject %p\r\n", func));

	func = FindDbgkpPostModuleMessages();
	KdPrint(("FindDbgkpPostModuleMessages %p\r\n", func));
}

