#pragma once

#include <ntifs.h>
#include "comm/DbgStruct.h"
#include "comm\ObjectType.h"
#include "Struct.h"
#include "Peb.h"

typedef struct _SUBSECTION
{
	struct _CONTROL_AREA* ControlArea;
	PVOID SubsectionBase;
	PVOID NextSubsection;
	ULONG32 PtesInSubsection;
	ULONG32 UnusedPtes;
	PVOID GlobalPerSessionHead;
	union
	{
		ULONG32 x1;
	}u;
	ULONG32 StartingSector;
	ULONG32 NumberOfFullSectors;
}SUBSECTION, *PSUBSECTION;

typedef struct _SEGMENT_OBJECT                     // 9 elements, 0x28 bytes (sizeof) 
{
	/*0x000*/     VOID* BaseAddress;
	/*0x004*/     ULONG32      TotalNumberOfPtes;
	/*0x008*/     union _LARGE_INTEGER SizeOfSegment;            // 4 elements, 0x8 bytes (sizeof)  
	/*0x010*/     ULONG32      NonExtendedPtes;
	/*0x014*/     ULONG32 ImageCommitment;		//这个成员经过分析我们重新定义一下                                                   
	/*0x018*/     struct _CONTROL_AREA* ControlArea;
	/*0x01C*/     PSUBSECTION Subsection;
	/*0x020*/     struct _MMSECTION_FLAGS*	MmSectionFlags;
	/*0x024*/     void* MmSubSectionFlags;
}SEGMENT_OBJECT, *PSEGMENT_OBJECT;


typedef struct _SECTION {
	MMADDRESS_NODE Address;
	PSEGMENT Segment;
	LARGE_INTEGER SizeOfSection;
	union {
		ULONG LongFlags;
		MMSECTION_FLAGS Flags;
	} u;
	ULONG InitialPageProtection;
} SECTION, *PSECTION;

#define LPC_REQUEST             1
#define LPC_REPLY               2
#define LPC_DATAGRAM            3
#define LPC_LOST_REPLY          4
#define LPC_PORT_CLOSED         5
#define LPC_CLIENT_DIED         6
#define LPC_EXCEPTION           7
#define LPC_DEBUG_EVENT         8
#define LPC_ERROR_EVENT         9
#define LPC_CONNECTION_REQUEST 10

#define DBGKM_MSG_OVERHEAD \
    (FIELD_OFFSET(DBGKM_APIMSG, u.Exception) - sizeof(PORT_MESSAGE))

#define DBGKM_API_MSG_LENGTH(TypeSize) \
    ((sizeof(DBGKM_APIMSG) << 16) | (DBGKM_MSG_OVERHEAD + (TypeSize)))

#define DBGKM_FORMAT_API_MSG(m,Number,TypeSize)             \
    (m).h.u1.Length = DBGKM_API_MSG_LENGTH((TypeSize));     \
    (m).h.u2.ZeroInit = LPC_DEBUG_EVENT;                    \
    (m).ApiNumber = (Number)

EXTERN_C FAST_MUTEX DbgkpProcessDebugPortMutex;
EXTERN_C POBJECT_TYPE g_HotGeDebugObject;
EXTERN_C ULONG g_DbgkpMaxModuleMsgs;

BOOLEAN EntryAcquireRundownProtectionByProcess(PEPROCESS eprocess);
VOID ExitReleaseRundownProtectionByProcess(PEPROCESS eprocess);

BOOLEAN IsThreadSystem(PETHREAD thread);

NTSTATUS DbgkClearProcessDebugObject(IN PEPROCESS Process,IN PDEBUG_OBJECT SourceDebugObject);

VOID DbgkpMarkProcessPeb(PEPROCESS Process);

VOID DbgkpFreeDebugEvent(IN PDEBUG_EVENT DebugEvent);

VOID DbgkpWakeTarget(IN PDEBUG_EVENT DebugEvent);

NTSTATUS DbgkpPostFakeThreadMessages(IN PEPROCESS Process,IN PDEBUG_OBJECT DebugObject,IN PETHREAD StartThread,OUT PETHREAD *pFirstThread,OUT PETHREAD *pLastThread);

NTSTATUS DbgkpPostModuleMessages(IN PEPROCESS Process,IN PETHREAD Thread,IN PDEBUG_OBJECT DebugObject);

NTSTATUS DbgkpPostFakeProcessCreateMessages(IN PEPROCESS Process,IN PDEBUG_OBJECT DebugObject,IN PETHREAD *pLastThread);

HANDLE DbgkpSectionToFileHandle(IN PVOID SectionObject);
HANDLE DbgkpProcessToFileHandle(IN PVOID Process);

PIMAGE_NT_HEADERS RtlImageNtHeader(PVOID baseAddr);

NTSTATUS MmGetFileNameForProcess(
	PEPROCESS eprocess,
	OUT POBJECT_NAME_INFORMATION *FileNameInfo
);

NTSTATUS MmGetFileNameForSection(PSECTION  SectionObject,OUT POBJECT_NAME_INFORMATION *FileNameInfo);

NTSTATUS DbgkpQueueMessage(IN PEPROCESS Process,IN PETHREAD Thread,IN OUT PDBGKM_APIMSG ApiMsg,IN ULONG Flags,IN PDEBUG_OBJECT TargetDebugObject);

VOID DbgkSendSystemDllMessages(IN PETHREAD thread, IN PDEBUG_OBJECT TargetDebugObject, DBGKM_APIMSG * apiMsg);

BOOLEAN DbgkpSuspendProcess(VOID);

NTSTATUS DbgkpSendApiMessage(ULONG Flags,PDBGKM_APIMSG apiMsg);

NTSTATUS DbgkpSetProcessDebugObject(IN PEPROCESS Process,IN PDEBUG_OBJECT DebugObject,IN NTSTATUS MsgStatus,IN PETHREAD LastThread);

VOID DbgkpOpenHandles(PDBGUI_WAIT_STATE_CHANGE WaitStateChange,PEPROCESS Process,PETHREAD Thread);

BOOLEAN DbgkpSuppressDbgMsg(PTEB teb);

VOID DbgkpConvertKernelToUserStateChange(PDBGUI_WAIT_STATE_CHANGE WaitStateChange, PDEBUG_EVENT DebugEvent);

VOID DbgkCreateThread(PETHREAD Thread);

VOID DbgkMapViewOfSection(IN PEPROCESS	Process,IN PVOID SectionObject,IN PVOID BaseAddress);

VOID  DbgkExitProcess(NTSTATUS ExitStatus);

VOID  DbgkExitThread(NTSTATUS ExitStatus);

VOID DbgkUnMapViewOfSection(IN PEPROCESS Process,IN PVOID BaseAddress);

BOOLEAN  DbgkForwardException(PEXCEPTION_RECORD ExceptionRecord, BOOLEAN DebugException, BOOLEAN SecondChance);