#pragma once
#include <ntifs.h>

typedef struct _HOOK
{
	LIST_ENTRY list;
	PUCHAR oldCode[28];  //保存原有字节
	ULONG64  oldSaveLen;  //保存的长度
	ULONG64 oldFunction;  //老函数地址
	ULONG64 OldCallAddr; // 原函数的CALL
	ULONG64 newFunction;  //新函数地址
	ULONG64 AsmDiapthFunction;  //派发地址，暂时无用
	ULONG64 retAddr;     //原函数被HOOK后 下面有效的起始地址
	BOOLEAN isHook;      //是否HOOK成功  
}HOOK,*PHOOK;


void InitHookObjectManager();
void DestoryHookObjectManager();
PHOOK FindHOOK(ULONG64 FunctionAddr);
BOOLEAN AddHeadHook(ULONG64 FunctionAddr, ULONG64 newFunctionAddr);
BOOLEAN RemoveHeadHook(ULONG64 FunctionAddr);
VOID RemoveAllHook();