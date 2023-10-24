#pragma once
#include <ntifs.h>
#include "../Peb.h"

typedef struct _PEB
{
	ULONG64 x;
	VOID* Mutant;                                                           //0x8
	VOID* ImageBaseAddress;                                                 //0x10
	PEB_LDR_DATA* Ldr;														 //0x18

}PEB, *PPEB;

EXTERN_C PPEB PsGetProcessPeb(__in PEPROCESS Process);

EXTERN_C PPEB32 PsGetProcessWow64Process(PEPROCESS eprocess);

ULONG_PTR GetModuleR3(HANDLE pid, char *moduleName, PULONG_PTR sizeImage);

