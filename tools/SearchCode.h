#pragma once
#include <ntifs.h>
typedef struct _FindCode
{
	UCHAR code[200];
	ULONG len;
	int offset;
	ULONG lastAddressOffset;
}FindCode, *PFindCode;

UCHAR charToHex(UCHAR * ch);

void initFindCodeStruct(PFindCode findCode, PCHAR code, ULONG64 offset, ULONG64 lastAddrOffset);
ULONG64 findAddressByCode(ULONG64 beginAddr, ULONG64 endAddr, PFindCode  findCode, ULONG size);
ULONG64 SearchNtCode(PCHAR code);
ULONG64 SearchNtCodeHead(PCHAR code,ULONG headOffset);

ULONG64 SearchNtFuncHead(PCHAR code);

//ËÑË÷Ä£¿é¿Õ°×µØ·½
ULONG64 findSpaceCode(ULONG64 BaseAddress);


ULONG GetWindowsVersionNumber();

NTSTATUS GetNtModuleBaseAndSize(ULONG64 * pModule, ULONG64 * pSize);