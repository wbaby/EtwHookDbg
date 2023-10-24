#include "tools.h"
#include <ntimage.h>
#include <intrin.h>


void wpoff()
{
	//KIRQL  irql = KeRaiseIrqlToDpcLevel();
	_disable();
	ULONG64 cr0 = __readcr0() & 0xfffffffffffeffffi64;
	__writecr0(cr0);
	//return irql;
}

void wpon(/*KIRQL  irql*/)
{
	ULONG64 cr0 = __readcr0() | 0x10000i64;
	__writecr0(cr0);
	_enable();
	//KeLowerIrql(irql);
}



NTSTATUS GetNtModuleBaseAndSizeEtw(ULONG64 * pModule, ULONG64 * pSize)
{
	if (pModule == NULL || pSize == NULL) return STATUS_UNSUCCESSFUL;
	ULONG BufferSize = PAGE_SIZE * 64;
	PVOID Buffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, '111');
	ULONG ReturnLength;
	NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation,
		Buffer,
		BufferSize,
		&ReturnLength
		);

	if (Status == STATUS_INFO_LENGTH_MISMATCH) {
		ExFreePoolWithTag(Buffer, '111');
		return STATUS_INFO_LENGTH_MISMATCH;
	}

	PRTL_PROCESS_MODULES            Modules;
	PRTL_PROCESS_MODULE_INFORMATION ModuleInfo;
	Modules = (PRTL_PROCESS_MODULES)Buffer;
	ModuleInfo = &(Modules->Modules[0]);
	*pModule = ModuleInfo->ImageBase;
	*pSize = ModuleInfo->ImageSize;

	ExFreePoolWithTag(Buffer, '111');

	return Status;
}


UCHAR charToHexETW(UCHAR * ch)
{
	unsigned char temps[2] = { 0 };
	for (int i = 0; i < 2; i++)
	{
		if (ch[i] >= '0' && ch[i] <= '9')
		{
			temps[i] = (ch[i] - '0');
		}
		else if (ch[i] >= 'A' && ch[i] <= 'F')
		{
			temps[i] = (ch[i] - 'A') + 0xA;
		}
		else if (ch[i] >= 'a' && ch[i] <= 'f')
		{
			temps[i] = (ch[i] - 'a') + 0xA;
		}
	}
	return ((temps[0] << 4) & 0xf0) | (temps[1] & 0xf);
}




void initFindCodeStructETW(PFindCodeEtw findCode, PCHAR code, ULONG64 offset, ULONG64 lastAddrOffset)
{

	memset(findCode, 0, sizeof(FindCodeEtw));

	findCode->lastAddressOffset = lastAddrOffset;
	findCode->offset = offset;

	PCHAR pTemp = code;
	ULONG64 i = 0;
	for (i = 0; *pTemp != '\0'; i++)
	{
		if (*pTemp == '*' || *pTemp == '?')
		{
			findCode->code[i] = *pTemp;
			pTemp++;
			continue;
		}

		findCode->code[i] = charToHexETW(pTemp);
		pTemp += 2;

	}

	findCode->len = i;
}


ULONG64 findAddressByCodeETW(ULONG64 beginAddr, ULONG64 endAddr, PFindCodeEtw  findCode, ULONG size)
{
	ULONG64 j = 0;
	LARGE_INTEGER rtna = { 0 };

	for (ULONG64 i = beginAddr; i <= endAddr; i++)
	{
		if (!MmIsAddressValid((PVOID)i))continue;


		for (j = 0; j < size; j++)
		{
			FindCodeEtw  fc = findCode[j];
			ULONG64 tempAddress = i;

			UCHAR * code = (UCHAR *)(tempAddress + fc.offset);
			BOOLEAN isFlags = FALSE;

			for (ULONG64 k = 0; k < fc.len; k++)
			{
				if (!MmIsAddressValid((PVOID)(code + k)))
				{
					isFlags = TRUE;
					break;
				}

				if (fc.code[k] == '*' || fc.code[k] == '?') continue;

				if (code[k] != fc.code[k])
				{
					isFlags = TRUE;
					break;
				}
			}

			if (isFlags) break;

		}

		//找到了
		if (j == size)
		{
			rtna.QuadPart = i;
			rtna.LowPart += findCode[0].lastAddressOffset;
			break;
		}

	}

	return rtna.QuadPart;
}

ULONG GetWindowsVersionNumberEtw()
{
	static ULONG gNumberVer = -1;
	if (gNumberVer != -1) return gNumberVer;

	RTL_OSVERSIONINFOW version = { 0 };
	RtlGetVersion(&version);

	if (version.dwMajorVersion <= 6)
	{
		gNumberVer = 0;
		return gNumberVer;
	}

	HANDLE hKey = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING KeyPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING SourceKeyName = RTL_CONSTANT_STRING(L"ReleaseId");

	PKEY_VALUE_PARTIAL_INFORMATION AcKeyInfo = NULL;
	KEY_VALUE_PARTIAL_INFORMATION KeyInfo;
	ULONG Length = 0;

	InitializeObjectAttributes(
		&ObjectAttributes,
		&KeyPath,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	Status = ZwOpenKey(&hKey, KEY_READ | KEY_WRITE, &ObjectAttributes);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Open the Key Handle Faild!! -- %#X\n", Status);
		return 0;
	}

	Status = ZwQueryValueKey(
		hKey,
		&SourceKeyName,
		KeyValuePartialInformation,
		&KeyInfo,
		sizeof(KEY_VALUE_PARTIAL_INFORMATION),
		&Length);

	if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
	{
		DbgPrint("读取SystemRoot键值失败!! - %#X\n", Status);
		ZwClose(hKey);
		return 0;
	}


	AcKeyInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, Length, 'tag2');
	if (NULL == AcKeyInfo)
	{
		DbgPrint("在分配保存Key键值的内存空间时失败!!");
		ZwClose(hKey);
		return 0;
	}

	//再次读取注册表键值
	Status = ZwQueryValueKey(
		hKey,
		&SourceKeyName,
		KeyValuePartialInformation,
		AcKeyInfo,
		Length,
		&Length);

	ULONG number = 0;
	if (NT_SUCCESS(Status))
	{

		UNICODE_STRING str = { 0 };
		WCHAR buffer[1024] = { 0 };
		memcpy(buffer, AcKeyInfo->Data, AcKeyInfo->DataLength);
		RtlInitUnicodeString(&str, buffer);
		RtlUnicodeStringToInteger(&str, 0, &number);
	}
	else
	{
		DbgPrint("读取SystemRoot键值失败!! - %#X\n", Status);
	}

	gNumberVer = number;

	ZwClose(hKey);
	ExFreePool(AcKeyInfo);
	return number;
}