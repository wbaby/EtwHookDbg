#include "Function.h"
#include "../tools/SearchCode.h"
#include "HookDebugApi.h"

NTSTATUS MmCopyVirtualMemory(
	IN PEPROCESS FromProcess,
	IN CONST VOID *FromAddress,
	IN PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN SIZE_T BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);

PCHAR PsGetProcessImageFileName(PEPROCESS Process);

FORCEINLINE VOID ProbeForWritePointer(IN PVOID *Address)
{

	if (Address >= (PVOID * const)MM_USER_PROBE_ADDRESS) {
		Address = (PVOID * const)MM_USER_PROBE_ADDRESS;
	}

	*((volatile PVOID *)Address) = *Address;
	return;
}

FORCEINLINE VOID ProbeForWriteUlong_ptr(IN PULONG_PTR Address)
{

	if (Address >= (ULONG_PTR * const)MM_USER_PROBE_ADDRESS) {
		Address = (ULONG_PTR * const)MM_USER_PROBE_ADDRESS;
	}

	*((volatile ULONG_PTR *)Address) = *Address;
	return;
}

FORCEINLINE VOID ProbeForWriteUlong(IN PULONG Address)
{

	if (Address >= (ULONG * const)MM_USER_PROBE_ADDRESS) {
		Address = (ULONG * const)MM_USER_PROBE_ADDRESS;
	}

	*((volatile ULONG *)Address) = *Address;
	return;
}

FORCEINLINE VOID ProbeForReadSmallStructure(
	IN PVOID Address,
	IN SIZE_T Size,
	IN ULONG Alignment
)

{

	ASSERT((Alignment == 1) || (Alignment == 2) ||
		(Alignment == 4) || (Alignment == 8) ||
		(Alignment == 16));

	if ((Size == 0) || (Size >= 0x10000)) {

		ASSERT(0);

		ProbeForRead(Address, Size, Alignment);

	}
	else {
		if (((ULONG_PTR)Address & (Alignment - 1)) != 0) {
			ExRaiseDatatypeMisalignment();
		}

		if ((PUCHAR)Address >= (UCHAR * const)MM_USER_PROBE_ADDRESS) {
			Address = (UCHAR * const)MM_USER_PROBE_ADDRESS;
		}

		_ReadWriteBarrier();
		*(volatile UCHAR *)Address;
	}
}


NTSTATUS NTAPI HotGeNtReadVirtualMemory(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__out_bcount(BufferSize) PVOID Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesRead
)
{
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	SIZE_T BytesCopied = 0;
	NTSTATUS Status = STATUS_SUCCESS;

	if (PreviousMode != KernelMode) {

		if (((PCHAR)BaseAddress + BufferSize < (PCHAR)BaseAddress) ||
			((PCHAR)Buffer + BufferSize < (PCHAR)Buffer) ||
			((PVOID)((PCHAR)BaseAddress + BufferSize) > MM_HIGHEST_USER_ADDRESS) ||
			((PVOID)((PCHAR)Buffer + BufferSize) > MM_HIGHEST_USER_ADDRESS)) {

			return STATUS_ACCESS_VIOLATION;
		}

		if (ARGUMENT_PRESENT(NumberOfBytesRead)) {
			try {
				ProbeForWriteUlong_ptr(NumberOfBytesRead);

			} except(EXCEPTION_EXECUTE_HANDLER) {
				return GetExceptionCode();
			}
		}
	}

	if (BufferSize != 0) {
		PEPROCESS Process = NULL;

		Status = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, PreviousMode, &Process, NULL);

		if (Status == STATUS_SUCCESS) {

			Status = MmCopyVirtualMemory(Process,
				BaseAddress,
				IoGetCurrentProcess(),
				Buffer,
				BufferSize,
				PreviousMode,
				&BytesCopied);

			//
			// Dereference the target process.
			//

			ObDereferenceObject(Process);
		}

	}
	



	if (ARGUMENT_PRESENT(NumberOfBytesRead)) {
		try {
			*NumberOfBytesRead = BytesCopied;

		} except(EXCEPTION_EXECUTE_HANDLER) {
			NOTHING;
		}
	}

	return Status;
}


NTSTATUS NTAPI HotGeNtWriteVirtualMemory(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__in_bcount(BufferSize) CONST VOID *Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesWritten
)
{
	SIZE_T BytesCopied;
	KPROCESSOR_MODE PreviousMode;
	PEPROCESS Process;
	NTSTATUS Status;
	PETHREAD CurrentThread;

	PAGED_CODE();

	//
	// Get the previous mode and probe output argument if necessary.
	//

	PreviousMode = ExGetPreviousMode();
	if (PreviousMode != KernelMode) {

		if (((PCHAR)BaseAddress + BufferSize < (PCHAR)BaseAddress) ||
			((PCHAR)Buffer + BufferSize < (PCHAR)Buffer) ||
			((PVOID)((PCHAR)BaseAddress + BufferSize) > MM_HIGHEST_USER_ADDRESS) ||
			((PVOID)((PCHAR)Buffer + BufferSize) > MM_HIGHEST_USER_ADDRESS)) {

			return STATUS_ACCESS_VIOLATION;
		}

		if (ARGUMENT_PRESENT(NumberOfBytesWritten)) {
			try {
				ProbeForWriteUlong_ptr(NumberOfBytesWritten);

			} except(EXCEPTION_EXECUTE_HANDLER) {
				return GetExceptionCode();
			}
		}
	}

	//
	// If the buffer size is not zero, then attempt to write data from the
	// current process address space into the target process address space.
	//

	BytesCopied = 0;
	Status = STATUS_SUCCESS;
	if (BufferSize != 0) {

		//
		// Reference the target process.
		//

		Status = ObReferenceObjectByHandle(ProcessHandle,
			0,
			*PsProcessType,
			PreviousMode,
			(PVOID *)&Process,
			NULL);

		//
		// If the process was successfully referenced, then attempt to
		// write the specified memory either by direct mapping or copying
		// through nonpaged pool.
		//

		if (Status == STATUS_SUCCESS) {

			Status = MmCopyVirtualMemory(PsGetCurrentProcess(),
				Buffer,
				Process,
				BaseAddress,
				BufferSize,
				PreviousMode,
				&BytesCopied);

			//
			// Dereference the target process.
			//

			ObDereferenceObject(Process);
		}
	}

	//
	// If requested, return the number of bytes read.
	//

	if (ARGUMENT_PRESENT(NumberOfBytesWritten)) {
		try {
			*NumberOfBytesWritten = BytesCopied;

		} except(EXCEPTION_EXECUTE_HANDLER) {
			NOTHING;
		}
	}

	return Status;
}


typedef ULONG WIN32_PROTECTION_MASK;
typedef PULONG PWIN32_PROTECTION_MASK;
typedef ULONG MM_PROTECTION_MASK;
typedef PULONG PMM_PROTECTION_MASK;

#define MM_ZERO_ACCESS         0  // this value is not used.
#define MM_READONLY            1
#define MM_EXECUTE             2
#define MM_EXECUTE_READ        3
#define MM_READWRITE           4  // bit 2 is set if this is writable.
#define MM_WRITECOPY           5
#define MM_EXECUTE_READWRITE   6
#define MM_EXECUTE_WRITECOPY   7

#define MM_NOCACHE            0x8
#define MM_GUARD_PAGE         0x10
#define MM_DECOMMIT           0x10   // NO_ACCESS, Guard page
#define MM_NOACCESS           0x18   // NO_ACCESS, Guard_page, nocache.
#define MM_UNKNOWN_PROTECTION 0x100  // bigger than 5 bits!

#define MM_INVALID_PROTECTION ((ULONG)-1)  // bigger than 5 bits!

#define MM_PROTECTION_WRITE_MASK     4
#define MM_PROTECTION_COPY_MASK      1
#define MM_PROTECTION_OPERATION_MASK 7 // mask off guard page and nocache.
#define MM_PROTECTION_EXECUTE_MASK   2

#define MM_SECURE_DELETE_CHECK 0x55


CCHAR MmUserProtectionToMask1[16] = {
	0,
	MM_NOACCESS,
	MM_READONLY,
	-1,
	MM_READWRITE,
	-1,
	-1,
	-1,
	MM_WRITECOPY,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1 };

CCHAR MmUserProtectionToMask2[16] = {
	0,
	MM_EXECUTE,
	MM_EXECUTE_READ,
	-1,
	MM_EXECUTE_READWRITE,
	-1,
	-1,
	-1,
	MM_EXECUTE_WRITECOPY,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1 };

#define MI_ADD_GUARD(ProtectCode)   (ProtectCode |= MM_GUARD_PAGE);
#define MI_IS_GUARD(ProtectCode)    ((ProtectCode >> 3) == (MM_GUARD_PAGE >> 3))

//
// Add no cache to the argument protection.
//

#define MI_ADD_NOCACHE(ProtectCode)     (ProtectCode |= MM_NOCACHE);
#define MI_IS_NOCACHE(ProtectCode)      ((ProtectCode >> 3) == (MM_NOCACHE >> 3))

//
// Add write combined to the argument protection.
//

#define MM_WRITECOMBINE (MM_NOCACHE | MM_GUARD_PAGE)
#define MI_ADD_WRITECOMBINE(ProtectCode)   (ProtectCode |= MM_WRITECOMBINE);
#define MI_IS_WRITECOMBINE(ProtectCode)    (((ProtectCode >> 3) == (MM_WRITECOMBINE >> 3)) && (ProtectCode & 0x7))

MM_PROTECTION_MASK FASTCALL MiMakeProtectionMask(IN WIN32_PROTECTION_MASK Win32Protect)
{
	ULONG Field1;
	ULONG Field2;
	MM_PROTECTION_MASK ProtectCode;

	if (Win32Protect >= (PAGE_WRITECOMBINE * 2)) {
		return MM_INVALID_PROTECTION;
	}

	Field1 = Win32Protect & 0xF;
	Field2 = (Win32Protect >> 4) & 0xF;

	//
	// Make sure at least one field is set.
	//

	if (Field1 == 0) {
		if (Field2 == 0) {

			//
			// Both fields are zero, return failure.
			//

			return MM_INVALID_PROTECTION;
		}
		ProtectCode = MmUserProtectionToMask2[Field2];
	}
	else {
		if (Field2 != 0) {
			//
			//  Both fields are non-zero, return failure.
			//

			return MM_INVALID_PROTECTION;
		}
		ProtectCode = MmUserProtectionToMask1[Field1];
	}

	if (ProtectCode == -1) {
		return MM_INVALID_PROTECTION;
	}

	if (Win32Protect & PAGE_GUARD) {

		if ((ProtectCode == MM_NOACCESS) ||
			(Win32Protect & (PAGE_NOCACHE | PAGE_WRITECOMBINE))) {

			//
			// Invalid protection -
			// guard and either no access, no cache or write combine.
			//

			return MM_INVALID_PROTECTION;
		}

		MI_ADD_GUARD(ProtectCode);
	}

	if (Win32Protect & PAGE_NOCACHE) {

		ASSERT((Win32Protect & PAGE_GUARD) == 0);  // Already checked above

		if ((ProtectCode == MM_NOACCESS) ||
			(Win32Protect & PAGE_WRITECOMBINE)) {

			//
			// Invalid protection -
			// nocache and either no access or write combine.
			//

			return MM_INVALID_PROTECTION;
		}

		MI_ADD_NOCACHE(ProtectCode);
	}

	if (Win32Protect & PAGE_WRITECOMBINE) {

		ASSERT((Win32Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0);  // Already checked above

		if (ProtectCode == MM_NOACCESS) {

			//
			// Invalid protection, no access and write combine.
			//

			return MM_INVALID_PROTECTION;
		}

		MI_ADD_WRITECOMBINE(ProtectCode);
	}

	return ProtectCode;
}



NTSTATUS MiProtectVirtualMemory(
	IN PEPROCESS Process,
	IN PVOID *BaseAddress,
	IN PSIZE_T RegionSize,
	IN WIN32_PROTECTION_MASK NewProtectWin32,
	IN PWIN32_PROTECTION_MASK LastProtect
) 
{
	typedef NTSTATUS (*MiProtectVirtualMemoryProc)(
		IN PEPROCESS Process,
		IN PVOID *BaseAddress,
		IN PSIZE_T RegionSize,
		IN WIN32_PROTECTION_MASK NewProtectWin32,
		IN PWIN32_PROTECTION_MASK LastProtect
	);

	static MiProtectVirtualMemoryProc MiProtectVirtualMemoryFunc = NULL;

	if (!MiProtectVirtualMemoryFunc)
	{
		//¿ªÊ¼ËÑ
		PUCHAR temp = (PUCHAR)GetNtProtectVirtualMemoryFunc();

		for (int i = 0; i < 400; i++)
		{
			if (temp[i] == 0x48 && temp[i + 1] == 0x8D &&
				temp[i + 5] == 0x48 && temp[i + 6] == 0x8b &&
				temp[i + 8] == 0xe8)
			{
				ULONG64 currentAddr = (ULONG64)(temp + i + 8);
				LONG64 offset = *(PLONG)(currentAddr + 1);
				MiProtectVirtualMemoryFunc = (MiProtectVirtualMemoryProc)(currentAddr + 5 + offset);
				break;
			}
		}

		//MiProtectVirtualMemoryFunc = (MiProtectVirtualMemoryProc)SearchNtFuncHead("4C8B224C89***4C89***65********4889******418BC9E8****448BC88944**83");
	}
	
	if (MiProtectVirtualMemoryFunc)
	{
		return MiProtectVirtualMemoryFunc(Process, BaseAddress, RegionSize, NewProtectWin32, LastProtect);
	}

	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI HotGeNtProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
)
{
	KAPC_STATE ApcState;
	PEPROCESS Process;
	KPROCESSOR_MODE PreviousMode;
	NTSTATUS Status;
	ULONG Attached = FALSE;
	PVOID CapturedBase;
	SIZE_T CapturedRegionSize;
	ULONG ProtectionMask;
	ULONG LastProtect = 0;
	PETHREAD CurrentThread;
	PEPROCESS CurrentProcess;

	PAGED_CODE();

	//
	// Check the protection field.
	//

	ProtectionMask = MiMakeProtectionMask(NewProtect);

	if (ProtectionMask == MM_INVALID_PROTECTION) {
		return STATUS_INVALID_PAGE_PROTECTION;
	}

	CurrentThread = PsGetCurrentThread();

	CurrentProcess = PsGetCurrentProcess();

	PreviousMode = ExGetPreviousMode();

	if (PreviousMode != KernelMode) {

		//
		// Capture the region size and base address under an exception handler.
		//

		try {

			ProbeForWritePointer(BaseAddress);
			ProbeForWriteUlong_ptr(RegionSize);
			ProbeForWriteUlong(OldProtect);

			//
			// Capture the region size and base address.
			//

			CapturedBase = *BaseAddress;
			CapturedRegionSize = *RegionSize;

		} except(EXCEPTION_EXECUTE_HANDLER) {

			//
			// If an exception occurs during the probe or capture
			// of the initial values, then handle the exception and
			// return the exception code as the status value.
			//

			return GetExceptionCode();
		}
	}
	else {

		//
		// Capture the region size and base address.
		//

		CapturedRegionSize = *RegionSize;
		CapturedBase = *BaseAddress;
	}

	//
	// Make sure the specified starting and ending addresses are
	// within the user part of the virtual address space.
	//

	if (CapturedBase > MM_HIGHEST_USER_ADDRESS) {

		//
		// Invalid base address.
		//

		return STATUS_INVALID_PARAMETER_2;
	}

	if ((ULONG_PTR)MM_HIGHEST_USER_ADDRESS - (ULONG_PTR)CapturedBase <
		CapturedRegionSize) {

		//
		// Invalid region size;
		//

		return STATUS_INVALID_PARAMETER_3;
	}

	if (CapturedRegionSize == 0) {
		return STATUS_INVALID_PARAMETER_3;
	}

	Status = ObReferenceObjectByHandle(ProcessHandle,
		0,
		*PsProcessType,
		PreviousMode,
		(PVOID *)&Process,
		NULL);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	//
	// If the specified process is not the current process, attach
	// to the specified process.
	//

	if (CurrentProcess != Process) {
		KeStackAttachProcess(Process, &ApcState);
		Attached = TRUE;
	}

	Status = MiProtectVirtualMemory(Process,
		&CapturedBase,
		&CapturedRegionSize,
		NewProtect,
		&LastProtect);


	if (Attached) {
		KeUnstackDetachProcess(&ApcState);
	}

	ObDereferenceObject(Process);

	//
	// Establish an exception handler and write the size and base
	// address.
	//

	try {

		*RegionSize = CapturedRegionSize;
		*BaseAddress = CapturedBase;
		*OldProtect = LastProtect;

	} except(EXCEPTION_EXECUTE_HANDLER) {
		NOTHING;
	}

	return Status;
}



NTSTATUS HotGeNtSetContextThread(
	__in HANDLE ThreadHandle,
	__in PCONTEXT ThreadContext
)
{
	KPROCESSOR_MODE Mode;
	NTSTATUS Status;
	PETHREAD Thread;
	PETHREAD CurrentThread;

	PAGED_CODE();

	//
	// Get previous mode and reference specified thread.
	//

	CurrentThread = PsGetCurrentThread();
	Mode = ExGetPreviousMode();

	Status = ObReferenceObjectByHandle(ThreadHandle,
		0,
		*PsThreadType,
		Mode,
		&Thread,
		NULL);

	//
	// If the reference was successful, the check if the specified thread
	// is a system thread.
	//

	if (NT_SUCCESS(Status)) {

		//
		// If the thread is not a system thread, then attempt to get the
		// context of the thread.
		//

		if (IoIsSystemThread(Thread) == FALSE) {

			wchar_t wa_PsSetContextThread[] = { 0xE3B3, 0xE390, 0xE3B0, 0xE386, 0xE397, 0xE3A0, 0xE38C, 0xE38D, 0xE397, 0xE386, 0xE39B, 0xE397, 0xE3B7, 0xE38B, 0xE391, 0xE386, 0xE382, 0xE387, 0xE3E3, 0xE3E3 };

			for (int i = 0; i < 20; i++)
			{
				wa_PsSetContextThread[i] ^= 0x6D6D;
				wa_PsSetContextThread[i] ^= 0x8E8E;
			};

			typedef NTSTATUS(*PsSetContextThreadProc)(
				__in PETHREAD Thread,
				__in PCONTEXT ThreadContext,
				__in KPROCESSOR_MODE Mode
				);

			UNICODE_STRING unFuncNamePsSetContextThread = { 0 };
			RtlInitUnicodeString(&unFuncNamePsSetContextThread, wa_PsSetContextThread);
			PsSetContextThreadProc PsSetContextThreadFunc = (PsSetContextThreadProc)MmGetSystemRoutineAddress(&unFuncNamePsSetContextThread);

			DbgPrintEx(77, 0, "[db]:%s set dr0 = %llx,dr7=%llx\r\n", PsGetProcessImageFileName(IoGetCurrentProcess()), ThreadContext->Dr0, ThreadContext->Dr7);

			Status = PsSetContextThreadFunc(Thread, ThreadContext, Mode);

		}
		else {
			Status = STATUS_INVALID_HANDLE;
		}

		ObDereferenceObject(Thread);
	}

	return Status;
}

NTSTATUS HotGeNtGetContextThread(
	__in HANDLE ThreadHandle,
	__inout PCONTEXT ThreadContext
)
{
	KPROCESSOR_MODE Mode;
	NTSTATUS Status;
	PETHREAD Thread;
	PETHREAD CurrentThread;

	PAGED_CODE();

	//
	// Get previous mode and reference specified thread.
	//

	CurrentThread = PsGetCurrentThread();
	Mode = ExGetPreviousMode();

	Status = ObReferenceObjectByHandle(ThreadHandle,
		0,
		*PsThreadType,
		Mode,
		&Thread,
		NULL);

	//
	// If the reference was successful, the check if the specified thread
	// is a system thread.
	//

	if (NT_SUCCESS(Status)) {

		//
		// If the thread is not a system thread, then attempt to get the
		// context of the thread.
		//
		
		if (IoIsSystemThread(Thread) == FALSE) {

			wchar_t wa_PsGetContextThread[] = { 0xE3B3, 0xE390, 0xE3A4, 0xE386, 0xE397, 0xE3A0, 0xE38C, 0xE38D, 0xE397, 0xE386, 0xE39B, 0xE397, 0xE3B7, 0xE38B, 0xE391, 0xE386, 0xE382, 0xE387, 0xE3E3, 0xE3E3 };

			for (int i = 0; i < 20; i++)
			{
				wa_PsGetContextThread[i] ^= 0x6D6D;
				wa_PsGetContextThread[i] ^= 0x8E8E;
			};


			typedef NTSTATUS(*PsGetContextThreadProc)(
				__in PETHREAD Thread,
				__in PCONTEXT ThreadContext,
				__in KPROCESSOR_MODE Mode
				);


			UNICODE_STRING unFuncNamePsGetContextThread = { 0 };
			RtlInitUnicodeString(&unFuncNamePsGetContextThread, wa_PsGetContextThread);
			PsGetContextThreadProc PsGetContextThreadFunc = (PsGetContextThreadProc)MmGetSystemRoutineAddress(&unFuncNamePsGetContextThread);


		
			Status = PsGetContextThreadFunc(Thread, ThreadContext, Mode);
			if (Mode == UserMode)
			{
				DbgPrintEx(77, 0, "[db]:%s get dr0 = %llx,dr7=%llx\r\n", PsGetProcessImageFileName(IoGetCurrentProcess()), ThreadContext->Dr0, ThreadContext->Dr7);
				//ThreadContext->Dr7 = 0x400;
				//ThreadContext->Dr0 = 0;
				//ThreadContext->Dr1 = 0;
				//ThreadContext->Dr2 = 0;
				//ThreadContext->Dr3 = 0;
			}
			
			

		}
		else {
			Status = STATUS_INVALID_HANDLE;
		}

		ObDereferenceObject(Thread);
	}

	return Status;

}