/*
*	Module Name:
*		ntint.h
*
*	Abstract:
*		Header file that defines Windows-specific types and structures. An
*		extension of Windows.h.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*
*	Special thanks to Nemanja (Nemi) Mulasmajic <nm@triplefault.io>
*	for his help with the POC.
*
*/

#pragma once

#define EtwpStartTrace		1
#define EtwpStopTrace		2
#define EtwpQueryTrace		3
#define EtwpUpdateTrace		4
#define EtwpFlushTrace		5

#define WNODE_FLAG_TRACED_GUID			0x00020000  // denotes a trace
#define EVENT_TRACE_BUFFERING_MODE      0x00000400  // Buffering mode only
#define EVENT_TRACE_FLAG_SYSTEMCALL     0x00000080  // system calls

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES	16
#define IMAGE_SIZEOF_SHORT_NAME             8

#define IA32_LSTAR_MSR 0xC0000082

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;






typedef struct _IMAGE_EXPORT_DIRECTORY {
	ULONG   Characteristics;
	ULONG   TimeDateStamp;
	USHORT  MajorVersion;
	USHORT  MinorVersion;
	ULONG   Name;
	ULONG   Base;
	ULONG   NumberOfFunctions;
	ULONG   NumberOfNames;
	ULONG   AddressOfFunctions;     // RVA from base of image
	ULONG   AddressOfNames;         // RVA from base of image
	ULONG   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	USHORT e_magic;                     // Magic number
	USHORT e_cblp;                      // Bytes on last page of file
	USHORT e_cp;                        // Pages in file
	USHORT e_crlc;                      // Relocations
	USHORT e_cparhdr;                   // Size of header in paragraphs
	USHORT e_minalloc;                  // Minimum extra paragraphs needed
	USHORT e_maxalloc;                  // Maximum extra paragraphs needed
	USHORT e_ss;                        // Initial (relative) SS value
	USHORT e_sp;                        // Initial SP value
	USHORT e_csum;                      // Checksum
	USHORT e_ip;                        // Initial IP value
	USHORT e_cs;                        // Initial (relative) CS value
	USHORT e_lfarlc;                    // File address of relocation table
	USHORT e_ovno;                      // Overlay number
	USHORT e_res[4];                    // Reserved words
	USHORT e_oemid;                     // OEM identifier (for e_oeminfo)
	USHORT e_oeminfo;                   // OEM information; e_oemid specific
	USHORT e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG		VirtualAddress;
	ULONG		Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_SECTION_HEADER {
	UCHAR		Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		ULONG	PhysicalAddress;
		ULONG	VirtualSize;
	} Misc;
	ULONG   VirtualAddress;
	ULONG   SizeOfRawData;
	ULONG   PointerToRawData;
	ULONG   PointerToRelocations;
	ULONG   PointerToLinenumbers;
	USHORT  NumberOfRelocations;
	USHORT  NumberOfLinenumbers;
	ULONG   Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	USHORT      Magic;
	UCHAR       MajorLinkerVersion;
	UCHAR       MinorLinkerVersion;
	ULONG       SizeOfCode;
	ULONG       SizeOfInitializedData;
	ULONG       SizeOfUninitializedData;
	ULONG       AddressOfEntryPoint;
	ULONG       BaseOfCode;
	ULONGLONG   ImageBase;
	ULONG       SectionAlignment;
	ULONG       FileAlignment;
	USHORT      MajorOperatingSystemVersion;
	USHORT      MinorOperatingSystemVersion;
	USHORT      MajorImageVersion;
	USHORT      MinorImageVersion;
	USHORT      MajorSubsystemVersion;
	USHORT      MinorSubsystemVersion;
	ULONG       Win32VersionValue;
	ULONG       SizeOfImage;
	ULONG       SizeOfHeaders;
	ULONG       CheckSum;
	USHORT      Subsystem;
	USHORT      DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	ULONG       LoaderFlags;
	ULONG       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_FILE_HEADER {
	USHORT		Machine;
	USHORT		NumberOfSections;
	ULONG		TimeDateStamp;
	ULONG		PointerToSymbolTable;
	ULONG		NumberOfSymbols;
	USHORT		SizeOfOptionalHeader;
	USHORT		Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS64 {
	ULONG                   Signature;
	IMAGE_FILE_HEADER       FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _WNODE_HEADER
{
	ULONG BufferSize;        // Size of entire buffer inclusive of this ULONG
	ULONG ProviderId;    // Provider Id of driver returning this buffer
	union
	{
		ULONG64 HistoricalContext;  // Logger use
		struct
		{
			ULONG Version;           // Reserved
			ULONG Linkage;           // Linkage field reserved for WMI
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	union
	{
		ULONG CountLost;         // Reserved
		HANDLE KernelHandle;     // Kernel handle for data block
		LARGE_INTEGER TimeStamp; // Timestamp as returned in units of 100ns
								 // since 1/1/1601
	} DUMMYUNIONNAME2;
	GUID Guid;                  // Guid for data block returned with results
	ULONG ClientContext;
	ULONG Flags;             // Flags, see below
} WNODE_HEADER, *PWNODE_HEADER;

typedef struct _EVENT_TRACE_PROPERTIES {
	WNODE_HEADER	Wnode;
	ULONG			BufferSize;
	ULONG			MinimumBuffers;
	ULONG			MaximumBuffers;
	ULONG			MaximumFileSize;
	ULONG			LogFileMode;
	ULONG			FlushTimer;
	ULONG			EnableFlags;
	LONG			AgeLimit;
	ULONG			NumberOfBuffers;
	ULONG			FreeBuffers;
	ULONG			EventsLost;
	ULONG			BuffersWritten;
	ULONG			LogBuffersLost;
	ULONG			RealTimeBuffersLost;
	HANDLE			LoggerThreadId;
	ULONG			LogFileNameOffset;
	ULONG			LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, *PEVENT_TRACE_PROPERTIES;

NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader (_In_ PVOID ModuleAddress);
