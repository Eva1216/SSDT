#include "stdafx.h"
#include <windows.h>
#include <winnt.h>
#include <WindowsX.h>
#include <commctrl.h>
#include <stdio.h>
 
#define ibaseDD *(PDWORD)&ibase

HINSTANCE g_hInst;
HWND hWinMain, hList;
#define ID_LISTVIEW 104
#pragma comment(lib,"comctl32")

#define RVATOVA(base,offset) ((PVOID)((DWORD)(base)+(DWORD)(offset)))
#define ibaseDD *(PDWORD)&ibase
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct {
	WORD    offset : 12;
	WORD    type : 4;
} IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;


typedef ULONG(WINAPI *ZWQUERYSYSTEMINFORMATION)(
	DWORD    SystemInformationClass,
	PVOID    SystemInformation,
	ULONG    SystemInformationLength,
	PULONG    ReturnLength);
ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = NULL;

typedef enum _SYSDBG_COMMAND {
	// 以下是NT 5.1 新增的
	//从内核空间拷贝到用户空间，或者从用户空间拷贝到用户空间
	//但是不能从用户空间拷贝到内核空间    
	SysDbgReadVirtualMemory = 8,

	//从用户空间拷贝到内核空间，或者从用户空间拷贝到用户空间
	//但是不能从内核空间拷贝到用户空间    
	SysDbgWriteVirtualMemory = 9,

} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

typedef struct _MEMORY_CHUNKS {
	ULONG Address;
	PVOID Data;
	ULONG Length;
}MEMORY_CHUNKS, *PMEMORY_CHUNKS;

typedef NTSTATUS(NTAPI * ZWSYSTEMDEBUGCONTROL) (
	SYSDBG_COMMAND ControlCode,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength,
	PULONG ReturnLength
	);

ZWSYSTEMDEBUGCONTROL ZwSystemDebugControl = NULL;

typedef struct _SYSTEM_MODULE_INFORMATION { //Information Class 11
	ULONG    Reserved[2];
	PVOID    Base;
	ULONG    Size;
	ULONG    Flags;
	USHORT    Index;
	USHORT    Unknown;
	USHORT    LoadCount;
	USHORT    ModuleNameOffset;
	CHAR    ImageName[256];
}SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

#define    SystemModuleInformation    11

typedef struct
{
	CHAR fname[100];
	ULONG address1;
	ULONG address2;
} SSDT_LIST_ENTRY;

SSDT_LIST_ENTRY *ssdt_list;

/////////////////////////////////////////////////////////////////////////
BOOL LocateNtdllEntry()
{
	HMODULE ntdll_dll = NULL;

	if (!(ntdll_dll = GetModuleHandle("ntdll.dll"))) return FALSE;
	if (!(ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(ntdll_dll, "ZwQuerySystemInformation")))
		return FALSE;
	if (!(ZwSystemDebugControl = (ZWSYSTEMDEBUGCONTROL)GetProcAddress(ntdll_dll, "ZwSystemDebugControl")))
		return FALSE;

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////
BOOL DebugPrivilege(TCHAR *PName, BOOL bEnable)
{
	BOOL              fOk = FALSE;
	HANDLE            hToken;
	TOKEN_PRIVILEGES  tp;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
		LookupPrivilegeValue(NULL, PName, &tp.Privileges[0].Luid);
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;
}

//////////////////////////////////////////////////////////////////////////
DWORD GetHeaders(PCHAR ibase,
	PIMAGE_FILE_HEADER *pfh,
	PIMAGE_OPTIONAL_HEADER *poh,
	PIMAGE_SECTION_HEADER *psh)

{
	PIMAGE_DOS_HEADER mzhead = (PIMAGE_DOS_HEADER)ibase;

	if ((mzhead->e_magic != IMAGE_DOS_SIGNATURE) ||
		(ibaseDD[mzhead->e_lfanew] != IMAGE_NT_SIGNATURE))
		return FALSE;

	*pfh = (PIMAGE_FILE_HEADER)&ibase[mzhead->e_lfanew];
	if (((PIMAGE_NT_HEADERS)*pfh)->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	*pfh = (PIMAGE_FILE_HEADER)((PBYTE)*pfh + sizeof(IMAGE_NT_SIGNATURE));

	*poh = (PIMAGE_OPTIONAL_HEADER)((PBYTE)*pfh + sizeof(IMAGE_FILE_HEADER));
	if ((*poh)->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return FALSE;

	*psh = (PIMAGE_SECTION_HEADER)((PBYTE)*poh + sizeof(IMAGE_OPTIONAL_HEADER));
	return TRUE;
}


//////////////////////////////////////////////////////////////////////////
// 搜索函数名称
//////////////////////////////////////////////////////////////////////////
void FindExport()
{
	PIMAGE_FILE_HEADER    pfh;
	PIMAGE_OPTIONAL_HEADER    poh;
	PIMAGE_SECTION_HEADER    psh;
	PIMAGE_EXPORT_DIRECTORY ped;
	DWORD *arrayOfFunctionNames;
	DWORD* arrayOfFunctionAddresses;
	WORD* arrayOfFunctionOrdinals;
	DWORD functionOrdinal, functionAddress;

	HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
	GetHeaders((PCHAR)hNtdll, &pfh, &poh, &psh);
	if (poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
	{
		ped = (PIMAGE_EXPORT_DIRECTORY)(poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (BYTE*)hNtdll);
		arrayOfFunctionNames = (DWORD*)(ped->AddressOfNames + (BYTE*)hNtdll);
		arrayOfFunctionAddresses = (DWORD*)((BYTE*)hNtdll + ped->AddressOfFunctions);
		arrayOfFunctionNames = (DWORD*)((BYTE*)hNtdll + ped->AddressOfNames);
		arrayOfFunctionOrdinals = (WORD*)((BYTE*)hNtdll + ped->AddressOfNameOrdinals);

		for (int i = 0; i<ped->NumberOfNames; i++)
		{
			char* fun_name = (char*)((BYTE*)hNtdll + arrayOfFunctionNames[i]);
			functionOrdinal = arrayOfFunctionOrdinals[i] + ped->Base - 1;
			functionAddress = (DWORD)((BYTE*)hNtdll + arrayOfFunctionAddresses[functionOrdinal]);
			if (fun_name[0] == 'N'&&fun_name[1] == 't')
			{
				WORD number = *((WORD*)(functionAddress + 1));
				if (number>ped->NumberOfNames) continue;
				lstrcpy(ssdt_list[number].fname, fun_name);
			}
		}
	}
}

DWORD FindKiServiceTable(HMODULE hModule, DWORD dwKSDT)
{
	PIMAGE_FILE_HEADER    pfh;
	PIMAGE_OPTIONAL_HEADER    poh;
	PIMAGE_SECTION_HEADER    psh;
	PIMAGE_BASE_RELOCATION    pbr;
	PIMAGE_FIXUP_ENTRY    pfe;

	DWORD    dwFixups = 0, i, dwPointerRva, dwPointsToRva, dwKiServiceTable;
	BOOL    bFirstChunk;

	GetHeaders((PCHAR)hModule, &pfh, &poh, &psh);

	// loop thru relocs to speed up the search
	if ((poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) &&
		(!((pfh->Characteristics)&IMAGE_FILE_RELOCS_STRIPPED))) {

		pbr = (PIMAGE_BASE_RELOCATION)RVATOVA(poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, hModule);

		bFirstChunk = TRUE;
		// 1st IMAGE_BASE_RELOCATION.VirtualAddress of ntoskrnl is 0
		while (bFirstChunk || pbr->VirtualAddress) {
			bFirstChunk = FALSE;

			pfe = (PIMAGE_FIXUP_ENTRY)((DWORD)pbr + sizeof(IMAGE_BASE_RELOCATION));

			for (i = 0; i<(pbr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) >> 1; i++, pfe++) {
				if (pfe->type == IMAGE_REL_BASED_HIGHLOW) {
					dwFixups++;
					dwPointerRva = pbr->VirtualAddress + pfe->offset;
					// DONT_RESOLVE_DLL_REFERENCES flag means relocs aren't fixed
					dwPointsToRva = *(PDWORD)((DWORD)hModule + dwPointerRva) - (DWORD)poh->ImageBase;

					// does this reloc point to KeServiceDescriptorTable.Base?
					if (dwPointsToRva == dwKSDT) {
						// check for mov [mem32],imm32. we are trying to find 
						// "mov ds:_KeServiceDescriptorTable.Base, offset _KiServiceTable"
						// from the KiInitSystem.
						if (*(PWORD)((DWORD)hModule + dwPointerRva - 2) == 0x05c7) {
							// should check for a reloc presence on KiServiceTable here
							// but forget it
							dwKiServiceTable = *(PDWORD)((DWORD)hModule + dwPointerRva + 4) - poh->ImageBase;
							return dwKiServiceTable;
						}
					}

				}
				// should never get here
			}
			*(PDWORD)&pbr += pbr->SizeOfBlock;
		}
	}

	return 0;
}

DWORD    dwKSDT;                // rva of KeServiceDescriptorTable
DWORD    dwKiServiceTable;    // rva of KiServiceTable
DWORD    dwKernelBase, dwServices = 0;
//////////////////////////////////////////////////////////////////////////
void GetSSDT()
{
	HMODULE    hKernel;
	PCHAR    pKernelName;
	PDWORD    pService;
	PIMAGE_FILE_HEADER    pfh;
	PIMAGE_OPTIONAL_HEADER    poh;
	PIMAGE_SECTION_HEADER    psh;

	ULONG n;

	// get system modules - ntoskrnl is always first there

	ZwQuerySystemInformation(SystemModuleInformation, &n, 0, &n);
	PULONG p = new ULONG[n];
	ZwQuerySystemInformation(SystemModuleInformation, p, n * sizeof(*p), 0);
	PSYSTEM_MODULE_INFORMATION module = PSYSTEM_MODULE_INFORMATION(p + 1);

	// imagebase
	dwKernelBase = (DWORD)module->Base;
	// filename - it may be renamed in the boot.ini
	pKernelName = module->ModuleNameOffset + module->ImageName;

	// map ntoskrnl - hopefully it has relocs
	hKernel = LoadLibraryEx(pKernelName, 0, DONT_RESOLVE_DLL_REFERENCES);
	if (!hKernel) {
		return;
	}

	// our own export walker is useless here - we have GetProcAddress :)
	if (!(dwKSDT = (DWORD)GetProcAddress(hKernel, "KeServiceDescriptorTable"))) {
		return;
	}

	// get KeServiceDescriptorTable rva
	dwKSDT -= (DWORD)hKernel;
	// find KiServiceTable
	if (!(dwKiServiceTable = FindKiServiceTable(hKernel, dwKSDT))) {
		return;
	}

	// let's dump KiServiceTable contents

	// MAY FAIL!!!
	// should get right ServiceLimit here, but this is trivial in the kernel mode
	GetHeaders((PCHAR)hKernel, &pfh, &poh, &psh);
	dwServices = 0;

	for (pService = (PDWORD)((DWORD)hKernel + dwKiServiceTable);
		*pService - poh->ImageBase<poh->SizeOfImage;
		pService++, dwServices++)
	{
		ssdt_list[dwServices].address1 = *pService - poh->ImageBase + dwKernelBase;
	}
	FreeLibrary(hKernel);
	//读取现在的
	MEMORY_CHUNKS QueryBuff;
	DWORD *address2 = new DWORD[dwServices];
	QueryBuff.Address = dwKernelBase + dwKiServiceTable;
	QueryBuff.Data = address2;
	QueryBuff.Length = sizeof(DWORD)*dwServices;
	DWORD ReturnLength;
	ZwSystemDebugControl
	(
		SysDbgReadVirtualMemory,
		&QueryBuff,
		sizeof(MEMORY_CHUNKS),
		NULL,
		0,
		&ReturnLength
	);

	//LV_ITEM lvi;
	//lvi.mask = LVIF_TEXT;
	char tmp[10];
	//ListView_DeleteAllItems(hList);
	for (int j = 0; j<dwServices; j++)
	{
		if (ssdt_list[j].address1 != address2[j])
		{
			wsprintf(tmp, "0x%02X", j);
			printf("SSDT Hook Func Index:%d\r\n", j);

			wsprintf(tmp, "0x%08X", ssdt_list[j].address1);
			printf("%s Original Address:%x\r\n", ssdt_list[j].fname, ssdt_list[j].address1);

			wsprintf(tmp, "0x%08X", address2[j]);

			ssdt_list[j].address2 = address2[j];
			printf("%s Fake	Address:%x\r\n", ssdt_list[j].fname, ssdt_list[j].address1);

			//搜索模块
			for (int i = 0; i<*p; i++)
			{
				if (ssdt_list[j].address2>(DWORD)module[i].Base&&ssdt_list[j].address2<(DWORD)module[i].Base + module[i].Size)
				{
					//ListView_SetItemText(hList, j, 4, module[i].ImageName);
					printf("ImageName:%s\r\n\r\n\r\n", module[i].ImageName);
					break;
				}
			}
		}
		
	}

	delete[] p;
	delete[] address2;
}



int main()
{
	ssdt_list = new SSDT_LIST_ENTRY[500];
	LocateNtdllEntry();
	FindExport();
	DebugPrivilege(SE_DEBUG_NAME, TRUE);
	GetSSDT();
	getchar();
	getchar();
	delete[] ssdt_list;

}