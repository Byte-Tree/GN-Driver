#pragma once
#include "../pch.h"
#include "mx64/mx64.h"
#include "VirtualAddressDescription/VirtualAddressDescription.h"

#define PAGE_OFFSET_SIZE 12
typedef PVOID(*PsGetProcessSectionBaseAddress)(PEPROCESS Process);
typedef NTSTATUS(*pZwProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG ProtectSize, ULONG NewProtect, PULONG OldProtect);
typedef struct HardwarePteX64 {
	ULONG64 valid : 1;               //!< [0]
	ULONG64 write : 1;               //!< [1]
	ULONG64 owner : 1;               //!< [2]
	ULONG64 write_through : 1;       //!< [3]
	ULONG64 cache_disable : 1;       //!< [4]
	ULONG64 accessed : 1;            //!< [5]
	ULONG64 dirty : 1;               //!< [6]
	ULONG64 large_page : 1;          //!< [7]
	ULONG64 global : 1;              //!< [8]
	ULONG64 copy_on_write : 1;       //!< [9]
	ULONG64 prototype : 1;           //!< [10]
	ULONG64 reserved0 : 1;           //!< [11]
	ULONG64 page_frame_number : 36;  //!< [12:47]
	ULONG64 reserved1 : 4;           //!< [48:51]
	ULONG64 software_ws_index : 11;  //!< [52:62]
	ULONG64 no_execute : 1;          //!< [63]
}HardwarePte, * PHardwarePte;
typedef struct _MLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY64    InLoadOrderLinks;
	LIST_ENTRY64    InMemoryOrderLinks;
	LIST_ENTRY64    InInitializationOrderLinks;
	PVOID            DllBase;
	PVOID            EntryPoint;
	ULONG            SizeOfImage;
	UNICODE_STRING    FullDllName;
	UNICODE_STRING     BaseDllName;
	ULONG            Flags;
	USHORT            LoadCount;
	USHORT            TlsIndex;
	PVOID            SectionPointer;
	ULONG            CheckSum;
	PVOID            LoadedImports;
	PVOID            EntryPointActivationContext;
	PVOID            PatchInformation;
	LIST_ENTRY64    ForwarderLinks;
	LIST_ENTRY64    ServiceTagLinks;
	LIST_ENTRY64    StaticLinks;
	PVOID            ContextInformation;
	ULONG64            OriginalBase;
	LARGE_INTEGER    LoadTime;
} MLDR_DATA_TABLE_ENTRY, * PMLDR_DATA_TABLE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY64
{
	ULONG Reserved[4];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY64, * PSYSTEM_MODULE_INFORMATION_ENTRY64;
typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;//内核中以加载的模块的个数
	SYSTEM_MODULE_INFORMATION_ENTRY64 Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

#define PROCESS_ACTIVE_PROCESS_LINKS_OFFSET 0x2f0//0x188 0x2e8
#define LDR_OFFSET_IN_PEB 0x018
#define InLoadOrderModuleList_OFFSET 0x010
#define PROCESSPARAMETERS_OFFSET_IN_PEB 0x20

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// Read/Write Process Memory By CR3 Define:
//////////////////////////////////////////////////////////////////////////////////////////////////////////
#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180
//#define WINDOWS_22H2 22621
//#define WINDOWS_23H2 22631
#define PAGE_OFFSET_SIZE 12

extern "C" NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);

//恢复vad的结构
struct RESTORE_VAD
{
	HANDLE pid;
	MMVAD old_vad;
	PMMVAD p_current_vad;
};


class MemoryTools
{
private:
	pZwProtectVirtualMemory ZwProtectVirtualMemory = 0;
	ULONG64 system_version_number = 0;
	RTL_OSVERSIONINFOEXW system_version = { NULL };
	RTL_OSVERSIONINFOEXW GetOsVersionNumber();
	
//////////////////////////////////////////////////////////////////////////////////////////////////////////
// Hide Memory By VAD:
//////////////////////////////////////////////////////////////////////////////////////////////////////////
private:
	int m_eprocess_vadroot_offset = 0;
	RESTORE_VAD old_vad[10] = { NULL };
	bool hide_vad_status = false;
	DWORD hide_vad_count = 0;

public:
	void* operator new(size_t size, POOL_TYPE pool_type = NonPagedPool);
	void operator delete(void* pointer);

public:
	MemoryTools();
	~MemoryTools();
	PVOID64 MDLReadMemory(IN HANDLE pid, IN DWORD64 address, IN ULONG size);
	DWORD ReadDWORD(IN DWORD64 address);
	int ReadInt(IN DWORD64 address);
	DWORD64 ReadDWORD64(IN DWORD64 address);
	__int64 ReadInt64(IN DWORD64 address);
	bool WriteDWORD(IN DWORD64 address, IN DWORD data);
	bool WriteInt(IN DWORD64 address, IN int data);
	bool WriteDWORD64(IN DWORD64 address, IN DWORD64 data);
	bool WriteInt64(IN DWORD64 address, IN __int64 data);
	PVOID AllocateMemory(IN HANDLE pid, IN ULONG64 allocsize, IN ULONG protect);
	NTSTATUS FreeMemory(IN HANDLE pid, IN ULONG64 free_address, IN ULONG64 memory_size);
	ULONG SetMemoryProtect(IN HANDLE pid, IN PVOID address, IN SIZE_T size, IN ULONG protect);
	NTSTATUS StartHook(IN __int64 address, IN __int64 my_func_address);
	HMODULE GetModuleHandle(IN HANDLE pid, IN const wchar_t* module_name);
	PVOID GetModuleHandleImageSize(IN HANDLE pid, IN const wchar_t* module_name);
	PVOID GetKernelModuleByZwQuerySystemInformation(IN const char* modulename, OUT ULONG* module_size);
	BYTE* ToBytes(DWORD64 num);
	ULONGLONG GetPspNotifyEnableMask();
	NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED* Dst, IN CONST VOID UNALIGNED* Src, IN ULONG Length);

	//////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Set memory page pte:
	//////////////////////////////////////////////////////////////////////////////////////////////////////////
private:
	ULONG64 PTE_BASE, PDE_BASE, PPE_BASE, PXE_BASE;
	ULONG64 GetPteAddress(IN PVOID addr);
	ULONG64 GetPdeAddress(IN PVOID addr);
	ULONG64 GetPpeAddress(IN PVOID addr);
	ULONG64 GetPxeAddress(IN PVOID addr);
	ULONG64 GetPteBase();
	void InitPTE();
public:
	void SetMemoryPage(IN ULONG64 virtualaddress, IN ULONG size);

public:
	BOOLEAN SetExecutePage(IN HANDLE pid, IN ULONG64 virtualaddress, IN ULONG size);

	//////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Read/Write Process Memory By MDL:
	//////////////////////////////////////////////////////////////////////////////////////////////////////////
private:
	NTSTATUS ReadProcessMemoryByMDL(IN HANDLE pid, IN PVOID address, OUT PVOID out_data, IN ULONG size);
	NTSTATUS WriteProcessMemoryByMDL(IN HANDLE pid, IN PVOID address, IN PVOID write_data, IN ULONG size);
public:
	NTSTATUS ReadMemoryByMDL(IN ULONG pid, IN PVOID address, IN ULONG size, OUT PVOID read_buffer);
	NTSTATUS WriteMemoryByMDL(IN ULONG pid, IN PVOID address, OUT PVOID write_data, IN ULONG size);

	//////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Read/Write Process Memory By CR3 No Attacht:
	//////////////////////////////////////////////////////////////////////////////////////////////////////////
private:
	static const uint64_t PMASK = (~0xfull << 8) & 0xfffffffffull;
	PVOID GetProcessBaseAddress(HANDLE pid);
	DWORD GetUserDirectoryTableBaseOffset();
	ULONG_PTR GetProcessCr3(PEPROCESS pProcess);
	ULONG_PTR GetKernelDirBase();
	NTSTATUS ReadVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* read);
	NTSTATUS WriteVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* written);
	NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead);
	NTSTATUS WritePhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten);
	uint64_t TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress);
	NTSTATUS ReadProcessMemoryNoAttach(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read);
	NTSTATUS WriteProcessMemoryNoAttach(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written);

public:
	//Read
	PVOID ReadProcessMemoryByCR3NoAttach(IN ULONG pid, IN PVOID targetaddress, IN SIZE_T read_size);
	//Write
	NTSTATUS WriteProcessMemoryByCR3NoAttach(IN ULONG pid, IN PVOID targetaddress, IN PVOID write_data, IN SIZE_T write_size);

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// Read/Write Process Memory By CR3:
//////////////////////////////////////////////////////////////////////////////////////////////////////////
private:

public:

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// Hide Memory By VAD:
//////////////////////////////////////////////////////////////////////////////////////////////////////////
private:
	NTSTATUS GetSystemVadRootOffset(PRTL_OSVERSIONINFOEXW os_info);
	ULONG GetVadCountNumber(IN PALL_VADS buffer, IN PMMVAD target_vad);
	PMMVAD GetVadByCountNumber(IN PALL_VADS buffer, IN ULONG count_number);
	ULONG_PTR GetVadByAddress(IN PALL_VADS buffer, IN ULONG64 hide_address);
	PMMVAD GetVadByFlags(IN PALL_VADS buffer, IN ULONG flags);
	void EnumVad(IN PMMVAD vad, IN PALL_VADS buffer, IN ULONG count);
	NTSTATUS EnumProcessVad(IN PEPROCESS eprocess, IN PALL_VADS buffer, IN ULONG count);

public:
	NTSTATUS SetMemoryVADProtection(IN HANDLE pid, IN ULONG64 virtual_address, IN ULONG virtual_address_size, DWORD new_protection);
	NTSTATUS HideMemoryByVAD(IN HANDLE pid, IN ULONG64 virtual_address, IN ULONG virtual_address_size);
	void RestoreVAD();
	HANDLE GetOldVadPID() { return old_vad[0].pid; }

};


