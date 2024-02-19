#pragma once
#include "../pch.h"
#include <intsafe.h>

extern "C" PCHAR PsGetProcessImageFileName(PEPROCESS pEProcess);
typedef NTSTATUS(*pfnNtContinue)(IN PCONTEXT Context, IN BOOLEAN TestAlert);

//枚举内核模块句柄
typedef enum
{
    MmTagTypeDS = 'SD'             //PrintAllLoadedMoudleByDriverSection
}MmTagType;
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union {
        ULONG FlagGroup;
        ULONG Flags;
    };
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64 InLoadOrderLinks;
    LIST_ENTRY64 InMemoryOrderLinks;
    LIST_ENTRY64 InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG32    SizeOfImage;
    UINT8      Unknow0[0x4];
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
}LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;                 // Not filled in
    PVOID MappedBase;
    PVOID ImageBase;
    __int64 ImageSize;
    __int64 Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES
{
    __int64 NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
typedef struct _DRIVER_ITEM {
    ULONG64 base;
    ULONG size;
    ULONG flags;
    USHORT load_seq;
    USHORT init_seq;
    UCHAR  path[256];
} DRIVER_ITEM, * PDRIVER_ITEM;
typedef struct _DRIVER_INFO {
    ULONG count;
    DRIVER_ITEM items[1];
} DRIVER_INFO, * PDRIVER_INFO;

typedef struct _MSYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} MSYSTEM_MODULE_ENTRY, * PMSYSTEM_MODULE_ENTRY;
typedef struct _MSYSTEM_MODULE {
    PVOID 	Reserved1;
    PVOID 	Reserved2;
    PVOID 	ImageBaseAddress;
    ULONG 	ImageSize;
    ULONG 	Flags;
    unsigned short 	Id;
    unsigned short 	Rank;
    unsigned short 	Unknown;
    unsigned short 	NameOffset;
    unsigned char 	Name[MAXIMUM_FILENAME_LENGTH];
} MSYSTEM_MODULE, * PMSYSTEM_MODULE;
typedef struct _MSYSTEM_MODULE_INFORMATION {
    ULONG                       ModulesCount;
    MSYSTEM_MODULE_ENTRY         Modules[1];
    ULONG                       Count;
    MSYSTEM_MODULE 	            Sys_Modules[1];
} MSYSTEM_MODULE_INFORMATION, * PMSYSTEM_MODULE_INFORMATION;


class Tools
{
private:
	PDRIVER_OBJECT m_pdriverobject = NULL;
    //系统回调开关
    PBYTE PspNotifyEnableMask;
    //SSDT函数访问模式偏移
    UINT previous_mode_offset = 0;
    UCHAR original_previous_mode = NULL;
    //EPROCESS结构中的进程名偏移
    DWORD eprocess_processname_offset = 0;

private:
    pfnNtContinue NtContinue = NULL;

public:
	void* operator new(size_t size, POOL_TYPE pool_type = NonPagedPool);
	void operator delete(void* pointer);

private:
    //查询SSDT
    PVOID GetProcAddress(WCHAR* FuncName);
    ULONGLONG Get_SSDT_Base_HIGH();
    ULONGLONG Get_SSDT_Base_LOW();

    static NTSTATUS FD_SetFileCompletion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);
    HANDLE  FD_OpenFile(WCHAR file_path[]);
    BOOLEAN FD_StripFileAttributes(HANDLE FileHandle);
    BOOLEAN FD_DeleteFile(HANDLE FileHandle);
    ULONGLONG GetPspNotifyEnableMask();
    UINT GetPreviousModeOffset();

public:
    bool DisablePspNotify();
    bool EnablePspNotify();
    bool ChangePrevKernelMode(PUCHAR address);
    bool RestorePrevKernelMode(PUCHAR address);
    PUCHAR GetPreviousModeAddress();

    //封装Nt系列函数
public:
    NTSTATUS MyNtContinue(PCONTEXT context, BOOLEAN TestAlert);

public:
	Tools(PDRIVER_OBJECT pdriverobject);
	~Tools();
	NTSTATUS GetProcessNameByID(IN ULONG pid, OUT char* process_name);
    PVOID EnumKernelModulehandle(IN PWCHAR module_name);
    NTSTATUS DeleteDriverFile(PUNICODE_STRING pdriver_path);
    NTSTATUS DeleteFile(IN WCHAR file_path[]);
    NTSTATUS KillProcessById(IN HANDLE pid);
    void KernelSleep(LONG msec);
    ULONG GetIndexByName(const char* sdName);
    ULONGLONG GetSSDTFunction(ULONGLONG Index);
    char* itoa(int num, char* str, int radix);
    DWORD GetProcessNameOffsetByEprocess();
    BOOLEAN RtlStringContains(PSTRING str, PSTRING sub_str, BOOLEAN case_isensitive);
    BOOLEAN GetKernelProcessInfo(IN const char* name, IN ULONG64& image_size, IN PVOID& image_base);
    BOOLEAN GetSectionData(CONST CHAR* image_name, CONST CHAR* section_name, ULONG64& section_size, PVOID& section_base_address);

};



