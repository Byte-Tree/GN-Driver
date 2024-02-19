//////////////////////////////////////////////////////////////////////////////////////////////////////////
//		 通讯的结构体，Driver和Driver-Lib一起包含，只需要改一个就行
//			 每个结构体的第一个成员作为control_code控制劫持通讯
//////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma once

enum ReadWriteModle
{
	_MDL,
	_CR3,
	_CR3NOATTACH,
};

typedef struct _GetProcessName_Data
{
	ULONG control_code;
	ULONG pid;
	char process_name[256] = { NULL };
	NTSTATUS return_status;
}GetProcessName_Data, * PGetProcessName_Data;

typedef struct _KernelModuleHandleStruct
{
	ULONG control_code;
	WCHAR kernel_module_name[MAX_PATH];
}KernelModuleHandleStruct, * PKernelModuleHandleStruct;

typedef struct _KillProcessStruct
{
	ULONG control_code;
	ULONG pid;
}KillProcessStruct, * PKillProcessStruct;

typedef struct _DeleteExecuteFileStruct
{
	ULONG control_code;
	WCHAR file_path[MAX_PATH];
}DeleteExecuteFileStruct, * PDeleteExecuteFileStruct;

typedef struct _SetMemoryProtectStruct
{
	ULONG control_code;
	ULONG pid;
	PVOID64 address;
	SIZE_T size;
	ULONG protect_attribute;
	PULONG old_protect_attribute;
}SetMemoryProtectStruct, * PSetMemoryProtectStruct;

typedef struct _SetExecutePageStruct
{
	ULONG control_code;
	ULONG pid;
	ULONG64 virtualaddress;
	ULONG size;
}SetExecutePageStruct, * PSetExecutePageStruct;

typedef struct _VADMemoryStruct
{
	ULONG control_code;
	ULONG pid;
	ULONG memory_size;
	ULONG64 memory_address;
	ULONG32 protection;
}VADMemoryStruct, * PVADMemoryStruct;

typedef struct _AllocMemoryStruct
{
	ULONG control_code;
	ULONG pid;
	SIZE_T allocsize;
	ULONG protect;
}AllocMemoryStruct, * PAllocMemoryStruct;

typedef struct _FreeMemoryStruct
{
	ULONG control_code;
	ULONG pid;
	ULONG64 free_address;
	ULONG64 memory_size;
}FreeMemoryStruct, * PFreeMemoryStruct;

typedef struct _MemoryStruct
{
	ULONG control_code;
	ULONG pid;
	ULONG64 target_address;//地址不能用一个指针指向你申请的地址 这样传过去内核里面 只有一个r3的地址 但是r0访问不到这个申请到的r3地址的
	ULONG read_and_write_data_size;//读和写的长度都用这一个控制
	PVOID write_data;
	//BYTE write_data[1024 * 1024 * 2];
}MemoryStruct, * PMemoryStruct;

typedef struct _ModuleStruct
{
	ULONG control_code;
	ULONG pid;
	WCHAR module_name[MAX_PATH];
}ModuleStruct, * PModuleStruct;

typedef struct _InjectByHackThreadStruct
{
	ULONG control_code;
	ULONG pid;
	DWORD tid;
	ULONG64 param_buffer_address;
	ULONG64 loader_shellcode_address;
	ULONG64 createthread_address;
	LONG kernel_wait_millisecond;
	ReadWriteModle readwrite_modle;
}InjectByHackThreadStruct, * PInjectByHackThreadStruct;

typedef struct _InjectByInstCallbackStruct
{
	ULONG control_code;
	ULONG pid;
	ULONG64 param_buffer_address;
	ULONG64 loader_shellcode_address;
	ULONG64 createthread_address;
	LONG kernel_wait_millisecond;
	ULONG64 RtlCaptureContext;
	ULONG64 NtContinue;
	BOOL isclear_proccallback;
}InjectByInstCallbackStruct, * PInjectByInstCallbackStruct;

typedef struct _KernelThreadStruct
{
	ULONG control_code;
	char kernel_module_name[MAX_PATH] = { NULL };
	char judgment[16] = { NULL };
	HANDLE tid = 0;
}KernelThreadStruct, * PKernelThreadStruct;



