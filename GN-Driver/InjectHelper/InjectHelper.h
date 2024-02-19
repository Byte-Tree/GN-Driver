#pragma once
#include "../pch.h"

extern "C" NTSTATUS ZwOpenThread(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ PCLIENT_ID ClientId);
extern "C" NTSTATUS NtSetInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;
	ULONG Reserved;
	PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;


class InjectHelper
{
private:

public:
	void* operator new(size_t size, POOL_TYPE pool_type = NonPagedPool);
	void operator delete(void* pointer);
	PVOID WriteStartShellCode(IN HANDLE pid, IN ULONG64 rip, IN ULONG64 param_buffer_address, IN ULONG64 loader_shellcode_address, IN ULONG64 createthread_address);
	NTSTATUS MyNtSetInformationProcess(IN HANDLE ProcessHandle, IN ULONG ProcessInformationClass, IN PVOID ProcessInformation, IN ULONG ProcessInformationLength);
	PVOID InitInstCallBackShellCode(IN HANDLE pid, IN ULONG64 param_buffer_address, IN ULONG64 loader_shellcode_address, IN ULONG64 createthread_address, IN ULONG64 rtlcapturecontext_address, IN ULONG64 ntcontinue_address);

public:
	InjectHelper();
	~InjectHelper();
	//劫持线程rip注入
	NTSTATUS InjectByHackThread(IN HANDLE pid, IN ULONG64 param_buffer_address, IN ULONG64 loader_shellcode_address, IN LONG kernel_wait_millisecond, IN ULONG64 createthread_address);
	//创建远程线程注入，CF需要处理ACE的LdrInitializeThunk钩子
	NTSTATUS InjectByCreateThread(IN HANDLE pid, IN ULONG64 param_buffer_address, IN ULONG64 loader_shellcode_address, IN LONG kernel_wait_millisecond);
	//创建Instrumentationcallback回调注入
	NTSTATUS InjectByInstCallBack(IN HANDLE pid, IN ULONG64 param_buffer_address, IN ULONG64 loader_shellcode_address, IN ULONG64 createthread_address, IN ULONG64 rtlcapturecontext_address, IN ULONG64 ntcontinue_address, IN LONG kernel_wait_millisecond, IN BOOL isclear_proccallback);

};



