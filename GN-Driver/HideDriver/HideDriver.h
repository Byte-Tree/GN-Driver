#pragma once
#include "../pch.h"

#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)

typedef struct _DRIVER_LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID      DllBase;
	PVOID      EntryPoint;
}DRIVER_LDR_DATA_TABLE_ENTRY, * PDRIVER_LDR_DATA_TABLE_ENTRY;

typedef NTSTATUS(__fastcall* MiProcessLoaderEntry)(PVOID pDriverSection, int bLoad);
extern "C" NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(__in PUNICODE_STRING ObjectName, __in ULONG Attributes, __in_opt PACCESS_STATE AccessState, __in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType, __in KPROCESSOR_MODE AccessMode, __inout_opt PVOID ParseContext, __out PVOID * Object);
extern "C" POBJECT_TYPE * IoDriverObjectType;

struct Old_Driver_Information
{
	DRIVER_OBJECT old_driver_object = { NULL };
	DRIVER_LDR_DATA_TABLE_ENTRY old_ldrEntry = { NULL };
};

class HideDriver
{
private:
	Old_Driver_Information old_driver_information = { NULL };

private:
	ULONG GetOsVersionNumber();
	void KernelSleep(LONG msec);
	PVOID GetProcAddress(WCHAR* FuncName);
	ULONG64 GetMiUnloadSystemImageAddress();
	MiProcessLoaderEntry GetMiProcessLoaderEntry(ULONG64 StartAddress);
	void InitInLoadOrderLinks(PDRIVER_LDR_DATA_TABLE_ENTRY LdrEntry);
	NTSTATUS GetDriverObjectByName(PDRIVER_OBJECT* lpObj, WCHAR* DriverDirName);
	void SupportSEH(PDRIVER_OBJECT pDriverObject);
	NTSTATUS HideDriverWin7(PDRIVER_OBJECT pTargetDriverObject);
	NTSTATUS HideDriverWin10(PDRIVER_OBJECT pTargetDriverObject);

public:
	bool hide_statu = false;
	PDRIVER_OBJECT self_driver_object = nullptr;
	ULONG64 MiUnloadSystemImageAddress = 0;
	MiProcessLoaderEntry m_MiProcessLoaderEntry = NULL;

public:
	void* operator new(size_t size, POOL_TYPE pool_type = NonPagedPool);
	void operator delete(void* pointer);
	PDRIVER_OBJECT GetDriverObject() { return self_driver_object; }
	static void ReInitializeDriver(PDRIVER_OBJECT p_object, PVOID context, ULONG Count);
	static void DeletDriverObject(PVOID start_context);

public:
	HideDriver(PDRIVER_OBJECT p_object);
	~HideDriver();

};


