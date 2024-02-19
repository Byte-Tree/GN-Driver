#pragma once
#include "../pch.h"
#include "../IRPControl/IRPControl.h"
#include "../MemoryTools/MemoryTools.h"
#include "../Minifilter/Minifilter.h"
#include "../Tools/Tools.h"
#include "../HideDriver/HideDriver.h"
#include "../Monitor/Monitor.h"
#include "../Thread/Thread.h"
#include "../InjectHelper/InjectHelper.h"

#ifdef _WIN64
typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY listEntry;
	ULONG64 __Undefined1;
	ULONG64 __Undefined2;
	ULONG64 __Undefined3;
	ULONG64 NonPagedDebugInfo;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllPath;
	UNICODE_STRING FullDllName;
	//UNICODE_STRING path;
	//UNICODE_STRING name;
	ULONG   Flags;
	USHORT  LoadCount;
	USHORT  __Undefined5;
	ULONG64 __Undefined6;
	ULONG   CheckSum;
	ULONG   __padding1;
	ULONG   TimeDateStamp;
	ULONG   __padding2;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#else
typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY listEntry;
	ULONG unknown1;
	ULONG unknown2;
	ULONG unknown3;
	ULONG unknown4;
	ULONG unknown5;
	ULONG unknown6;
	ULONG unknown7;
	UNICODE_STRING path;
	UNICODE_STRING name;
	ULONG   Flags;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#endif

//用来控制win7及以下可用于劫持的驱动名称
#if _WIN10_OR_HIGHER
	#define HackDriverName L"\\Device\\Null"
#else
	#define HackDriverName L"\\Device\\win7"//win7还没找可用劫持的驱动
#endif


NTSTATUS RegisterIoControl();
NTSTATUS RegisterIoControlold();
NTSTATUS CreateMyDevice(PDRIVER_OBJECT pdriverobject);
void UnLoad(PDRIVER_OBJECT pdriverobject);
void MainFunction(PDRIVER_OBJECT pdriverobject, PUNICODE_STRING registry_path);
NTSTATUS InitMiniFilter(PDRIVER_OBJECT pdriverobject, PUNICODE_STRING registry_path);
NTSTATUS MiniFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS flags);
FLT_PREOP_CALLBACK_STATUS Pre_Operation_Callback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS Read_Pre_Operation_Callback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS Write_Pre_Operation_Callback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);


//导出全局变量
extern MiniFilter* minifilter;
extern Tools* tools;
extern MemoryTools* memorytools;
extern HideDriver* hide_driver;
extern Monitor* monitor;
extern Thread* thread;
extern InjectHelper* injecthelper;

