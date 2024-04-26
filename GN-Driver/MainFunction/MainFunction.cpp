//////////////////////////////////////////////////////////////////////////////////////////////////////////
//							调用DriverEntry后进入，作为各个功能初始化的入口
//////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "MainFunction.h"

//MiniFilter 回调函数
CONST FLT_OPERATION_REGISTRATION _Call_Back[] =
{
	{ IRP_MJ_CREATE, 0, Pre_Operation_Callback, NULL },
	{ IRP_MJ_READ, 0, Read_Pre_Operation_Callback, NULL },
	{ IRP_MJ_WRITE, 0, Write_Pre_Operation_Callback, NULL },
	//{ IRP_MJ_SET_INFORMATION, 0, Pre_Operation_Callback, NULL, NULL },
	//{ IRP_MJ_QUERY_INFORMATION, 0, Pre_Operation_Callback, NULL, NULL },
	//{ IRP_MJ_QUERY_VOLUME_INFORMATION, 0, Pre_Operation_Callback, NULL, NULL },
	//{ IRP_MJ_SET_VOLUME_INFORMATION, 0, Pre_Operation_Callback, NULL, NULL },
	//{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, Pre_Operation_Callback, NULL, NULL },
	//{ IRP_MJ_NETWORK_QUERY_OPEN, 0, Pre_Operation_Callback, NULL, NULL },
	//{ IRP_MJ_DIRECTORY_CONTROL, 0, NULL, FltDirCtrlPostOperation, NULL },
	{ IRP_MJ_OPERATION_END }
};
MiniFilter* minifilter = nullptr;
MemoryTools* memorytools = nullptr;
Tools* tools = nullptr;
HideDriver* hide_driver = nullptr;
Monitor* monitor = nullptr;
Thread* thread = nullptr;
InjectHelper* injecthelper = nullptr;


NTSTATUS RegisterIoControl()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PFILE_OBJECT file_object = nullptr;
	PDEVICE_OBJECT p_device_object = nullptr;
	UNICODE_STRING device_name = { NULL };
	
	RtlInitUnicodeString(&device_name, L"\\Device\\Null");//需要劫持的设备名称 HackDriverName
	status = IoGetDeviceObjectPointer(&device_name, FILE_ALL_ACCESS, &file_object, &p_device_object);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[GN]:IoGetDeviceObjectPointer() errorcode:%p", (DWORD64)status);
		return status;
	}
	
	//取消文件的引用
	if (!file_object)
		ObDereferenceObject(file_object);
	
	////填充特征码
	ULONG64 target_address = memorytools->GetPspNotifyEnableMask();
	memorytools->SetMemoryPage(target_address, 20);

	//下Hook
	ULONG64 myfunc = (ULONG64)HackDispatchRoutine;
	BYTE hook_code[14] = { 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	memcpy((PVOID)&hook_code[6], (PVOID)&myfunc, 8);
	memorytools->RtlSuperCopyMemory((PVOID)target_address, (PVOID)hook_code, 14);
	
	p_device_object->DriverObject->FastIoDispatch->FastIoDeviceControl = (PFAST_IO_DEVICE_CONTROL)target_address;
	return STATUS_SUCCESS;
}

NTSTATUS RegisterIoControlold()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PFILE_OBJECT file_object = nullptr;
	PDEVICE_OBJECT p_device_object = nullptr;
	UNICODE_STRING device_name = { NULL };
	
	RtlInitUnicodeString(&device_name, L"\\Device\\Null");//需要劫持的设备名称 HackDriverName
	status = IoGetDeviceObjectPointer(&device_name, FILE_ALL_ACCESS, &file_object, &p_device_object);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[GN]:IoGetDeviceObjectPointer() errorcode:%p", (DWORD64)status);
		return status;
	}
	
	//取消文件的引用
	if (!file_object)
		ObDereferenceObject(file_object);

	p_device_object->DriverObject->FastIoDispatch->FastIoDeviceControl = (PFAST_IO_DEVICE_CONTROL)HackDispatchRoutine;
	return STATUS_SUCCESS;
}

NTSTATUS CreateMyDevice(PDRIVER_OBJECT pdriverobject)
{
	NTSTATUS Status;
	PDEVICE_OBJECT pDevice;									//用来返回创建的设备
	UNICODE_STRING DeviceName;								//创建设备名称 devName
	UNICODE_STRING SymboLinkName;							//系统链接名称

	//注册派遣函数
	pdriverobject->MajorFunction[IRP_MJ_CREATE] = GN_DispatchRoutine;
	pdriverobject->MajorFunction[IRP_MJ_CLOSE] = GN_DispatchRoutine;
	pdriverobject->MajorFunction[IRP_MJ_READ] = GN_DispatchRoutine;
	pdriverobject->MajorFunction[IRP_MJ_WRITE] = GN_DispatchRoutine;
	pdriverobject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = GN_DispatchRoutine;
	RtlInitUnicodeString(&DeviceName, Driver_Name);			//对DeviceName初始化为字符串：\\Device\\GN_Device
	Status = IoCreateDevice(pdriverobject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevice);
	if (!NT_SUCCESS(Status))
	{
		if (Status == STATUS_INSUFFICIENT_RESOURCES)
			DbgPrint("[GN]:%s-> 资源不足！", __FUNCTION__);
		if (Status == STATUS_OBJECTID_EXISTS)
			DbgPrint("[GN]:%s-> 指定对象名已存在！", __FUNCTION__);
		if (Status == STATUS_OBJECT_NAME_COLLISION)
			DbgPrint("[GN]:%s-> 对象名有冲突！", __FUNCTION__);
		DbgPrint("[GN]:%s-> ！！！创建设备失败！！！", __FUNCTION__);
		return Status;
	}
	pdriverobject->Flags |= DO_BUFFERED_IO;					//设置驱动读写方式为缓冲区读写
	RtlInitUnicodeString(&SymboLinkName, Driver_Link_Name);	//创建设备的链接名称 将设备暴露到R3层可见
	Status = IoCreateSymbolicLink(&SymboLinkName, &DeviceName);
	if (!NT_SUCCESS(Status))
	{
		IoDeleteDevice(pDevice);
		DbgPrint("[GN]:%s-> 设备创建失败后删除设备成功！", __FUNCTION__);
		return Status;
	}
	pdriverobject->DriverUnload = UnLoad;	//指定驱动卸载

	return STATUS_SUCCESS;
}

void UnLoad(PDRIVER_OBJECT pdriverobject)
{
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING SymboLinkName;
	//释放变量空间
	delete memorytools;
	delete tools;
	delete minifilter;
	delete hide_driver;
	if (monitor) delete monitor;
	if (thread) delete thread;
	if (injecthelper) delete injecthelper;

	//一个设备变量用来获取删除的设备对象
	pDevice = pdriverobject->DeviceObject;
	IoDeleteDevice(pDevice);
	RtlInitUnicodeString(&SymboLinkName, Driver_Link_Name);
	IoDeleteSymbolicLink(&SymboLinkName);
	DbgPrint("[GN]:%s-> Good bye GN-Driver.", __FUNCTION__);
}

void MainFunction(PDRIVER_OBJECT pdriverobject, PUNICODE_STRING registry_path)
{
	//VMProtectBegin("MainFunction");
	
	//Init all function
	memorytools = new MemoryTools();
	tools = new Tools(pdriverobject);
#ifndef KDMAPPER_LOAD
	hide_driver = new HideDriver(pdriverobject);
#endif
	thread = new Thread();
	injecthelper = new InjectHelper();

#ifndef KDMAPPER_LOAD
	if (!NT_SUCCESS(InitMiniFilter(pdriverobject, registry_path)))
		DbgPrint("[GN]:InitMiniFilter() Error");
	//Delete Driver File
	if (!NT_SUCCESS(tools->DeleteDriverFile(&((PKLDR_DATA_TABLE_ENTRY)pdriverobject->DriverSection)->FullDllPath)))
		DbgPrint("[GN]:DeleteDriverFile() Error");
#endif

	//VMProtectEnd();
}

//初始化MiniFilter
NTSTATUS InitMiniFilter(PDRIVER_OBJECT pdriverobject, PUNICODE_STRING registry_path)
{
	minifilter = new MiniFilter();
	if (!minifilter->WriteMiniFilterReg(registry_path))
	{
		DbgPrint("[GN]:InitMiniFilter()-> WriteMiniFilterReg() Failed\n");
		return STATUS_UNSUCCESSFUL;
	}
	if (!minifilter->MiniFilterInit(pdriverobject, _Call_Back, MiniFilterUnload))
	{
		DbgPrint("[GN]:InitMiniFilter()-> MiniFilterInit() Failed...");
		return STATUS_UNSUCCESSFUL;
	}
	if (!minifilter->StartMiniFilter())
	{
		DbgPrint("[GN]:InitMiniFilter()-> StartMiniFilter() Failed...");
		return STATUS_UNSUCCESSFUL;
	}
	DbgPrint("[GN]:InitMiniFilter()-> MiniFilterInit Success");
	return STATUS_SUCCESS;
}

//Minifilter卸载回调函数
NTSTATUS MiniFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS flags)
{
	if (minifilter->GetFilterHandle())
	{
		FltUnregisterFilter(minifilter->GetFilterHandle());
		minifilter->SetFilterHandle(NULL);
	}
	DbgPrint("[GN]:MiniFilterUnload()-> MiniFilter Unload Success...");
	return STATUS_SUCCESS;
}

//Pre表示操作之前  Post表示操作之后
FLT_PREOP_CALLBACK_STATUS Pre_Operation_Callback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
	HANDLE process_id = NULL;
	char process_name[MAX_PATH] = { NULL };
	PFLT_FILE_NAME_INFORMATION filename_information;

	//获取文件名
	if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &filename_information)))
	{
		if (NT_SUCCESS(FltParseFileNameInformation(filename_information)))
		{
			WCHAR filename_path[4096] = { NULL };
			RtlCopyMemory(filename_path, filename_information->Name.Buffer, filename_information->Name.MaximumLength);
			_wcsupr(filename_path);

			process_id = PsGetProcessId(FltGetRequestorProcess(Data));
			tools->GetProcessNameByID((ULONG)process_id, process_name);
			if ((_stricmp(process_name, "crossfire.exe") == 0) ||
				(_stricmp(process_name, "SGuard64.exe") == 0))
			{
				////输出操作的文件
				//DbgPrint("[GN]:%s() 操作进程ID：%d,进程名：%s,重定向文件:%S", __FUNCTION__, process_id, process_name, filename_information->Name.Buffer);

				if (wcsstr(filename_path, L"GN-LOADER.EXE")|| 
					wcsstr(filename_path, L"GN-INITDRIVER.EXE")|| 
					wcsstr(filename_path, L"GN-DRIVER.SYS"))
				{
					DbgPrint("[GN]:%s()->!!!拦截操作进程ID：%d,进程名：%s,重定向文件:%S", __FUNCTION__, process_id, process_name, filename_information->Name.Buffer);
					DbgPrint("[GN]:%s()->!!!拦截重定向文件:%S", __FUNCTION__, filename_information->Name.Buffer);
					DbgPrint("[GN]:%s()->!!!拦截访问模式：%d ,(0:KernelMode,1:UserMode,2:MaximumMode)", __FUNCTION__, Data->RequestorMode);
					//PWCHAR newfilename = L"\\None";
					PWCHAR newfilename = L"\\Device\\HarddiskVolume1\\Windows\\System32\\ntdll.dll";
					if (!NT_SUCCESS(IoReplaceFileObjectName(Data->Iopb->TargetFileObject, newfilename, wcslen(newfilename) * 2)))
					{
						DbgPrint("[GN]:%s()->重定向缓冲区失败！", __FUNCTION__);
						return FLT_PREOP_SUCCESS_NO_CALLBACK;
					}
					Data->IoStatus.Status = STATUS_REPARSE;
					Data->IoStatus.Information = IO_REPARSE;
					FltSetCallbackDataDirty(Data);//操作中改变数据 需要调用此函数设置数据为dirty提醒系统进行数据更新
					DbgPrint("[GN]:%s()->!!!拦截新文件路径:%S", __FUNCTION__, Data->Iopb->TargetFileObject->FileName.Buffer);
					return FLT_PREOP_COMPLETE;
				}

				//if (wcsstr(filename_path, L"GN-LOADER.EXE"))
				//{
				//	DbgPrint("[GN]:%s()->!!!拦截重定向文件:%S", __FUNCTION__, filename_information->Name.Buffer);
				//	DbgPrint("[GN]:%s()->!!!拦截访问模式：%d ,(0:KernelMode,1:UserMode,2:MaximumMode)", __FUNCTION__, Data->RequestorMode);
				//	PWCHAR newfilename = L"\\None";
				//	if (!NT_SUCCESS(IoReplaceFileObjectName(Data->Iopb->TargetFileObject, newfilename, wcslen(newfilename) * 2)))
				//	{
				//		DbgPrint("[GN]:%s()->重定向缓冲区失败！", __FUNCTION__);
				//		return FLT_PREOP_SUCCESS_NO_CALLBACK;
				//	}
				//	Data->IoStatus.Status = STATUS_REPARSE;
				//	Data->IoStatus.Information = IO_REPARSE;
				//	FltSetCallbackDataDirty(Data);//操作中改变数据 需要调用此函数设置数据为dirty提醒系统进行数据更新
				//	DbgPrint("[GN]:%s()->!!!拦截新文件路径:%S", __FUNCTION__, Data->Iopb->TargetFileObject->FileName.Buffer);
				//	return FLT_PREOP_COMPLETE;
				//}
				//if (wcsstr(filename_path, L"GN-DRIVER.SYS"))
				//{
				//	DbgPrint("[GN]:%s()->!!!拦截重定向文件:%S", __FUNCTION__, filename_information->Name.Buffer);
				//	DbgPrint("[GN]:%s()->!!!拦截访问模式：%d ,(0:KernelMode,1:UserMode,2:MaximumMode)", __FUNCTION__, Data->RequestorMode);
				//	PWCHAR newfilename = L"\\None";
				//	if (!NT_SUCCESS(IoReplaceFileObjectName(Data->Iopb->TargetFileObject, newfilename, wcslen(newfilename) * 2)))
				//	{
				//		DbgPrint("[GN]:%s()->重定向缓冲区失败！", __FUNCTION__);
				//		return FLT_PREOP_SUCCESS_NO_CALLBACK;
				//	}
				//	Data->IoStatus.Status = STATUS_REPARSE;
				//	Data->IoStatus.Information = IO_REPARSE;
				//	FltSetCallbackDataDirty(Data);//操作中改变数据 需要调用此函数设置数据为dirty提醒系统进行数据更新
				//	DbgPrint("[GN]:%s()->!!!拦截新文件路径:%S", __FUNCTION__, Data->Iopb->TargetFileObject->FileName.Buffer);
				//	return FLT_PREOP_COMPLETE;
				//}
				//if (wcsstr(filename_path, L"GN-INITDRIVER.EXE"))
				//{
				//	DbgPrint("[GN]:%s()->!!!拦截重定向文件:%S", __FUNCTION__, filename_information->Name.Buffer);
				//	DbgPrint("[GN]:%s()->!!!拦截访问模式：%d ,(0:KernelMode,1:UserMode,2:MaximumMode)", __FUNCTION__, Data->RequestorMode);
				//	PWCHAR newfilename = L"\\None";
				//	if (!NT_SUCCESS(IoReplaceFileObjectName(Data->Iopb->TargetFileObject, newfilename, wcslen(newfilename) * 2)))
				//	{
				//		DbgPrint("[GN]:%s()->重定向缓冲区失败！", __FUNCTION__);
				//		return FLT_PREOP_SUCCESS_NO_CALLBACK;
				//	}
				//	Data->IoStatus.Status = STATUS_REPARSE;
				//	Data->IoStatus.Information = IO_REPARSE;
				//	FltSetCallbackDataDirty(Data);//操作中改变数据 需要调用此函数设置数据为dirty提醒系统进行数据更新
				//	DbgPrint("[GN]:%s()->!!!拦截新文件路径:%S", __FUNCTION__, Data->Iopb->TargetFileObject->FileName.Buffer);
				//	return FLT_PREOP_COMPLETE;
				//}
			}
		}
		FltReleaseFileNameInformation(filename_information);
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS Read_Pre_Operation_Callback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
	PFLT_FILE_NAME_INFORMATION filename_information;
	//获取文件名
	if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &filename_information)))
	{
		if (NT_SUCCESS(FltParseFileNameInformation(filename_information)))
		{
			WCHAR filename_path[4096] = { NULL };
			RtlCopyMemory(filename_path, filename_information->Name.Buffer, filename_information->Name.MaximumLength);
			_wcsupr(filename_path);
			//if (wcsstr(filename_path, L"DWM.EXE"))
			//{
			//	DbgPrint("[GN]:%s-> IRP_MJ_READ重定向文件:%S", __FUNCTION__, filename_information->Name.Buffer);
			//	PWCHAR newfilename = L"\\None";
			//	if (!NT_SUCCESS(IoReplaceFileObjectName(Data->Iopb->TargetFileObject, newfilename, wcslen(newfilename) * 2)))
			//	{
			//		DbgPrint("[GN]:%s-> IRP_CREATE重定向缓冲区失败！", __FUNCTION__);
			//		return FLT_PREOP_SUCCESS_NO_CALLBACK;
			//	}
			//	Data->IoStatus.Status = STATUS_REPARSE;
			//	Data->IoStatus.Information = IO_REPARSE;
			//	FltSetCallbackDataDirty(Data);//操作中改变数据 需要调用此函数设置数据为dirty提醒系统进行数据更新
			//	DbgPrint("[GN]:%s-> IRP_MJ_READ新文件路径:%S", __FUNCTION__, Data->Iopb->TargetFileObject->FileName.Buffer);
			//	return FLT_PREOP_COMPLETE;
			//}
		}
		FltReleaseFileNameInformation(filename_information);
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS Write_Pre_Operation_Callback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
	PFLT_FILE_NAME_INFORMATION filename_information;
	//获取文件名
	if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &filename_information)))
	{
		if (NT_SUCCESS(FltParseFileNameInformation(filename_information)))
		{
			WCHAR filename_path[4096] = { NULL };
			RtlCopyMemory(filename_path, filename_information->Name.Buffer, filename_information->Name.MaximumLength);
			_wcsupr(filename_path);
			//if (wcsstr(filename_path, L"DWM.EXE"))
			//{
			//	DbgPrint("[GN]:%s-> IRP_MJ_WRITE重定向文件:%S", __FUNCTION__, filename_information->Name.Buffer);
			//	PWCHAR newfilename = L"\\None";
			//	if (!NT_SUCCESS(IoReplaceFileObjectName(Data->Iopb->TargetFileObject, newfilename, wcslen(newfilename) * 2)))
			//	{
			//		DbgPrint("[GN]:%s-> IRP_CREATE重定向缓冲区失败！", __FUNCTION__);
			//		return FLT_PREOP_SUCCESS_NO_CALLBACK;
			//	}
			//	Data->IoStatus.Status = STATUS_REPARSE;
			//	Data->IoStatus.Information = IO_REPARSE;
			//	FltSetCallbackDataDirty(Data);//操作中改变数据 需要调用此函数设置数据为dirty提醒系统进行数据更新
			//	DbgPrint("[GN]:%s-> IRP_MJ_WRITE新文件路径:%S", __FUNCTION__, Data->Iopb->TargetFileObject->FileName.Buffer);
			//	return FLT_PREOP_COMPLETE;
			//}
		}
		FltReleaseFileNameInformation(filename_information);
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}




