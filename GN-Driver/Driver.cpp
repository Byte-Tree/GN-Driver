//////////////////////////////////////////////////////////////
//   链接器 -> 高级 -> 入口点 -> CustomDriverEntry (自定义)
//    C/C++ -> 代码生成 -> 安全检查 -> 禁用安全检查 (/GS-)
//////////////////////////////////////////////////////////////
#include "pch.h"
#include "IRPControl/IRPControl.h"
#include "MainFunction/MainFunction.h"


extern "C" NTSTATUS CustomDriverEntry(PDRIVER_OBJECT p_driver_object, PUNICODE_STRING path)
{
	DbgPrint("[GN]:%s-> Hello Kdmapper... GN-Driver.", __FUNCTION__);
	//DbgBreakPoint();

	//初始化主功能
	MainFunction(p_driver_object, path);
	//再注册驱动io_dispatch    劫持null.sys进行通讯
	//if (!NT_SUCCESS(RegisterIoControlold()))
	if (!NT_SUCCESS(RegisterIoControl()))
		DbgPrint("[GN]:劫持通讯失败...\n");

	return 0;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status = STATUS_SUCCESS;

	DbgPrint("[GN]:%s-> Hello GN-Driver.", __FUNCTION__);
	//DbgBreakPoint();

#if CURRENT_IO_DISPATCH == _HACK_IO_DISPATCH
	//初始化主功能
	MainFunction(DriverObject, RegistryPath);
	//再注册驱动io_dispatch    劫持null.sys进行通讯
	if (!NT_SUCCESS(RegisterIoControl()))
		return STATUS_UNSUCCESSFUL;
#else
	//原始的创建设备注册io通讯
	if (CreateMyDevice(DriverObject) != STATUS_SUCCESS)
	{//创建设备失败
		DbgPrint("[GN]:%s-> 创建驱动设备失败", __FUNCTION__);
		return STATUS_UNSUCCESSFUL;
	}
	MainFunction(DriverObject, RegistryPath);		//初始化主功能
#endif

	return Status;
}

