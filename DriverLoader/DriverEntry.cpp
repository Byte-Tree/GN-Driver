/////////////////////////////////////////////////////////////////////////////////////////
//						用这个驱动映射内存加载一个未签名的驱动文件
/////////////////////////////////////////////////////////////////////////////////////////
#include <ntifs.h>
#include <ntdef.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>
#include <wdf.h>
#include <wdm.h>
#include <ntstrsafe.h>

#pragma comment(lib, "NtStrSafe.lib")
#pragma comment(lib, "NtosKrnl.lib")


VOID DriverUnload(PDRIVER_OBJECT p_driver_object)
{


	DbgPrint("[dbg]:DriverLoader Exit...");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT p_driver_object, PUNICODE_STRING p_path)
{
	DbgPrint("[dbg]:DriverLoader Entry...");



	p_driver_object->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;//写完后加载完成用STATUS_UNSUCCESSFUL伪装未成功加载
}

