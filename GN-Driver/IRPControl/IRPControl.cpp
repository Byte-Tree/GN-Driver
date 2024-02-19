//////////////////////////////////////////////////////////////////////////////////////////////////////////
//										与R3进行通讯的派遣函数
//								  GN-DispatchRoutine为原始的通讯方案
//								  KackDispatchRoutine为劫持通讯方案
//////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "IRPControl.h"


NTSTATUS GN_DispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	ULONG info = 0;
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG mf = stack->MajorFunction;//区分不同的IRP
	switch (mf)
	{
	case IRP_MJ_DEVICE_CONTROL:
	{
		ULONG IrpCode = stack->Parameters.DeviceIoControl.IoControlCode;
		switch (IrpCode)
		{
		case GetKernelModuleHandle_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(DWORD64*)buffer = (DWORD64)tools->EnumKernelModulehandle((PWCHAR)buffer);
			//DbgPrint("[GN]:返回模块句柄：%p", *(DWORD64*)buffer);//现在的buffer是指针指向数据，*(__int64*)buffer是读取数据
			info = sizeof(DWORD64);
			break;
		}
		case SetMemoryProtect_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(ULONG*)buffer = memorytools->SetMemoryProtect((HANDLE)((PSetMemoryProtectStruct)buffer)->pid, ((PSetMemoryProtectStruct)buffer)->address, ((PSetMemoryProtectStruct)buffer)->size, ((PSetMemoryProtectStruct)buffer)->protect_attribute);
			info = sizeof(ULONG);
			break;
		}
		case SetExecutePage_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(ULONG*)buffer = memorytools->SetExecutePage((HANDLE)((PSetExecutePageStruct)buffer)->pid, ((PSetExecutePageStruct)buffer)->virtualaddress, ((PSetExecutePageStruct)buffer)->size);
			info = sizeof(ULONG);
			break;
		}
		case AllocMemory_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(PVOID*)buffer = memorytools->AllocateMemory((HANDLE)((PAllocMemoryStruct)buffer)->pid, ((PAllocMemoryStruct)buffer)->allocsize, ((PAllocMemoryStruct)buffer)->protect);
			info = sizeof(PVOID);
			break;
		}
		case FreeMemory_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(ULONG*)buffer = memorytools->FreeMemory((HANDLE)((PFreeMemoryStruct)buffer)->pid, ((PFreeMemoryStruct)buffer)->free_address, ((PFreeMemoryStruct)buffer)->memory_size);
			info = sizeof(ULONG);
			break;
		}
		case GetModuleHandle_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(PVOID*)buffer = memorytools->GetModuleHandle((HANDLE)((PModuleStruct)buffer)->pid, ((PModuleStruct)buffer)->module_name);
			info = sizeof(PVOID);
			break;
		}
		case HidMemoryByVAD_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(ULONG*)buffer = memorytools->HideMemoryByVAD((HANDLE)((PVADMemoryStruct)buffer)->pid, ((PVADMemoryStruct)buffer)->memory_address, ((PVADMemoryStruct)buffer)->memory_size);
			info = sizeof(ULONG);
			break;
		}
		case ReadPhysicalProcessMemoryBy_CR3:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(PVOID*)buffer = memorytools->ReadProcessMemoryByCR3NoAttach(((PMemoryStruct)buffer)->pid, (PVOID)((PMemoryStruct)buffer)->target_address, ((PMemoryStruct)buffer)->read_and_write_data_size);
			info = sizeof(PVOID);
			break;
		}
		case WritePhysicalProcessMemoryBy_CR3:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(LONG*)buffer = memorytools->WriteProcessMemoryByCR3NoAttach(((PMemoryStruct)buffer)->pid, (PVOID)((PMemoryStruct)buffer)->target_address, &((PMemoryStruct)buffer)->write_data, ((PMemoryStruct)buffer)->read_and_write_data_size);
			info = sizeof(LONG);
			break;
		}
		case ReadProcessMemoryBy_MDL:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			if (!NT_SUCCESS(memorytools->ReadMemoryByMDL(((PMemoryStruct)buffer)->pid, (PVOID)((PMemoryStruct)buffer)->target_address, ((PMemoryStruct)buffer)->read_and_write_data_size, buffer)))
				*(PVOID*)buffer = 0;
			info = ((PMemoryStruct)buffer)->read_and_write_data_size;
			break;
		}
		case WriteProcessMemoryBy_MDL:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(LONG*)buffer = memorytools->WriteMemoryByMDL(((PMemoryStruct)buffer)->pid, (PVOID)((PMemoryStruct)buffer)->target_address, &((PMemoryStruct)buffer)->write_data, ((PMemoryStruct)buffer)->read_and_write_data_size);
			info = sizeof(LONG);
			break;
		}
		case KillProcess_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(LONG*)buffer = tools->KillProcessById(*(HANDLE*)buffer);
			info = sizeof(LONG);
			break;
		}
		case DeleteFile_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(ULONG*)buffer = tools->DeleteFile((WCHAR*)buffer);
			info = sizeof(LONG);
			break;
		}
		case SetMemoryVADProtection_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(LONG*)buffer = memorytools->SetMemoryVADProtection((HANDLE)((PVADMemoryStruct)buffer)->pid, ((PVADMemoryStruct)buffer)->memory_address, ((PVADMemoryStruct)buffer)->memory_size, ((PVADMemoryStruct)buffer)->protection);
			info = sizeof(LONG);
			break;
		}
		case InjectByHackThread_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(LONG*)buffer = injecthelper->InjectByHackThread((HANDLE)((PInjectByHackThreadStruct)buffer)->pid, ((PInjectByHackThreadStruct)buffer)->param_buffer_address, ((PInjectByHackThreadStruct)buffer)->loader_shellcode_address, ((PInjectByHackThreadStruct)buffer)->kernel_wait_millisecond, ((PInjectByHackThreadStruct)buffer)->createthread_address);
			info = sizeof(LONG);
			break;
		}
		case InjectByCreateThread_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(LONG*)buffer = injecthelper->InjectByCreateThread((HANDLE)((PInjectByHackThreadStruct)buffer)->pid, ((PInjectByHackThreadStruct)buffer)->param_buffer_address, ((PInjectByHackThreadStruct)buffer)->loader_shellcode_address, ((PInjectByHackThreadStruct)buffer)->kernel_wait_millisecond);
			info = sizeof(LONG);
			break;
		}
		case InjectByInstrumentationCallback_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(LONG*)buffer = injecthelper->InjectByInstCallBack((HANDLE)((PInjectByInstCallbackStruct)buffer)->pid, ((PInjectByInstCallbackStruct)buffer)->param_buffer_address, ((PInjectByInstCallbackStruct)buffer)->loader_shellcode_address, ((PInjectByInstCallbackStruct)buffer)->createthread_address, ((PInjectByInstCallbackStruct)buffer)->RtlCaptureContext, ((PInjectByInstCallbackStruct)buffer)->NtContinue, ((PInjectByInstCallbackStruct)buffer)->kernel_wait_millisecond, ((PInjectByInstCallbackStruct)buffer)->isclear_proccallback);
			info = sizeof(LONG);
			break;
		}
		case SuspendKernelThread_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(BOOL*)buffer = thread->SuspendKernelThread(((PKernelThreadStruct)buffer)->kernel_module_name, ((PKernelThreadStruct)buffer)->judgment);
			info = sizeof(BOOL);
			break;
		}
		case SuspendKernelThreadByID_code:
		{
			PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
			*(BOOL*)buffer = thread->SuspendKernelThreadByID(((PKernelThreadStruct)buffer)->kernel_module_name, ((PKernelThreadStruct)buffer)->tid);
			info = sizeof(BOOL);
			break;
		}
		}
	}
	case IRP_MJ_CREATE:
	{
		break;
	}
	case IRP_MJ_CLOSE:
	{
		break;
	}
	case IRP_MJ_READ:
	{
		break;
	}
	}
	Irp->IoStatus.Information = info;//当 IRP 引发数据的传送操作，通常设置 Information 值为传送的字节数。
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);//指令完成派遣函数
	return Status;
}

BOOLEAN HackDispatchRoutine(IN _FILE_OBJECT* file_object, IN BOOLEAN wait, IN PVOID input_buffer, IN ULONG input_buffer_length, OUT PVOID output_buffer, IN ULONG output_buffer_length, IN ULONG io_control_code, OUT PIO_STATUS_BLOCK io_status, IN _DEVICE_OBJECT* device_object)
{
	if (MmIsAddressValid(input_buffer) && MmIsAddressValid((PUCHAR)input_buffer + input_buffer_length - 1))
	{
		PULONG control_code = (PULONG)input_buffer;
		switch (*(ULONG*)control_code)
		{
			case GetKernelModuleHandle_code:
			{
				PKernelModuleHandleStruct buffer = (PKernelModuleHandleStruct)input_buffer;
				*(DWORD64*)output_buffer = (DWORD64)tools->EnumKernelModulehandle(buffer->kernel_module_name);
#if _INFORELEASE
				DbgPrint("[GN]:返回模块句柄：%p", *(DWORD64*)buffer);//现在的buffer是指针指向数据，*(__int64*)buffer是读取数据
#endif
				output_buffer_length = sizeof(DWORD64);
				break;
			}
			case SetMemoryProtect_code:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(ULONG*)output_buffer = memorytools->SetMemoryProtect((HANDLE)((PSetMemoryProtectStruct)buffer)->pid, ((PSetMemoryProtectStruct)buffer)->address, ((PSetMemoryProtectStruct)buffer)->size, ((PSetMemoryProtectStruct)buffer)->protect_attribute);
				output_buffer_length = sizeof(ULONG);
				break;
			}
			case SetExecutePage_code:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(ULONG*)output_buffer = memorytools->SetExecutePage((HANDLE)((PSetExecutePageStruct)buffer)->pid, ((PSetExecutePageStruct)buffer)->virtualaddress, ((PSetExecutePageStruct)buffer)->size);
				output_buffer_length = sizeof(ULONG);
				break;
			}
			case AllocMemory_code:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(PVOID*)output_buffer = memorytools->AllocateMemory((HANDLE)((PAllocMemoryStruct)buffer)->pid, ((PAllocMemoryStruct)buffer)->allocsize, ((PAllocMemoryStruct)buffer)->protect);
				output_buffer_length = sizeof(PVOID);
				break;
			}
			case FreeMemory_code:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(ULONG*)output_buffer = memorytools->FreeMemory((HANDLE)((PFreeMemoryStruct)buffer)->pid, ((PFreeMemoryStruct)buffer)->free_address, ((PFreeMemoryStruct)buffer)->memory_size);
				output_buffer_length = sizeof(ULONG);
				break;
			}
			case GetModuleHandle_code:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(PVOID*)output_buffer = memorytools->GetModuleHandle((HANDLE)((PModuleStruct)buffer)->pid, ((PModuleStruct)buffer)->module_name);
				output_buffer_length = sizeof(PVOID);
				break;
			}
			case HidMemoryByVAD_code:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(ULONG*)output_buffer = memorytools->HideMemoryByVAD((HANDLE)((PVADMemoryStruct)buffer)->pid, ((PVADMemoryStruct)buffer)->memory_address, ((PVADMemoryStruct)buffer)->memory_size);
				output_buffer_length = sizeof(ULONG);
				break;
			}
			case ReadPhysicalProcessMemoryBy_CR3:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(PVOID*)output_buffer = memorytools->ReadProcessMemoryByCR3NoAttach(((PMemoryStruct)buffer)->pid, (PVOID)((PMemoryStruct)buffer)->target_address, ((PMemoryStruct)buffer)->read_and_write_data_size);
				output_buffer_length = sizeof(PVOID);
				break;
			}
			case WritePhysicalProcessMemoryBy_CR3:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(LONG*)output_buffer = memorytools->WriteProcessMemoryByCR3NoAttach(((PMemoryStruct)buffer)->pid, (PVOID)((PMemoryStruct)buffer)->target_address, &((PMemoryStruct)buffer)->write_data, ((PMemoryStruct)buffer)->read_and_write_data_size);
				output_buffer_length = sizeof(LONG);
				break;
			}
			case ReadProcessMemoryBy_MDL:
			{
				PVOID buffer = (PVOID)input_buffer;
				if (!NT_SUCCESS(memorytools->ReadMemoryByMDL(((PMemoryStruct)buffer)->pid, (PVOID)((PMemoryStruct)buffer)->target_address, ((PMemoryStruct)buffer)->read_and_write_data_size, output_buffer)))
					*(PVOID*)output_buffer = 0;
				output_buffer_length = ((PMemoryStruct)buffer)->read_and_write_data_size;
				break;
			}
			case WriteProcessMemoryBy_MDL:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(LONG*)output_buffer = memorytools->WriteMemoryByMDL(((PMemoryStruct)buffer)->pid, (PVOID)((PMemoryStruct)buffer)->target_address, &((PMemoryStruct)buffer)->write_data, ((PMemoryStruct)buffer)->read_and_write_data_size);
				output_buffer_length = sizeof(LONG);
				break;
			}
			case KillProcess_code:
			{
				PKillProcessStruct buffer = (PKillProcessStruct)input_buffer;
				*(LONG*)output_buffer = tools->KillProcessById((HANDLE)buffer->pid);
				output_buffer_length = sizeof(LONG);
				break;
			}
			case DeleteFile_code:
			{
				PDeleteExecuteFileStruct buffer = (PDeleteExecuteFileStruct)input_buffer;
				*(ULONG*)output_buffer = tools->DeleteFile(buffer->file_path);
				output_buffer_length = sizeof(LONG);
				break;
			}
			case SetMemoryVADProtection_code:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(LONG*)output_buffer = memorytools->SetMemoryVADProtection((HANDLE)((PVADMemoryStruct)buffer)->pid, ((PVADMemoryStruct)buffer)->memory_address, ((PVADMemoryStruct)buffer)->memory_size, ((PVADMemoryStruct)buffer)->protection);
				output_buffer_length = sizeof(LONG);
				break;
			}
			case InjectByHackThread_code:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(LONG*)output_buffer = injecthelper->InjectByHackThread((HANDLE)((PInjectByHackThreadStruct)buffer)->pid, ((PInjectByHackThreadStruct)buffer)->param_buffer_address, ((PInjectByHackThreadStruct)buffer)->loader_shellcode_address, ((PInjectByHackThreadStruct)buffer)->kernel_wait_millisecond, ((PInjectByHackThreadStruct)buffer)->createthread_address);
				output_buffer_length = sizeof(LONG);
				break;
			}
			case InjectByCreateThread_code:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(LONG*)output_buffer = injecthelper->InjectByCreateThread((HANDLE)((PInjectByHackThreadStruct)buffer)->pid, ((PInjectByHackThreadStruct)buffer)->param_buffer_address, ((PInjectByHackThreadStruct)buffer)->loader_shellcode_address, ((PInjectByHackThreadStruct)buffer)->kernel_wait_millisecond);
				output_buffer_length = sizeof(LONG);
				break;
			}
			case InjectByInstrumentationCallback_code:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(LONG*)output_buffer = injecthelper->InjectByInstCallBack((HANDLE)((PInjectByInstCallbackStruct)buffer)->pid, ((PInjectByInstCallbackStruct)buffer)->param_buffer_address, ((PInjectByInstCallbackStruct)buffer)->loader_shellcode_address, ((PInjectByInstCallbackStruct)buffer)->createthread_address, ((PInjectByInstCallbackStruct)buffer)->RtlCaptureContext, ((PInjectByInstCallbackStruct)buffer)->NtContinue, ((PInjectByInstCallbackStruct)buffer)->kernel_wait_millisecond, ((PInjectByInstCallbackStruct)buffer)->isclear_proccallback);
				output_buffer_length = sizeof(LONG);
				break;
			}
			case SuspendKernelThread_code:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(BOOL*)output_buffer = thread->SuspendKernelThread(((PKernelThreadStruct)buffer)->kernel_module_name, ((PKernelThreadStruct)buffer)->judgment);
				output_buffer_length = sizeof(BOOL);
				break;
			}
			case SuspendKernelThreadByID_code:
			{
				PVOID buffer = (PVOID)input_buffer;
				*(BOOL*)output_buffer = thread->SuspendKernelThreadByID(((PKernelThreadStruct)buffer)->kernel_module_name, ((PKernelThreadStruct)buffer)->tid);
				output_buffer_length = sizeof(BOOL);
				break;
			}
			case HelloDriver_code:
			{
				*(int*)output_buffer = 0x123;
				output_buffer_length = sizeof(int);
				break;
			}
		}
		//完成IO
		io_status->Information = 0;
		io_status->Status = STATUS_SUCCESS;
	}
	return TRUE;
}



