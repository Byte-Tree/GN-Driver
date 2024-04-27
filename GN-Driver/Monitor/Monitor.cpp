//////////////////////////////////////////////////////////////////////////////////////////////////////////
//						本来用于VAD隐藏内存后监视进程恢复VAD，后面可以再加功能
//////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "Monitor.h"
#include "../MainFunction/MainFunction.h"


Monitor::Monitor(IN HANDLE pid)
{
    NTSTATUS status = NULL;

    this->SetPID(pid);

    status = this->InitMonitor();
    if (!NT_SUCCESS(status))
        DbgPrint("[GN]:%s-> InitMonitor() errorcode:%p\n", __FUNCTION__, status);

}

Monitor::~Monitor()
{
	//PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);
	PsSetCreateProcessNotifyRoutine(CreateProcessNotify, TRUE);
	//this->DestroyList();
}

//public
void* Monitor::operator new(size_t size, POOL_TYPE pool_type)
{
#pragma warning(disable : 4996)
    return ExAllocatePoolWithTag(pool_type, size, 'Moni');
#pragma warning(default : 4996)
}

void Monitor::operator delete(void* pointer)
{
    ExFreePoolWithTag(pointer, 'Moni');
}

NTSTATUS Monitor::InitMonitor()
{
    NTSTATUS status = STATUS_SUCCESS;

    ////创建进程回调
    //status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE);//STATUS_ACCESS_DENIED
    //if (!NT_SUCCESS(status))
    //    DbgPrint("[GN]:%s-> PsSetCreateProcessNotifyRoutineEx() errorcode:%p\n", __FUNCTION__, status);
    status = PsSetCreateProcessNotifyRoutine(CreateProcessNotify, FALSE);
    if (!NT_SUCCESS(status))
        DbgPrint("[GN]:%s-> PsSetCreateProcessNotifyRoutine() errorcode:%p\n", __FUNCTION__, status);

    ////初始化时间、锁、链表头
    //KeInitializeEvent(&monitor->m_event, SynchronizationEvent, TRUE);
    //KeInitializeSpinLock(&monitor->m_lock);
    //InitializeListHead(&monitor->list_head);

    return status;
}

PPROCESSNODE Monitor::InitListNode()
{
	PPROCESSNODE pNode = NULL;

#pragma warning(disable : 4996)
	pNode = (PPROCESSNODE)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESSNODE), MEM_TAG);
#pragma warning(default : 4996)
	if (pNode == NULL)
		return NULL;

	return pNode;
}

void Monitor::DestroyList()
{
	// 释放链表所有内存
	while (TRUE)
	{
		// 从链表中取出一个节点
		PPROCESSNODE pNode = (PPROCESSNODE)ExInterlockedRemoveHeadList(&this->list_head, &this->m_lock);
		if (NULL != pNode)
		{
			if (NULL != pNode->pProcessInfo)
			{
				ExFreePoolWithTag(pNode->pProcessInfo, MEM_TAG);
			}
			ExFreePoolWithTag(pNode, MEM_TAG);
		}
		else
			break;
	}
}

BOOLEAN Monitor::GetPathByFileObject(PFILE_OBJECT FileObject, WCHAR* wzPath)
{
	BOOLEAN bGetPath = FALSE;

	POBJECT_NAME_INFORMATION ObjectNameInformation = NULL;
	__try
	{
		if (FileObject && MmIsAddressValid(FileObject) && wzPath)
		{
			//KdPrint(("MmIsAddressValid success."));
			if (NT_SUCCESS(IoQueryFileDosDeviceName(FileObject, &ObjectNameInformation)))   //注意该函数调用后要释放内存
			{
				//KdPrint(("IoQueryFileDosDeviceName success."));
				wcsncpy(wzPath, ObjectNameInformation->Name.Buffer, ObjectNameInformation->Name.Length);

				bGetPath = TRUE;

				ExFreePool(ObjectNameInformation);
			}


			if (!bGetPath)
			{
				//if (IoVolumeDeviceToDosName || RtlVolumeDeviceToDosName)
				{
					NTSTATUS	Status = STATUS_UNSUCCESSFUL;
					ULONG		ulRet = 0;
#pragma warning(disable : 4996)
					PVOID		Buffer = ExAllocatePool(PagedPool, 0x1000);
#pragma warning(default : 4996)

					if (Buffer)
					{
						// ObQueryNameString : \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\VMwareTray.exe
						memset(Buffer, 0, 0x1000);
						Status = ObQueryNameString(FileObject, (POBJECT_NAME_INFORMATION)Buffer, 0x1000, &ulRet);
						if (NT_SUCCESS(Status))
						{
							POBJECT_NAME_INFORMATION Temp = (POBJECT_NAME_INFORMATION)Buffer;
							//KdPrint(("ObQueryNameString success.%wZ\r\n", Temp));

							WCHAR szHarddiskVolume[100] = L"\\Device\\HarddiskVolume";

							if (Temp->Name.Buffer != NULL)
							{
								if (Temp->Name.Length / sizeof(WCHAR) > wcslen(szHarddiskVolume) &&
									!_wcsnicmp(Temp->Name.Buffer, szHarddiskVolume, wcslen(szHarddiskVolume)))
								{
									// 如果是以 "\\Device\\HarddiskVolume" 这样的形式存在的，那么再查询其卷名。
									UNICODE_STRING uniDosName;

									if (NT_SUCCESS(IoVolumeDeviceToDosName(FileObject->DeviceObject, &uniDosName)))
									{
										if (uniDosName.Buffer != NULL)
										{

											wcsncpy(wzPath, uniDosName.Buffer, uniDosName.Length);
											wcsncat(wzPath, Temp->Name.Buffer + wcslen(szHarddiskVolume) + 1, Temp->Name.Length - (wcslen(szHarddiskVolume) + 1));
											bGetPath = TRUE;
										}

										ExFreePool(uniDosName.Buffer);
									}

									else if (NT_SUCCESS(RtlVolumeDeviceToDosName(FileObject->DeviceObject, &uniDosName)))
									{
										if (uniDosName.Buffer != NULL)
										{

											wcsncpy(wzPath, uniDosName.Buffer, uniDosName.Length);
											wcsncat(wzPath, Temp->Name.Buffer + wcslen(szHarddiskVolume) + 1, Temp->Name.Length - (wcslen(szHarddiskVolume) + 1));
											bGetPath = TRUE;
										}

										ExFreePool(uniDosName.Buffer);
									}

								}
								else
								{
									// 如果不是以 "\\Device\\HarddiskVolume" 这样的形式开头的，那么直接复制名称。
									wcsncpy(wzPath, Temp->Name.Buffer, Temp->Name.Length);
									bGetPath = TRUE;
								}
							}
						}

						ExFreePool(Buffer);
					}
				}
			}
		}
	}
	__except (1)
	{
		DbgPrint("[GN]:%s-. GetPathByFileObject Catch __Except\r\n", __FUNCTION__);
		bGetPath = FALSE;
	}

	return bGetPath;
}

BOOLEAN Monitor::GetProcessPathBySectionObject(HANDLE ulProcessID, WCHAR* wzProcessPath)
{
    PEPROCESS			EProcess = NULL;
    PFILE_OBJECT		FileObject = NULL;
    BOOLEAN				bGetPath = FALSE;

    if (NT_SUCCESS(PsLookupProcessByProcessId(ulProcessID, &EProcess)))
    {
        PsReferenceProcessFilePointer(EProcess, &FileObject);
        if (FileObject && MmIsAddressValid(FileObject))
        {
            FileObject = (PFILE_OBJECT)((ULONG_PTR)FileObject & 0xFFFFFFFFFFFFFFF0);
            bGetPath = GetPathByFileObject(FileObject, wzProcessPath);
            if (!bGetPath)
            {
                //DbgPrint("[GN]:Failed to get process full path by object, FileObject = 0x%08X", FileObject);
            }
        }
    }
    else
    {
        DbgPrint("[GN]:Failed to call PsLookupProcessByProcessId.\r\n");
    }

    if (bGetPath == FALSE)
    {
        wcscpy(wzProcessPath, L"Unknow");
    }

    return bGetPath;

}

void Monitor::CreateProcessNotifyEx(IN PEPROCESS eprocess, IN HANDLE pid, IN PPS_CREATE_NOTIFY_INFO create_info)
{
    if (create_info != NULL)
    {
        LARGE_INTEGER current_systemtime = { NULL };
        LARGE_INTEGER current_localtime = { NULL };
        WCHAR process_path[MAX_STRING_LENGTH] = { NULL };

        //获取时间
        KeQuerySystemTime(&current_systemtime);
        ExSystemTimeToLocalTime(&current_systemtime, &current_localtime);

        //获取进程路径
		monitor->GetProcessPathBySectionObject(create_info->ParentProcessId, process_path);

		PPROCESSNODE p_node = monitor->InitListNode();
		if (p_node != NULL)
		{
			ULONG parent_process_length = wcslen(process_path) * sizeof(WCHAR) + sizeof(WCHAR);
			ULONG process_length = create_info->ImageFileName->Length + sizeof(WCHAR);
			ULONG commandline_length = (ULONG)(create_info->CommandLine == NULL ? 0 : create_info->CommandLine + sizeof(WCHAR));

			SIZE_T number_of_bytes = sizeof(PROCESSINFO) + parent_process_length + process_length + commandline_length;

#pragma warning(disable : 4996)
			p_node->pProcessInfo = (PPROCESSINFO)ExAllocatePoolWithTag(NonPagedPool, number_of_bytes, MEM_TAG);
#pragma warning(default : 4996)

			p_node->pProcessInfo->bIsCreate = true;
			p_node->pProcessInfo->hParentProcessId = create_info->ParentProcessId;
			p_node->pProcessInfo->ulParentProcessLength = parent_process_length;
			p_node->pProcessInfo->hProcessId = pid;
			p_node->pProcessInfo->ulProcessLength = process_length;
			p_node->pProcessInfo->ulCommandLineLength = commandline_length;

			RtlTimeToTimeFields(&current_localtime, &p_node->pProcessInfo->time);

			RtlCopyBytes(p_node->pProcessInfo->uData, process_path, parent_process_length);
			RtlCopyBytes(p_node->pProcessInfo->uData + parent_process_length, create_info->ImageFileName->Buffer, create_info->ImageFileName->Length);
			p_node->pProcessInfo->uData[parent_process_length + create_info->ImageFileName->Length + 0] = '\0';
			p_node->pProcessInfo->uData[parent_process_length + create_info->ImageFileName->Length + 1] = '\0';
			RtlCopyBytes(p_node->pProcessInfo->uData + parent_process_length + process_length, create_info->CommandLine->Buffer, create_info->CommandLine->Length);
			p_node->pProcessInfo->uData[parent_process_length + process_length + create_info->CommandLine->Length + 0] = '\0';
			p_node->pProcessInfo->uData[parent_process_length + process_length + create_info->CommandLine->Length + 1] = '\0';

			ExInterlockedInsertTailList(&monitor->list_head, (PLIST_ENTRY)p_node, &monitor->m_lock);
			KeSetEvent(&monitor->m_event, 0, FALSE);
		}
    }
	else
	{
		DbgPrint("[GN]:%s-> 检测到进程：%d 退出\n", __FUNCTION__, pid);
		if (monitor->m_pid == memorytools->GetOldVadPID())
		{
			DbgPrint("[GN]:退出进程等于处理vad后的进程!!!\n");
		}
	}
}

void Monitor::CreateProcessNotify(IN HANDLE parent_pid, IN HANDLE pid, IN BOOLEAN create)
{
	WCHAR			parent_process_path[512] = { NULL };
	WCHAR			process_path[512] = { NULL };
	UNICODE_STRING	process_parameters = { NULL };

	monitor->GetProcessPathBySectionObject(parent_pid, parent_process_path);
	monitor->GetProcessPathBySectionObject(pid, process_path);

	if (!create)
	{
		//DbgPrint("[GN]:进程[%04ld] %ws退出，父进程：[%04ld] %ws\n", pid, process_parameters, parent_pid, parent_process_path);

		//监视vad
		if (pid == monitor->m_pid)
		{
			//.
			//DbgPrint("[GN]:monitor->m_pid：%d，memorytools->GetOldVadPID():%d\n", monitor->m_pid, memorytools->GetOldVadPID());
			memorytools->RestoreVAD();
		}
	}
	//else
	//	DbgPrint("[GN]:父进程：[%04ld] %ws, 创建了进程：[%04ld] %ws", parent_pid, parent_process_path, pid, process_path);
}



