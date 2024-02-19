//////////////////////////////////////////////////////////////////////////////////////////////////////////
//		               内核线程相关的函数在这里初始化并定义好，方便其他模块调用和管理维护
//////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "Thread.h"
#include "../MainFunction/MainFunction.h"


Thread::Thread()
{
    this->NtSuspendThread = (pfnNtSuspendThread)tools->GetSSDTFunction(tools->GetIndexByName("NtSuspendThread"));
    this->NtResumeThread = (pfnNtResumeThread)tools->GetSSDTFunction(tools->GetIndexByName("NtResumeThread"));
    this->NtGetContextThread = (pfnNtGetContextThread)tools->GetSSDTFunction(tools->GetIndexByName("NtGetContextThread"));
    this->NtSetContextThread = (pfnNtSetContextThread)tools->GetSSDTFunction(tools->GetIndexByName("NtSetContextThread"));
    this->NtOpenThread = (pfnNtOpenThread)tools->GetSSDTFunction(tools->GetIndexByName("NtOpenThread"));
    this->NtQueryInformationThread = (pfnNtQueryInformationThread)tools->GetSSDTFunction(tools->GetIndexByName("NtQueryInformationThread"));
    this->mNtCreateThreadEx = (pfnNtCreateThreadEx)tools->GetSSDTFunction(tools->GetIndexByName("NtCreateThreadEx"));

    UNICODE_STRING ustr1 = RTL_CONSTANT_STRING(L"PsGetContextThread");
    this->mPsGetContextThread = (pfnPsGetContextThread)MmGetSystemRoutineAddress(&ustr1);

    UNICODE_STRING ustr2 = RTL_CONSTANT_STRING(L"PsSetContextThread");
    this->mPsSetContextThread = (pfnPsGetContextThread)MmGetSystemRoutineAddress(&ustr2);

    UNICODE_STRING PsGetThreadTeb_string = RTL_CONSTANT_STRING(L"PsGetThreadTeb");
    this->mPsGetThreadTeb = (pfnPsGetThreadTeb)MmGetSystemRoutineAddress(&PsGetThreadTeb_string);

    UNICODE_STRING ZwGetNextThread_string = RTL_CONSTANT_STRING(L"ZwGetNextThread");
    this->mZwGetNextThread = (pfnZwGetNextThread)MmGetSystemRoutineAddress(&ZwGetNextThread_string);
    //判断是否导出，未导出则使用特征码搜索
    if (!this->mZwGetNextThread)
    {
        UNICODE_STRING ZwGetNotificationResourceManagerString = RTL_CONSTANT_STRING(L"ZwGetNotificationResourceManager");
        PUCHAR ZwGetNotificationResourceManager = (PUCHAR)MmGetSystemRoutineAddress(&ZwGetNotificationResourceManagerString);
        if (ZwGetNotificationResourceManager)
        {
            PUCHAR starAddress = ZwGetNotificationResourceManager - 78;
            for (; starAddress < ZwGetNotificationResourceManager - 8; starAddress++)
            {
                if (starAddress[0] == 0x48 && starAddress[1] == 0x8B && starAddress[2] == 0xC4)
                {
                    this->mZwGetNextThread = (pfnZwGetNextThread)starAddress;
                    break;
                }
            }
        }
    }

    UNICODE_STRING ZwQuerySystemInformation_string = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
    this->mZwQuerySystemInformation = (pfnZwQuerySystemInformation)MmGetSystemRoutineAddress(&ZwQuerySystemInformation_string);

    UNICODE_STRING ZwQueryInformationThread_string = RTL_CONSTANT_STRING(L"ZwQueryInformationThread");
    this->mZwQueryInformationThread = (pfnZwQueryInformationThread)MmGetSystemRoutineAddress(&ZwQueryInformationThread_string);

#if _INFORELEASE

    DbgPrint("[GN]:NtSuspendThread：%p\n", NtSuspendThread);
    DbgPrint("[GN]:NtResumeThread：%p\n", NtResumeThread);
    DbgPrint("[GN]:NtGetContextThread：%p\n", NtGetContextThread);
    DbgPrint("[GN]:NtSetContextThread：%p\n", NtSetContextThread);
    DbgPrint("[GN]:mPsGetContextThread:%p", mPsGetContextThread);
    DbgPrint("[GN]:mPsSetContextThread:%p", mPsSetContextThread);
    DbgPrint("[GN]:mPsGetThreadTeb:%p", mPsGetThreadTeb);
    DbgPrint("[GN]:mZwGetNextThread:%p", mZwGetNextThread);
    DbgPrint("[GN]:mZwQuerySystemInformation:%p", mZwQuerySystemInformation);
    DbgPrint("[GN]:mZwQueryInformationThread:%p", mZwQueryInformationThread);

#endif // _INFORELEASE
}

Thread::~Thread()
{
}

void* Thread::operator new(size_t size, POOL_TYPE pool_type)
{
    return ExAllocatePoolWithTag(pool_type, size, 'abcf');
}

void Thread::operator delete(void* pointer)
{
    ExFreePoolWithTag(pointer, 'abcf');
}

PVOID Thread::PsGetThreadTeb(IN PETHREAD Thread)
{
    return this->mPsGetThreadTeb(Thread);
}

NTSTATUS Thread::SuspendThread(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount)
{
    if (!tools->DisablePspNotify())
    {
        DbgPrint("[GN]:%s-> DisablePspNotify() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }
    if (!tools->ChangePrevKernelMode(tools->GetPreviousModeAddress()))
    {
        DbgPrint("[GN]:%s-> ChangePrevKernelMode() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = this->NtSuspendThread(ThreadHandle, PreviousSuspendCount);

    if (!tools->EnablePspNotify())
    {
        DbgPrint("[GN]:%s-> EnablePspNotify() error", __FUNCTION__);
        status = -1;
    }
    if(!tools->RestorePrevKernelMode(tools->GetPreviousModeAddress()))
    {
        DbgPrint("[GN]:%s-> RestorePrevKernelMode() error", __FUNCTION__);
        status = -2;
    }
    return status;
}

NTSTATUS Thread::ResumeThread(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount)
{
    if (!tools->DisablePspNotify())
    {
        DbgPrint("[GN]:%s-> DisablePspNotify() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }
    if (!tools->ChangePrevKernelMode(tools->GetPreviousModeAddress()))
    {
        DbgPrint("[GN]:%s-> ChangePrevKernelMode() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = this->NtResumeThread(ThreadHandle, PreviousSuspendCount);

    if (!tools->EnablePspNotify())
    {
        DbgPrint("[GN]:%s-> EnablePspNotify() error", __FUNCTION__);
        status = -1;
    }
    if (!tools->RestorePrevKernelMode(tools->GetPreviousModeAddress()))
    {
        DbgPrint("[GN]:%s-> RestorePrevKernelMode() error", __FUNCTION__);
        status = -2;
    }
    return status;
}

NTSTATUS Thread::GetContextThread(IN HANDLE ThreadHandle, OUT PCONTEXT ThreadContext)
{
    if (!tools->DisablePspNotify())
    {
        DbgPrint("[GN]:%s-> DisablePspNotify() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }
    if (!tools->ChangePrevKernelMode(tools->GetPreviousModeAddress()))
    {
        DbgPrint("[GN]:%s-> ChangePrevKernelMode() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = this->NtGetContextThread(ThreadHandle, ThreadContext);

    if (!tools->EnablePspNotify())
    {
        DbgPrint("[GN]:%s-> EnablePspNotify() error", __FUNCTION__);
        status = -1;
    }
    if (!tools->RestorePrevKernelMode(tools->GetPreviousModeAddress()))
    {
        DbgPrint("[GN]:%s-> RestorePrevKernelMode() error", __FUNCTION__);
        status = -2;
    }
    return status;
}

NTSTATUS Thread::SetContextThread(IN HANDLE ThreadHandle, IN PCONTEXT ThreadContext)
{
    if (!tools->DisablePspNotify())
    {
        DbgPrint("[GN]:%s-> DisablePspNotify() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }
    if (!tools->ChangePrevKernelMode(tools->GetPreviousModeAddress()))
    {
        DbgPrint("[GN]:%s-> ChangePrevKernelMode() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = this->NtSetContextThread(ThreadHandle, ThreadContext);

    if (!tools->EnablePspNotify())
    {
        DbgPrint("[GN]:%s-> EnablePspNotify() error", __FUNCTION__);
        status = -1;
    }
    if (!tools->RestorePrevKernelMode(tools->GetPreviousModeAddress()))
    {
        DbgPrint("[GN]:%s-> RestorePrevKernelMode() error", __FUNCTION__);
        status = -1;
    }
    return status;
}

KTRAP_FRAME Thread::GetContextByEThread(PETHREAD pethread)
{
    __try
    {
        PKTRAP_FRAME threadContext = (PKTRAP_FRAME) * (PULONG64)((ULONG64)pethread + this->ktrap_frame_offset);
        return *threadContext;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s-> errorcode:%p", __FUNCTION__, STATUS_UNSUCCESSFUL);
        KTRAP_FRAME threadContext = { NULL };
        return threadContext;
    }
}

NTSTATUS Thread::SetContextByEThread(PETHREAD pethread, KTRAP_FRAME context)
{
    __try
    {
        PKTRAP_FRAME threadContext = (PKTRAP_FRAME) * (PULONG64)((ULONG64)pethread + this->ktrap_frame_offset);
        *threadContext = context;
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s-> errorcode:%p", __FUNCTION__, STATUS_UNSUCCESSFUL);
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS Thread::OpenThread(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId)
{
    if (!tools->DisablePspNotify())
    {
        DbgPrint("[GN]:%s-> DisablePspNotify() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }
    if (!tools->ChangePrevKernelMode(tools->GetPreviousModeAddress()))
    {
        DbgPrint("[GN]:%s-> ChangePrevKernelMode() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = this->NtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);

    if (!tools->EnablePspNotify())
    {
        DbgPrint("[GN]:%s-> EnablePspNotify() error", __FUNCTION__);
        status = -1;
    }
    if (!tools->RestorePrevKernelMode(tools->GetPreviousModeAddress()))
    {
        DbgPrint("[GN]:%s-> RestorePrevKernelMode() error", __FUNCTION__);
        status = -1;
    }
    return status;
}

NTSTATUS Thread::PsGetContextThread(IN PETHREAD Thread, OUT PCONTEXT ThreadContext, IN KPROCESSOR_MODE Mode)
{
    return this->mPsGetContextThread(Thread, ThreadContext, Mode);
}

NTSTATUS Thread::PsSetContextThread(IN PETHREAD Thread, OUT PCONTEXT ThreadContext, IN KPROCESSOR_MODE Mode)
{
    return this->mPsSetContextThread(Thread, ThreadContext, Mode);
}

PETHREAD Thread::GetFirstThread(PEPROCESS tempep)
{
    PETHREAD pretthreadojb = NULL, ptempthreadobj = NULL;
    PLIST_ENTRY plisthead = NULL;
    PLIST_ENTRY plistflink = NULL;
    int i = 0;

    plisthead = (PLIST_ENTRY)((PUCHAR)tempep + 0x30);

    plistflink = plisthead->Flink;

    ptempthreadobj = (PETHREAD)((PUCHAR)plistflink - 0x2f8);

    return ptempthreadobj;
}

DWORD Thread::GetThreadIdByModuleName(IN HANDLE pid, IN const wchar_t* module_name)
{
    ULONG process_id = NULL;
    PETHREAD pEthread = NULL;
    ULONG ThreadCount = NULL;
    PEPROCESS eprocess = NULL;
    //KAPC_STATE kapc_state = { 0 };
    PCLIENT_ID pcid = NULL;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &eprocess)))
        return 0;

    __try
    {
        //KeStackAttachProcess(eprocess, &kapc_state);
        while (process_id < 100000)
        {
            NTSTATUS status = PsLookupThreadByThreadId((HANDLE)process_id, &pEthread);
            if (NT_SUCCESS(status))
            {
                //判断线程是否属于指定的进程
                if (IoThreadToProcess(pEthread) == eprocess)
                {
                    //遍历到属于pid的线程
                    pcid = (PCLIENT_ID)((UCHAR*)pEthread + 0x1EC);
                    DbgPrint("[GN]:pid:%d,tid:%d", pcid->UniqueProcess, pcid->UniqueThread);
                    DbgPrint("[GN]:线程起始地址：%p", (ULONG64)((UCHAR*)pEthread + 0x224));


                    ThreadCount++;
                }
                ObDereferenceObject(pEthread);
            }
            process_id += 4;
        }
        DbgPrint("[GN]:线程总数：%d\n", ThreadCount);

        //KeUnstackDetachProcess(&kapc_state);
        ObDereferenceObject(eprocess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:异常...");
    }

    return 0;
}

NTSTATUS Thread::NtCreateThreadEx(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID StartAddress, IN PVOID Parameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT PVOID ByteBuffer)
{
    if (!tools->DisablePspNotify())
    {
        DbgPrint("[GN]:%s-> DisablePspNotify() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }
    if (!tools->ChangePrevKernelMode(tools->GetPreviousModeAddress()))
    {
        DbgPrint("[GN]:%s-> ChangePrevKernelMode() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = this->mNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartAddress, Parameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, ByteBuffer);

    if (!tools->EnablePspNotify())
    {
        DbgPrint("[GN]:%s-> EnablePspNotify() error", __FUNCTION__);
        status = -1;
    }
    if (!tools->RestorePrevKernelMode(tools->GetPreviousModeAddress()))
    {
        DbgPrint("[GN]:%s-> RestorePrevKernelMode() error", __FUNCTION__);
        status = -1;
    }
    return status;
}

NTSTATUS Thread::ZwGetNextThread(IN HANDLE ProcessHandle, IN HANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN ULONG HandleAttributes, IN ULONG Flags, OUT PHANDLE NewThreadHandle)
{
    return this->mZwGetNextThread(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, NewThreadHandle);
}

NTSTATUS Thread::ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength)
{
    return this->mZwQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS Thread::ZwQueryInformationThread(IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, IN PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength)
{
    return this->mZwQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}

bool Thread::SuspendKernelThread(const char* kernel_module_name, const char* judgment_tag)
{
    bool return_value = false;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PSYSTEM_PROCESSES process_info = NULL;
    PSYSTEM_PROCESSES temp_alloc = NULL;    //这个留作以后释放指针的时候用。
    ULONG process_info_length;
    ULONG next_offset;

    ULONG kernel_module_handle_size = 0;
    DWORD64 kernel_module_handle = (DWORD64)memorytools->GetKernelModuleByZwQuerySystemInformation(kernel_module_name, &kernel_module_handle_size);
    DWORD64 kernel_module_handle_end = kernel_module_handle + kernel_module_handle_size;
    if (kernel_module_handle)
    {
        __try
        {
            //第一次使用肯定是缓冲区不够，在极少数的情况下第二次会出现不够，所以用while循环
            status = thread->ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, process_info, 0, &process_info_length);
            while (STATUS_INFO_LENGTH_MISMATCH == status)
            {
                process_info = (PSYSTEM_PROCESSES)ExAllocatePoolWithTag(NonPagedPool, process_info_length, '1aes');
                temp_alloc = process_info;
                if (NULL == process_info)
                {
                    DbgPrint("[GN]:%s-> allocatePoolWithTag failed", __FUNCTION__);
                    return false;
                }
                status = thread->ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, process_info, process_info_length, &process_info_length);
            }
            if (!NT_SUCCESS(status))
            {
                DbgPrint("[GN]:%s-> [error]:++++%d", __FUNCTION__, status);
                ExFreePoolWithTag(temp_alloc, '1aes');
                return false;
            }

            do
            {
                if (MmIsAddressValid(process_info->ProcessName.Buffer) && NULL != process_info)
                {
                    ////遍历系统进程线程
                    if (_wcsicmp(process_info->ProcessName.Buffer, L"System") == 0)
                    {
                        PSYSTEM_THREADS process_thread = process_info->Threads;
                        for (ULONG i = 0; i < process_info->ThreadCount; i++)
                        {
                            if ((process_thread->StartAddress >= (PVOID)kernel_module_handle) && (process_thread->StartAddress <= (PVOID)kernel_module_handle_end))
                            {
                                DbgPrint("[GN]:线程ID：%d，线程地址：%p，线程状态：%d，线程切换次数：%d，基本优先权：%d，优先权：%d\n",
                                    process_thread->ClientID.UniqueThread, process_thread->StartAddress, process_thread->ThreadState, process_thread->ContextSwitchCount,
                                    process_thread->BasePriority, process_thread->Priority);
                                
                                //将线程地址转换为字符串
                                char judgment[16] = { NULL };
                                tools->itoa((INT)process_thread->StartAddress, judgment, 16);
                                if (strlen(judgment) == 8)	
                                    strcpy(judgment, &judgment[5]);
                                else
                                    strcpy(judgment, &judgment[4]);
                                //DbgPrint("[GN]:转换后的数据：%s\n", judgment);

                                if (_stricmp(judgment, judgment_tag) == 0)
                                {
                                    HANDLE thread_handle = NULL;
                                    OBJECT_ATTRIBUTES obj = { NULL };
                                    CLIENT_ID cid = { NULL };

                                    cid.UniqueProcess = (HANDLE)4;//4是系统进程
                                    cid.UniqueThread = process_thread->ClientID.UniqueThread;
                                    InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                                    status = ZwOpenThread(&thread_handle, THREAD_ALL_ACCESS, &obj, &cid);
                                    if (NT_SUCCESS(status))
                                    {
                                        status = this->SuspendThread(thread_handle, NULL);
                                        if (NT_SUCCESS(status))
                                        {
                                            DbgPrint("[GN]:暂停线程成功\n");
                                            return_value = true;
                                        }
                                        ZwClose(thread_handle);
                                    }
                                }
                            }
                            process_thread++;
                        }
                    }
                }

                next_offset = process_info->NextEntryDelta;
                process_info = (PSYSTEM_PROCESSES)((PUCHAR)process_info + process_info->NextEntryDelta);

            } while (next_offset != 0);

            ExFreePoolWithTag(temp_alloc, '1aes');
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DbgPrint("[GN]:异常");
        }
    }
    else
        DbgPrint("[GN]:%s-> 获取内核模块句柄失败！", __FUNCTION__);
    return return_value;
}

bool Thread::SuspendKernelThreadByID(const char* kernel_module_name, HANDLE tid)
{
    bool return_value = false;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PSYSTEM_PROCESSES process_info = NULL;
    PSYSTEM_PROCESSES temp_alloc = NULL;    //这个留作以后释放指针的时候用。
    ULONG process_info_length;
    ULONG next_offset;

    ULONG kernel_module_handle_size = 0;
    DWORD64 kernel_module_handle = (DWORD64)memorytools->GetKernelModuleByZwQuerySystemInformation(kernel_module_name, &kernel_module_handle_size);
    DWORD64 kernel_module_handle_end = kernel_module_handle + kernel_module_handle_size;
    if (kernel_module_handle)
    {
        __try
        {
            //第一次使用肯定是缓冲区不够，在极少数的情况下第二次会出现不够，所以用while循环
            status = thread->ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, process_info, 0, &process_info_length);
            while (STATUS_INFO_LENGTH_MISMATCH == status)
            {
                process_info = (PSYSTEM_PROCESSES)ExAllocatePoolWithTag(NonPagedPool, process_info_length, '1aes');
                temp_alloc = process_info;
                if (NULL == process_info)
                {
                    DbgPrint("[GN]:%s-> allocatePoolWithTag failed", __FUNCTION__);
                    return false;
                }
                status = thread->ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, process_info, process_info_length, &process_info_length);
            }
            if (!NT_SUCCESS(status))
            {
                DbgPrint("[GN]:%s-> [error]:++++%d", __FUNCTION__, status);
                ExFreePoolWithTag(temp_alloc, '1aes');
                return false;
            }

            do
            {
                if (MmIsAddressValid(process_info->ProcessName.Buffer) && NULL != process_info)
                {
                    ////遍历系统进程线程
                    if (_wcsicmp(process_info->ProcessName.Buffer, L"System") == 0)
                    {
                        PSYSTEM_THREADS process_thread = process_info->Threads;
                        for (ULONG i = 0; i < process_info->ThreadCount; i++)
                        {
                            if ((process_thread->StartAddress >= (PVOID)kernel_module_handle) && (process_thread->StartAddress <= (PVOID)kernel_module_handle_end))
                            {
                                if (process_thread->ClientID.UniqueThread == tid)
                                {
                                    DbgPrint("[GN]:线程ID：%d，线程地址：%p，线程状态：%d，线程切换次数：%d\n", process_thread->ClientID.UniqueThread, process_thread->StartAddress, process_thread->ThreadState, process_thread->ContextSwitchCount);

                                    HANDLE thread_handle = NULL;
                                    OBJECT_ATTRIBUTES obj = { NULL };
                                    CLIENT_ID cid = { NULL };

                                    cid.UniqueProcess = (HANDLE)4;//4是系统进程
                                    cid.UniqueThread = process_thread->ClientID.UniqueThread;
                                    InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                                    status = ZwOpenThread(&thread_handle, THREAD_ALL_ACCESS, &obj, &cid);
                                    if (NT_SUCCESS(status))
                                    {
                                        status = this->SuspendThread(thread_handle, NULL);
                                        if (NT_SUCCESS(status))
                                        {
                                            DbgPrint("[GN]:暂停线程成功\n");
                                            return_value = true;
                                        }
                                        ZwClose(thread_handle);
                                    }
                                }
                            }
                            process_thread++;
                        }
                    }
                }

                next_offset = process_info->NextEntryDelta;
                process_info = (PSYSTEM_PROCESSES)((PUCHAR)process_info + process_info->NextEntryDelta);

            } while (next_offset != 0);

            ExFreePoolWithTag(temp_alloc, '1aes');
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DbgPrint("[GN]:异常");
        }
    }
    else
        DbgPrint("[GN]:%s-> 获取内核模块句柄失败！", __FUNCTION__);
    return return_value;
}

//void Thread::GetThread(int Pid)
//{
//    ULONG pTargetProcess;
//    ULONG pTargetThread;
//    ULONG pNotAlertableThread;
//    ULONG pSystemProcess;
//    ULONG pTempThread;
//    ULONG pNextEntry, pListHead, pThNextEntry, pThListHead, pMyProcess;
//    //PTHREAD_INFO 
//    DWORD dwPidOffset = 0x084;
//    DWORD dwPNameOffset = 0x174;
//    int bFindTid = 0;
//    if (dwPidOffset == 0 || dwPNameOffset == 0)
//    {
//        DbgPrint("[GN]:Get Offset Fail...");
//        dwPidOffset = 0x084; dwPNameOffset = 0x174;
//    }
//    if (0 == Pid)
//        return;
//    //获得系统进程
//    pMyProcess = pSystemProcess = (ULONG)PsGetCurrentProcess();
//
//    if (!pSystemProcess)
//    {
//        DbgPrint("[GN]:PsGetCurrentProcess() error");
//        return;
//    }
//
//    __try
//    {
//        //获取进程列表头(+0x088 ActiveProcessLinks : _LIST_ENTRY)
//        pListHead = pSystemProcess + 0x88;
//        //得到下一个EPROCESS结构的ActiveProcessLinks偏移地址
//        pNextEntry = *(ULONG*)pListHead;
//        if (!pNextEntry)
//            DbgPrint("[GN]:pNextEntry error");
//        else
//        {
//            while (pNextEntry != pListHead)
//            {
//                DbgPrint("[GN]:得到EPROCESS的首地址");
//                //得到EPROCESS的首地址
//                pSystemProcess = pNextEntry - 0x88;
//                //进程名偏移
//                //+0x174 ImageFileName:[16] UChar
//                //DbgPrint("ProcessName %s PID:%x\n",(char*)pSystemProcess+dwPNameOffset,*(int*)((char*)pSystemProcess+dwPidOffset));
//
//                //Is this explorer.exe?
//                //DbgBreakPoint();
//
//                //if(_strnicmp((char*)pSystemProcess+dwPNameOffset,"explorer.exe",12)==0)
//                if (*(int*)((char*)pSystemProcess + dwPidOffset) == Pid)
//                {
//                    DbgPrint("[GN]:得到进程的EPROCESS结构的地址");
//                    //得到进程的EPROCESS结构的地址
//                    bFindTid = 1;
//                    pTargetProcess = pSystemProcess;
//
//                    pTargetThread = pNotAlertableThread = 0;
//
//                    //获取线程列表头
//                    //+0x050 ThreadListHead   : _LIST_ENTRY
//                    //也就是_KPROCESS(PCB)中ThreadListHead的偏移地址
//                    pThListHead = pSystemProcess + 0x50;
//                    //得到ETHREAD结构中_KTHREAD(Tcb)的+0x1b0 ThreadListEntry  : _LIST_ENTRY地址
//                    pThNextEntry = *(ULONG*)pThListHead;
//                    //Now we loop through it's threads, seeking an alertable thread
//                    while (pThNextEntry != pThListHead)
//                    {
//                        DbgPrint("[GN]:得到所属ETHREAD的首地址");
//                        //所属ETHREAD的首地址
//                        pTempThread = pThNextEntry - 0x1b0;
//                        //DbgPrint("ethread address is:0x%x\n",(ULONG *)pTempThread);
//                        //DbgPrint("Start Address  is:0x%x\n",*(DWORD *)(pTempThread+0x228));
//                        //线程ID
//                        //ETHREAD+0x1ec Cid : _CLIENT_ID为进程ID
//                        //再向下+4为线程ID
//                        //DbgPrint("thread Id is %d\n",*(ULONG *)(pTempThread+0x1f0));
//
//                        ULONG thread_id = *(ULONG*)(pTempThread + 0x1f0);
//                        ULONG64 start_address = *(int*)(pTempThread + 0x228);
//                        PULONG pethread = (ULONG*)pTempThread;
//
//                        pNotAlertableThread = pTempThread;
//
//                        //下一个线程块
//                        pThNextEntry = *(ULONG*)pThNextEntry;
//                    }
//                    break;
//                }
//                //下一个进程块
//                pNextEntry = *(ULONG*)pNextEntry;
//            }
//        }
//        if (bFindTid == 1)
//        {
//            return;
//        }
//    }
//    __except (EXCEPTION_EXECUTE_HANDLER)
//    {
//        DbgPrint("[GN]:遍历线程抛出异常");
//    }
//    return;
//}

