//////////////////////////////////////////////////////////////////////////////////////////////////////////
//		达到不触发PG（一些老系统还是会被PG）抹掉自身驱动的一些特征，21h2以上卸载不蓝屏，以下卸载驱动蓝精灵
//////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "HideDriver.h"
#include "../MainFunction/MainFunction.h"


HideDriver::HideDriver(PDRIVER_OBJECT p_object)
{
    hide_driver = this;
    self_driver_object = p_object;

    //需要用的时候才取消注释，问题：卸载驱动蓝屏
    if (hide_driver->GetOsVersionNumber() > 8000)
    {
        if (NT_SUCCESS(hide_driver->HideDriverWin10(p_object)))
            IoRegisterDriverReinitialization(p_object, HideDriver::ReInitializeDriver, NULL);
    }
    else
        hide_driver->HideDriverWin7(p_object);

    DbgPrint("[GN]:%s-> success!\n", __FUNCTION__);
}

HideDriver::~HideDriver()
{
    ////修复驱动特征
    //if (this->hide_statu)
    //{
    //    this->self_driver_object->DriverSection = this->old_driver_information.old_driver_object.DriverSection;
    //    this->self_driver_object->DriverStart = this->old_driver_information.old_driver_object.DriverStart;
    //    this->self_driver_object->DriverSize = this->old_driver_information.old_driver_object.DriverSize;
    //    this->self_driver_object->DriverUnload = this->old_driver_information.old_driver_object.DriverUnload;
    //    this->self_driver_object->DriverInit = this->old_driver_information.old_driver_object.DriverInit;
    //    this->self_driver_object->DeviceObject = this->old_driver_information.old_driver_object.DeviceObject;
    //    //恢复seh
    //    PDRIVER_LDR_DATA_TABLE_ENTRY ldrEntry = NULL;
    //    ldrEntry = (PDRIVER_LDR_DATA_TABLE_ENTRY)(this->self_driver_object->DriverSection);
    //    ldrEntry->DllBase = this->old_driver_information.old_ldrEntry.DllBase;
    //    //this->m_MiProcessLoaderEntry(self_driver_object->DriverSection, 1);
    //}
}

//public
void* HideDriver::operator new(size_t size, POOL_TYPE pool_type)
{
    return ExAllocatePoolWithTag(pool_type, size, 'abca');
}

void HideDriver::operator delete(void* pointer)
{
    ExFreePoolWithTag(pointer, 'abca');
}

//private
ULONG HideDriver::GetOsVersionNumber()
{
    //Windows 10（20H2）    19042
    //Windows 10（2004)     19041
    //Windows 10（1909）    18363
    //Windows 10（1903）    18362
    //Windows 10（1809）    17763
    //Windows 10（1803）    17134
    //Windows 10（1709）    16299
    //Windows 10（1703）    15063
    //Windows 10（1607）    14393
    //Windows 10（1511）    10586
    //Windows 10 (1507)     10240
    //Windows 8.1（更新1）  MajorVersion = 6 MinorVersion = 3 BuildNumber = 9600
    //Windows 8.1           MajorVersion = 6 MinorVersion = 3 BuildNumber = 9200
    //Windows 8             MajorVersion = 6 MinorVersion = 2 BuildNumber = 9200
    RTL_OSVERSIONINFOW version = { 0 };
    NTSTATUS status = RtlGetVersion(&version);
    if (!NT_SUCCESS(status))
        return 0;
    else
        return version.dwBuildNumber;
}

void HideDriver::KernelSleep(LONG msec)
{
    LARGE_INTEGER my_interval;
    my_interval.QuadPart = DELAY_ONE_MILLISECOND;
    my_interval.QuadPart *= msec;
    KeDelayExecutionThread(KernelMode, 0, &my_interval);
}

// 取出指定函数地址
PVOID HideDriver::GetProcAddress(WCHAR* FuncName)
{
    UNICODE_STRING u_FuncName = { 0 };
    PVOID ref = NULL;
    RtlInitUnicodeString(&u_FuncName, FuncName);
    ref = MmGetSystemRoutineAddress(&u_FuncName);
    return ref;
}

// 特征定位 MiUnloadSystemImage
ULONG64 HideDriver::GetMiUnloadSystemImageAddress()
{
    __try
    {
        // 在MmUnloadSystemImage函数中搜索的Code
/*
lyshark.com: kd> uf MmUnloadSystemImage
    fffff801`37943512 83caff          or      edx,0FFFFFFFFh
    fffff801`37943515 488bcf          mov     rcx,rdi
    fffff801`37943518 488bd8          mov     rbx,rax
    fffff801`3794351b e860b4ebff      call    nt!MiUnloadSystemImage (fffff801`377fe980)
*/
        CHAR MmUnloadSystemImage_Code[] = "\x83\xCA\xFF"  // or      edx, 0FFFFFFFFh
            "\x48\x8B\xCF"                                // mov     rcx, rdi
            "\x48\x8B\xD8"                                // mov     rbx, rax
            "\xE8";                                       // call    nt!MiUnloadSystemImage (fffff801`377fe980)

        ULONG_PTR MmUnloadSystemImageAddress = 0;
        ULONG_PTR MiUnloadSystemImageAddress = 0;
        ULONG_PTR StartAddress = 0;

        MmUnloadSystemImageAddress = (ULONG_PTR)GetProcAddress(L"MmUnloadSystemImage");
        if (MmUnloadSystemImageAddress == 0)
            return 0;

        // 在MmUnloadSystemImage中搜索特征码寻找MiUnloadSystemImage
        StartAddress = MmUnloadSystemImageAddress;
        while (StartAddress < MmUnloadSystemImageAddress + 0x500)
        {
            if (memcmp((VOID*)StartAddress, MmUnloadSystemImage_Code, strlen(MmUnloadSystemImage_Code)) == 0)
            {
                // 跳过call之前的指令
                StartAddress += strlen(MmUnloadSystemImage_Code);

                // 取出 MiUnloadSystemImage地址
                MiUnloadSystemImageAddress = *(LONG*)StartAddress + StartAddress + 4;
                break;
            }
            ++StartAddress;
        }

        if (MiUnloadSystemImageAddress != 0)
            return MiUnloadSystemImageAddress;
        else
            return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s() error", __FUNCTION__);
        return 0;
    }
}

// 特征定位 MiProcessLoaderEntry
MiProcessLoaderEntry HideDriver::GetMiProcessLoaderEntry(ULONG64 StartAddress)
{
    __try
    {
        if (StartAddress == 0)
            return NULL;
        while (StartAddress < StartAddress + 0x600)
        {
            // 操作数MiProcessLoaderEntry内存地址是动态变化的
            /*
            lyshark.com: kd> uf MiUnloadSystemImage
                fffff801`377fed19 33d2            xor     edx,edx
                fffff801`377fed1b 488bcb          mov     rcx,rbx
                fffff801`377fed1e e84162b4ff      call    nt!MiProcessLoaderEntry (fffff801`37344f64)
                fffff801`377fed23 8b05d756f7ff    mov     eax,dword ptr [nt!PerfGlobalGroupMask (fffff801`37774400)]
                fffff801`377fed29 a804            test    al,4
                fffff801`377fed2b 7440            je      nt!MiUnloadSystemImage+0x3ed (fffff801`377fed6d)  Branch
                E8 call | 8B 05 mov eax
            */

            // fffff801`377fed1e   | fffff801`377fed23
            // 判断特征 0xE8(call) | 0x8B 0x05(mov eax)
            if (*(UCHAR*)StartAddress == 0xE8 && *(UCHAR*)(StartAddress + 5) == 0x8B && *(UCHAR*)(StartAddress + 6) == 0x05)
            {
                // 跳过一个字节call的E8
                StartAddress++;

                // StartAddress + 1 + 4
                return (MiProcessLoaderEntry)(*(LONG*)StartAddress + StartAddress + 4);
            }
            ++StartAddress;
        }
        return NULL;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
        DbgPrint("[GN]:%s() error", __FUNCTION__);
    }
}

void HideDriver::InitInLoadOrderLinks(PDRIVER_LDR_DATA_TABLE_ENTRY LdrEntry)
{
    InitializeListHead(&LdrEntry->InLoadOrderLinks);
    InitializeListHead(&LdrEntry->InMemoryOrderLinks);
}

NTSTATUS HideDriver::GetDriverObjectByName(PDRIVER_OBJECT* lpObj, WCHAR* DriverDirName)
{
    NTSTATUS status = STATUS_SUCCESS;
    PDRIVER_OBJECT pBeepObj = NULL;
    UNICODE_STRING DevName = { 0 };

    if (!MmIsAddressValid(lpObj))
        return STATUS_INVALID_ADDRESS;

    RtlInitUnicodeString(&DevName, DriverDirName);

    status = (NTSTATUS)ObReferenceObjectByName(&DevName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&pBeepObj);

    if (NT_SUCCESS(status))
        *lpObj = pBeepObj;
    else
    {
        DbgPrint("[GN]:Get Obj faild...error:0x%x", status);
    }

    return status;
}

void HideDriver::SupportSEH(PDRIVER_OBJECT pDriverObject)
{
    PDRIVER_OBJECT pTempDrvObj = NULL;
    PDRIVER_LDR_DATA_TABLE_ENTRY ldrEntry = NULL;

    //if (NT_SUCCESS(GetDriverObjectByName(&pTempDrvObj, L"\\Driver\\beep")))
    if (NT_SUCCESS(GetDriverObjectByName(&pTempDrvObj, L"\\Driver\\tdx")))
    {
        if (pTempDrvObj != NULL)
        {
            //挂seh前先保存原始数据
            this->old_driver_information.old_ldrEntry = *(PDRIVER_LDR_DATA_TABLE_ENTRY)(pDriverObject->DriverSection);
            this->old_driver_information.old_ldrEntry.DllBase = pDriverObject->DriverStart;
            //将获取到的驱动对象节点赋值给自身LDR
            ldrEntry = (PDRIVER_LDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
            ldrEntry->DllBase = pTempDrvObj->DriverStart;
            ObDereferenceObject(pTempDrvObj);
        }
        else
            DbgPrint("[GN]:UnSupport SEH...");
    }
}

NTSTATUS HideDriver::HideDriverWin7(PDRIVER_OBJECT pTargetDriverObject)
{
    DbgPrint("[GN]:%s->", __FUNCTION__);
    UNICODE_STRING usFuncName = { 0 };
    PUCHAR pMiProcessLoaderEntry = NULL;
    size_t i = 0;
    RtlInitUnicodeString(&usFuncName, L"EtwWriteString");
    pMiProcessLoaderEntry = (PUCHAR)MmGetSystemRoutineAddress(&usFuncName);
    pMiProcessLoaderEntry = pMiProcessLoaderEntry - 0x600;
    __try 
    {
        for (i = 0; i < 0x600; i++)
        {
            if (*pMiProcessLoaderEntry == 0xbb && *(pMiProcessLoaderEntry + 1) == 0x01 && *(pMiProcessLoaderEntry + 2) == 0x0 &&
                *(pMiProcessLoaderEntry + 5) == 0x48 && *(pMiProcessLoaderEntry + 0xc) == 0x8a && *(pMiProcessLoaderEntry + 0xd) == 0xd3
                && *(pMiProcessLoaderEntry + 0xe) == 0xe8)
            {
                pMiProcessLoaderEntry = pMiProcessLoaderEntry - 0x40;
                for (i = 0; i < 0x30; i++)
                {
                    if (*pMiProcessLoaderEntry == 0x90 && *(pMiProcessLoaderEntry + 1) == 0x48)
                    {
                        pMiProcessLoaderEntry++;
                        //找到地址赋值
                        this->m_MiProcessLoaderEntry = (MiProcessLoaderEntry)pMiProcessLoaderEntry;
                        return STATUS_SUCCESS;
                    }
                    pMiProcessLoaderEntry++;
                }
                return STATUS_UNSUCCESSFUL;
            }
            pMiProcessLoaderEntry++;
        }
        return STATUS_UNSUCCESSFUL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        this->m_MiProcessLoaderEntry = 0;
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS HideDriver::HideDriverWin10(PDRIVER_OBJECT pTargetDriverObject)
{
    this->MiUnloadSystemImageAddress = this->GetMiUnloadSystemImageAddress();
    if (this->MiUnloadSystemImageAddress == NULL)
        return STATUS_UNSUCCESSFUL;
    //else
    //    DbgPrint("[GN]:MiUnloadSystemImageAddress:%p", MiUnloadSystemImageAddress);
    MiProcessLoaderEntry MiProcessLoaderEntryAddress = this->GetMiProcessLoaderEntry(this->MiUnloadSystemImageAddress);
    if (MiProcessLoaderEntryAddress == NULL)
        return STATUS_UNSUCCESSFUL;
    //else
    //    DbgPrint("[GN]:MiProcessLoaderEntryAddress:%p", MiProcessLoaderEntryAddress);
    return STATUS_SUCCESS;
}

//public static
void HideDriver::ReInitializeDriver(PDRIVER_OBJECT p_object, PVOID context, ULONG Count)
{
    __try
    {
        if (hide_driver->GetOsVersionNumber() > 8000)
        {
            //>win 10
            hide_driver->m_MiProcessLoaderEntry = hide_driver->GetMiProcessLoaderEntry(hide_driver->MiUnloadSystemImageAddress);
            if (hide_driver->m_MiProcessLoaderEntry == NULL)
                return;
        }
        hide_driver->SupportSEH(p_object);
        hide_driver->m_MiProcessLoaderEntry(p_object->DriverSection, 0);
        hide_driver->InitInLoadOrderLinks((PDRIVER_LDR_DATA_TABLE_ENTRY)p_object->DriverSection);
        ////破坏驱动对象特征前保存原始信息
        //hide_driver->old_driver_information.old_driver_object.DriverSection = p_object->DriverSection;
        //hide_driver->old_driver_information.old_driver_object.DriverStart = p_object->DriverStart;
        //hide_driver->old_driver_information.old_driver_object.DriverSize = p_object->DriverSize;
        //hide_driver->old_driver_information.old_driver_object.DriverUnload = p_object->DriverUnload;
        //hide_driver->old_driver_information.old_driver_object.DriverInit = p_object->DriverInit;
        //hide_driver->old_driver_information.old_driver_object.DeviceObject = p_object->DeviceObject;
        //破坏驱动对象特征
        p_object->DriverSection = NULL;
        p_object->DriverStart = NULL;
        p_object->DriverSize = 0;
        p_object->DriverUnload = NULL;
        p_object->DriverInit = NULL;
        p_object->DeviceObject = NULL;
        hide_driver->hide_statu = true;
        
        //////测试seh
        ////HANDLE hThread = NULL;
        ////PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, DeletDriverObject, NULL);
        //hide_driver->KernelSleep(500);
        //delete hide_driver;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s() error", __FUNCTION__);
        return;
    }
}

void HideDriver::DeletDriverObject(PVOID start_context)
{
    PULONG_PTR pZero = NULL;
    hide_driver->KernelSleep(10000);
    //////ObMakeTemporaryObject(hide_driver->GetDriverObject());
    DbgPrint("[GN]:test seh");
    __try
    {
        *pZero = 0x100;
    }
    __except (1)
    {
        DbgPrint("[GN]:seh success");
        hide_driver->KernelSleep(500);
        delete hide_driver;
    }
}



