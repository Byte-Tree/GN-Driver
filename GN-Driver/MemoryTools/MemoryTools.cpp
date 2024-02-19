//////////////////////////////////////////////////////////////////////////////////////////////////////////
//		                            内存相关的功能，包括读写 内存隐藏
//             调用VAD隐藏内存后启动了一个进程监视回调类，用于监视进程退出后恢复VAD，不恢复然蓝屏
//////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "MemoryTools.h"
#include "../MainFunction/MainFunction.h"

#pragma warning( disable : 4244)
#pragma warning( disable : 4172)


MemoryTools::MemoryTools()
{
    //获取os版本
    this->system_version = this->GetOsVersionNumber();
    this->system_version_number = this->system_version.dwBuildNumber;

    //获取vadroot偏移
    this->GetSystemVadRootOffset(&this->system_version);
    //DbgPrint("[GN]:%s-> 系统版本%lld", __FUNCTION__, this->system_version_number);

    ZwProtectVirtualMemory = (pZwProtectVirtualMemory)((UINT64)ZwWaitForSingleObject + 2432);
}

MemoryTools::~MemoryTools()
{
    //驱动先于进程退出前就先恢复vad
    this->RestoreVAD();
}

//public
void* MemoryTools::operator new(size_t size, POOL_TYPE pool_type)
{
    return ExAllocatePoolWithTag(pool_type, size, 'abcd');
}

void MemoryTools::operator delete(void* pointer)
{
    ExFreePoolWithTag(pointer, 'abcd');
}

//private
RTL_OSVERSIONINFOEXW MemoryTools::GetOsVersionNumber()
{
    RTL_OSVERSIONINFOEXW version = { 0 };

    NTSTATUS status = RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[GN]:%s-> RtlGetVersion() errorcode:%p\n", __FUNCTION__, status);
        return version;
    }

    return version;
}

//public
PVOID64 MemoryTools::MDLReadMemory(IN HANDLE pid, IN DWORD64 address, IN ULONG size)
{
    PVOID64 retdata = 0, tempdata = 0;
    PEPROCESS eprocess = NULL;
    KAPC_STATE apc_state = { NULL };
    PsLookupProcessByProcessId(pid, &eprocess);
    if (!eprocess)
        return 0;
    __try
    {
        tempdata = ExAllocatePool(PagedPool, size);
    }
    __except (1)
    {
        return 0;
    }
    KeStackAttachProcess(eprocess, &apc_state);
    __try
    {
        ProbeForRead((PVOID64)address, size, 1);
        RtlCopyMemory(tempdata, (PVOID64)address, size);
    }
    __except (1)
    {
        return 0;
    }
    ObDereferenceObject(eprocess);
    KeUnstackDetachProcess(&apc_state);
    RtlCopyMemory(retdata, tempdata, size);
    ExFreePool(tempdata);
    return retdata;
}

DWORD MemoryTools::ReadDWORD(IN DWORD64 address)
{
    return *(DWORD*)address;
}

int MemoryTools::ReadInt(IN DWORD64 address)
{
    return *(int*)address;
}

DWORD64 MemoryTools::ReadDWORD64(IN DWORD64 address)
{
    return *(DWORD64*)address;
}

__int64 MemoryTools::ReadInt64(IN DWORD64 address)
{
    return *(__int64*)address;
}

bool MemoryTools::WriteDWORD(IN DWORD64 address, IN DWORD data)
{
    *(DWORD*)address = data;
    return true;
}

bool MemoryTools::WriteInt(IN DWORD64 address, IN int data)
{
    *(int*)address = data;
    return true;
}

bool MemoryTools::WriteDWORD64(IN DWORD64 address, IN DWORD64 data)
{
    *(DWORD64*)address = data;
    return true;
}

bool MemoryTools::WriteInt64(IN DWORD64 address, IN __int64 data)
{
    *(__int64*)address = data;
    return true;
}

PVOID MemoryTools::AllocateMemory(IN HANDLE pid, IN ULONG64 allocsize, IN ULONG protect)
{
    PVOID alloc_address = NULL;
    PEPROCESS eprocess = NULL;
    KAPC_STATE kapc_state = { 0 };

    NTSTATUS status = PsLookupProcessByProcessId(pid, &eprocess);
    if (!NT_SUCCESS(status))
        return NULL;
    //如果当前找到的进程已经退出
    if (PsGetProcessExitStatus(eprocess) != STATUS_PENDING)
        return NULL;

    KeStackAttachProcess(eprocess, &kapc_state);
    status = ZwAllocateVirtualMemory(NtCurrentProcess(), &alloc_address, 0, &allocsize, MEM_COMMIT, protect);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[GN]:%s-> ZwAllocateVirtualMemory() error code:%p", __FUNCTION__, status);
        KeUnstackDetachProcess(&kapc_state);
        ObDereferenceObject(eprocess);
        return NULL;
    }

    //DbgPrint("[GN]:申请的内存地址：%p", alloc_address);
    KeUnstackDetachProcess(&kapc_state);
    ObDereferenceObject(eprocess);
    return alloc_address;
}

NTSTATUS MemoryTools::FreeMemory(IN HANDLE pid, IN ULONG64 free_address, IN ULONG64 memory_size)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS eprocess = NULL;
    HANDLE hprocess = NULL;
    OBJECT_ATTRIBUTES object = { sizeof(OBJECT_ATTRIBUTES) };
    CLIENT_ID cid_process = { 0 };

    cid_process.UniqueProcess = pid;

    status = PsLookupProcessByProcessId(pid, &eprocess);
    if (!NT_SUCCESS(status)) return status;

    //打开进程
    status = ZwOpenProcess(&hprocess, PROCESS_ALL_ACCESS, &object, &cid_process);
    if (!NT_SUCCESS(status))
    {
        //STATUS_INVALID_CID
        DbgPrint("[GN]:%s-> ZwOpenProcess errorcode:%p", __FUNCTION__, status);
        ObDereferenceObject(eprocess);
        return status;
    }

    //释放虚拟内存
    status = ZwFreeVirtualMemory(hprocess, (PVOID*)&free_address, &memory_size, MEM_RELEASE);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[GN]:%s-> ZwFreeVirtualMemory() error code:%p", __FUNCTION__, status);
        ZwClose(hprocess);
        ObDereferenceObject(eprocess);
        return status;
    }

    ZwClose(hprocess);
    ObDereferenceObject(eprocess);
    return status;
}

ULONG MemoryTools::SetMemoryProtect(IN HANDLE pid, IN PVOID address, IN SIZE_T size, IN ULONG protect)
{
    ULONG old_protect = 0;
    KAPC_STATE apc_state = { 0 };
    PEPROCESS eprocess = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    //DbgPrint("[GN]:pid:%d,address:%p,size:%d,protect:%d", pid, address, size, protect);
    if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &eprocess)))
    {
        __try
        {
            KeStackAttachProcess(eprocess, &apc_state);         //附加来切换到目标进程()
            status = ZwProtectVirtualMemory(NtCurrentProcess(), &address, (PULONG)&size, protect, &old_protect);
            if (!NT_SUCCESS(status))
            {
                KeUnstackDetachProcess(&apc_state);             //切换到原进程()
                DbgPrint("[GN]:%s-> ZwProtectVirtualMemory() Error ：%p", __FUNCTION__, status);
                return status;
            }
            KeUnstackDetachProcess(&apc_state);                 //切换到原进程()
            status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DbgPrint("[GN]:%s-> 抛出异常", __FUNCTION__);
            status = STATUS_UNSUCCESSFUL;
        }
    }
    else
        DbgPrint("[GN]:%s()-> PsLookupProcessByProcessId() Error", __FUNCTION__);
    ObDereferenceObject(eprocess);                      //引用计数-1
    return status;
}

NTSTATUS MemoryTools::StartHook(IN __int64 address, IN __int64 my_func_address)
{
    BYTE hook_code[5] = { 0xE9,0x00,0x00,0x00,0x00 };
    *(int*)(hook_code + 1) = (unsigned int)((__int64)my_func_address - (__int64)address - 5);//unsigned int无符号整型，否则计算出的偏移有偏差导致崩溃
    return RtlSuperCopyMemory((PVOID)address, hook_code, sizeof(hook_code));
}

HMODULE MemoryTools::GetModuleHandle(IN HANDLE pid, IN const wchar_t* module_name)
{
    HMODULE p_module = NULL;
    KAPC_STATE kapc_state = { 0 };
    PEPROCESS eprocess = NULL;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &eprocess)))
        return 0;

    PPEB peb = PsGetProcessPeb(eprocess);
    KeStackAttachProcess(eprocess, &kapc_state);
    __try
    {
        ULONG64 ldr = *(PULONG64)((ULONG64)peb + LDR_OFFSET_IN_PEB);
        PLIST_ENTRY64 p_list_head = (PLIST_ENTRY64)(ldr + InLoadOrderModuleList_OFFSET);
        PLIST_ENTRY64 p_mod = (PLIST_ENTRY64)p_list_head->Flink;
        PMLDR_DATA_TABLE_ENTRY ldm;

        while (p_mod != p_list_head)
        {
            ldm = CONTAINING_RECORD(p_mod, MLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (_wcsicmp(module_name, ldm->BaseDllName.Buffer) == 0)//判断要隐藏的DLL基址跟结构中的基址是否一样
            {
                p_module = (HMODULE)ldm->DllBase;//找到dll地址
                break;
            }
            p_mod = (PLIST_ENTRY64)p_mod->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s-> error", __FUNCTION__);
        return 0;
    }

    KeUnstackDetachProcess(&kapc_state);
    ObDereferenceObject(eprocess);
    return p_module;
}

PVOID MemoryTools::GetModuleHandleImageSize(IN HANDLE pid, IN const wchar_t* module_name)
{
    PVOID p_module = NULL;
    KAPC_STATE kapc_state = { 0 };
    PEPROCESS eprocess = NULL;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &eprocess)))
        return 0;

    PPEB peb = PsGetProcessPeb(eprocess);
    KeStackAttachProcess(eprocess, &kapc_state);
    __try
    {
        ULONG64 ldr = *(PULONG64)((ULONG64)peb + LDR_OFFSET_IN_PEB);
        PLIST_ENTRY64 p_list_head = (PLIST_ENTRY64)(ldr + InLoadOrderModuleList_OFFSET);
        PLIST_ENTRY64 p_mod = (PLIST_ENTRY64)p_list_head->Flink;
        PMLDR_DATA_TABLE_ENTRY ldm;

        while (p_mod != p_list_head)
        {
            ldm = CONTAINING_RECORD(p_mod, MLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (_wcsicmp(module_name, ldm->BaseDllName.Buffer) == 0)//判断要隐藏的DLL基址跟结构中的基址是否一样
            {
                p_module = (PVOID)((DWORD64)ldm->DllBase + ldm->SizeOfImage);
                break;
            }
            p_mod = (PLIST_ENTRY64)p_mod->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s-> error", __FUNCTION__);
        return 0;
    }

    KeUnstackDetachProcess(&kapc_state);
    ObDereferenceObject(eprocess);
    return p_module;
}

PVOID MemoryTools::GetKernelModuleByZwQuerySystemInformation(IN const char* modulename, OUT ULONG* module_size)
{
    ULONG ulInfoLength = 0;
    PVOID pBuffer = NULL;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    PVOID base = NULL;
    do
    {
        ntStatus = thread->ZwQuerySystemInformation(SystemModuleInformation, NULL, NULL, &ulInfoLength);
        if ((ntStatus == STATUS_INFO_LENGTH_MISMATCH))
        {
            pBuffer = ExAllocatePoolWithTag(PagedPool, ulInfoLength, 'ISQZ');
            if (pBuffer == NULL)
            {
                DbgPrint("【PrintLoadedModule】Allocate Memory Failed\r\n");
                break;
            }
            ntStatus = thread->ZwQuerySystemInformation(SystemModuleInformation, pBuffer, ulInfoLength, &ulInfoLength);
            if (!NT_SUCCESS(ntStatus))
            {
                DbgPrint("[GN]:%s-> ZwQuerySystemInformation Failed\n", __FUNCTION__);
                break;
            }

            PSYSTEM_MODULE_INFORMATION pModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
            if (pModuleInformation)
            {
                for (ULONG i = 0; i < pModuleInformation->Count; i++)
                {
                    //DbgPrint("【PrintLoadedModule】Image:%-50s\tBase:0x%p\n", pModuleInformation->Module[i].ImageName, pModuleInformation->Module[i].Base);
                    if (_stricmp(modulename, pModuleInformation->Module[i].ImageName + pModuleInformation->Module[i].ModuleNameOffset) == 0)
                    {
                        //DbgPrint("[GN]:【PrintLoadedModule】Image:%-50s\tBase:0x%p\n", pModuleInformation->Module[i].ImageName, pModuleInformation->Module[i].Base);
                        base = pModuleInformation->Module[i].Base;
                        *module_size = pModuleInformation->Module[i].Size;
                        break;
                    }
                }
                //DbgPrint("【PrintLoadedModule】遍历完成\r\n");
            }

            ntStatus = STATUS_SUCCESS;
        }
    } while (0);

    if (pBuffer)
        ExFreePoolWithTag(pBuffer, 'ISQZ');
    return base;
}

BYTE* MemoryTools::ToBytes(DWORD64 num)
{
    BYTE bytes[8] = {};
    bytes[0] = num;
    bytes[1] = num >> 8;
    bytes[2] = num >> 16;
    bytes[3] = num >> 24;
    bytes[4] = num >> 32;
    bytes[5] = num >> 40;
    bytes[6] = num >> 48;
    bytes[7] = num >> 56;
    return bytes;
}

ULONGLONG MemoryTools::GetPspNotifyEnableMask()
{
    PUCHAR startaddr = 0, Endaddr = 0;
    PUCHAR i = NULL;
    UCHAR b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19, b20;
    ULONGLONG temp = 0;
    ULONGLONG addr = 0;

    PVOID null_base = NULL;
    ULONG64 null_size = NULL;

    if (tools->GetSectionData("null.sys", ".text", null_size, null_base))
    {
        //DbgPrint("[GN]:.text address:%p", null_base);
        startaddr = (PUCHAR)null_base;
        //DbgPrint("[GN]:开始搜索地址：%p", startaddr);
        if (startaddr == NULL)
            return 0;
        Endaddr = (PUCHAR)startaddr + 0x10000;
        for (i = startaddr; i < Endaddr; i++)//往下搜索
        {
            b1 = *i;
            b2 = *(i + 1);
            b3 = *(i + 2);
            b4 = *(i + 3);
            b5 = *(i + 4);
            b6 = *(i + 5);
            b7 = *(i + 6);
            b8 = *(i + 7);
            b9 = *(i + 8);
            b10 = *(i + 9);
            b11 = *(i + 10);
            b12 = *(i + 11);
            b13 = *(i + 12);
            b14 = *(i + 13);
            b15 = *(i + 14);
            b16 = *(i + 15);
            b17 = *(i + 16);
            b18 = *(i + 17);
            b19 = *(i + 18);
            b20 = *(i + 19);
            if (b1 == 0xCC && b2 == 0xCC && b3 == 0xCC && b4 == 0xCC && b5 == 0xCC && b6 == 0xCC && b7 == 0xCC && b8 == 0xCC
                && b9 == 0xCC && b10 == 0xCC && b11 == 0xCC && b12 == 0xCC && b13 == 0xCC && b14 == 0xCC && b15 == 0xCC &&
                b16 == 0xCC && b17 == 0xCC && b18 == 0xCC && b19 == 0xCC && b20 == 0xCC)
            {
                //memcpy(&temp, i + 2, 4);
                addr = (ULONGLONG)i;//(ULONGLONG)temp + (ULONGLONG)i + 6;
                //DbgPrint("[GN]:搜到的特征码地址:%p,%02X\n", addr, *(PBYTE)addr);
                return addr;
            }
        }
    }

    return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// Set memory page pte:
//////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG64 MemoryTools::GetPteAddress(IN PVOID addr)
{
    return (ULONG64)(((((ULONG64)addr & 0xffffffffffff) >> 12) << 3) + this->PTE_BASE);
}

ULONG64 MemoryTools::GetPdeAddress(IN PVOID addr)
{
    return (ULONG64)(((((ULONG64)addr & 0xffffffffffff) >> 21) << 3) + this->PDE_BASE);
}

ULONG64 MemoryTools::GetPpeAddress(IN PVOID addr)
{
    return (ULONG64)(((((ULONG64)addr & 0xffffffffffff) >> 30) << 3) + this->PPE_BASE);
}

ULONG64 MemoryTools::GetPxeAddress(IN PVOID addr)
{
    return (ULONG64)(((((ULONG64)addr & 0xffffffffffff) >> 39) << 3) + this->PXE_BASE);
}

ULONG64 MemoryTools::GetPteBase()
{
    ULONG64 pte_base = NULL;
    if (this->system_version_number == 7601 || this->system_version_number == 7600 || this->system_version_number < 14393)
    {
        return pte_base = 0xFFFFF68000000000ull;
    }
    else
    {
        UNICODE_STRING unName = { 0 };
        RtlInitUnicodeString(&unName, L"MmGetVirtualForPhysical");
        PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&unName);
        return pte_base = *(PULONG64)(func + 0x22);
    }
    return pte_base;
}

void MemoryTools::InitPTE()
{
    this->PTE_BASE = this->GetPteBase();
    this->PDE_BASE = this->GetPteAddress((PVOID)PTE_BASE);
    this->PPE_BASE = this->GetPteAddress((PVOID)PDE_BASE);
    this->PXE_BASE = this->GetPteAddress((PVOID)PPE_BASE);
    return;
}

void MemoryTools::SetMemoryPage(IN ULONG64 virtualaddress, IN ULONG size)
{
    this->InitPTE();
    ULONG64 startaddress = virtualaddress & (~0xFFF);
    ULONG64 endAddress = (virtualaddress + size) & (~0xFFF);
    int count = 0;
    while (endAddress >= startaddress)
    {
        PHardwarePte pde = (PHardwarePte)GetPdeAddress((PVOID)startaddress);
        //DbgPrint("[GN]:修改之前pde = %llx", *pde);
        if (MmIsAddressValid(pde) && (pde->valid == 1))
        {
            pde->no_execute = 0;
            pde->write = 1;
        }
        PHardwarePte pte = (PHardwarePte)GetPteAddress((PVOID)startaddress);
        //DbgPrint("[GN]:修改之前pte = %llx", *pte);
        if (MmIsAddressValid(pte) && (pte->valid == 1))
        {
            pte->no_execute = 0;
            pte->write = 1;//1为开启权限，就是有写入权限
        }
        startaddress += PAGE_SIZE;
        //DbgPrint("[GN]:pde = %p pte = %p address = %p", pde, pte, startaddress);
        //DbgPrint("[GN]:修改之后pde = %llx pte = %llx", *pde, *pte);
    }
}

BOOLEAN MemoryTools::SetExecutePage(IN HANDLE pid, IN ULONG64 virtualaddress, IN ULONG size)
{
    //DbgPrint("[GN]:pid：%d,address：%p,size：%d", pid, virtualaddress, size);
    PEPROCESS eprocess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &eprocess);
    if (!NT_SUCCESS(status))
        return FALSE;
    if (PsGetProcessExitStatus(eprocess) != STATUS_PENDING)         //如果当前找到的进程已经退出
        return FALSE;
    KAPC_STATE kapc_state = { 0 };
    PMDL mdl = NULL;

    KeStackAttachProcess(eprocess, &kapc_state);                    //附加进程
    mdl = IoAllocateMdl((PVOID)virtualaddress, size, FALSE, FALSE, NULL);
    if (mdl != NULL)
    {
        __try
        {
            MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);//防止物理页换出去,其实是利用它触发缺页异常，换上页面后锁住
            this->SetMemoryPage(virtualaddress, size);
            MmUnmapLockedPages((PVOID)virtualaddress, mdl);
            MmUnlockPages(mdl);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DbgPrint("[GN]:%s-> error!", __FUNCTION__);
        }
    }
    IoFreeMdl(mdl);
    KeUnstackDetachProcess(&kapc_state);                            //附加脱离进程
    ObDereferenceObject(eprocess);
    return TRUE;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// Read/Write Process Memory By MDL:
//////////////////////////////////////////////////////////////////////////////////////////////////////////
//private:
NTSTATUS MemoryTools::ReadProcessMemoryByMDL(IN HANDLE pid, IN PVOID address, OUT PVOID out_data, IN ULONG size)
{
    NTSTATUS status = STATUS_SUCCESS;
    KAPC_STATE kapc_state = { 0 };
    PEPROCESS eprocess = NULL;
    PVOID buffer = NULL;
    PMDL mdl = NULL;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &eprocess)))
        return STATUS_UNSUCCESSFUL;

    buffer = ExAllocatePoolWithTag(NonPagedPool, size, 'MDLR');
    if (buffer == NULL || !MmIsAddressValid(buffer)) return STATUS_UNSUCCESSFUL;
    RtlZeroMemory(buffer, size);

    KeStackAttachProcess(eprocess, &kapc_state);
    mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
    if (mdl != NULL)
    {
        __try
        {
            MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
            PVOID paddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
            RtlMoveMemory(buffer, paddress, size);
            MmUnmapLockedPages(paddress, mdl);
            MmUnlockPages(mdl);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DbgPrint("[GN]:%s-> error", __FUNCTION__);
            return STATUS_UNSUCCESSFUL;
        }
    }
    else
        return STATUS_UNSUCCESSFUL;

    IoFreeMdl(mdl);
    KeUnstackDetachProcess(&kapc_state);
    ObDereferenceObject(eprocess);
    RtlMoveMemory(out_data, buffer, size);
    ExFreePool(buffer);
    return status;
}

NTSTATUS MemoryTools::WriteProcessMemoryByMDL(IN HANDLE pid, IN PVOID address, IN PVOID write_data, IN ULONG size)
{
    NTSTATUS status = STATUS_SUCCESS;
    KAPC_STATE kapc_state = { 0 };
    PEPROCESS eprocess = NULL;
    PVOID buffer = NULL;
    PMDL mdl = NULL;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &eprocess)))
        return STATUS_UNSUCCESSFUL;

    buffer = ExAllocatePoolWithTag(NonPagedPool, size, 'MDLW');
    if (buffer == NULL || !MmIsAddressValid(buffer)) return STATUS_UNSUCCESSFUL;
    RtlMoveMemory(buffer, write_data, size);

    KeStackAttachProcess(eprocess, &kapc_state);
    mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
    if (mdl != NULL)
    {
        __try
        {
            MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
            PVOID paddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
            RtlMoveMemory(paddress, buffer, size);
            MmUnmapLockedPages(paddress, mdl);
            MmUnlockPages(mdl);
            status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DbgPrint("[GN]:%s-> error", __FUNCTION__);
            status = STATUS_UNSUCCESSFUL;
        }
    }
    else
        status = STATUS_UNSUCCESSFUL;
    IoFreeMdl(mdl);
    KeUnstackDetachProcess(&kapc_state);
    ObDereferenceObject(eprocess);
    ExFreePool(buffer);
    return status;
}

NTSTATUS MemoryTools::RtlSuperCopyMemory(IN VOID UNALIGNED* Dst, IN CONST VOID UNALIGNED* Src, IN ULONG Length)
{
    NTSTATUS status = STATUS_SUCCESS;
    //MDL是一个对物理内存的描述，负责把虚拟内存映射到物理内存
    PMDL pmdl = IoAllocateMdl(Dst, Length, 0, 0, NULL);//分配mdl
    if (pmdl != NULL)
    {
        __try
        {
            MmProbeAndLockPages(pmdl, KernelMode, IoReadAccess);//build mdl
            unsigned int* Mapped = (unsigned int*)MmMapLockedPagesSpecifyCache(pmdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);//锁住内存
            KIRQL kirql = KeRaiseIrqlToDpcLevel();
            RtlCopyMemory(Mapped, Src, Length);
            KeLowerIrql(kirql);
            MmUnmapLockedPages(Mapped, pmdl);
            MmUnlockPages(pmdl);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = STATUS_UNSUCCESSFUL;//失败
            DbgPrint("[GN]:%s-> MmMapLockedPages error", __FUNCTION__);
        }
    }
    else status = STATUS_UNSUCCESSFUL;
    IoFreeMdl(pmdl);
    return status;
}

//public:
NTSTATUS MemoryTools::ReadMemoryByMDL(IN ULONG pid, IN PVOID address,IN ULONG size, OUT PVOID read_buffer)
{
    return this->ReadProcessMemoryByMDL((HANDLE)pid, address, read_buffer, size);
}

NTSTATUS MemoryTools::WriteMemoryByMDL(IN ULONG pid, IN PVOID address, OUT PVOID write_data, IN ULONG size)
{
    return this->WriteProcessMemoryByMDL((HANDLE)pid, address, write_data, size);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// ReadProcess Memory By CR3 No Attacht:
//////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID MemoryTools::GetProcessBaseAddress(HANDLE pid)
{
    PEPROCESS pProcess = NULL;
    if (pid == 0) return (PVOID)STATUS_UNSUCCESSFUL;

    NTSTATUS NtRet = PsLookupProcessByProcessId(pid, &pProcess);
    if (NtRet != STATUS_SUCCESS) return (PVOID)NtRet;

    PVOID Base = PsGetProcessSectionBaseAddress(pProcess);
    ObDereferenceObject(pProcess);
    return Base;
}

DWORD MemoryTools::GetUserDirectoryTableBaseOffset()
{
    RTL_OSVERSIONINFOW ver = { 0 };
    RtlGetVersion(&ver);

    switch (ver.dwBuildNumber)
    {
    case WINDOWS_1803:
        return 0x0278;
        break;
    case WINDOWS_1809:
        return 0x0278;
        break;
    case WINDOWS_1903:
        return 0x0280;
        break;
    case WINDOWS_1909:
        return 0x0280;
        break;
    case WINDOWS_2004:
        return 0x0388;
        break;
    case WINDOWS_20H2:
        return 0x0388;
        break;
    case WINDOWS_21H1:
        return 0x0388;
        break;
    default:
        return 0x0388;
    }
}

//check normal dirbase if 0 then get from UserDirectoryTableBas
ULONG_PTR MemoryTools::GetProcessCr3(PEPROCESS pProcess)
{
    PUCHAR process = (PUCHAR)pProcess;
    ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
    if (process_dirbase == 0)
    {
        DWORD UserDirOffset = GetUserDirectoryTableBaseOffset();
        ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
        return process_userdirbase;
    }
    return process_dirbase;
}

ULONG_PTR MemoryTools::GetKernelDirBase()
{
    PUCHAR process = (PUCHAR)PsGetCurrentProcess();
    ULONG_PTR cr3 = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
    return cr3;
}

NTSTATUS MemoryTools::ReadVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* read)
{
    uint64_t paddress = TranslateLinearAddress(dirbase, address);
    return ReadPhysicalAddress((PVOID)paddress, buffer, size, read);
}

NTSTATUS MemoryTools::WriteVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* written)
{
    uint64_t paddress = TranslateLinearAddress(dirbase, address);
    return WritePhysicalAddress((PVOID)paddress, buffer, size, written);
}

NTSTATUS MemoryTools::ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
    MM_COPY_ADDRESS AddrToRead = { 0 };
    AddrToRead.PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;
    return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

//MmMapIoSpaceEx limit is page 4096 byte
NTSTATUS MemoryTools::WritePhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
{
    if (!TargetAddress)
        return STATUS_UNSUCCESSFUL;

    PHYSICAL_ADDRESS AddrToWrite = { 0 };
    AddrToWrite.QuadPart = (LONGLONG)TargetAddress;

    PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

    if (!pmapped_mem)
        return STATUS_UNSUCCESSFUL;

    memcpy(pmapped_mem, lpBuffer, Size);

    *BytesWritten = Size;
    MmUnmapIoSpace(pmapped_mem, Size);
    return STATUS_SUCCESS;
}

uint64_t MemoryTools::TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress)
{
    directoryTableBase &= ~0xf;

    uint64_t pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
    uint64_t pte = ((virtualAddress >> 12) & (0x1ffll));
    uint64_t pt = ((virtualAddress >> 21) & (0x1ffll));
    uint64_t pd = ((virtualAddress >> 30) & (0x1ffll));
    uint64_t pdp = ((virtualAddress >> 39) & (0x1ffll));

    SIZE_T readsize = 0;
    uint64_t pdpe = 0;
    ReadPhysicalAddress((PVOID)(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
    if (~pdpe & 1)
        return 0;

    uint64_t pde = 0;
    ReadPhysicalAddress((PVOID)((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
    if (~pde & 1)
        return 0;

    /* 1GB large page, use pde's 12-34 bits */
    if (pde & 0x80)
        return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

    uint64_t pteAddr = 0;
    ReadPhysicalAddress((PVOID)((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
    if (~pteAddr & 1)
        return 0;

    /* 2MB large page */
    if (pteAddr & 0x80)
        return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

    virtualAddress = 0;
    ReadPhysicalAddress((PVOID)((pteAddr & PMASK) + 8 * pte), &virtualAddress, sizeof(virtualAddress), &readsize);
    virtualAddress &= PMASK;

    if (!virtualAddress)
        return 0;

    return virtualAddress + pageOffset;
}

NTSTATUS MemoryTools::ReadProcessMemoryNoAttach(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read)
{
    PEPROCESS pProcess = NULL;
    if (pid == 0) return STATUS_UNSUCCESSFUL;
    NTSTATUS NtRet = PsLookupProcessByProcessId(pid, &pProcess);
    if (NtRet != STATUS_SUCCESS) return NtRet;
    ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
    ObDereferenceObject(pProcess);

    SIZE_T CurOffset = 0;
    SIZE_T TotalSize = size;
    while (TotalSize)
    {
        uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
        if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;
        ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
        SIZE_T BytesRead = 0;
        NtRet = ReadPhysicalAddress((PVOID)CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), ReadSize, &BytesRead);
        TotalSize -= BytesRead;
        CurOffset += BytesRead;
        if (NtRet != STATUS_SUCCESS) break;
        if (BytesRead == 0) break;
    }
    *read = CurOffset;
    return NtRet;
}

NTSTATUS MemoryTools::WriteProcessMemoryNoAttach(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written)
{
    __try
    {
        PEPROCESS pProcess = NULL;
        if (pid == 0) return STATUS_UNSUCCESSFUL;

        NTSTATUS NtRet = PsLookupProcessByProcessId(pid, &pProcess);
        if (NtRet != STATUS_SUCCESS) return NtRet;

        ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
        ObDereferenceObject(pProcess);

        SIZE_T CurOffset = 0;
        SIZE_T TotalSize = size;
        while (TotalSize)
        {
            uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
            if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

            ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
            SIZE_T BytesWritten = 0;
            NtRet = WritePhysicalAddress((PVOID)CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), WriteSize, &BytesWritten);
            TotalSize -= BytesWritten;
            CurOffset += BytesWritten;
            if (NtRet != STATUS_SUCCESS) break;
            if (BytesWritten == 0) break;
        }
        *written = CurOffset;
        return NtRet;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:CR3计算异常！");
        return STATUS_UNSUCCESSFUL;
    }
}

PVOID MemoryTools::ReadProcessMemoryByCR3NoAttach(IN ULONG pid, IN PVOID targetaddress, IN SIZE_T read_size)
{
    __try
    {
        char buffer[64] = { 0 };
        SIZE_T read;
        //PVOID Base = GetProcessBaseAddress((HANDLE)pid);
        //ReadProcessMemory((HANDLE)pid, (PVOID)(Base), &buf, 32, &read);
        //DbgPrint("[GN]:转换后的地址：%p,buf：%p,读取的数据：%p", (PVOID)((DWORD64)Base + (DWORD64)targetaddress), buf, read);
        if (NT_SUCCESS(ReadProcessMemoryNoAttach((HANDLE)pid, targetaddress, &buffer, 64, &read)))
        {
            //DbgPrint("[GN]:读取地址：%p,buf：%p,读取的数据：%p", (DWORD64)targetaddress, *(PVOID*)buffer, read);
            return *(PVOID*)buffer;
        }
        else
            return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s() error", __FUNCTION__);
        return 0;
    }
}

NTSTATUS MemoryTools::WriteProcessMemoryByCR3NoAttach(IN ULONG pid, IN PVOID targetaddress, IN PVOID write_data, IN SIZE_T write_size)
{
    __try
    {
        SIZE_T written = 0;
        PVOID buffer = write_data;
        //DbgPrint("[GN]:接收到的数据：%p,Copy的数据：%d,大小:%d", write_data, buffer, write_size);
        //if (NT_SUCCESS(WriteProcessMemoryNoAttach((HANDLE)pid, targetaddress, buffer, 64, &written)))
        if (NT_SUCCESS(WriteProcessMemoryNoAttach((HANDLE)pid, targetaddress, buffer, 1048576, &written)))
        {
            //DbgPrint("[GN]:写入地址：%p,buf：%p,写过字节数：%p", (DWORD64)targetaddress, *(PVOID*)buffer, written);
            return STATUS_SUCCESS;
        }
        else
        {
            DbgPrint("[GN]:%s-> error !", __FUNCTION__);
            return STATUS_UNSUCCESSFUL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }
    return FALSE;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// Hide Memory By VAD:
//////////////////////////////////////////////////////////////////////////////////////////////////////////
//private:
NTSTATUS MemoryTools::GetSystemVadRootOffset(PRTL_OSVERSIONINFOEXW os_info)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG ver_short = (os_info->dwMajorVersion << 8) | (os_info->dwMinorVersion << 4) | os_info->wServicePackMajor;
    DbgPrint("[GN]:当前版本号：%d,创建版本号：%d", ver_short, os_info->dwBuildNumber);

    switch (ver_short)
    {
        // Windows 7 | Windows 7 SP1
    case WINVER_7:
    case WINVER_7_SP1:
    {
        this->m_eprocess_vadroot_offset = 0x448;
        break;
    }
        // Windows 8
    case WINVER_8:
    {
        this->m_eprocess_vadroot_offset = 0x590;
        break;
    }
        // Windows 8.1
    case WINVER_81:
    {
        this->m_eprocess_vadroot_offset = 0x5D8;
        break; 
    }
    case WINVER_10:
    {
        // Windows10 Windows11
        if (os_info->dwBuildNumber == 10586)
        {
            this->m_eprocess_vadroot_offset = 0x610;
            break;
        }
        else if (os_info->dwBuildNumber == 14393)
        {
            this->m_eprocess_vadroot_offset = 0x620;
            break;
        }
        else if (os_info->dwBuildNumber == 15063)
        {
            this->m_eprocess_vadroot_offset = 0x628;
            break;
        }
        else if (os_info->dwBuildNumber == 16299)
        {
            this->m_eprocess_vadroot_offset = 0x628;
            break;
        }
        else if (os_info->dwBuildNumber == 17134)
        {
            this->m_eprocess_vadroot_offset = 0x628;
            break;
        }
        else if (os_info->dwBuildNumber == 17763)
        {
            this->m_eprocess_vadroot_offset = 0x628;
            break;
        }
        else if (os_info->dwBuildNumber == 18362 || os_info->dwBuildNumber == 18363)
        {
            this->m_eprocess_vadroot_offset = 0x658;
            break;
        }
        else if (os_info->dwBuildNumber == 19041 || os_info->dwBuildNumber == 19042 || os_info->dwBuildNumber == 19043 ||
            os_info->dwBuildNumber == 19044 || os_info->dwBuildNumber == 22000 || os_info->dwBuildNumber == 22621/*Win11 22H2*/
            || os_info->dwBuildNumber == 22631/*Win11 23H2*/)
        {
            this->m_eprocess_vadroot_offset = 0x7D8;
            break;

        }
        else
            return 0;
    }
    default:
        break;
    }

    return status;
}

ULONG MemoryTools::GetVadCountNumber(IN PALL_VADS buffer, IN PMMVAD target_vad)
{
    ULONG64 startptr = ((ULONG64)target_vad->Core.StartingVpnHigh) << 32;
    startptr = (startptr | target_vad->Core.StartingVpn) << PAGE_SHIFT;

    for (size_t i = 0; i < buffer->nCnt; i++)
    {
        if ((ULONG64)buffer->VadInfos[i].startVpn == startptr)
        {
            //DbgPrint("[GN]:找到个计数位置：%d,startVpn：%p\n", i, buffer->VadInfos[i].startVpn);
            return i;
        }
    }
    return 0;
}

PMMVAD MemoryTools::GetVadByCountNumber(IN PALL_VADS buffer, IN ULONG count_number)
{
    return (PMMVAD)buffer->VadInfos[count_number].pVad;
}

ULONG_PTR MemoryTools::GetVadByAddress(IN PALL_VADS buffer, IN ULONG64 hide_address)
{
    ULONG_PTR p_vad = NULL;

    for (size_t i = 0; i < buffer->nCnt; i++)
    {
        //DbgPrint("[GN]:枚举的地址：%p，当前地址：%p\n", (ULONG64)buffer->VadInfos[i].startVpn, hide_address);
        if ((ULONG64)buffer->VadInfos[i].startVpn == hide_address)
        {
            p_vad = (buffer->VadInfos[i].pVad);
            //DbgPrint("[GN]:找到地址：%p,startVpn：%p\n", hide_address, buffer->VadInfos[i].startVpn);
            return p_vad;
        }
    }

    return p_vad;
}

PMMVAD MemoryTools::GetVadByFlags(IN PALL_VADS buffer, IN ULONG flags)
{
    PMMVAD p_vad = NULL;

    for (size_t i = 0; i < buffer->nCnt; i++)
    {
        //DbgPrint("[GN]:枚举的flags：%d，当前flags：%d\n", (ULONG)buffer->VadInfos[i].flags, flags);
        if ((ULONG)buffer->VadInfos[i].flags == flags)
        {
            p_vad = (PMMVAD)buffer->VadInfos[i].pVad;
            DbgPrint("[GN]:找到标志：%d,startVpn：%p\n", buffer->VadInfos[i].flags, buffer->VadInfos[i].startVpn);
            return p_vad;
        }
    }

    return p_vad;
}

//这两个先把所有节点保存到buffer
void MemoryTools::EnumVad(IN PMMVAD vad, IN PALL_VADS buffer, IN ULONG count)
{
    //验证数据
    if (!vad || !buffer || !count)
        return;

    __try
    {
        if (count > buffer->nCnt)
        {
            //得到起始页
            //ULONG64 startptr = (ULONG64)vad->Core.StartingVpnHigh;
            //startptr = startptr << 32;
            ULONG64 startptr = ((ULONG64)vad->Core.StartingVpnHigh) << 32;

            //得到结束页
            //ULONG64 endptr = (ULONG64)vad->Core.EndingVpnHigh;
            //endptr = endptr << 32;
            ULONG64 endptr = ((ULONG64)vad->Core.EndingVpnHigh) << 32;

            //得到根节点
            buffer->VadInfos[buffer->nCnt].pVad = (ULONG_PTR)vad;//vad_root就是个地址，MMVAD结构体

            //起始页真实虚拟地址：StartingVpn * 0x1000
            buffer->VadInfos[buffer->nCnt].startVpn = (startptr | vad->Core.StartingVpn) << PAGE_SHIFT;
            //结束页真实虚拟地址：EndVpn * 0x1000 + 0xFFF
            buffer->VadInfos[buffer->nCnt].endVpn = ((endptr | vad->Core.EndingVpn) << PAGE_SHIFT) + 0xFFF;
            //VAD标志 928 = Mapped  104988 = Private ...
            buffer->VadInfos[buffer->nCnt].flags = vad->Core.u1.Flags.flag;

            //验证节点可读性
            if (MmIsAddressValid(vad->Subsection) && MmIsAddressValid(vad->Subsection->ControlArea))
            {
                if (MmIsAddressValid((PVOID)((vad->Subsection->ControlArea->FilePointer.Value >> 4) << 4)))
                {
                    buffer->VadInfos[buffer->nCnt].pFileObject = ((vad->Subsection->ControlArea->FilePointer.Value >> 4) << 4);
                }
            }

            buffer->nCnt++;
        }

        //枚举左子树
        if (vad->Core.VadNode.Left)
            this->EnumVad((PMMVAD)vad->Core.VadNode.Left, buffer, count);
        //枚举右子树
        if (vad->Core.VadNode.Right)
            this->EnumVad((PMMVAD)vad->Core.VadNode.Right, buffer, count);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s-> error\n", __FUNCTION__);
    }
}

NTSTATUS MemoryTools::EnumProcessVad(IN PEPROCESS eprocess, IN PALL_VADS buffer, IN ULONG count)
{
    NTSTATUS status = STATUS_SUCCESS;
    PRTL_AVL_TREE vad_table = NULL;
    PMMVAD vad_root = NULL;

    if (this->m_eprocess_vadroot_offset == NULL)
    {
        DbgPrint("[GN]:%s-> this->m_eprocess_vadroot_offset is null\n", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }

    //与偏移相加得到vad头节点
    vad_table = (PRTL_AVL_TREE)((UCHAR*)eprocess + this->m_eprocess_vadroot_offset);
    if (!MmIsAddressValid(vad_table))
    {
        DbgPrint("[GN]:%s-> MmIsAddressValid() error", __FUNCTION__);
        ObDereferenceObject(eprocess);
        return status = STATUS_UNSUCCESSFUL;
    }
    __try
    {
        //取到vad头节点
        vad_root = (PMMVAD)vad_table->Root;
        //DbgPrint("[GN]:获取到的vad_root地址：%p", vad_root);

        if (count > buffer->nCnt)
        {
            //得到起始页
            ULONG64 startptr = ((ULONG64)vad_root->Core.StartingVpnHigh) << 32;

            //得到结束页
            ULONG64 endptr = ((ULONG64)vad_root->Core.EndingVpnHigh) << 32;

            //得到根节点
            buffer->VadInfos[buffer->nCnt].pVad = (ULONG_PTR)vad_root;//就存vad的地址

            //起始页真实虚拟地址：StartingVpn * 0x1000
            buffer->VadInfos[buffer->nCnt].startVpn = (startptr | vad_root->Core.StartingVpn) << PAGE_SHIFT;
            //结束页真实虚拟地址：EndVpn * 0x1000 + 0xFFF
            buffer->VadInfos[buffer->nCnt].endVpn = ((endptr | vad_root->Core.EndingVpn) << PAGE_SHIFT) + 0xFFF;
            //VAD标志 928 = Mapped  104988 = Private ...
            buffer->VadInfos[buffer->nCnt].flags = vad_root->Core.u1.Flags.flag;

            //验证节点可读性
            if (MmIsAddressValid(vad_root->Subsection) && MmIsAddressValid(vad_root->Subsection->ControlArea))
            {
                if (MmIsAddressValid((PVOID)((vad_root->Subsection->ControlArea->FilePointer.Value >> 4) << 4)))
                {
                    buffer->VadInfos[buffer->nCnt].pFileObject = ((vad_root->Subsection->ControlArea->FilePointer.Value >> 4) << 4);
                }
            }

            buffer->nCnt++;
        }

        //枚举左子树
        if (vad_table->Root->Left)
            this->EnumVad((PMMVAD)vad_table->Root->Left, buffer, count);
        //枚举右子树
        if (vad_table->Root->Right)
            this->EnumVad((PMMVAD)vad_table->Root->Right, buffer, count);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s-> error", __FUNCTION__);
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}

//public:
NTSTATUS MemoryTools::SetMemoryVADProtection(IN HANDLE pid, IN ULONG64 virtual_address, IN ULONG virtual_address_size, DWORD new_protection)
{
    //DbgPrint("[GN]:传入的地址：%p,大小：%d,属性：%d", virtual_address, virtual_address_size, new_protection);
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS eprocess = NULL;

    //通过pid获得eprocess
    status = PsLookupProcessByProcessId(pid, &eprocess);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[GN]:%s-> PsLookupProcessByProcessId errorcode:%p", __FUNCTION__, status);
        status = STATUS_UNSUCCESSFUL;
        return status;
    }

    __try
    {
        //默认1000个线程
        int VAD_INDO_size = sizeof(VAD_INFO);
        int ULONG_size = sizeof(ULONG);
        ULONG size = VAD_INDO_size * 0x5000 + ULONG_size;
        //分配临时空间
        PALL_VADS buffer = (PALL_VADS)ExAllocatePoolWithTag(PagedPool, size, 'VAD');
        //根据传入长度得到枚举数量
        ULONG count = (size - sizeof(ULONG)) / sizeof(VAD_INFO);
        //DbgPrint("[GN]:VAD_INDO_size:%d,ULONG_size:%d,size:%d,count:%d,buffer.nCnt:%d\n", VAD_INDO_size, ULONG_size, size, count, buffer->nCnt);

        //枚举vad
        if (!NT_SUCCESS(this->EnumProcessVad(eprocess, buffer, count)))
        {
            DbgPrint("[GN]:%s-> EnumProcessVad() failed!\n", __FUNCTION__);
            status = STATUS_UNSUCCESSFUL;
        }
        else
        {
            ////输出VAD信息
            //for (size_t i = 0; i < buffer->nCnt; i++)
            //{
            //    DbgPrint("[GN]:StartVpn = %p | EndVpn = %p | PVAD = %p | Flags = %d | pFileObject = %p | Protection = %d\n",
            //        buffer->VadInfos[i].startVpn, buffer->VadInfos[i].endVpn, buffer->VadInfos[i].pVad,
            //        buffer->VadInfos[i].flags, buffer->VadInfos[i].pFileObject, ((PMMVAD)buffer->VadInfos[i].pVad)->Core.u1.Flags.PrivateVadFlags.Protection);
            //}

            PMMVAD p_vad = (PMMVAD)this->GetVadByAddress(buffer, virtual_address);
            if (p_vad == NULL)
            {
                DbgPrint("[GN]:获得隐藏地址失败！p_vad is null\n");
                if (buffer)
                    ExFreePoolWithTag(buffer, 'VAD');
                ObDereferenceObject(eprocess);
                return STATUS_UNSUCCESSFUL;
            }
            DbgPrint("[GN]:取到的Protection:%d\n", p_vad->Core.u1.Flags.PrivateVadFlags.Protection);


            if (buffer)
                ExFreePoolWithTag(buffer, 'VAD');
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s-> error\n", __FUNCTION__);
        status = STATUS_UNSUCCESSFUL;
    }

    ObDereferenceObject(eprocess);
    return status;
}

NTSTATUS MemoryTools::HideMemoryByVAD(IN HANDLE pid, IN ULONG64 virtual_address, IN ULONG virtual_address_size)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS eprocess = NULL;

    //通过pid获得eprocess
    status = PsLookupProcessByProcessId(pid, &eprocess);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[GN]:%s-> PsLookupProcessByProcessId errorcode:%p", __FUNCTION__, status);
        status = STATUS_UNSUCCESSFUL;
        return status;
    }

    __try
    {
        //默认1000个线程
        int VAD_INDO_size = sizeof(VAD_INFO);
        int ULONG_size = sizeof(ULONG);
        ULONG size = VAD_INDO_size * 0x5000 + ULONG_size;
        //分配临时空间
        PALL_VADS buffer = (PALL_VADS)ExAllocatePoolWithTag(PagedPool, size, 'VAD');
        //根据传入长度得到枚举数量
        ULONG count = (size - sizeof(ULONG)) / sizeof(VAD_INFO);
        //DbgPrint("[GN]:VAD_INDO_size:%d,ULONG_size:%d,size:%d,count:%d,buffer.nCnt:%d\n", VAD_INDO_size, ULONG_size, size, count, buffer->nCnt);

        //枚举vad
        if (!NT_SUCCESS(this->EnumProcessVad(eprocess, buffer, count)))
        {
            DbgPrint("[GN]:%s-> EnumProcessVad() failed!\n", __FUNCTION__);
            status = STATUS_UNSUCCESSFUL;
        }
        else
        {
            ////输出VAD信息
            //for (size_t i = 0; i < buffer->nCnt; i++)
            //{
            //    DbgPrint("[GN]:StartVpn = %p | EndVpn = %p | PVAD = %p | Flags = %d | pFileObject = %p\n",
            //        buffer->VadInfos[i].startVpn, buffer->VadInfos[i].endVpn, buffer->VadInfos[i].pVad,
            //        buffer->VadInfos[i].flags, buffer->VadInfos[i].pFileObject);
            //    //DbgPrint("[GN]:StartVpn = %p | EndVpn = %p | PVAD = %p | Flags = %d | pFileObject = %p | FileName:%S\n",
            //    //    buffer->VadInfos[i].startVpn, buffer->VadInfos[i].endVpn, buffer->VadInfos[i].pVad,
            //    //    buffer->VadInfos[i].flags, buffer->VadInfos[i].pFileObject, buffer->VadInfos[i].FileName->Name.Buffer);
            //}
            
            PMMVAD p_vad2 = (PMMVAD)this->GetVadByAddress(buffer, virtual_address);
            //DbgPrint("[GN]:取到的p_vad2地址:%p,指向的startvpn：%p,endvpn:%p\n", p_vad2, p_vad2->Core.StartingVpn, p_vad2->Core.EndingVpn);
            if (p_vad2 == NULL)
            {
                DbgPrint("[GN]:获得隐藏地址失败！p_vad2 is null\n");
                if (buffer)
                    ExFreePoolWithTag(buffer, 'VAD');
                ObDereferenceObject(eprocess);
                return STATUS_UNSUCCESSFUL;
            }
            //通过需要隐藏的地址得到上一个vad节点
            PMMVAD p_vad1 = this->GetVadByCountNumber(buffer, (this->GetVadCountNumber(buffer, p_vad2) - 1));
            if (p_vad1 == NULL)
            {
                DbgPrint("[GN]:获得隐藏地址失败！p_vad2 is null\n");
                if (buffer)
                    ExFreePoolWithTag(buffer, 'VAD');
                ObDereferenceObject(eprocess);
                return STATUS_UNSUCCESSFUL;
            }
            //DbgPrint("[GN]:取到的p_vad1地址:%p,指向的startvpn：%p,endvpn:%p\n", p_vad1, p_vad1->Core.StartingVpn, p_vad1->Core.EndingVpn);

            //初始化监视进程类方便还原vad树
            if (!monitor) monitor = new Monitor(pid);
            monitor->SetPID(pid);
            //处理前保存原始vad
            this->hide_vad_status = true;
            //保存进程id
            this->old_vad[this->hide_vad_count].pid = pid;
            //保存vad指针
            this->old_vad[this->hide_vad_count].p_current_vad = p_vad2;
            //保存原始数据
            RtlCopyMemory(&this->old_vad[this->hide_vad_count].old_vad, p_vad2, sizeof(MMVAD));
            //处理计数 + 1
            this->hide_vad_count++;

            //进行隐藏处理
            p_vad2->Core.StartingVpn = p_vad1->Core.StartingVpn;
            p_vad2->Core.EndingVpn = p_vad1->Core.EndingVpn;

            //关机前修复否则蓝屏
            DbgPrint("[GN]:隐藏内存完成\n");


            //p_vad2->Core.StartingVpn = old_vad.Core.StartingVpn;
            //p_vad2->Core.EndingVpn = old_vad.Core.EndingVpn;
            //DbgPrint("[GN]:恢复内存完成\n");

            if (buffer)
                ExFreePoolWithTag(buffer, 'VAD');
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s-> error\n", __FUNCTION__);
        status = STATUS_UNSUCCESSFUL;
    }

    ObDereferenceObject(eprocess);
    return status;
}

void MemoryTools::RestoreVAD()
{
    if (this->hide_vad_status)
    {
        for (size_t i = 0; i < this->hide_vad_count; i++)
        {
            //恢复vad
            this->old_vad[i].p_current_vad->Core.StartingVpn = this->old_vad[i].old_vad.Core.StartingVpn;
            this->old_vad[i].p_current_vad->Core.EndingVpn = this->old_vad[i].old_vad.Core.EndingVpn;
        }
        this->hide_vad_status = false;
        this->hide_vad_count = 0;
        DbgPrint("[GN]:%s-> VAD修复完成\n", __FUNCTION__);
    }
}

void Test()
{


}




//ULONG64 GetPteAddress(PVOID addr)
//{
//    return (ULONG64)(((((ULONG64)addr & 0xffffffffffff) >> 12) << 3) + PTE_BASE);
//}
//ULONG64 GetPdeAddress(PVOID addr)
//{
//    return (ULONG64)(((((ULONG64)addr & 0xffffffffffff) >> 21) << 3) + PDE_BASE);
//}
//ULONG64 GetPpeAddress(PVOID addr)
//{
//    return (ULONG64)(((((ULONG64)addr & 0xffffffffffff) >> 30) << 3) + PPE_BASE);
//}
//ULONG64 GetPxeAddress(PVOID addr)
//{
//    return (ULONG64)(((((ULONG64)addr & 0xffffffffffff) >> 39) << 3) + PXE_BASE);
//}
//ULONG64 GetPteBase()
//{
//    ULONG64 pte_base = NULL;
//    if (this->system_version_number == 7601 || this->system_version_number == 7600 || this->system_version_number < 14393)
//    {
//        pte_base = 0xFFFFF68000000000ull;
//        return pte_base;
//    }
//    else
//    {
//        UNICODE_STRING unName = { 0 };
//        RtlInitUnicodeString(&unName, L"MmGetVirtualForPhysical");
//        PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&unName);
//        pte_base = *(PULONG64)(func + 0x22);
//        return pte_base;
//    }
//    return pte_base;
//}
//void InitPTE()
//{
//    PTE_BASE = GetPteBase();
//    PDE_BASE = GetPteAddress((PVOID)PTE_BASE);
//    PPE_BASE = GetPteAddress((PVOID)PDE_BASE);
//    PXE_BASE = GetPteAddress((PVOID)PPE_BASE);
//    return;
//}
//BOOLEAN SetExecutePage(ULONG64 VirtualAddress, ULONG size)
//{
//    InitPTE();
//    ULONG64 startAddress = VirtualAddress & (~0xFFF);
//    ULONG64 endAddress = (VirtualAddress + size) & (~0xFFF);
//    int count = 0;
//    while (endAddress >= startAddress)
//    {
//        PHardwarePte pde = (PHardwarePte)GetPdeAddress((PVOID)startAddress);
//        if (MmIsAddressValid(pde) && pde->valid)
//        {
//            pde->no_execute = 0;
//        }
//        PHardwarePte pte = (PHardwarePte)GetPteAddress((PVOID)startAddress);
//        if (MmIsAddressValid(pte) && pte->valid)
//        {
//            pte->no_execute = 0;
//        }
//        startAddress += PAGE_SIZE;
//    }
//    return TRUE;
//}
