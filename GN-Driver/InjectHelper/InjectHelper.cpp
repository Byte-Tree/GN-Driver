//////////////////////////////////////////////////////////////////////////////////////////////////////////
//		                                      ע��DLL���
//////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "InjectHelper.h"
#include "../MainFunction/MainFunction.h"

#define DLL_PROCESS_ATTACH   1   


InjectHelper::InjectHelper()
{
}

InjectHelper::~InjectHelper()
{
}

void* InjectHelper::operator new(size_t size, POOL_TYPE pool_type)
{
#pragma warning(disable : 4996)
    return ExAllocatePoolWithTag(pool_type, size, 'abcb');
#pragma warning(default : 4996)
}

void InjectHelper::operator delete(void* pointer)
{
    ExFreePoolWithTag(pointer, 'abcb');
}

PVOID InjectHelper::WriteStartShellCode(IN HANDLE pid, IN ULONG64 rip, IN ULONG64 param_buffer_address, IN ULONG64 loader_shellcode_address, IN ULONG64 createthread_address)
{
    PVOID start_code_address = NULL;

    //�������
    if ((rip == NULL) || (loader_shellcode_address == NULL))
    {
        DbgPrint("[GN]:%s-> params is error!", __FUNCTION__);
        return 0;
    }

    //���빹��hookע��ĵ�ַ��ֻ����ɶ���д�ڴ棬�����޸Ŀ�ִ������
    start_code_address = memorytools->AllocateMemory(pid, 0x1000, PAGE_READWRITE);
    if (!start_code_address)
    {
        DbgPrint("[GN]:%s-> hookcode_address alloc fialde", __FUNCTION__);
        return 0;
    }
#ifdef _INFORELEASE
    DbgPrint("[GN]:�����start_code_address��ַ��%p", start_code_address);
#endif

    //BYTE start_shellcode[58] = {
    //0x51,	//push rcx
    //0x50,	//push rax
    //0x48,0xB9,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 , //mov rcx,modulebase(param_buffer_address)
    //0x48,0xBA,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00 , //mov rdx,DLL_PROCESS_ATTACH
    //0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 , //mov rax,dll_entryaddr(loader_shellcode_address)
    //0x48,0x83,0xEC,0x28,								//sub rsp,28
    //0xFF,0xD0,											//call rax
    //0x48,0x83,0xC4,0x28,								//add rsp,28
    //0x58,												//pop rax
    //0x59,												//pop rcx
    //0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00//jmp Rip
    //};
    ////�������
    //memcpy(start_shellcode + 4, (PVOID)&param_buffer_address, 8);
    ////memcpy(start_shellcode + 14, (PVOID)DLL_PROCESS_ATTACH, 8);
    //memcpy(start_shellcode + 24, (PVOID)&loader_shellcode_address, 8);
    //memcpy(start_shellcode + sizeof(start_shellcode) - 8, (PVOID)&rip, 8);

    BYTE start_shellcode[48] = {
        0x51,	//push rcx
        0x50,	//push rax
        0x48,0xB9,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,//mov rcx,param_buffer
        0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,//mov rax,loadershellcode_address
        0x48,0x83,0xEC,0x38,								//sub rsp,38
        0xFF,0xD0,											//call rax
        0x48,0x83,0xC4,0x38,								//add rsp,38
        0x58,												//pop rax
        0x59,												//pop rcx
        0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00//jmp Rip
    };
    memcpy((start_shellcode + 0x04), (PVOID)&param_buffer_address, 8);
    memcpy((start_shellcode + 0x0E), (PVOID)&loader_shellcode_address, 8);
    memcpy((start_shellcode + 0x28), (PVOID)&rip, 8);
    
    //////����start_shellcode ż������
    ////BYTE start_shellcode[96] = {
    ////    0x54,       //push rsp
    ////    0x50,       //push rax
    ////    0x53,       //push rbx
    ////    0x51,       //push rcx
    ////    0x52,       //push rdx
    ////    0x55,       //push rbp
    ////    0x56,       //push rsi
    ////    0x57,       //push rdi
    ////    0x41,0x50,  //push r8
    ////    0x41,0x51,  //push r9
    ////    0x41,0x52,  //push r10
    ////    0x41,0x53,  //push r11
    ////    0x41,0x54,  //push r12
    ////    0x41,0x55,  //push r13
    ////    0x41,0x56,  //push r14
    ////    0x41,0x57,  //push r15
    ////    0x9C,       //pushfq
    ////    0x48,0x83,0xEC,0x38,								//sub rsp,38
    ////    0x48,0xB9,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  //mov rcx, param_buffer (offset:0x1F)
    ////    0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  //mov rax, loadershellcode_address (offset:0x29)
    ////    0x90,0x90,											//call rax
    ////    //0xFF,0xD0,											//call rax
    ////    0x48,0x83,0xC4,0x38,								//add rsp,38
    ////    0x9D,       //popfq
    ////    0x41,0x5F,  //pop r15
    ////    0x41,0x5E,  //pop r14
    ////    0x41,0x5D,  //pop r13
    ////    0x41,0x5C,  //pop r12
    ////    0x41,0x5B,  //pop r11
    ////    0x41,0x5A,  //pop r10
    ////    0x41,0x59,  //pop r9
    ////    0x41,0x58,  //pop r8
    ////    0x5F,       //pop rdi
    ////    0x5E,       //pop rsi
    ////    0x5D,       //pop rbp
    ////    0x5A,       //pop rdx
    ////    0x59,       //pop rcx
    ////    0x5B,       //pop rbx
    ////    0x58,       //pop rax
    ////    0x5C,       //pop rsp
    ////    0x50,       //push rax
    ////    0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  //mov rax, rip_return_address (offset:0x53)
    ////    0x48,0x87,0x04,0x24,                                //xchg [rsp],rax
    ////    0xC3 };                                             //ret
    ////memcpy((start_shellcode + 0x1F), (PVOID)&param_buffer_address, 8);
    ////memcpy((start_shellcode + 0x29), (PVOID)&loader_shellcode_address, 8);
    ////memcpy((start_shellcode + 0x53), (PVOID)&rip, 8);
    //
    ////����start_shellcode ż������
    //BYTE start_shellcode[131] = {
    //    0x54,       //push rsp
    //    0x50,       //push rax
    //    0x53,       //push rbx
    //    0x51,       //push rcx
    //    0x52,       //push rdx
    //    0x55,       //push rbp
    //    0x56,       //push rsi
    //    0x57,       //push rdi
    //    0x41,0x50,  //push r8
    //    0x41,0x51,  //push r9
    //    0x41,0x52,  //push r10
    //    0x41,0x53,  //push r11
    //    0x41,0x54,  //push r12
    //    0x41,0x55,  //push r13
    //    0x41,0x56,  //push r14
    //    0x41,0x57,  //push r15
    //    0x9C,       //pushfq
    //    0x48,0x83,0xEC,0x80,								//sub rsp,38
    //    0x31,0xC0,                                          //xor eax,eax
    //    0x48,0xBA,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,  //mov rdx,0102030405060708 ������ַ��0x21
    //    0x4C,0x8D,0x0A,                                     //lea r9,[rdx]
    //    0x36,0x48,0x89,0x44,0x24,0x28,                      //mov ss::[rsp+28],rax
    //    0x48,0xBA,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,  //mov rdx,0807060504030201 �̵߳�ַ��0x34
    //    0x4C,0x8D,0x02,                                     //lea r8,[rdx]
    //    0x31,0xD2,                                          //xor edx,edx
    //    0x36,0x89,0x44,0x24,0x20,                           //mov ss::[rsp+20],eax
    //    0x31,0xC9,                                          //xor ecx,ecx
    //    0x48,0xB8,0x88,0x88,0x88,0x88,0x88,0x88,0x88,0x88,  //mov rax,8888888888888888 CreateThread��ַ��0x4A
    //    0xFF,0xD0,                                          //call rax
    //    0x31,0xC0,                                          //xor eax,eax
    //    0x48,0x83,0xC4,0x80,								//add rsp,38
    //    0x9D,       //popfq
    //    0x41,0x5F,  //pop r15
    //    0x41,0x5E,  //pop r14
    //    0x41,0x5D,  //pop r13
    //    0x41,0x5C,  //pop r12
    //    0x41,0x5B,  //pop r11
    //    0x41,0x5A,  //pop r10
    //    0x41,0x59,  //pop r9
    //    0x41,0x58,  //pop r8
    //    0x5F,       //pop rdi
    //    0x5E,       //pop rsi
    //    0x5D,       //pop rbp
    //    0x5A,       //pop rdx
    //    0x59,       //pop rcx
    //    0x5B,       //pop rbx
    //    0x58,       //pop rax
    //    0x5C,       //pop rsp
    //    0x50,       //push rax
    //    0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  //mov rax, rip_return_address (offset:0x76)
    //    0x48,0x87,0x04,0x24,                                //xchg [rsp],rax
    //    0xC3 };                                             //ret
    //memcpy((start_shellcode + 0x21), (PVOID)&param_buffer_address, 8);
    //memcpy((start_shellcode + 0x34), (PVOID)&loader_shellcode_address, 8);
    //memcpy((start_shellcode + 0x4A), (PVOID)&createthread_address, 8);
    //memcpy((start_shellcode + 0x76), (PVOID)&rip, 8);

    memorytools->WriteMemoryByMDL((ULONG)pid, start_code_address, &start_shellcode, sizeof(start_shellcode));           //��Ŀ�����д��startshellcode

    //д�����ݺ��޸��ں˲��ִ�����ԣ�ʧ�ܷ���0
    if (!memorytools->SetExecutePage(pid, (ULONG64)start_code_address, 0x1000))
    {
        DbgPrint("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
        memorytools->FreeMemory(pid, (ULONG64)start_code_address, 0x1000);
        return 0;
    }

    return start_code_address;
}

NTSTATUS InjectHelper::InjectByHackThread(IN HANDLE pid, IN ULONG64 param_buffer_address, IN ULONG64 loader_shellcode_address, IN LONG kernel_wait_millisecond, IN ULONG64 createthread_address)
{
    __try
    {
        PEPROCESS eprocess = NULL;
        NTSTATUS status = STATUS_SUCCESS;
        HANDLE thread_handle = NULL;
        PVOID thread_object = NULL;
        OBJECT_ATTRIBUTES obj = { NULL };
        CLIENT_ID cid = { NULL };
        ULONG previouscount = NULL;
        KAPC_STATE kapc = { NULL };
        PKTRAP_FRAME current_trap = { NULL };
        ULONG64 start_shellcode_address = NULL;

        //��ȡ����EPROCESS
        status = PsLookupProcessByProcessId(pid, &eprocess);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("[GN]:PsLookupProcessByProcessId() error");
            return STATUS_UNSUCCESSFUL;
        }

        //���ӵ�������
        KeStackAttachProcess(eprocess, &kapc);

        //��ȡ��ǰ���������̵߳�������
        status = thread->ZwGetNextThread((HANDLE)-1, (HANDLE)0, 0x1FFFFF, 0x240, 0, &thread_handle);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("[GN]:%s-> ZwGetNextThread() errorcode:%p", __FUNCTION__, status);
        
            //���븽�ӽ���
            KeUnstackDetachProcess(&kapc);
            //������
            ObDereferenceObject(eprocess);
            return status;
        }

        //�ڶ��������ṩ������֤����������������Ȩ�ޣ��򷵻�ָ���������ĵ���Ӧָ�롣
        status = ObReferenceObjectByHandle(thread_handle, 0x1FFFFF, *PsThreadType, KernelMode, &thread_object, NULL);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("[GN]:%s-> ObReferenceObjectByHandle() errorcode:%p", __FUNCTION__, status);
        
            //���븽�ӽ���
            KeUnstackDetachProcess(&kapc);
            //������
            ObDereferenceObject(eprocess);
            return status;
        }

        //��ͣ�߳�
        status = thread->SuspendThread(thread_handle, &previouscount);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("[GN]:%s-> SuspendThread() errorcode:%p", __FUNCTION__, status);
            ZwClose(thread_handle);
        
            //�ͷ��̶߳�������
            ObDereferenceObject(thread_object);
            //���븽�ӽ���
            KeUnstackDetachProcess(&kapc);
            //������
            ObDereferenceObject(eprocess);
            return status;
        }
        
        //��֤ETHREAD��ַ�Ƿ�ɶ�
        if (MmIsAddressValid((PVOID) * (ULONG64*)((ULONG64)thread_object + thread->GetTrapFrameOffset())))
        {
            current_trap = (PKTRAP_FRAME)(*(ULONG64*)((ULONG64)thread_object + thread->GetTrapFrameOffset()));
#ifdef _INFORELEASE
            DbgPrint("[GN]:��ǰRip��%p", current_trap->Rip);
#endif

            //��Ŀ�����д��start_shell_code
            start_shellcode_address = (ULONG64)this->WriteStartShellCode(pid, current_trap->Rip, param_buffer_address, loader_shellcode_address, createthread_address);
            //�������Ϸ���
            if (!start_shellcode_address)
            {
                DbgPrint("[GN]:%s-> start_shellcode_address is null", __FUNCTION__);
            
                //ʧ�ָܻ��߳�����
                thread->ResumeThread(thread_handle, &previouscount);
                //�ر��߳̾��
                ZwClose(thread_handle);
                //�ͷ��̶߳�������
                ObDereferenceObject(thread_object);
                //���븽�ӽ���
                KeUnstackDetachProcess(&kapc);
                //������
                ObDereferenceObject(eprocess);
                return STATUS_UNSUCCESSFUL;
            }

            //�޸�rip�ٳ�
            current_trap->Rip = start_shellcode_address;
            //DbgPrint("[GN]:�ں˲�ٳֺ��rip��%p", current_trap->Rip);
        }
        else
        {
            DbgPrint("[GN]:%s-> MmIsAddressValid() Failed!", __FUNCTION__);
            return STATUS_UNSUCCESSFUL;
        }

        //�ָ��߳�
        status = thread->ResumeThread(thread_handle, &previouscount);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("[GN]:%s-> SuspendThread() errorcode:%p", __FUNCTION__, status);
            ZwClose(thread_handle);
        
            //�ͷ��̶߳�������
            ObDereferenceObject(thread_object);
            //���븽�ӽ���
            KeUnstackDetachProcess(&kapc);
            //������
            ObDereferenceObject(eprocess);
            return status;
        }

        //�ر��߳̾��
        ZwClose(thread_handle);
        //�ͷ��̶߳�������
        ObDereferenceObject(thread_object);
        //���븽�ӽ���
        KeUnstackDetachProcess(&kapc);
        //������
        ObDereferenceObject(eprocess);

        //��ʱ ����ͷ�������ڴ�ռ�
        tools->KernelSleep(kernel_wait_millisecond);
        if (!NT_SUCCESS(memorytools->FreeMemory(pid, start_shellcode_address, 0x1000)))
            DbgPrint("[GN]:%s-> FreeMemory() error!", __FUNCTION__);
        return status;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s-> exception...", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS InjectHelper::InjectByCreateThread(IN HANDLE pid, IN ULONG64 param_buffer_address, IN ULONG64 loader_shellcode_address, IN LONG kernel_wait_millisecond)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS eprocess = NULL;
    KAPC_STATE apc_state = { NULL };
    HANDLE process_handle = NULL;
    HANDLE thread_handle = NULL;
    OBJECT_ATTRIBUTES object = { sizeof(OBJECT_ATTRIBUTES) };
    CLIENT_ID cid = { NULL };

    status = PsLookupProcessByProcessId(pid, &eprocess);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[GN]:%s-> PsLookupProcessByProcessId() errorcode:%p\n", __FUNCTION__, status);
        return status;
    }

    //��Ŀ�����
    cid.UniqueProcess = pid;
    cid.UniqueThread = 0;
    status = ZwOpenProcess(&process_handle, PROCESS_ALL_ACCESS, &object, &cid);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[GN]:%s-> ZwOpenProcess() errorcode:%p\n", __FUNCTION__, status);
        return status;
    }

    //�����߳���������
    OBJECT_ATTRIBUTES object_attributes = { 0 };
    //ָ��һ��������������  ���ֻ�����ں�ģʽ���ʡ�
    InitializeObjectAttributes(&object_attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = thread->NtCreateThreadEx(&thread_handle, THREAD_ALL_ACCESS, &object_attributes, process_handle,
        (PVOID)loader_shellcode_address,    //�߳�������ַ
        (PVOID)param_buffer_address,        //�߳���������
        FALSE, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[GN]:%s-> NtCreateThreadEx() errorcode:%p\n", __FUNCTION__, status);
        ZwClose(process_handle);
        ObReferenceObject(eprocess);
        return status;
    }

    //�û��������ʱ
    tools->KernelSleep(kernel_wait_millisecond);

    ZwClose(process_handle);
    ObReferenceObject(eprocess);
    return status;
}

NTSTATUS InjectHelper::MyNtSetInformationProcess(IN HANDLE ProcessHandle, IN ULONG ProcessInformationClass, IN PVOID ProcessInformation, IN ULONG ProcessInformationLength)
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

    NTSTATUS status = NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);

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

PVOID InjectHelper::InitInstCallBackShellCode(IN HANDLE pid, IN ULONG64 param_buffer_address, IN ULONG64 loader_shellcode_address, IN ULONG64 createthread_address, IN ULONG64 rtlcapturecontext_address, IN ULONG64 ntcontinue_address)
{
    //����ִ��hook���ڴ�
    PVOID hookcode_address = memorytools->AllocateMemory(pid, 0x1000, PAGE_READWRITE);
    if (!hookcode_address)
        return 0;

    //BYTE hookcode[] = {
    //0x65,0x48,0x89,0x24,0x25,0xE0,0x02,0x00,0x00,   //mov gs:[2E0],rsp
    //0x65,0x4C,0x89,0x14,0x25,0xD8,0x02,0x00,0x00,   //mov gs:[2D8],r10
    //0x4C,0x8B,0xD1,                                 //mov r10,rcx
    //0x48,0x81,0xEC,0xD0,0x04,0x00,0x00,             //sub rsp,04D0
    //0x48,0x83,0xE4,0xF0,                            //and rsp,-10
    //0x48,0x8B,0xCC,                                 //mov rcx,rsp
    //0xFF,0x15,0xD7,0x01,0x00,0x00,                  //call qword ptr [���RtlCaptureContext�ĵ�ַ] (ƫ�ƣ�+0x200)
    //0x48,0x83,0xEC,0x20,                            //sub rsp,20
    //0xE8,0x02,0x00,0x00,0x00,                       //call myroutine
    //0xCC,0xCC,                                      //int 3 int 3
    //0x40,0x53,                                          //push rbx
    //0x48,0x83,0xEC,0x20,                                //sub rsp,20
    //0x65,0x48,0x8B,0x04,0x25,0xD8,0x02,0x00,0x00,       //mov rax,gs:[02D8]
    //0x48,0x8B,0xD9,                                     //mov rbx,rcx
    //0x48,0x89,0x81,0xF8,0x00,0x00,0x00,                 //mov [rcx+F8],rax
    //0x65,0x48,0x8B,0x04,0x25,0xE0,0x02,0x00,0x00,       //mov rax,gs:[2E0]
    //0x48,0x83,0x3D,0xB2,0x01,0x00,0x00,0x00,            //cmp qword ptr[����ж�ֵ�ĵ�ַ],00 (��ǰ�жϣ���ֹ���ݶ�ȡʧ�� ƫ�ƣ�0x210)
    //0x48,0x89,0x81,0x98,0x00,0x00,0x00,                 //mov [rcx+98],rax
    //0x48,0x8B,0x81,0xC8,0x00,0x00,0x00,                 //mov rax,[rcx+C8]
    //0x48,0x89,0x81,0x80,0x00,0x00,0x00,                 //mov [rcx+80],rax
    //0x75,0x28,                                          //jne ��תƫ��
    //0xC7,0x05,0x91,0x01,0x00,0x00,0x01,0x00,0x00,0x00,  //mov [����ж�ֵ�ĵ�ַ],00000001
    //0x48,0x83,0xEC,0x60,                                //sub rsp,38
    //0x48,0xB9,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  //mov rcx, param_address (offset:0x85)
    //0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  //mov rax, loadershellcode_address (offset:0x8F)
    //0xFF,0xD0,                                          //call rax
    //0x48,0x83,0xC4,0x60,                                //add rsp,38
    //0x33,0xD2,                                          //xor edx,edx
    //0x48,0x8B,0xCB,                                     //mov rcx,rbx
    //0x48,0x83,0xC4,0x20,                                //add rsp,20
    //0x5B,                                               //pop rbx
    //0x48,0xFF,0x25,0x72,0x01,0x00,0x00 };               //jmp NtContinue (����NtContinue��ַ��ƫ�ƣ�0x220)
    //memcpy((hookcode + 0x85), (PVOID)&param_buffer_address, 8);
    //memcpy((hookcode + 0x8F), (PVOID)&loader_shellcode_address, 8);
    //
    ////��Ŀ�����д��hookcode
    //memorytools->WriteMemoryByMDL((ULONG)pid, hookcode_address, hookcode, sizeof(hookcode));
    //memorytools->WriteMemoryByMDL((ULONG)pid, (PVOID)((ULONG64)hookcode_address + 0x200), (PVOID)&rtlcapturecontext_address, 8);
    //memorytools->WriteMemoryByMDL((ULONG)pid, (PVOID)((ULONG64)hookcode_address + 0x220), (PVOID)&ntcontinue_address, 8);

    BYTE hookcode[] = {
    0x65,0x48,0x89,0x24,0x25,0xE0,0x02,0x00,0x00,   //mov gs:[2E0],rsp
    0x65,0x4C,0x89,0x14,0x25,0xD8,0x02,0x00,0x00,   //mov gs:[2D8],r10
    0x4C,0x8B,0xD1,                                 //mov r10,rcx
    0x48,0x81,0xEC,0xD0,0x04,0x00,0x00,             //sub rsp,04D0
    0x48,0x83,0xE4,0xF0,                            //and rsp,-10
    0x48,0x8B,0xCC,                                 //mov rcx,rsp
    0xFF,0x15,0xD7,0x01,0x00,0x00,                  //call qword ptr [���RtlCaptureContext�ĵ�ַ] (ƫ�ƣ�+0x200)
    0x48,0x83,0xEC,0x20,                            //sub rsp,20
    0xE8,0x02,0x00,0x00,0x00,                       //call myroutine
    0xCC,0xCC,                                      //int 3 int 3
    0x40,0x53,                                          //push rbx
    0x48,0x83,0xEC,0x20,                                //sub rsp,20
    0x65,0x48,0x8B,0x04,0x25,0xD8,0x02,0x00,0x00,       //mov rax,gs:[02D8]
    0x48,0x8B,0xD9,                                     //mov rbx,rcx
    0x48,0x89,0x81,0xF8,0x00,0x00,0x00,                 //mov [rcx+F8],rax
    0x65,0x48,0x8B,0x04,0x25,0xE0,0x02,0x00,0x00,       //mov rax,gs:[2E0]
    0x48,0x83,0x3D,0xB2,0x01,0x00,0x00,0x00,            //cmp qword ptr[����ж�ֵ�ĵ�ַ],00 (��ǰ�жϣ���ֹ���ݶ�ȡʧ�� ƫ�ƣ�0x210)
    0x48,0x89,0x81,0x98,0x00,0x00,0x00,                 //mov [rcx+98],rax
    0x48,0x8B,0x81,0xC8,0x00,0x00,0x00,                 //mov rax,[rcx+C8]
    0x48,0x89,0x81,0x80,0x00,0x00,0x00,                 //mov [rcx+80],rax
    0x75,0x4B,                                          //jne ��תƫ��
    0xC7,0x05,0x91,0x01,0x00,0x00,0x01,0x00,0x00,0x00,  //mov [����ж�ֵ�ĵ�ַ],00000001
    0x48,0x83,0xEC,0x38,                                //sub rsp,38  60
    0x31,0xC0,                                          //xor eax,eax
    0x48,0xBA,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,  //mov rdx,0102030405060708 ������ַ��0x87
    0x4C,0x8D,0x0A,                                     //lea r9,[rdx]
    0x36,0x48,0x89,0x44,0x24,0x28,                      //mov ss::[rsp+28],rax
    0x48,0xBA,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,  //mov rdx,0807060504030201 �̵߳�ַ��0x9A
    0x4C,0x8D,0x02,                                     //lea r8,[rdx]
    0x31,0xD2,                                          //xor edx,edx
    0x36,0x89,0x44,0x24,0x20,                           //mov ss::[rsp+20],eax
    0x31,0xC9,                                          //xor ecx,ecx
    0x48,0xB8,0x88,0x88,0x88,0x88,0x88,0x88,0x88,0x88,  //mov rax,8888888888888888 CreateThread��ַ��0xB0
    0xFF,0xD0,                                          //call rax
    0x31,0xC0,                                          //xor eax,eax
    0x48,0x83,0xC4,0x38,                                //add rsp,38  60
    0x33,0xD2,                                          //xor edx,edx
    0x48,0x8B,0xCB,                                     //mov rcx,rbx
    0x48,0x83,0xC4,0x20,                                //add rsp,20
    0x5B,                                               //pop rbx
    0x48,0xFF,0x25,0x4F,0x01,0x00,0x00 };               //jmp NtContinue (����NtContinue��ַ��ƫ�ƣ�0x220)
    memcpy((hookcode + 0x87), (PVOID)&param_buffer_address, 8);
    memcpy((hookcode + 0x9A), (PVOID)&loader_shellcode_address, 8);
    memcpy((hookcode + 0xB0), (PVOID)&createthread_address, 8);
    
    //��Ŀ�����д��hookcode
    memorytools->WriteMemoryByMDL((ULONG)pid, hookcode_address, hookcode, sizeof(hookcode));
    memorytools->WriteMemoryByMDL((ULONG)pid, (PVOID)((ULONG64)hookcode_address + 0x200), (PVOID)&rtlcapturecontext_address, 8);
    memorytools->WriteMemoryByMDL((ULONG)pid, (PVOID)((ULONG64)hookcode_address + 0x220), (PVOID)&ntcontinue_address, 8);

    //д�����ݺ��޸��ں˿�ִ������
    if (!memorytools->SetExecutePage(pid, (ULONG64)hookcode_address, sizeof(hookcode_address)))
    {
        DbgPrint("[GN]:%s-> SetExecutePage() error\n", __FUNCTION__);
        memorytools->FreeMemory(pid, (ULONG64)hookcode_address, sizeof(hookcode_address));
        return 0;
    }

    DbgPrint("[GN]:hookcode_address:%p", hookcode_address);

    return hookcode_address;
}

NTSTATUS InjectHelper::InjectByInstCallBack(IN HANDLE pid, IN ULONG64 param_buffer_address, IN ULONG64 loader_shellcode_address, IN ULONG64 createthread_address, IN ULONG64 rtlcapturecontext_address, IN ULONG64 ntcontinue_address, IN LONG kernel_wait_millisecond, IN BOOL isclear_proccallback)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE process_handle = NULL;
    OBJECT_ATTRIBUTES obj = { NULL };
    CLIENT_ID cid = { NULL };

    cid.UniqueProcess = pid;
    cid.UniqueThread = 0;
    status = ZwOpenProcess(&process_handle, PROCESS_ALL_ACCESS, &obj, &cid);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[GN]:%s-> ZwOpenProcess() errorcode:%p\n", __FUNCTION__, status);
        return status;
    }

    //����InstrumentationCallback��hookcode
    PVOID instrumentationcallback_address = this->InitInstCallBackShellCode(pid, param_buffer_address, loader_shellcode_address, createthread_address, rtlcapturecontext_address, ntcontinue_address);
    if (!instrumentationcallback_address)
    {
        DbgPrint("[GN]:%s-> instrumentationcallback_address is null", __FUNCTION__);
        ZwClose(process_handle);
        return STATUS_UNSUCCESSFUL;
    }

    //����InstrumentationCallback����
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info = { NULL };
    info.Version = 0;
    info.Reserved = 0;
    info.Callback = instrumentationcallback_address;
    status = this->MyNtSetInformationProcess(process_handle, 0x28, &info, sizeof(info));
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[GN]:%s-> NtSetInformationProcess() errorcode:%p\n", __FUNCTION__, status);
        ZwClose(process_handle);
        return status;
    }

    //�ȴ��ָ��ص���ʱ��
    tools->KernelSleep(kernel_wait_millisecond);

    //����ص�
    if (isclear_proccallback)
    {
        info.Version = 0;
        info.Reserved = 0;
        info.Callback = 0;
        status = this->MyNtSetInformationProcess(process_handle, 0x28, &info, sizeof(info));
        if (!NT_SUCCESS(status))
        {
            DbgPrint("[GN]:%s-> NtSetInformationProcess() errorcode:%p\n", __FUNCTION__, status);
            ZwClose(process_handle);
            return status;
        }
    }

    //�ͷ�������ڴ�
    memorytools->FreeMemory(pid, (ULONG64)instrumentationcallback_address, 0x1000);
    ZwClose(process_handle);
    return status;
}



