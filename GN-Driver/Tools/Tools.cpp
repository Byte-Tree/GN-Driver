//////////////////////////////////////////////////////////////////////////////////////////////////////////
//		                            Щ�򵥵Ĺ��ܷ����������ú�ά��
//////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "Tools.h"
#include "../MainFunction/MainFunction.h"

#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL);


Tools::Tools(PDRIVER_OBJECT pdriverobject)
{
    m_pdriverobject = pdriverobject;
    this->PspNotifyEnableMask = (PBYTE)this->GetPspNotifyEnableMask();
    this->previous_mode_offset = this->GetPreviousModeOffset();

    //��SSDT�����ҵ�Nt����
    this->NtContinue = (pfnNtContinue)this->GetSSDTFunction(this->GetIndexByName("NtContinue"));

    //ͨ��EPROCESS�ṹ��ȡ��������ƫ��
    eprocess_processname_offset = this->GetProcessNameOffsetByEprocess();

}

Tools::~Tools()
{
}

void* Tools::operator new(size_t size, POOL_TYPE pool_type)
{
#pragma warning(disable : 4996)
    return ExAllocatePoolWithTag(pool_type, size, 'abcg');
#pragma warning(default : 4996)
}

void Tools::operator delete(void* pointer)
{
    ExFreePoolWithTag(pointer, 'abcg');
}

NTSTATUS Tools::GetProcessNameByID(IN ULONG pid, OUT char* process_name)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE process_handle = NULL;
    OBJECT_ATTRIBUTES object_attributes = { NULL };
    CLIENT_ID cid = { (HANDLE)pid,0 };
    PEPROCESS eprocess = { NULL };
    InitializeObjectAttributes(&object_attributes, 0, 0, 0, 0);
    //�򿪽��̻�þ��
    status = ZwOpenProcess(&process_handle, PROCESS_ALL_ACCESS, &object_attributes, &cid);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[GN]:GetProcessNameByID()->ZwOpenProcess() Error:%d", status);
        return status;
    }
    //�õ�EPROCESS�ṹ�еĽ�����
    status = ObReferenceObjectByHandle(process_handle, FILE_READ_DATA, 0, KernelMode, (PVOID*)&eprocess, 0);
    if (NT_SUCCESS(status))
    {
        //char* processname = (char*)eprocess + 0x174;
        memcpy(process_name, PsGetProcessImageFileName(eprocess), 256);
        //DbgPrint("[GN]:processname:%s", processname);
        //DbgPrint("[GN]:psname:%s", process_name);
        ZwClose(process_handle);
        status = STATUS_SUCCESS;
        return status;
    }
    else
    {
        ZwClose(process_handle);
        DbgPrint("[GN]:GetProcessNameByID()->ObReferenceObjectByHandle() Error:%d", status);
        return status;
    }
}

PVOID Tools::EnumKernelModulehandle(IN PWCHAR module_name)
{
    //VMProtectBegin("EnumKernelModulehandle");

    //DbgPrint("[GN]:module_name:%S", module_name);
    if ((this->m_pdriverobject) && (this->m_pdriverobject->DriverSection))
    {
        do
        {
            PLDR_DATA_TABLE_ENTRY64 pldte = (PLDR_DATA_TABLE_ENTRY64)this->m_pdriverobject->DriverSection;
            if (pldte != NULL)
            {
                const PLIST_ENTRY64 pListHeaderInLoadOrder = (PLIST_ENTRY64)pldte->InLoadOrderLinks.Flink;
                if (pListHeaderInLoadOrder != NULL)
                {
                    PLIST_ENTRY64 pListTemp = pListHeaderInLoadOrder;
                    do
                    {
                        PLDR_DATA_TABLE_ENTRY64 pldteTemp = (PLDR_DATA_TABLE_ENTRY64)CONTAINING_RECORD(pListTemp, LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);
                        if ((pldteTemp != NULL) && (pldteTemp->BaseDllName.Buffer != NULL) && (pldteTemp->FullDllName.Buffer != NULL))
                        {
                            if (_wcsicmp(module_name, pldteTemp->BaseDllName.Buffer) == 0)
                            {
                                DbgPrint("[GN]:ģ������%S", pldteTemp->BaseDllName.Buffer);
                                DbgPrint("[GN]:EntryPoint:%p", pldteTemp->EntryPoint);
                                DbgPrint("[GN]:ģ���ַ:%p", pldteTemp->DllBase);
                                return pldteTemp->DllBase;
                            }
                        }
                        pListTemp = (PLIST_ENTRY64)pListTemp->Flink;
                    } while (pListTemp != pListHeaderInLoadOrder);
                }
            }
        } while (false);
    }
    return 0;

    //VMProtectEnd();
}

NTSTATUS Tools::DeleteDriverFile(PUNICODE_STRING pdriver_path)
{
    //VMProtectBegin("DeleteDriverFile");

    //DbgPrint("[GN]:�ļ�·����%S\n", pdriver_path->Buffer);

    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE FileHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, pdriver_path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, 0);

    NTSTATUS Status = IoCreateFileEx(&FileHandle, SYNCHRONIZE | DELETE, &ObjectAttributes, &IoStatusBlock, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE,
        FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0, CreateFileTypeNone, nullptr, IO_NO_PARAMETER_CHECKING, nullptr);

    if (!NT_SUCCESS(Status))
        return Status;

    PFILE_OBJECT FileObject;
    Status = ObReferenceObjectByHandleWithTag(FileHandle, SYNCHRONIZE | DELETE, *IoFileObjectType, KernelMode, 'eliF', reinterpret_cast<PVOID*>(&FileObject), nullptr);
    if (!NT_SUCCESS(Status))
    {
        ObCloseHandle(FileHandle, KernelMode);
        return Status;
    }

    const PSECTION_OBJECT_POINTERS SectionObjectPointer = FileObject->SectionObjectPointer;
    SectionObjectPointer->ImageSectionObject = nullptr;

    // call MmFlushImageSection, make think no backing image and let NTFS to release file lock
    CONST BOOLEAN ImageSectionFlushed = MmFlushImageSection(SectionObjectPointer, MmFlushForDelete);

    ObfDereferenceObject(FileObject);
    ObCloseHandle(FileHandle, KernelMode);

    if (ImageSectionFlushed)
    {
        // chicken fried rice
        Status = ZwDeleteFile(&ObjectAttributes);
        if (NT_SUCCESS(Status))
            return Status;
    }
    return Status;

    //VMProtectEnd();
}

PVOID Tools::GetProcAddress(WCHAR* FuncName)
{
    UNICODE_STRING u_FuncName = { 0 };
    PVOID ref = NULL;
    RtlInitUnicodeString(&u_FuncName, FuncName);
    ref = MmGetSystemRoutineAddress(&u_FuncName);
    return ref;
}

ULONG Tools::GetIndexByName(const char* sdName)
{
    NTSTATUS Status;
    HANDLE FileHandle;
    IO_STATUS_BLOCK ioStatus;
    FILE_STANDARD_INFORMATION FileInformation;
    //����NTDLL·��
    UNICODE_STRING uniFileName;
    RtlInitUnicodeString(&uniFileName, L"\\SystemRoot\\system32\\ntdll.dll");

    //��ʼ�����ļ�������
    OBJECT_ATTRIBUTES objectAttributes;
    InitializeObjectAttributes(&objectAttributes, &uniFileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    //�����ļ�

    Status = IoCreateFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &objectAttributes,
        &ioStatus, 0, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
    if (!NT_SUCCESS(Status))
        return 0;
    //��ȡ�ļ���Ϣ

    Status = ZwQueryInformationFile(FileHandle, &ioStatus, &FileInformation,
        sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
    if (!NT_SUCCESS(Status)) {
        ZwClose(FileHandle);
        return 0;
    }
    //�ж��ļ���С�Ƿ����
    if (FileInformation.EndOfFile.HighPart != 0)
    {
        ZwClose(FileHandle);
        return 0;
    }
    //ȡ�ļ���С
    ULONG uFileSize = FileInformation.EndOfFile.LowPart;

    //�����ڴ�
#pragma warning(disable : 4996)
    PVOID pBuffer = ExAllocatePoolWithTag(PagedPool, uFileSize + 0x100, (ULONG)"Ntdl");
#pragma warning(default : 4996)
    if (pBuffer == NULL)
    {
        ZwClose(FileHandle);
        return 0;
    }

    //��ͷ��ʼ��ȡ�ļ�
    LARGE_INTEGER byteOffset;
    byteOffset.LowPart = 0;
    byteOffset.HighPart = 0;
    Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &ioStatus, pBuffer, uFileSize, &byteOffset, NULL);
    if (!NT_SUCCESS(Status))
    {
        ZwClose(FileHandle);
        return 0;
    }
    //ȡ��������
    PIMAGE_DOS_HEADER  pDosHeader;
    PIMAGE_NT_HEADERS  pNtHeaders;
    PIMAGE_SECTION_HEADER pSectionHeader;
    ULONGLONG     FileOffset;//������64λ���ģ��������ﲻ��32���ֽ�
    PIMAGE_EXPORT_DIRECTORY pExportDirectory;
    //DLL�ڴ�����ת��DOSͷ�ṹ
    pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
    //ȡ��PEͷ�ṹ
    pNtHeaders = (PIMAGE_NT_HEADERS)((ULONGLONG)pBuffer + pDosHeader->e_lfanew);
    //�ж�PEͷ��������Ƿ�Ϊ��

    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return 0;

    //ȡ��������ƫ��
    FileOffset = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    //ȡ����ͷ�ṹ
    pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONGLONG)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
    PIMAGE_SECTION_HEADER pOldSectionHeader = pSectionHeader;
    //�����ڽṹ���е�ַ����
    for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
    {
        if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
            FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
    }

    //�������ַ
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONGLONG)pBuffer + FileOffset);
    //ȡ������������ַ
    PLONG AddressOfFunctions;
    FileOffset = pExportDirectory->AddressOfFunctions;
    //�����ڽṹ���е�ַ����
    pSectionHeader = pOldSectionHeader;
    for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
    {
        if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
            FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
    }
    AddressOfFunctions = (PLONG)((ULONGLONG)pBuffer + FileOffset);//����ע��һ��foa��rva

    //ȡ��������������
    PUSHORT AddressOfNameOrdinals;
    FileOffset = pExportDirectory->AddressOfNameOrdinals;

    //�����ڽṹ���е�ַ����
    pSectionHeader = pOldSectionHeader;
    for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
    {
        if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
            FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
    }
    AddressOfNameOrdinals = (PUSHORT)((ULONGLONG)pBuffer + FileOffset);//ע��һ��foa��rva

    //ȡ�������������
    PULONG AddressOfNames;
    FileOffset = pExportDirectory->AddressOfNames;

    //�����ڽṹ���е�ַ����
    pSectionHeader = pOldSectionHeader;
    for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
    {
        if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
            FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
    }
    AddressOfNames = (PULONG)((ULONGLONG)pBuffer + FileOffset);//ע��һ��foa��rva
    //DbgPrint("\n AddressOfFunctions %llX AddressOfNameOrdinals %llX AddressOfNames %llX  \n", (ULONGLONG)AddressOfFunctions- (ULONGLONG)pBuffer, (ULONGLONG)AddressOfNameOrdinals- (ULONGLONG)pBuffer, (ULONGLONG)AddressOfNames- (ULONGLONG)pBuffer);
    //DbgPrint("\n AddressOfFunctions %llX AddressOfNameOrdinals %llX AddressOfNames %llX  \n", pExportDirectory->AddressOfFunctions, pExportDirectory->AddressOfNameOrdinals, pExportDirectory->AddressOfNames);

    //����������
    ULONG uNameOffset;
    ULONG uOffset;
    LPSTR FunName;
    PVOID pFuncAddr;
    ULONG uServerIndex;
    ULONG uAddressOfNames;
    for (ULONG uIndex = 0; uIndex < pExportDirectory->NumberOfNames; uIndex++, AddressOfNames++, AddressOfNameOrdinals++)
    {
        uAddressOfNames = *AddressOfNames;
        pSectionHeader = pOldSectionHeader;
        for (UINT32 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
        {
            if (pSectionHeader->VirtualAddress <= uAddressOfNames && uAddressOfNames <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
                uOffset = uAddressOfNames - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
        }
        FunName = (LPSTR)((ULONGLONG)pBuffer + uOffset);
        if (FunName[0] == 'Z' && FunName[1] == 'w')
        {
            pSectionHeader = pOldSectionHeader;
            uOffset = (ULONG)AddressOfFunctions[*AddressOfNameOrdinals];
            for (UINT32 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
            {
                if (pSectionHeader->VirtualAddress <= uOffset && uOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
                    uNameOffset = uOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
            }
            pFuncAddr = (PVOID)((ULONGLONG)pBuffer + uNameOffset);
            uServerIndex = *(PULONG)((ULONGLONG)pFuncAddr + 4);
            FunName[0] = 'N';
            FunName[1] = 't';
            //���ָ���ı��
            if (!_stricmp(FunName, (const char*)sdName))
            {
                ExFreePoolWithTag(pBuffer, (ULONG)"Ntdl");
                ZwClose(FileHandle);
                return uServerIndex;
            }
            //DbgPrint("Name: %s index:%d\n ", FunName, uServerIndex);//index��%d\n, uServerIndex
        }
    }

    ExFreePoolWithTag(pBuffer, (ULONG)"Ntdl");
    ZwClose(FileHandle);
    return 0;
}

ULONGLONG Tools::Get_SSDT_Base_HIGH()
{//�߰汾���� 1904
    BYTE KiSystemServiceStart_pattern[13] = { 0x8B,0xF8,0xC1,0xEF,0x07,0x83,0xE7,0x20,0x25,0xFF,0x0F,0x00,0x00 };
    //"\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F\x00\x00";
    UNICODE_STRING unis_strnicmp;
    RtlInitUnicodeString(&unis_strnicmp, L"_strnicmp");
    ULONGLONG CodeScanStart = (ULONGLONG)MmGetSystemRoutineAddress(&unis_strnicmp);
    ULONGLONG CodeScanEnd = (ULONGLONG)&KdDebuggerNotPresent;
    ULONGLONG i, tbl_address, b;
    for (i = 0; i < CodeScanEnd - CodeScanStart; i++)
    {
        if (!memcmp((char*)(ULONGLONG)CodeScanStart + i,
            (char*)KiSystemServiceStart_pattern, 13))
        {
            for (b = 0; b < 50; b++)
            {
                tbl_address = ((ULONGLONG)CodeScanStart + i + b);
                if (*(USHORT*)((ULONGLONG)tbl_address) == (USHORT)0x8d4c)
                    return ((LONGLONG)tbl_address + 7) + *(LONG*)(tbl_address + 3);
            }
        }
    }
    return 0;
}

ULONGLONG Tools::Get_SSDT_Base_LOW()
{
    PUCHAR msr = (PUCHAR)__readmsr(0xC0000082);
    PUCHAR startaddr = 0, Endaddr = 0;
    PUCHAR i = NULL;
    UCHAR b1, b2, b3;
    ULONG temp = 0;
    ULONGLONG addr = 0;

    //DbgPrint("msr c0000082��ֵ:%p\n", msr);
    //0f01f8          swapgs
    //654889242510000000 mov   qword ptr gs:[10h],rsp
    if (*(msr + 0x9) == 0x00)//nt!KiSystemCall64
    {
        startaddr = msr;
        Endaddr = startaddr + 0x500;
    }
    //0f01f8          swapgs
    //654889242510700000 mov   qword ptr gs:[7010h],rsp
    else if (*(msr + 0x9) == 0x70)//nt!KiSystemCall64Shadow
    {
        PUCHAR pKiSystemCall64Shadow = msr;
        PUCHAR EndSearchAddress = pKiSystemCall64Shadow + 0x500;
        PUCHAR i = NULL;
        INT Temp = 0;
        for (i = pKiSystemCall64Shadow; i < EndSearchAddress; i++)//��������
        {
            if (MmIsAddressValid(i) && MmIsAddressValid(i + 5))
            {
                if (*i == 0xe9 && *(i + 5) == 0xc3)
                {
                    //e963e8e7ff      jmp     nt!KiSystemServiceUser (fffff803`7648fc02)
                    //c3              ret
                    memcpy(&Temp, i + 1, 4);
                    startaddr = Temp + (i + 5);
                    //DbgPrint("KiSystemServiceUser�ĵ�ַ:%p\n", startaddr);
                    Endaddr = startaddr + 0x500;
                }
            }
        }
    }

    for (i = startaddr; i < Endaddr; i++)//��������
    {
        b1 = *i;
        b2 = *(i + 1);
        b3 = *(i + 2);
        //4c8d15659b3b00  lea     r10,[nt!KeServiceDescriptorTable (fffff803`76849880)]
        if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)
        {
            memcpy(&temp, i + 3, 4);
            addr = (ULONGLONG)temp + (ULONGLONG)i + 7;
            //DbgPrint("SSDT��ַ:%p\n", addr);
            return addr;
        }
    }
    return 0;
}

ULONGLONG Tools::GetSSDTFunction(ULONGLONG Index)
{
    if (!Index)
        return 0;

    LONG dwTemp = 0;
    ULONGLONG qwTemp = 0, stb = 0, ret = 0;
    PSYSTEM_SERVICE_TABLE ssdt = (PSYSTEM_SERVICE_TABLE)this->Get_SSDT_Base_LOW();
    if (!ssdt)//�Ǹ߰汾
    {
        DbgPrint("�Ǹ߰汾\n");
        ssdt = (PSYSTEM_SERVICE_TABLE)this->Get_SSDT_Base_HIGH();
    }
    if (!ssdt)
        return 0;
    stb = (ULONGLONG)(ssdt->ServiceTableBase);
    qwTemp = stb + 4 * Index;
    dwTemp = *(PLONG)qwTemp;
    dwTemp = dwTemp >> 4;
    ret = stb + (LONG64)dwTemp;
    return ret;
}

NTSTATUS Tools::FD_SetFileCompletion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
    Irp->UserIosb->Status = Irp->IoStatus.Status;
    Irp->UserIosb->Information = Irp->IoStatus.Information;

    KeSetEvent(Irp->UserEvent, IO_NO_INCREMENT, FALSE);

    IoFreeIrp(Irp);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

HANDLE Tools::FD_OpenFile(WCHAR file_path[])
{
    NTSTATUS            ntStatus;
    UNICODE_STRING      FileName;
    OBJECT_ATTRIBUTES   objectAttributes;
    HANDLE              hFile;
    IO_STATUS_BLOCK     ioStatus;

    // ȷ��IRQL��PASSIVE_LEVEL��  
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        DbgPrint("[GN]:KeGetCurrentIrql() error");
        return NULL;
    }

    // ��ʼ���ļ���  
    RtlInitUnicodeString(&FileName, file_path);
    //DbgPrint("[GN]:FileName ��%ws\n", FileName.Buffer);

    //��ʼ����������  
    InitializeObjectAttributes(&objectAttributes, &FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // ���ļ�  
    ntStatus = IoCreateFile(&hFile, FILE_READ_ATTRIBUTES, &objectAttributes, &ioStatus,
        0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, 0, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
    //DbgPrint("[GN]:IoCreateFile : %016LLX\n", ntStatus);
    if (!NT_SUCCESS(ntStatus))
        return NULL;

    return  hFile;
}

BOOLEAN Tools::FD_StripFileAttributes(HANDLE FileHandle)
{
    NTSTATUS                ntStatus = STATUS_SUCCESS;
    PFILE_OBJECT            fileObject;
    PDEVICE_OBJECT          DeviceObject;
    PIRP                    Irp;
    KEVENT                  SycEvent;
    FILE_BASIC_INFORMATION  FileInformation;
    IO_STATUS_BLOCK         ioStatus;
    PIO_STACK_LOCATION      irpSp;

    // ��ȡ�ļ�����  
    ntStatus = ObReferenceObjectByHandle(FileHandle, DELETE,
        *IoFileObjectType, KernelMode, (PVOID*)&fileObject, NULL);
    if (!NT_SUCCESS(ntStatus))
    {
        DbgPrint("[GN]:ObReferenceObjectByHandle error!");
        return FALSE;
    }

    // ��ȡ��ָ���ļ�������������豸����  
    DeviceObject = IoGetRelatedDeviceObject(fileObject);

    // ����IRP  
    Irp = IoAllocateIrp(DeviceObject->StackSize, TRUE);
    if (Irp == NULL)
    {
        ObDereferenceObject(fileObject);

        DbgPrint("[GN]:FD_StripFileAttributes IoAllocateIrp error");
        return FALSE;
    }

    // ��ʼ��ͬ���¼�����  
    KeInitializeEvent(&SycEvent, SynchronizationEvent, FALSE);

    memset(&FileInformation, 0, 0x28);
    FileInformation.FileAttributes = FILE_ATTRIBUTE_NORMAL;

    // ��ʼ��IRP  
    Irp->AssociatedIrp.SystemBuffer = &FileInformation;
    Irp->UserEvent = &SycEvent;
    Irp->UserIosb = &ioStatus;
    Irp->Tail.Overlay.OriginalFileObject = fileObject;
    Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
    Irp->RequestorMode = KernelMode;

    // ����IRP��ջ��Ϣ  
    irpSp = IoGetNextIrpStackLocation(Irp);
    irpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
    irpSp->DeviceObject = DeviceObject;
    irpSp->FileObject = fileObject;
    irpSp->Parameters.SetFile.Length = sizeof(FILE_BASIC_INFORMATION);
    irpSp->Parameters.SetFile.FileInformationClass = FileBasicInformation;
    irpSp->Parameters.SetFile.FileObject = fileObject;

    // �����������  
    IoSetCompletionRoutine(Irp, Tools::FD_SetFileCompletion, NULL, TRUE, TRUE, TRUE);

    // �ɷ�IRP  
    IoCallDriver(DeviceObject, Irp);

    // �ȴ�IRP�����  
    KeWaitForSingleObject(&SycEvent, Executive, KernelMode, TRUE, NULL);

    // �ݼ����ü���  
    ObDereferenceObject(fileObject);

    return TRUE;
}

BOOLEAN Tools::FD_DeleteFile(HANDLE FileHandle)
{
    NTSTATUS          ntStatus = STATUS_SUCCESS;
    PFILE_OBJECT      fileObject;
    PDEVICE_OBJECT    DeviceObject;
    PIRP              Irp;
    KEVENT            SycEvent;
    FILE_DISPOSITION_INFORMATION    FileInformation;
    IO_STATUS_BLOCK                 ioStatus;
    PIO_STACK_LOCATION              irpSp;
    PSECTION_OBJECT_POINTERS        pSectionObjectPointer;

    // ��ȡ�ļ�����  
    ntStatus = ObReferenceObjectByHandle(FileHandle, DELETE,
        *IoFileObjectType, KernelMode, (PVOID*)&fileObject, NULL);
    if (!NT_SUCCESS(ntStatus))
    {
        DbgPrint("[GN]:ObReferenceObjectByHandle error!");
        return FALSE;
    }

    // ��ȡ��ָ���ļ�������������豸����  
    DeviceObject = IoGetRelatedDeviceObject(fileObject);

    // ����IRP  
    Irp = IoAllocateIrp(DeviceObject->StackSize, TRUE);
    if (Irp == NULL)
    {
        ObDereferenceObject(fileObject);
        DbgPrint("[GN]:FD_DeleteFile IoAllocateIrp error");
        return FALSE;
    }

    // ��ʼ��ͬ���¼�����  
    KeInitializeEvent(&SycEvent, SynchronizationEvent, FALSE);

    FileInformation.DeleteFile = TRUE;

    // ��ʼ��IRP  
    Irp->AssociatedIrp.SystemBuffer = &FileInformation;
    Irp->UserEvent = &SycEvent;
    Irp->UserIosb = &ioStatus;
    Irp->Tail.Overlay.OriginalFileObject = fileObject;
    Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
    Irp->RequestorMode = KernelMode;

    // ����IRP��ջ  
    irpSp = IoGetNextIrpStackLocation(Irp);
    irpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
    irpSp->DeviceObject = DeviceObject;
    irpSp->FileObject = fileObject;
    irpSp->Parameters.SetFile.Length = sizeof(FILE_DISPOSITION_INFORMATION);
    irpSp->Parameters.SetFile.FileInformationClass = FileDispositionInformation;
    irpSp->Parameters.SetFile.FileObject = fileObject;

    // �����������  
    IoSetCompletionRoutine(Irp, FD_SetFileCompletion, NULL, TRUE, TRUE, TRUE);

    // ���û����3�У����޷�ɾ���������е��ļ�  
    pSectionObjectPointer = fileObject->SectionObjectPointer;
    pSectionObjectPointer->ImageSectionObject = 0;
    pSectionObjectPointer->DataSectionObject = 0;

    // �ɷ�IRP  
    IoCallDriver(DeviceObject, Irp);

    // �ȴ�IRP���  
    KeWaitForSingleObject(&SycEvent, Executive, KernelMode, TRUE, NULL);

    // �ݼ����ü���  
    ObDereferenceObject(fileObject);

    return TRUE;
}

ULONGLONG Tools::GetPspNotifyEnableMask()
{
    PUCHAR startaddr = 0, Endaddr = 0;
    PUCHAR i = NULL;
    UCHAR b1, b2, b3, b4;
    ULONGLONG temp = 0;
    ULONGLONG addr = 0;
    UNICODE_STRING unisPsSetCreateProcessNotifyRoutine;
    ULONGLONG pfnPsSetCreateProcessNotifyRoutine;
    RtlInitUnicodeString(&unisPsSetCreateProcessNotifyRoutine, L"PsSetCreateProcessNotifyRoutine");
    pfnPsSetCreateProcessNotifyRoutine = (ULONGLONG)MmGetSystemRoutineAddress(&unisPsSetCreateProcessNotifyRoutine);
    if (pfnPsSetCreateProcessNotifyRoutine == NULL)
        return 0;
    //DbgPrint("pfnPsSetCreateProcessNotifyRoutine %p\n", pfnPsSetCreateProcessNotifyRoutine);
    startaddr = (PUCHAR)pfnPsSetCreateProcessNotifyRoutine; 
    Endaddr = (PUCHAR)pfnPsSetCreateProcessNotifyRoutine + 0x500;
    for (i = startaddr; i < Endaddr; i++)//��������
    {
        b1 = *i;
        b2 = *(i + 1);
        b3 = *(i + 6);
        b4 = *(i + 7);
        //fffff805`697575ba 8b0530102600    mov     eax,dword ptr [nt!PspNotifyEnableMask (fffff805`699b85f0)]
        //fffff805`697575c0 a804            test    al,4
        if (b1 == 0x8b && b2 == 0x05 && b3 == 0xa8 && b4 == 0x04)
        {
            memcpy(&temp, i + 2, 4);
            addr = (ULONGLONG)temp + (ULONGLONG)i + 6;
            //DbgPrint("[GN]:PspNotifyEnableMask��ַ:%p,%02X\n", addr, *(PBYTE)addr);
            return addr;
        }
    }
    return 0;
}

UINT Tools::GetPreviousModeOffset()
{
    UINT offset = 0;
    UNICODE_STRING unisExGetPreviousMode;
    UINT64 ExGetPreviousMode1;

    RtlInitUnicodeString(&unisExGetPreviousMode, L"ExGetPreviousMode");
    ExGetPreviousMode1 = (UINT64)(MmGetSystemRoutineAddress(&unisExGetPreviousMode));
    //DbgPrint("ExGetPreviousMode1:%p\n", ExGetPreviousMode1);
    if (ExGetPreviousMode1 == 0)
        return 0;
    //Ѱ��PreviousMode1ƫ�� win10��0x232
    if (ExGetPreviousMode1)
    {
        for (UINT64 addr = (UINT64)ExGetPreviousMode1; addr < (UINT64)ExGetPreviousMode1 + 20; addr++)
        {

            if (MmIsAddressValid((PVOID)addr) && *(unsigned char*)(addr) == 0x80 && MmIsAddressValid((PVOID)(addr + 5)) && *(unsigned char*)(addr + 5) == 0xC3)
            {
                offset = *(UINT*)(addr + 1);
                break;
            }
        }
    }
    if (!offset)
    {
        DbgPrint("[GN]:PreviousModeOffset is null");
        return 0;
    }

    return offset;
}

bool Tools::DisablePspNotify()
{
    //��������ϵͳ�ص�
    if (!this->PspNotifyEnableMask)
        return false;
    *this->PspNotifyEnableMask = 0x00;
    return true;
}

bool Tools::EnablePspNotify()
{
    if (!this->PspNotifyEnableMask)
        return false;
    //�ָ�����ϵͳ�ص�
    *this->PspNotifyEnableMask = 0x0F;
    return true;
}

bool Tools::ChangePrevKernelMode(PUCHAR address)
{
    //��Ϊ�ں�ģʽ 0
    if (!address)
        return false;
    //�޸�ǰ�ȱ���
    this->original_previous_mode = *address;
    *address = KernelMode;
    return true;
}

bool Tools::RestorePrevKernelMode(PUCHAR address)
{
    //��Ϊԭ����ģʽ
    if (!address)
        return false;
    *address = this->original_previous_mode;
    this->original_previous_mode = NULL;
    return true;
}

PUCHAR Tools::GetPreviousModeAddress()
{
    return ((PUCHAR)PsGetCurrentThread() + this->previous_mode_offset);
}

NTSTATUS Tools::MyNtContinue(PCONTEXT context, BOOLEAN TestAlert)
{
    if (!this->DisablePspNotify())
    {
        DbgPrint("[GN]:%s-> DisablePspNotify() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }
    if (!this->ChangePrevKernelMode(this->GetPreviousModeAddress()))
    {
        DbgPrint("[GN]:%s-> ChangePrevKernelMode() error", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = this->NtContinue(context, TestAlert);

    if (!this->EnablePspNotify())
    {
        DbgPrint("[GN]:%s-> EnablePspNotify() error", __FUNCTION__);
        status = -1;
    }
    if (!this->RestorePrevKernelMode(this->GetPreviousModeAddress()))
    {
        DbgPrint("[GN]:%s-> RestorePrevKernelMode() error", __FUNCTION__);
        status = -2;
    }
    return status;
}

NTSTATUS Tools::DeleteFile(IN WCHAR file_path[])
{
    HANDLE hFile = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    __try 
    {
        //���ļ�
        hFile = this->FD_OpenFile(file_path);
        if (hFile == NULL)
        {
            DbgPrint("[GN]:%s-> FD_OpenFile error!\n", __FUNCTION__);
            return status = STATUS_UNSUCCESSFUL;
        }
    
        //ȥ��ֻ�����ԣ�����ɾ��ֻ���ļ�  
        if (this->FD_StripFileAttributes(hFile) == FALSE)
        {
            ZwClose(hFile);
            DbgPrint("[GN]:%s-> FD_StripFileAttributes error!\n", __FUNCTION__);
            return status = STATUS_UNSUCCESSFUL;
        }
    
        //ɾ���ļ�  
        if (!this->FD_DeleteFile(hFile))
            status = STATUS_UNSUCCESSFUL;
        ZwClose(hFile);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) 
    {
        DbgPrint("[GN]:%s-> execption!", __FUNCTION__);
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}

NTSTATUS Tools::KillProcessById(IN HANDLE pid)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hprocess;
    OBJECT_ATTRIBUTES object_attributes;
    CLIENT_ID cid;

    //��ʼ��
    InitializeObjectAttributes(&object_attributes, 0, 0, 0, 0);
    cid.UniqueProcess = pid;
    cid.UniqueThread = 0;

    __try
    {
        //�򿪽���
        status = ZwOpenProcess(&hprocess, PROCESS_ALL_ACCESS, &object_attributes, &cid);
        if (NT_SUCCESS(status))
        {
            //��������
            status = ZwTerminateProcess(hprocess, status);
            //�رվ��
            ZwClose(hprocess);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[GN]:%s-> exception...", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }

    return status;
}

void Tools::KernelSleep(LONG msec)
{
    LARGE_INTEGER my_interval;
    my_interval.QuadPart = DELAY_ONE_MILLISECOND;
    my_interval.QuadPart *= msec;
    KeDelayExecutionThread(KernelMode, 0, &my_interval);
}

char* Tools::itoa(int num, char* str, int radix)
{
    char index[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";//������
    unsigned unum;//���Ҫת���������ľ���ֵ,ת�������������Ǹ���
    int i = 0, j, k;//i����ָʾ�����ַ�����Ӧλ��ת��֮��i��ʵ�����ַ����ĳ��ȣ�ת����˳��������ģ��������������k����ָʾ����˳��Ŀ�ʼλ��;j����ָʾ����˳��ʱ�Ľ�����

    //��ȡҪת���������ľ���ֵ
    if (radix == 10 && num < 0)//Ҫת����ʮ�����������Ǹ���
    {
        unum = (unsigned)-num;//��num�ľ���ֵ����unum
        str[i++] = '-';//���ַ�����ǰ������Ϊ'-'�ţ�����������1
    }
    else unum = (unsigned)num;//����numΪ����ֱ�Ӹ�ֵ��unum

    //ת�����֣�ע��ת�����������
    do
    {
        str[i++] = index[unum % (unsigned)radix];//ȡunum�����һλ��������Ϊstr��Ӧλ��ָʾ������1
        unum /= radix;//unumȥ�����һλ

    } while (unum);//ֱ��unumΪ0�˳�ѭ��

    str[i] = '\0';//���ַ���������'\0'�ַ���c�����ַ�����'\0'������

    //��˳���������
    if (str[0] == '-') k = 1;//����Ǹ��������Ų��õ������ӷ��ź��濪ʼ����
    else k = 0;//���Ǹ�����ȫ����Ҫ����

    char temp;//��ʱ��������������ֵʱ�õ�
    for (j = k; j <= (i - 1) / 2; j++)//ͷβһһ�Գƽ�����i��ʵ�����ַ����ĳ��ȣ��������ֵ�ȳ�����1
    {
        temp = str[j];//ͷ����ֵ����ʱ����
        str[j] = str[i - 1 + k - j];//β����ֵ��ͷ��
        str[i - 1 + k - j] = temp;//����ʱ������ֵ(��ʵ����֮ǰ��ͷ��ֵ)����β��
    }
    return str;//����ת������ַ���
}

DWORD Tools::GetProcessNameOffsetByEprocess()
{
    DWORD procNameOffset;
    PEPROCESS curproc = PsGetCurrentProcess();

    for (int i = 0; i < 4096; i++)
    {
        if (!strncmp("System", (PCHAR)curproc + i, strlen("System")))
        {
            procNameOffset = i;
            return procNameOffset;
        }
    }

    return 0;
}

BOOLEAN Tools::RtlStringContains(PSTRING str, PSTRING sub_str, BOOLEAN case_isensitive)
{
    if (str == NULL || sub_str == NULL || str->Length < sub_str->Length)
        return FALSE;

    CONST USHORT NumCharsDiff = (str->Length - sub_str->Length);
    STRING Slice = *str;
    Slice.Length = sub_str->Length;

    for (USHORT i = 0; i <= NumCharsDiff; ++i, ++Slice.Buffer, Slice.MaximumLength -= 1)
    {
        if (RtlEqualString(&Slice, sub_str, case_isensitive))
            return TRUE;
    }

    return FALSE;
}

BOOLEAN Tools::GetKernelProcessInfo(IN const char* name, IN ULONG64& image_size, IN PVOID& image_base)
{
    ULONG Bytes;
    NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &Bytes);
#pragma warning(disable : 4996)
    PMSYSTEM_MODULE_INFORMATION Mods = (PMSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, Bytes, 'dHyH');
#pragma warning(default : 4996)
    if (Mods == NULL)
        return FALSE;

    RtlSecureZeroMemory(Mods, Bytes);

    Status = ZwQuerySystemInformation(SystemModuleInformation, Mods, Bytes, &Bytes);
    if (NT_SUCCESS(Status) == FALSE)
    {
        ExFreePoolWithTag(Mods, 'dHyH');
        return FALSE;
    }

    STRING TargetProcessName;
    RtlInitString(&TargetProcessName, name);

    for (ULONG i = 0; i < Mods->ModulesCount; i++)
    {
        STRING CurrentModuleName;
        RtlInitString(&CurrentModuleName, (PCSZ)Mods->Modules[i].FullPathName);

        if (this->RtlStringContains(&CurrentModuleName, &TargetProcessName, TRUE) != NULL)
        {
            if (Mods->Modules[i].ImageSize != NULL)
            {
                image_size = Mods->Modules[i].ImageSize;
                image_base = Mods->Modules[i].ImageBase;
                ExFreePoolWithTag(Mods, 'dHyH');
                return TRUE;
            }
        }
    }

    ExFreePoolWithTag(Mods, 'dHyH');
    return FALSE;
}

BOOLEAN Tools::GetSectionData(CONST CHAR* image_name, CONST CHAR* section_name, ULONG64& section_size, PVOID& section_base_address)
{
    ULONG64 ImageSize = 0;
    PVOID ImageBase = 0;

    if (GetKernelProcessInfo(image_name, ImageSize, ImageBase) == FALSE)
        return FALSE;

    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS32 NtHeader = (PIMAGE_NT_HEADERS32)(DosHeader->e_lfanew + (ULONG64)ImageBase);
    ULONG NumSections = NtHeader->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);

    STRING TargetSectionName;
    RtlInitString(&TargetSectionName, section_name);

    for (ULONG i = 0; i < NumSections; i++)
    {
        STRING CurrentSectionName;
        RtlInitString(&CurrentSectionName, (PCSZ)Section->Name);
        if (CurrentSectionName.Length > 8)
            CurrentSectionName.Length = 8;

        if (RtlCompareString(&CurrentSectionName, &TargetSectionName, FALSE) == 0)
        {
            section_size = Section->Misc.VirtualSize;
            section_base_address = (PVOID)((ULONG64)ImageBase + (ULONG64)Section->VirtualAddress);

            return TRUE;
        }
        Section++;
    }

    return FALSE;
}



