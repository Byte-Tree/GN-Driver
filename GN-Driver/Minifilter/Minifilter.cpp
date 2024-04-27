//////////////////////////////////////////////////////////////////////////////////////////////////////////
//			微文件过滤系统的加载函数，功能函数卸载MainFunction.cpp（本来功能也要写在这里，属于屎山）
//////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "Minifilter.h"


MiniFilter::MiniFilter()
{
}

MiniFilter::~MiniFilter()
{
}

void* MiniFilter::operator new(size_t size, POOL_TYPE pool_type)
{
#pragma warning(disable : 4996)
	return ExAllocatePoolWithTag(pool_type, size, 'abce');
#pragma warning(default : 4996)
}

void MiniFilter::operator delete(void* pointer)
{
	ExFreePoolWithTag(pointer, 'abce');
}

NTSTATUS MiniFilter::GetFileName(const PUNICODE_STRING pImageFilePath, PUNICODE_STRING pFileName)
{
	static UNICODE_STRING UnicodeString = RTL_CONSTANT_STRING(L"*\\*");
	if (MmIsAddressValid(pImageFilePath) == FALSE || pImageFilePath->Buffer == NULL || pImageFilePath->Length <= sizeof(wchar_t) || MmIsAddressValid(pFileName) == FALSE)
	{
		ASSERT(FALSE);
		return STATUS_UNSUCCESSFUL;
	}
	if (pImageFilePath->Buffer[0] == OBJ_NAME_PATH_SEPARATOR || FsRtlIsNameInExpression(&UnicodeString, pImageFilePath, TRUE, NULL))
	{
		PWCHAR p;
		ULONG l;
		p = &pImageFilePath->Buffer[pImageFilePath->Length >> 1];
		while (*(p - 1) != OBJ_NAME_PATH_SEPARATOR)
			p--;
		l = (ULONG)(&pImageFilePath->Buffer[pImageFilePath->Length >> 1] - p);
		l *= sizeof(WCHAR);
		pFileName->MaximumLength = pFileName->Length = (USHORT)l;
		pFileName->Buffer = p;
	}
	else
	{
		pFileName->Length = pImageFilePath->Length;
		pFileName->Buffer = pImageFilePath->Buffer;
	}
	return STATUS_SUCCESS;
}

BOOLEAN MiniFilter::WriteMiniFilterReg(PUNICODE_STRING regpath)
{
	static wchar_t DependOnService[] = L"DependOnService";
	static wchar_t Group[] = L"Group";
	static wchar_t GroupName[] = L"Filter";
	static wchar_t DefaultInstance[] = L"DefaultInstance";
	static wchar_t DependOnServiceName[] = L"FltMgr";
	static wchar_t Altitude[] = L"Altitude";
	static wchar_t AltitudeNum[] = L"429999";
	static wchar_t AltitudeFlags[] = L"Flags";
	static wchar_t szAltitudeNum[64] = { 0 };
	static wchar_t szServerNameInstances[MAX_PATH] = { 0 };
	static wchar_t szProtectFileInstance[MAX_PATH] = { 0 };
	static wchar_t szInstances[MAX_PATH] = { 0 };
	BOOLEAN bRet = TRUE;
	ULONG ValueLength = 0;
	UNICODE_STRING DriverName = { 0 };
	ULONG ulValue;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG nAltitude = 429998;
	do
	{
		ValueLength = wcslen(DependOnServiceName) * sizeof(wchar_t);
		status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, DependOnService, REG_SZ, DependOnServiceName, ValueLength);
		if (!NT_SUCCESS(status))
		{
			bRet = FALSE;
			break;
		}
		ValueLength = wcslen(GroupName) * sizeof(wchar_t);
		status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, Group, REG_SZ, GroupName, ValueLength);
		if (!NT_SUCCESS(status))
		{
			bRet = FALSE;
			break;
		}
		GetFileName(regpath, &DriverName);
		RtlStringCbPrintfExW(szServerNameInstances, sizeof(szServerNameInstances), NULL, NULL, STRSAFE_FILL_BEHIND_NULL, L"%wZ\\Instances", regpath);
		status = RtlCreateRegistryKey(RTL_REGISTRY_ABSOLUTE, szServerNameInstances);
		if (!NT_SUCCESS(status))
		{
			bRet = FALSE;
			break;
		}
		RtlStringCbPrintfExW(szInstances, sizeof(szInstances), NULL, NULL, STRSAFE_FILL_BEHIND_NULL, L"%wZ Instance", &DriverName);
		ValueLength = wcslen(szInstances) * sizeof(wchar_t) + sizeof(wchar_t);		//ps这里的长度要加一个sizeof(wchar_t)，否则会注册失败
		status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szServerNameInstances, DefaultInstance, REG_SZ, szInstances, ValueLength);
		if (!NT_SUCCESS(status))
		{
			bRet = FALSE;
			break;
		}
		RtlStringCbPrintfExW(szProtectFileInstance, sizeof(szProtectFileInstance), NULL, NULL, STRSAFE_FILL_BEHIND_NULL, L"%s\\%wZ Instance", szServerNameInstances, &DriverName);
		status = RtlCreateRegistryKey(RTL_REGISTRY_ABSOLUTE, szProtectFileInstance);
		if (!NT_SUCCESS(status))
		{
			bRet = FALSE;
			break;
		}
		ValueLength = wcslen(AltitudeNum) * sizeof(wchar_t);
		status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szProtectFileInstance, Altitude, REG_SZ, AltitudeNum, ValueLength);	//szProtectFileInstance
		if (!NT_SUCCESS(status))
		{
			bRet = FALSE;
			break;
		}
		ulValue = 0;
		status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szProtectFileInstance, AltitudeFlags, REG_DWORD, &ulValue, sizeof(ULONG));
		if (!NT_SUCCESS(status))
		{
			bRet = FALSE;
			break;
		}
	} while (FALSE);
	return bRet;
}

BOOLEAN MiniFilter::MiniFilterInit(PDRIVER_OBJECT _Drive_Object, CONST FLT_OPERATION_REGISTRATION* OperationRegistration, CONST PFLT_FILTER_UNLOAD_CALLBACK FilterUnloadCallback)
{
	NTSTATUS status = -1;
	_Filter_Registration.Size = sizeof(FLT_REGISTRATION);
	_Filter_Registration.Version = FLT_REGISTRATION_VERSION;
	_Filter_Registration.Flags = 0;
	_Filter_Registration.ContextRegistration = NULL;
	_Filter_Registration.OperationRegistration = OperationRegistration;			//回调函数
	_Filter_Registration.FilterUnloadCallback = FilterUnloadCallback;			//卸载例程
	_Filter_Registration.InstanceSetupCallback = NULL;
	_Filter_Registration.InstanceQueryTeardownCallback = NULL;
	_Filter_Registration.InstanceTeardownCompleteCallback = NULL;
	_Filter_Registration.InstanceTeardownStartCallback = NULL;
	_Filter_Registration.GenerateFileNameCallback = NULL;
	_Filter_Registration.NormalizeContextCleanupCallback = NULL;
	_Filter_Registration.NormalizeNameComponentCallback = NULL;
	_Filter_Registration.NormalizeNameComponentExCallback = NULL;
	_Filter_Registration.TransactionNotificationCallback = NULL;
	status = FltRegisterFilter(_Drive_Object, &_Filter_Registration, &_Filter_Handle);
	if (!NT_SUCCESS(status))
	{
		DbgPrint_1Param("FltRegisterFilter code:%x---\n", status);
		return FALSE;
	}
	return TRUE;
}

BOOLEAN MiniFilter::StartMiniFilter()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	status = FltStartFiltering(_Filter_Handle);
	if (!NT_SUCCESS(status))
	{
		FltUnregisterFilter(_Filter_Handle);
		return FALSE;
	}
	return TRUE;
}





