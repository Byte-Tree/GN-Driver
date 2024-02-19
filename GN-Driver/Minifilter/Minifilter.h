#pragma once
#include "../pch.h"
#include <fltKernel.h>
#pragma comment(lib, "fltMgr.lib")


class MiniFilter
{
private:
	PFLT_FILTER      _Filter_Handle = NULL;
	FLT_REGISTRATION _Filter_Registration = { 0 };

public:
	void* operator new(size_t size, POOL_TYPE pool_type = NonPagedPool);
	void operator delete(void* pointer);
	void SetFilterHandle(PFLT_FILTER data) { _Filter_Handle = data; }
	PFLT_FILTER GetFilterHandle() { return _Filter_Handle; }
	FLT_REGISTRATION GetFilterRegistration() { return _Filter_Registration; }

public:
	MiniFilter();
	~MiniFilter();
	NTSTATUS GetFileName(const PUNICODE_STRING pImageFilePath, PUNICODE_STRING pFileName);
	BOOLEAN WriteMiniFilterReg(PUNICODE_STRING regpath);
	BOOLEAN MiniFilterInit(PDRIVER_OBJECT _Drive_Object, CONST FLT_OPERATION_REGISTRATION* OperationRegistration, CONST PFLT_FILTER_UNLOAD_CALLBACK FilterUnloadCallback);
	BOOLEAN StartMiniFilter();

};



