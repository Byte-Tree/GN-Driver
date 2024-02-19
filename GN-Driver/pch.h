#pragma once
#ifdef __cplusplus
extern "C"
{
#endif
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
#ifdef __cplusplus
}
#endif
//�ر������ؾ���
#pragma warning( disable : 4291 )
//�رշ�ָ����Ϊ����
#pragma warning( disable : 6066)
#pragma warning( disable : 6273)
#pragma warning( disable : 4302)
#pragma warning( disable : 4311)
//�ر�x64.h��̬�淶����
#pragma warning( disable : 5040)

//�ٳ�ͨѶ
#define CURRENT_IO_DISPATCH _HACK_IO_DISPATCH
//kdmapper��������
#define KDMAPPER_LOAD _ISKDMAPPER

//Driver Link Name
#define Driver_Link_Name L"\\??\\GN_NewLinker"
#define Driver_Name L"\\Device\\GN_NewDevice"

//redefinition struct
#define uint64_t unsigned long long
#define uint8_t unsigned char

#define DbgPrint_1Param(fmt,var) {CHAR sOut[256];CHAR sfmt[50];sprintf_s(sfmt,"%s%s","[GN]:",fmt);sprintf_s(sOut,(sfmt),var);DbgPrint(sOut);}
#define DbgPrint_2Param(fmt,var1,var2) {CHAR sOut[256];CHAR sfmt[50];sprintf_s(sfmt,"%s%s","[GN]:",fmt);sprintf_s(sOut,(sfmt),var1,var2);DbgPrint(sOut);}
#define DbgPrint_3Param(fmt,var1,var2,var3) {CHAR sOut[256];CHAR sfmt[50];sprintf_s(sfmt,"%s%s","[GN]:",fmt);sprintf_s(sOut,(sfmt),var1,var2,var3);DbgPrint(sOut);}


