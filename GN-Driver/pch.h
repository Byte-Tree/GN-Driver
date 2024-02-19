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
//关闭类重载警告
#pragma warning( disable : 4291 )
//关闭非指针作为警告
#pragma warning( disable : 6066)
#pragma warning( disable : 6273)
#pragma warning( disable : 4302)
#pragma warning( disable : 4311)
//关闭x64.h动态规范警告
#pragma warning( disable : 5040)

//劫持通讯
#define CURRENT_IO_DISPATCH _HACK_IO_DISPATCH
//kdmapper加载驱动
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


