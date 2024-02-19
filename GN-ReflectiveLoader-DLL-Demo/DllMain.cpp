#include <Windows.h>
#include <stdio.h>
#include "ReflectiveLoader-User/GN-ReflectiveLoader-User.h"

__int64 g_modulehandle = 0;


void TestFunc()
{
	AllocConsole();
	freopen("CONOUT$", "w", stdout);

	while (1)
	{
		printf("running... moduleaddress:%p\n", g_modulehandle);
		Sleep(3000);
	}
}

extern "C" __declspec(dllexport) BOOL MyDLLFunction(LPVOID data, DWORD data_length)
{
	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)TestFunc, NULL, NULL, NULL);
	char temp[1024] = { NULL };
	//sprintf_s(temp, "���õĲ�����%s", data);
	//printf("������û����ݣ�\n");
	//printf("%s\n", data);
	////MessageBoxA(NULL, temp, "MyDLLFunction", MB_OK);
	return TRUE;
}

void Test()
{
	OutputDebugStringA("[GN]:Dll Init");

}

//���Բ���ʹ��DllMain������ں�������Ȼ��ʹ��Ҳ��û�����
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		g_modulehandle = (__int64)hModule;
		////char temp[1024] = { NULL };
		////sprintf_s(temp, "this is DllMain address:%p", (__int64)hModule);
		////MessageBoxA(NULL, temp, "Hello", 0);
		//::MessageBoxA(NULL, "TestDll", "����", MB_OK);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Test, NULL, NULL, NULL);
		break;
	}
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

