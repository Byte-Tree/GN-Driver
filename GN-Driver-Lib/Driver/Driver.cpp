//////////////////////////////////////////////////////////////////////////////////////////////////////////
//		                                    给出lib的调用接口
//  使用时只需要将GN-ManualMap.h GN-ReflectiveLoader.h Driver.h GN-Driver-Lib.lib复制到另外的项目进行导入就行
//                          GN-Driver-Lib.lib生成在：\GN-LoaderDemo\Driver文件夹下
//  *********************************注意：目标项目需要进行以下配置：****************************************
//                              配置属性->高级->全程序优化 改成：无全程序优化
//                  配置属性->C/C++->代码生成->运行库 改成目标项目的对应版本（Release\Debug)
//////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "Driver.h"
#include "../../GN-Driver/IRPControl/MyStruct.h"

#include "../kdmapper/include/kdmapper.hpp"

#define MAX(a,b) (a>b?a:b)

#define CURRENT_IO_DISPATCH _HACK_IO_DISPATCH

#if CURRENT_IO_DISPATCH == _HACK_IO_DISPATCH
    #define DEVICE_LINK_NAME L"\\??\\Nul"					//符号链接名
#else
    #define DEVICE_LINK_NAME L"\\\\.\\GN_NewLinker"					//符号链接名
#endif
#define ServerHost "118.123.202.72:456"
#define DriverFilePath L"/RemoteFile/sys/GN-Driver.sys"
#define UDriverFilePath "/RemoteFile/sys/GN-Driver.sys"
#define UDriverFilePathTest "/RemoteFile/sys/GN-Drivertest.sys"

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)					//ntsubauth
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define OutputDebugStringA_1Param(fmt,var) {CHAR sOut[256];CHAR sfmt[50];sprintf_s(sfmt,"%s%s","",fmt);sprintf_s(sOut,(sfmt),var);OutputDebugStringA(sOut);}
#define OutputDebugStringA_2Param(fmt,var1,var2) {CHAR sOut[256];CHAR sfmt[50];sprintf_s(sfmt,"%s%s","",fmt);sprintf_s(sOut,(sfmt),var1,var2);OutputDebugStringA(sOut);}
#define OutputDebugStringA_3Param(fmt,var1,var2,var3) {CHAR sOut[256];CHAR sfmt[50];sprintf_s(sfmt,"%s%s","",fmt);sprintf_s(sOut,(sfmt),var1,var2,var3);OutputDebugStringA(sOut);}

struct PARAMX
{
    PVOID lpFileData;
    DWORD DataLength;
    PVOID LdrGetProcedureAddress;
    PVOID dwNtAllocateVirtualMemory;
    PVOID pLdrLoadDll;
    PVOID RtlInitAnsiString;
    PVOID RtlAnsiStringToUnicodeString;
    PVOID RtlFreeUnicodeString;
};

typedef NTSTATUS(WINAPI* pfnZwOpenProcess)(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ CLIENT_ID* ClientId);
typedef NTSTATUS(WINAPI* pfnQuerySystemInformation)(UINT, PVOID, DWORD, PDWORD);
typedef NTSTATUS(WINAPI* pfnLdrLoadDll)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef NTSTATUS(WINAPI* pfnLdrGetProcedureAddress)(IN PVOID DllHandle, IN PANSI_STRING ProcedureName OPTIONAL, IN ULONG ProcedureNumber OPTIONAL, OUT FARPROC* ProcedureAddress);
typedef VOID(WINAPI* pfnRtlFreeUnicodeString)(_Inout_ PUNICODE_STRING UnicodeString);
typedef VOID(WINAPI* pfnRtlInitAnsiString)(_Out_ PANSI_STRING DestinationString, _In_opt_ PCSZ SourceString);
typedef NTSTATUS(WINAPI* pfnRtlAnsiStringToUnicodeString)(_Inout_ PUNICODE_STRING DestinationString, _In_ PCANSI_STRING SourceString, _In_ BOOLEAN AllocateDestinationString);
typedef NTSTATUS(NTAPI* pfnNtAllocateVirtualMemory)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);
typedef struct _MSYSTEM_PROCESS_INFORMATION
{
    DWORD NextEntryDelta;
    DWORD ThreadCount;
    DWORD Reserved[6];
    FILETIME ftCreateTime;
    FILETIME ftUserTime;
    UNICODE_STRING ProcessName;
    DWORD BasePriority;
    DWORD ProcessID;
    DWORD InheritedFromProcessID;
    DWORD HandleCount;
    DWORD Reserved2[2];
    DWORD VmCounters;
    DWORD dCommitCharge;
    SYSTEM_THREAD_INFORMATION ThreadInfos[1];
}MSYSTEM_PROCESS_INFORMATION, * PMSYSTEM_PROCESS_INFORMATION;


Driver::Driver()
{
}

Driver::~Driver()
{
}

bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize, ULONG64 mdlptr)
{
    UNREFERENCED_PARAMETER(param1);
    UNREFERENCED_PARAMETER(param2);
    UNREFERENCED_PARAMETER(allocationPtr);
    UNREFERENCED_PARAMETER(allocationSize);
    UNREFERENCED_PARAMETER(mdlptr);
    //Log("[+] Callback example called" << std::endl);

    printf("[GN]:kdmapper 回调已被调用...\n");

    /*
    This callback occurs before call driver entry and
    can be usefull to pass more customized params in
    the last step of the mapping procedure since you
    know now the mapping address and other things
    */
    return true;
}

bool Driver::KdmapperInstallDriver()
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    ModuleStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS);

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    //printf("[GN]:HelloDriver value:%p\n", return_buffer);
    if ((int)return_buffer != 0x123)
    {
        HANDLE iqvw64e_device_handle = intel_driver::Load();
        if (iqvw64e_device_handle == INVALID_HANDLE_VALUE)
        {
            ::MessageBoxA(NULL, "iqvw64e_device_handle load error!", "警告", MB_OK);
            return false;
        }

        std::string sys_buffer;
        int sys_buffer_size = 0;
        sys_buffer_size = this->DownLoadFile(ServerHost, UDriverFilePath, &sys_buffer);
        if (sys_buffer_size <= 0)
        {
            ::MessageBoxA(NULL, "下发文件失败，请检查网络！", "警告", MB_OK);
            return false;
        }

        NTSTATUS exitCode = 0;
        bool passAllocationPtr = true;
        //if (!kdmapper::MapDriver(iqvw64e_device_handle, (BYTE*)(sys_buffer + sys_buffer_http_head), 0, 0, free, true, kdmapper::AllocationMode::AllocatePool, passAllocationPtr, callbackExample, &exitCode))
        if (!kdmapper::MapDriver(iqvw64e_device_handle, (BYTE*)(sys_buffer.data()), 0, 0, false, true, kdmapper::AllocationMode::AllocatePool, passAllocationPtr, callbackExample, &exitCode))
        {
            intel_driver::Unload(iqvw64e_device_handle);
            ::MessageBoxA(NULL, "MapDriver error!", "警告", MB_OK);
            return false;
        }

        if (!intel_driver::Unload(iqvw64e_device_handle))
            ::MessageBoxA(NULL, "未能卸载因特尔驱动", "提示", MB_OK);

        return true;
    }
    else
        return true;
}

bool Driver::User_Call_InstallSYS()
{
    int status = false;

    //GetCurrentDirectoryA(4096, this->sysfilepath);
    //strcat(this->sysfilepath, "\\GN-Driver.sys");
    //char* driver_file_buffer = (char*)malloc(1024 * 1024 * 3);
    //int driver_file_buffer_size = 0;
    //int driver_file_buffer_http_head = 0;
    //driver_file_buffer_size = this->DownLoadFile("112.18.159.36:456", "/RemoteFile/sys/GN-Driver.sys", driver_file_buffer, &driver_file_buffer_http_head, this->sysfilepath);
    //Sleep(5);
    //if (driver_file_buffer_size > 0)
    //{
    //    sprintf_s(this->sysfilename, "GN-Driver.sys");
    //    //drv.MyClearService(drv.sysfilename);
    //    status = this->InstallSYS(this->sysfilename, this->sysfilepath);
    //    if (status == 2)
    //    {
    //        this->MyDeleteFile();
    //        status = true;
    //    }
    //}
    //else
    //{
    //    MessageBoxA(NULL, "驱动加载失败（文件下发失败,请检查网络连接）！", "警告", MB_OK);
    //    return false;
    //}
    //if (driver_file_buffer)
    //    free(driver_file_buffer);


    //if (!this->GetProcessPIDW(L"GN-INITDRIVER.exe"))
    //{
    //    MessageBoxA(NULL, "出现错误，请联系开发者", "警告", MB_OK);
    //    exit(-1);
    //}

    GetCurrentDirectoryA(4096, this->sysfilepath);
    strcat(this->sysfilepath, "\\GN-Driver.sys");
    int driver_file_buffer_size = this->DownLoadFileByWinHttpEx(ServerHost, DriverFilePath, this->sysfilepath);
    //Sleep(5);
    if (driver_file_buffer_size > 0)
    {
        sprintf_s(this->sysfilename, "GN-Driver.sys");
        this->MyClearService(this->sysfilename);
        status = this->InstallSYS(this->sysfilename, this->sysfilepath);
        OutputDebugStringA_2Param("[GN]:%s-> InstallSYS():%d", __FUNCTION__, status);
        if ((status == 2) || (status != true))
        {
            //返回2：已开启服务，不需要重新加载
            this->MyDeleteFile();
            status = false;
        }
    }
    else
    {
        MessageBoxA(NULL, "驱动加载失败（文件下发失败,请检查网络连接）！", "警告", MB_OK);
        return false;
    }

    return status;
}

bool Driver::User_Call_UninstallSYS()
{
    return this->UninstallSYS(this->sysfilename);
}

void Driver::MyDeleteFile()
{
    while (strlen(this->sysfilepath) != 0)
    {
        if (remove(this->sysfilepath) == 0)
            break;
        Sleep(5);
    }
}

int Driver::InstallSYS(IN const char* lpszDriverName, IN const char* lpszDriverPath)
{
    //OutputDebugStringA_1Param("驱动名称：%s", this->sysfilename);
    //OutputDebugStringA_1Param("驱动路径：%s", this->sysfilepath);
    //printf("驱动路径：%s\n", this->sysfilepath);
    int bRet = FALSE;
    SC_HANDLE hServiceDDK = NULL;
    SC_HANDLE hServiceMgr = NULL;
    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); //SCM管理器的句柄
    if (hServiceMgr == NULL)
    {
        //OpenSCManager失败
        OutputDebugStringA_1Param("OpenSCManager() Faild %d", GetLastError());
        bRet = FALSE;
        goto BeforeLeave;
    }
    //创建驱动所对应的服务 //NT驱动程序的服务句柄
    hServiceDDK = CreateServiceA(hServiceMgr,
        lpszDriverName, //驱动程序的在注册表中的名字 
        lpszDriverName, // 注册表驱动程序的 DisplayName 值 （SCM管理器中显示的名字，或者cmd driverquery显示的名字）
        SERVICE_ALL_ACCESS, // 加载驱动程序的访问权限 （服务权限）
        SERVICE_KERNEL_DRIVER,// 表示加载的服务是驱动程序 (服务类型)
        SERVICE_DEMAND_START, // 注册表驱动程序的 Start 值 3// 2 3 1是开机自动启动 2已安装但得手动启动 3开机自动删除该驱动注册表信息
        SERVICE_ERROR_IGNORE, // 注册表驱动程序的 ErrorControl 值 
        lpszDriverPath, // 注册表驱动程序的 ImagePath 值 
        NULL,//加载组命令
        NULL,//TagId
        NULL,//依存关系
        NULL,//服务启动名
        NULL);//密码
    DWORD dwRtn;
    //判断服务是否失败
    if (hServiceDDK == NULL)
    {
        dwRtn = GetLastError();
        if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
        {
            //由于其他原因创建服务失败
            OutputDebugStringA_1Param("由于其他原因创建服务失败 %d", dwRtn);
            bRet = FALSE;
            goto BeforeLeave;
        }
        else
        {
            //服务创建失败，是由于服务已经创立过
            OutputDebugStringA("创建服务失败，是由于服务已经创立过");
        }
        // 驱动程序已经加载，只需要打开 
        hServiceDDK = OpenServiceA(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
        if (hServiceDDK == NULL)
        {
            //如果打开服务也失败，则意味错误
            dwRtn = GetLastError();
            OutputDebugStringA_1Param("打开服务失败 %d", dwRtn);
            bRet = FALSE;
            goto BeforeLeave;
        }
    }
    //开启此项服务
    bRet = StartService(hServiceDDK, NULL, NULL);
    if (!bRet)
    {
        DWORD dwRtn = GetLastError();
        if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
        {
            //printf("开启服务失败 %d\n", dwRtn);//5 拒绝访问
            char TempText[300] = { NULL };
            sprintf_s(TempText, "错误代码：%d", dwRtn);
            MessageBoxA(NULL, TempText, "警告", MB_OK);
            bRet = dwRtn;
            goto BeforeLeave;
        }
        else
        {
            if (dwRtn == ERROR_IO_PENDING)
            {
                //设备被挂住
                OutputDebugStringA_1Param("该串口操作被挂起（暂停）%d", dwRtn);
                bRet = FALSE;
                goto BeforeLeave;
            }
            else
            {
                //服务已经开启
                bRet = 2;
                OutputDebugStringA_1Param("服务已经是开启状态 %d", dwRtn);
                goto BeforeLeave;
            }
        }
    }
    //bRet = TRUE;
    //离开前关闭句柄
BeforeLeave:
    if (hServiceDDK)
        CloseServiceHandle(hServiceDDK);
    if (hServiceMgr)
        CloseServiceHandle(hServiceMgr);
    return bRet;
}

bool Driver::UninstallSYS(IN const char* lpszDriverName)
{
    BOOL bRet = FALSE;
    DWORD dwErrorCode = 0;
    SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄  
    SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄
    SERVICE_STATUS SvrSta;
    //打开SCM管理器  
    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hServiceMgr == NULL)
    {
        //打开SCM管理器失败  
        dwErrorCode = GetLastError();
        OutputDebugStringA_1Param("打开SCM管理器失败，错误代码：%d", dwErrorCode);
        goto BeforeLeave2;
    }
    //打开驱动所对应的服务  
    hServiceDDK = OpenServiceA(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
    if (hServiceDDK == NULL)
    {
        //打开驱动所对应的服务失败  
        dwErrorCode = GetLastError();
        OutputDebugStringA_1Param("打开服务失败，错误代码：%d", dwErrorCode);
        goto BeforeLeave2;
    }
    //停止驱动程序，如果停止失败，只有重新启动才能，再动态加载。    
    if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta))
    {
        dwErrorCode = GetLastError();
        OutputDebugStringA_1Param("停止服务失败，错误代码：%d", dwErrorCode);
        goto BeforeLeave2;
    }
    if (!DeleteService(hServiceDDK))
    {
        //卸载失败  
        dwErrorCode = GetLastError();
        OutputDebugStringA_1Param("删除注册表失败，错误代码：%d", dwErrorCode);
        goto BeforeLeave2;
    }
    bRet = TRUE;
BeforeLeave2:
    if (hServiceDDK)
        CloseServiceHandle(hServiceDDK);
    if (hServiceMgr)
        CloseServiceHandle(hServiceMgr);
    return bRet;
}

bool Driver::MyClearService(IN const char* lpszDriverName)
{
    BOOL bRet = FALSE;
    DWORD dwErrorCode = 0;
    SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄  
    SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄
    SERVICE_STATUS SvrSta;
    //打开SCM管理器  
    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hServiceMgr == NULL)
    {
        //////打开SCM管理器失败  
        ////dwErrorCode = GetLastError();
        //OutputDebugStringA_1Param("打开SCM管理器失败，错误代码：%d", GetLastError());
        goto BeforeLeave3;
    }
    //打开驱动所对应的服务  
    hServiceDDK = OpenServiceA(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
    if (hServiceDDK == NULL)
    {
        ////打开驱动所对应的服务失败
        //OutputDebugStringA_1Param("[GN]:打开服务失败，错误代码%d\n", GetLastError());
        bRet = TRUE;
        goto BeforeLeave3;
    }
    //停止驱动程序，如果停止失败，只有重新启动才能，再动态加载。这里调用错误
    if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta))
    {

        //OutputDebugStringA_1Param("停止服务失败，错误代码：%d，可能服务已是停止状态，此时注册表一定存在，下面准备删除注册表", GetLastError());
    }
    if (!DeleteService(hServiceDDK))
    {
        ////卸载失败
        //dwErrorCode = GetLastError();
        OutputDebugStringA_1Param("删除注册表失败，错误代码：%d，说明权限不够，建议用driver query查看是否存在注册表", GetLastError());
        goto BeforeLeave3;
    }
    bRet = TRUE;
BeforeLeave3:
    if (hServiceDDK)
        CloseServiceHandle(hServiceDDK);
    if (hServiceMgr)
        CloseServiceHandle(hServiceMgr);
    return bRet;
}

bool Driver::charTowchar(IN const char* MyChar, OUT wchar_t* MyWchar)
{
    int str_len = (int)strlen(MyChar);
    DWORD w_strlen = MultiByteToWideChar(CP_ACP, 0, MyChar, -1, NULL, 0);
    int Ret = MultiByteToWideChar(CP_ACP, 0, MyChar, str_len, MyWchar, w_strlen);
    if (Ret > 0)
    {
        MyWchar[Ret] = '\0';
        return TRUE;
    }
    return FALSE;
}

BYTE* Driver::ToBytes(DWORD64 num)
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

ULONG Driver::GetProcessPIDW(IN CONST WCHAR* ProcessName)
{
    PROCESSENTRY32 Processinformation = { 0 };
    HANDLE  Processsnapshot;
    BOOL Processhandle;
    Processsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Processsnapshot != 0)
    {
        Processinformation.dwSize = sizeof(PROCESSENTRY32);
        Processhandle = Process32First(Processsnapshot, &Processinformation);
        while (Processhandle != 0)
        {
            //printf("进程名：%S--------------------进程ID：%d\n", Processinformation.szExeFile, Processinformation.th32ProcessID);
            //OutputDebugStringA_2Param("[GN]:进程名：%S，进程ID：%d", Processinformation.szExeFile, Processinformation.th32ProcessID);
            if (_wcsicmp(ProcessName, Processinformation.szExeFile) == 0)
            {
                CloseHandle(Processsnapshot);
                return (ULONG)Processinformation.th32ProcessID;
            }
            Processhandle = Process32Next(Processsnapshot, &Processinformation);
        }
        CloseHandle(Processsnapshot);
    }
    return 0;
}

PVOID Driver::GetKernelModuleHandle(IN CONST WCHAR* module_name)
{
    PVOID return_buffer = NULL;
    ULONG dwWrite;
    KernelModuleHandleStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
    memcpy(data.kernel_module_name, module_name, (wcslen(module_name) + 1) * 2);

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH == _HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(DWORD64), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS), (LPVOID)module_name, (wcslen(module_name) + 1) * 2, &return_buffer, sizeof(DWORD64), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    return return_buffer;
}

HANDLE Driver::GetUserModuleHandle(IN CONST WCHAR* module_name)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    ModuleStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = this->m_pid;
    wcscpy(data.module_name, module_name);

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    return return_buffer;
}

HANDLE Driver::GetUserModuleHandleEx(IN ULONG pid, IN CONST WCHAR* module_name)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    ModuleStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = pid;
    wcscpy(data.module_name, module_name);

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    return return_buffer;
}

bool Driver::SetMemoryProtect(IN PVOID64 address, IN SIZE_T size, IN ULONG protect_attribute)
{
    ULONG dwWrite;
    ULONG return_buffer = NULL;
    SetMemoryProtectStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = this->m_pid; data.address = address; data.size = size; data.protect_attribute = protect_attribute;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

bool Driver::SetMemoryProtectEx(IN ULONG pid, IN PVOID64 address, IN SIZE_T size, IN ULONG protect_attribute)
{
    ULONG dwWrite;
    ULONG return_buffer = NULL;
    SetMemoryProtectStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = pid; data.address = address; data.size = size; data.protect_attribute = protect_attribute;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

bool Driver::SetExecutePage(IN ULONG64 virtualaddress, IN ULONG size)
{
    ULONG dwWrite;
    ULONG return_buffer = NULL;
    SetExecutePageStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = this->m_pid; data.virtualaddress = virtualaddress; data.size = size;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

bool Driver::SetExecutePageEx(IN ULONG pid, IN ULONG64 virtualaddress, IN ULONG size)
{
    ULONG dwWrite;
    ULONG return_buffer = NULL;
    SetExecutePageStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = pid; data.virtualaddress = virtualaddress; data.size = size;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

PVOID Driver::AllocMemory(IN ULONG size, IN ULONG protect)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    AllocMemoryStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = this->m_pid; data.allocsize = size; data.protect = protect;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    return return_buffer;
}

PVOID Driver::AllocMemoryEx(IN ULONG pid, IN ULONG size, IN ULONG protect)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    AllocMemoryStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = pid; data.allocsize = size; data.protect = protect;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    return return_buffer;
}

bool Driver::FreeMemory(IN ULONG64 free_address, IN ULONG memory_size)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    FreeMemoryStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = this->m_pid;
    data.free_address = free_address;
    data.memory_size = memory_size;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

bool Driver::FreeMemoryEx(IN ULONG pid, IN ULONG64 free_address, IN ULONG memory_size)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    FreeMemoryStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = pid;
    data.free_address = free_address;
    data.memory_size = memory_size;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

bool Driver::HideMemoryByVAD(IN ULONG64 virtual_address, IN ULONG virtual_address_size)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    VADMemoryStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = this->m_pid;
    data.memory_address = virtual_address;
    data.memory_size = virtual_address_size;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

bool Driver::HideMemoryByVADEx(IN ULONG pid, IN ULONG64 virtual_address, IN ULONG virtual_address_size)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    VADMemoryStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = pid;
    data.memory_address = virtual_address;
    data.memory_size = virtual_address_size;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

bool Driver::SetMemoryVADProtection(IN ULONG64 virtual_address, IN ULONG virtual_address_size, IN DWORD new_protection)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    VADMemoryStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = this->m_pid;
    data.memory_address = virtual_address;
    data.memory_size = virtual_address_size;
    data.protection = new_protection;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

bool Driver::SetMemoryVADProtectionEx(IN ULONG pid, IN ULONG64 virtual_address, IN ULONG virtual_address_size, IN DWORD new_protection)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    VADMemoryStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = pid;
    data.memory_address = virtual_address;
    data.memory_size = virtual_address_size;
    data.protection = new_protection;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

bool Driver::KillProcess(IN ULONG pid)
{
    ULONG dwWrite;
    KillProcessStruct data = { NULL };
    PVOID return_buffer = NULL;

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = pid;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH == _HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS), &pid, sizeof(pid), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

bool Driver::DeleteExecuteFile(IN WCHAR file_path[])
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    WCHAR temp_file_path[1024] = L"\\DosDevices\\";
    wcscat(temp_file_path, file_path);
    DeleteExecuteFileStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS);
    memcpy(data.file_path, temp_file_path, (wcslen(temp_file_path) + 1) * 2);

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH == _HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS), (PVOID)temp_file_path, (wcslen(temp_file_path) + 1) * 2, &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

DWORD Driver::GetProcessMainThread(DWORD pid)
{
    DWORD thread_id = 0;
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;

    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return(FALSE);

    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32))
    {
        OutputDebugStringA("[GN]:Thread32First() error");
        CloseHandle(hThreadSnap);
        return(FALSE);
    }

    do
    {
        if (te32.th32OwnerProcessID == pid)
        {
            thread_id = te32.th32ThreadID;
            //printf("tid:%d\n", te32.th32ThreadID);
            break;
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return thread_id;
}

//1、New新建状态：线程刚被创建，start方法之前的状态。
//2、Runnable运行状态：得到时间片运行中状态，Ready就绪，未得到时间片就绪状态。
//3、Blocked阻塞状态：如果遇到锁，线程就会变为阻塞状态等待另一个线程释放锁。
//4、Waiting等待状态：无限期等待。
//5、Time_Waiting超时等待状态：有明确结束时间的等待状态。
//6、Terminated终止状态：当线程结束完成之后就会变成此状态。
bool Driver::SuspendKernelThread(const char* kernel_module_name, const char* judgment)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    KernelThreadStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS);
    strcpy(data.kernel_module_name, kernel_module_name);
    strcpy(data.judgment, judgment);

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    return (bool)return_buffer;
}

bool Driver::SuspendKernelThreadByID(const char* kernel_module_name, HANDLE tid)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    KernelThreadStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS);
    strcpy(data.kernel_module_name, kernel_module_name);
    data.tid = tid;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    return (bool)return_buffer;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// DownLoad File:
//////////////////////////////////////////////////////////////////////////////////////////////////////////
//private
void Driver::SubString(char str[], char sub[], int index, size_t len)
{
    //判断截取位置是否合理，截取长度是否合理
    if (index < 0 || index > strlen(str) - 1 || len < 0 || len > strlen(str) - index)
        return;
    //循环的次数即截取的长度len 
    for (size_t i = 0; i < len; i++)
    {
        sub[i] = str[index];
        index++;
    }
    sub[len] = '\0';
}

__int64 Driver::RecvBuffer(SOCKET socket, std::string* p_buffer, int page_size)
{
    int recv_len = 0;
    __int64 total_recv_len = 0;

    while (1)
    {
        char* p_temp_buffer = new char[page_size];
        if (!p_temp_buffer)
            return 0;

        recv_len = recv(socket, p_temp_buffer, page_size, 0);//每次收page_size个字节大小的数据
        if (recv_len > 0)
        {
            p_buffer->append(p_temp_buffer, recv_len);

            if (p_temp_buffer)
            {
                delete[] p_temp_buffer;
                p_temp_buffer = nullptr;
            }

            total_recv_len += recv_len;//计算总长度
        }
        else
        {
            if (p_temp_buffer)
            {
                delete[] p_temp_buffer;
                p_temp_buffer = nullptr;
            }
            break;
        }
    }

    return total_recv_len;
}

//public
int Driver::DownLoadFile(IN const char* host, IN const char* get, IN std::string* p_buffer)
{
    //字符串处理
    char IP[20] = { 0 };
    char PORT[10] = { 0 };
    const char GET[5] = "GET ";
    const char MID[35] = " HTTP/1.1\r\nConnection:close\r\nHost:";
    const char END[5] = "\r\n\r\n";
    this->SubString((char*)host, IP, 0, (strstr(host, ":") - host));//去掉:xxx  这里用一个新的char[]来接收
    strcpy(PORT, strstr(host, ":") + 1);//得到端口

    /* 构造GET请求 */
    std::string get_param("GET ");
    get_param.append(get, strlen(get));
    get_param.append(" HTTP/1.1\r\nConnection:close\r\nHost:");
    get_param.append(host, strlen(host));
    get_param.append("\r\n\r\n");

    /* 初始化WSA */
    WSADATA wsdata = { NULL };
    WSAStartup(MAKEWORD(2, 2), &wsdata);

    //const char* hostname = "www.weather.com.cn";
    //struct hostent* host = gethostbyname(hostname); 

    /* 初始化一个连接服务器的结构体 */
    sockaddr_in serveraddr = { NULL };
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(atoi(PORT));
    /* 此处也可以不用这么做，不需要用gethostbyname，把网址ping一下，得出IP也可以 */
    serveraddr.sin_addr.S_un.S_addr = inet_addr(IP);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        OutputDebugStringA("create socket error");
        return -1;
    }
    if (::connect(sock, (struct sockaddr*)&serveraddr, sizeof(sockaddr_in)) == -1)
    {
        closesocket(sock);
        return -1;
    }

    /* 发送GET请求 */
    //get_param //"GET /admin/DL/1.dll HTTP/1.1\r\nConnection:close\r\nHost:112.45.36.163:81\r\n\r\n";
    if (!(send(sock, get_param.data(), (int)get_param.size(), 0) > 0))
    {
        OutputDebugStringA("send get param error");
        closesocket(sock);
        return -1;
    }

    /* 开始接收数据 */
    DWORD64 http_header = 0;
    int file_length = 0;
    std::string temp_buffer;
    auto total_recv_len = this->RecvBuffer(sock, &temp_buffer);

    //解析数据包
    http_header = strstr(temp_buffer.data(), "\r\n\r\n") - temp_buffer.data() + 4;//\r\n\r\n 占了4个字节
    file_length = atoi(strstr(temp_buffer.data(), "Content-Length") + strlen("Content-Length") + 2);//有一个:
    if (file_length == 0)
    {
        closesocket(sock);
        return -1;
    }

    p_buffer->clear();
    p_buffer->append(temp_buffer.substr(http_header, temp_buffer.size() - http_header));

    closesocket(sock);
    return file_length;
}

int Driver::DownLoadFile(IN const char* host, IN const char* get, IN char* bufRecv, IN int* phttpHead, IN const char* file_name)//错误返回-1 成功返回下载到的文件长度
{
    __try
    {
        //OutputDebugStringA("[GN]:0");
        //字符串处理
        char IP[20] = { 0 };
        char PORT[10] = { 0 };
        const char GET[] = "GET ";
        const char MID[] = " HTTP/1.1\r\nConnection:close\r\nHost:";
        const char END[] = "\r\n\r\n";
        //OutputDebugStringA("[GN]:1");
        SubString((char*)host, IP, 0, strstr(host, ":") - host);//去掉:xxx
        //OutputDebugStringA("[GN]:2");
        strcpy(PORT, strstr(host, ":") + 1);//得到端口
        //printf("port:%s\n", PORT);
        //OutputDebugStringA("[GN]:3");
        char* getParm = (char*)malloc(strlen(GET) + strlen(get) + strlen(MID) + strlen(host) + strlen(END));
        //OutputDebugStringA("[GN]:4");
        sprintf(getParm, "%s%s%s%s%s", GET, get, MID, host, END);
        //OutputDebugStringA("[GN]:5");
        //printf("%p\n", getParm);
        /* 初始化 */
        WSADATA wsdata = { NULL };
        WSAStartup(MAKEWORD(2, 2), &wsdata);
        //OutputDebugStringA("[GN]:6");

        //const char* hostname = "www.weather.com.cn";
        //struct hostent* host = gethostbyname(hostname); 

        /* 初始化一个连接服务器的结构体 */
        sockaddr_in serveraddr = { NULL };
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_port = htons(atoi(PORT));
        //OutputDebugStringA("[GN]:7");

        /* 此处也可以不用这么做，不需要用gethostbyname，把网址ping一下，得出IP也是可以的 */
        serveraddr.sin_addr.S_un.S_addr = inet_addr(IP);//112.45.36.163
        //OutputDebugStringA("[GN]:8");

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1)
        {
            printf("socket error\n");
            return -1;
        }
        //printf("socket succeed\n");

        if (::connect(sock, (struct sockaddr*)&serveraddr, sizeof(sockaddr_in)) == -1)
        {
            //g_dwErr = GetLastError();
            //printf("connect error %d\n", g_dwErr);
            closesocket(sock);
            return -1;
        }
        //printf("connect succeed\n");

        /* 构造GET请求 */
        const char* bufSend = getParm;//"GET /admin/DL/1.dll HTTP/1.1\r\nConnection:close\r\nHost:112.45.36.163:81\r\n\r\n";

        /* 发送GET请求 */
        if (send(sock, bufSend, strlen(bufSend), 0) > 0)
        {
            //printf("send succeed\n");
        }
        else
        {
            //g_dwErr = GetLastError();
            //printf("send error %d\n", g_dwErr);
            closesocket(sock);
            return -1;
        }

        /* 开始接收数据 */
        int recvLength = 0;
        int totalLength = 0;
        int httpHead = 0;
        int fileLength = 0;
        char* p = bufRecv;
        while (1)
        {
            recvLength = recv(sock, p, 40960, 0);//每次40k
            //Sleep(1);
            if (recvLength > 0)
            {
                p += recvLength;//指针后移
                totalLength += recvLength;//计算总长度
            }
            else
            {
                break;
            }
        }
        //printf("共收到%d个字节\n", totalLength);

        //解析数据包
        httpHead = strstr(bufRecv, "\r\n\r\n") - bufRecv + 4;//\r\n\r\n 占了4个字节
        fileLength = atoi(strstr(bufRecv, "Content-Length") + strlen("Content-Length") + 2);//有一个:
        if (fileLength == 0)
        {
            printf("报文错误\n");
            closesocket(sock);
            return -1;
        }
        else
        {
            //printf("响应头长度:%d\n", httpHead);
            //printf("文件长度:%d\n", fileLength);
        }

        //if (*(PWORD)(bufRecv + httpHead) != (WORD)0x5A4D)
        //    printf("注意！这不是一个可执行文件\n");
        FILE* fp = nullptr;
        char name[1024] = { NULL };
        strcat(name, file_name);
        //printf("filename:%s\n", name);
        fp = fopen(file_name, "wb");//w:以文本方式写入，wb以二进制方式写入
        fwrite(bufRecv + httpHead, fileLength, 1, fp);//写入到文件
        fclose(fp);

        *phttpHead = httpHead;//OK这样就好了
        closesocket(sock);
        return fileLength;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        OutputDebugStringA("[GN]:DownLoad Error, return 00");
        return 0;
    }
}

int Driver::DownLoadFileByWinHttp(IN const char* host, IN const wchar_t* file_path, OUT char* buffer)
{
    DWORD status = 0;
    char temp_host_name[20] = { NULL };
    wchar_t host_name[20 * 2] = { NULL };
    DWORD host_port = 0;

    //解析ip地址
    this->SubString((char*)host, temp_host_name, 0, strstr(host, ":") - host);
    this->charTowchar(temp_host_name, host_name);
    //OutputDebugStringA_1Param("[GN]:ip：%S", host_name);

    //解析端口号
    host_port = atoi(strstr(host, ":") + 1);
    if (host_port == 0) host_port = 80;
    //OutputDebugStringA_1Param("[GN]:port：%d", host_port);

    //初始化WinHttp
    HINTERNET h_session = WinHttpOpen(L"My Agent Name", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h_session)
    {
        OutputDebugStringA_1Param("[GN]:%s-> WinHttpOpen() error", __FUNCTION__);
        return 0;
    }

    //指定请求的http服务器
    HINTERNET h_connect = WinHttpConnect(h_session, host_name, host_port, 0);
    if (!h_connect)
    {
        OutputDebugStringA_1Param("[GN]:%s-> WinHttpConnect() error", __FUNCTION__);
        return 0;
    }

    //创建http请求句柄
    HINTERNET h_request = WinHttpOpenRequest(h_connect, L"GET", file_path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!h_request)
    {
        OutputDebugStringA_1Param("[GN]:%s-> WinHttpOpenRequest() error", __FUNCTION__);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        return 0;
    }

    //将指定请求发送到服务器
    bool h_result = WinHttpSendRequest(h_request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!h_result)
    {
        OutputDebugStringA_1Param("[GN]:%s-> WinHttpSendRequest() error", __FUNCTION__);
        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        return 0;
    }

    //等待服务器响应WinHttpSendRequest（）发起的http请求
    h_result = WinHttpReceiveResponse(h_request, NULL);
    if (!h_result)
    {
        OutputDebugStringA_1Param("[GN]:%s-> WinHttpReceiveResponse() error", __FUNCTION__);
        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        return 0;
    }

    //读取服务器响应数据的大小
    DWORD requestdata_size = 0;
    WinHttpQueryDataAvailable(h_request, &requestdata_size);
    status = requestdata_size;

    ////保存服务器响应数据的缓冲区
    //char* m_buffer = new char[requestdata_size + 1];
    //ZeroMemory(m_buffer, requestdata_size + 1);

    //读取服务器响应回来的数据
    DWORD readed = 0;
    while (WinHttpReadData(h_request, (char*)buffer, requestdata_size, &readed))
    {
        if (readed == 0)
            break;
    }
    //memcpy(buffer, m_buffer, requestdata_size + 1);

    //if (m_buffer) delete[] m_buffer;
    WinHttpCloseHandle(h_request);
    WinHttpCloseHandle(h_connect);
    WinHttpCloseHandle(h_session);
    return status;
}

int Driver::DownLoadFileByWinHttpEx(IN const char* host, IN const wchar_t* file_path, IN const char* save_path)
{
    DWORD status = 0;
    char temp_host_name[20] = { NULL };
    wchar_t host_name[20 * 2] = { NULL };
    DWORD host_port = 0;

    //解析ip地址
    this->SubString((char*)host, temp_host_name, 0, strstr(host, ":") - host);
    this->charTowchar(temp_host_name, host_name);
    //OutputDebugStringA_1Param("[GN]:ip：%S", host_name);

    //解析端口号
    host_port = atoi(strstr(host, ":") + 1);
    if (host_port == 0) host_port = 80;
    //OutputDebugStringA_1Param("[GN]:port：%d", host_port);

    //初始化WinHttp
    HINTERNET h_session = WinHttpOpen(L"My Agent Name", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h_session)
    {
        OutputDebugStringA_1Param("[GN]:%s-> WinHttpOpen() error", __FUNCTION__);
        return 0;
    }
    
    //指定请求的http服务器
    HINTERNET h_connect = WinHttpConnect(h_session, host_name, host_port, 0);
    if (!h_connect)
    {
        OutputDebugStringA_1Param("[GN]:%s-> WinHttpConnect() error", __FUNCTION__);
        return 0;
    }
    
    //创建http请求句柄
    HINTERNET h_request = WinHttpOpenRequest(h_connect, L"GET", file_path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if(!h_request)
    {
        OutputDebugStringA_1Param("[GN]:%s-> WinHttpOpenRequest() error", __FUNCTION__);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        return 0;
    }
    
    //将指定请求发送到服务器
    bool h_result = WinHttpSendRequest(h_request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!h_result)
    {
        OutputDebugStringA_1Param("[GN]:%s-> WinHttpSendRequest() error", __FUNCTION__);
        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        return 0;
    }
    
    //等待服务器响应WinHttpSendRequest（）发起的http请求
    h_result = WinHttpReceiveResponse(h_request, NULL);
    if(!h_result)
    {
        OutputDebugStringA_1Param("[GN]:%s-> WinHttpReceiveResponse() error", __FUNCTION__);
        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        return 0;
    }
    
    //读取服务器响应数据的大小
    DWORD requestdata_size = 0;
    WinHttpQueryDataAvailable(h_request, &requestdata_size);
    status = requestdata_size;
    
    //保存服务器响应数据的缓冲区
    char* m_buffer = new char[requestdata_size + 1];
    ZeroMemory(m_buffer, requestdata_size + 1);
    
    //读取服务器响应回来的数据
    std::ofstream outfile(save_path, std::ios::binary);
    DWORD readed = 0;
    while (WinHttpReadData(h_request, m_buffer, requestdata_size, &readed))
    {
        outfile.write(reinterpret_cast<const char*>(m_buffer), readed);
        if (readed == 0)
            break;
    }
    outfile.close();
    
    if (m_buffer) delete[] m_buffer;
    WinHttpCloseHandle(h_request);
    WinHttpCloseHandle(h_connect);
    WinHttpCloseHandle(h_session);
    return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// Read/Write Process Memory By MDL:
//////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL Driver::ReadFromKernelByMDL(IN ULONG pid, IN PVOID target_address, OUT PVOID read_buffer, IN SIZE_T read_data_size)
{
    __try
    {
        ULONG dwWrite;
        MemoryStruct data = { NULL };

        data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS);
        data.pid = pid; data.target_address = (ULONG64)target_address; data.read_and_write_data_size = read_data_size;
        HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
        BOOL hresult_dc = DeviceIoControl(hDevice, 0, &data, sizeof(data), read_buffer, read_data_size, &dwWrite, NULL);
#else
        BOOL hresult_dc = DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), read_buffer, read_data_size, &dwWrite, NULL);
#endif
        CloseHandle(hDevice);

        if (hresult_dc)
            return true;
        else
            return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        OutputDebugStringA_2Param("[GN]:%s() error code:%d", __FUNCTION__, GetLastError());
        return false;
    }
}

BOOL Driver::WriteToKernelByMDL(IN ULONG pid, IN PVOID target_address, IN PVOID write_data, IN SIZE_T write_data_size)
{
    __try
    {
        ULONG dwWrite;
        PVOID return_buffer = NULL;
        PMemoryStruct data = (PMemoryStruct)VirtualAlloc(0, write_data_size + sizeof(MemoryStruct), MEM_COMMIT, PAGE_READWRITE);

        data->control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS);
        data->pid = pid;
        data->target_address = (ULONG64)target_address;
        data->read_and_write_data_size = write_data_size;
        memcpy_s(&data->write_data, write_data_size, write_data, write_data_size);

        HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
        DeviceIoControl(hDevice, 0, data, write_data_size + sizeof(MemoryStruct), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
        DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS), data, write_data_size + sizeof(MemoryStruct), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
        CloseHandle(hDevice);

        VirtualFree(data, write_data_size + sizeof(MemoryStruct), MEM_FREE);
        if (NT_SUCCESS(return_buffer))
            return true;
        else
            return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        OutputDebugStringA_2Param("[GN]:%s() error code:%d", __FUNCTION__, GetLastError());
        return false;
    }
}

DWORD Driver::ReadIntByMDL(IN PVOID target_address)
{
    DWORD buffer = NULL;
    if (this->ReadFromKernelByMDL(this->m_pid, target_address, &buffer, sizeof(DWORD)))
        return buffer;
    else
        return 0;
}

DWORD Driver::ReadIntByMDLEx(IN ULONG pid, IN PVOID target_address)
{
    DWORD buffer = NULL;
    if (this->ReadFromKernelByMDL(pid, target_address, &buffer, sizeof(DWORD)))
        return buffer;
    else
        return 0;
}

DWORD64 Driver::ReadLongByMDL(IN PVOID target_address)
{
    DWORD64 buffer = NULL;
    if (this->ReadFromKernelByMDL(this->m_pid, target_address, &buffer, sizeof(DWORD64)))
        return buffer;
    else
        return 0;
}

DWORD64 Driver::ReadLongByMDLEx(IN ULONG pid, IN PVOID target_address)
{
    DWORD64 buffer = NULL;
    if (this->ReadFromKernelByMDL(pid, target_address, &buffer, sizeof(DWORD64)))
        return buffer;
    else
        return 0;
}

float Driver::ReadFloatByMDL(IN PVOID target_address)
{
    float buffer = NULL;
    if (this->ReadFromKernelByMDL(this->m_pid, target_address, &buffer, sizeof(float)))
        return buffer;
    else
        return 0;
}

float Driver::ReadFloatByMDLEx(IN ULONG pid, IN PVOID target_address)
{
    float buffer = NULL;
    if (this->ReadFromKernelByMDL(pid, target_address, &buffer, sizeof(float)))
        return buffer;
    else
        return 0;
}

BOOL Driver::ReadBytesByMDL(IN PVOID target_address, IN SIZE_T read_size, OUT BYTE* read_buffer)
{
    return this->ReadFromKernelByMDL(this->m_pid, target_address, read_buffer, read_size);
}

BOOL Driver::ReadBytesByMDLEx(IN ULONG pid, IN PVOID target_address, IN SIZE_T read_size, OUT BYTE* read_buffer)
{
    return this->ReadFromKernelByMDL(pid, target_address, read_buffer, read_size);
}

BOOL Driver::WriteIntByMDL(IN PVOID target_address, IN int write_data)
{
    if (this->WriteToKernelByMDL(this->m_pid, target_address, &write_data, sizeof(DWORD)))
        return true;
    else
        return false;
}

BOOL Driver::WriteIntByMDLEx(IN ULONG pid, IN PVOID target_address, IN int write_data)
{
    if (this->WriteToKernelByMDL(pid, target_address, &write_data, sizeof(DWORD)))
        return true;
    else
        return false;
}

BOOL Driver::WriteLongByMDL(IN PVOID target_address, IN DWORD64 write_data)
{
    if (this->WriteToKernelByMDL(this->m_pid, target_address, &write_data, sizeof(DWORD64)))
        return true;
    else
        return false;
}

BOOL Driver::WriteLongByMDLEx(IN ULONG pid, IN PVOID target_address, IN DWORD64 write_data)
{
    if (this->WriteToKernelByMDL(pid, target_address, &write_data, sizeof(DWORD64)))
        return true;
    else
        return false;
}

BOOL Driver::WriteFloatByMDL(IN PVOID target_address, IN float write_data)
{
    if (this->WriteToKernelByMDL(this->m_pid, target_address, &write_data, sizeof(float)))
        return true;
    else
        return false;
}

BOOL Driver::WriteFloatByMDLEx(IN ULONG pid, IN PVOID target_address, IN float write_data)
{
    if (this->WriteToKernelByMDL(pid, target_address, &write_data, sizeof(float)))
        return true;
    else
        return false;
}

BOOL Driver::WriteBytesByMDL(IN PVOID target_address, IN PVOID write_data, IN SIZE_T write_size)
{
    if (this->WriteToKernelByMDL(this->m_pid, target_address, write_data, write_size))
        return true;    else     return false;
}

BOOL Driver::WriteBytesByMDLEx(IN ULONG pid, IN PVOID target_address, IN PVOID write_data, IN SIZE_T write_size)
{
    if (this->WriteToKernelByMDL(pid, target_address, write_data, write_size))
        return true;    else     return false;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// Read/Write Process Memory By CR3:
//////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL Driver::ReadFromKernelByCR3NoAttach(IN ULONG pid, IN PVOID target_address, OUT PVOID read_buffer)
{
    __try
    {
        ULONG dwWrite;
        MemoryStruct data = { NULL };

        data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS);
        data.pid = pid; data.target_address = (ULONG64)target_address;

        HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
        BOOL hresult_dc = DeviceIoControl(hDevice, 0, &data, sizeof(data), read_buffer, 64, &dwWrite, NULL);
#else
        BOOL hresult_dc = DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), read_buffer, 64, &dwWrite, NULL);
#endif
        CloseHandle(hDevice);
        if (hresult_dc)
            return true;
        else
            return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        OutputDebugStringA_2Param("[GN]:%s() error code:%d", __FUNCTION__, GetLastError());
        return false;
    }
}

BOOL Driver::WriteToKernelByCR3NoAttach(IN ULONG pid, IN PVOID target_address, IN PVOID write_data, IN SIZE_T write_data_size)
{
    __try
    {
        ULONG dwWrite;
        PVOID return_buffer = NULL;
        PMemoryStruct data = (PMemoryStruct)VirtualAlloc(0, write_data_size + sizeof(MemoryStruct), MEM_COMMIT, PAGE_READWRITE);

        data->control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS);
        data->pid = pid;
        data->target_address = (ULONG64)target_address;
        data->read_and_write_data_size = write_data_size;
        memcpy_s(&data->write_data, write_data_size, write_data, write_data_size);

        HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
        DeviceIoControl(hDevice, 0, data, write_data_size + sizeof(MemoryStruct), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
        DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS), data, write_data_size + sizeof(MemoryStruct), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
        CloseHandle(hDevice);

        VirtualFree(data, write_data_size + sizeof(MemoryStruct), MEM_FREE);
        if (NT_SUCCESS(return_buffer))
            return true;
        else
            return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        OutputDebugStringA_2Param("[GN]:%s() error code:%d", __FUNCTION__, GetLastError());
        return false;
    }
}

//Read
DWORD Driver::ReadIntByCR3NoAttach(IN PVOID target_address)
{
    DWORD buffer = 0;
    if (ReadFromKernelByCR3NoAttach(this->m_pid, target_address, &buffer))
        return buffer;
    else
        return 0;
}

DWORD Driver::ReadIntByCR3NoAttachEx(IN ULONG pid, IN PVOID target_address)
{
    DWORD buffer = 0;
    if (ReadFromKernelByCR3NoAttach(pid, target_address, &buffer))
        return buffer;
    else
        return 0;
}

DWORD64 Driver::ReadLongByCR3NoAttach(IN PVOID target_address)
{
    DWORD64 buffer = 0;
    if (ReadFromKernelByCR3NoAttach(this->m_pid, target_address, &buffer))
        return buffer;
    else
        return 0;
}

DWORD64 Driver::ReadLongByCR3NoAttachEx(IN ULONG pid, IN PVOID target_address)
{
    DWORD64 buffer = 0;
    if (ReadFromKernelByCR3NoAttach(pid, target_address, &buffer))
        return buffer;
    else
        return 0;
}

float Driver::ReadFloatByCR3NoAttach(IN PVOID target_address)
{
    float buffer = 0;
    if (ReadFromKernelByCR3NoAttach(this->m_pid, target_address, &buffer))
        return buffer;
    else
        return 0;
}

float Driver::ReadFloatByCR3NoAttachEx(IN ULONG pid, IN PVOID target_address)
{
    float buffer = 0;
    if (ReadFromKernelByCR3NoAttach(pid, target_address, &buffer))
        return buffer;
    else
        return 0;
}

//Write
BOOL Driver::WriteIntByCR3NoAttach(IN PVOID target_address, IN int write_data)
{
    if (this->WriteToKernelByCR3NoAttach(this->m_pid, target_address, &write_data, sizeof(int)))
        return true;
    else
        return false;
}

BOOL Driver::WriteIntByCR3NoAttachEx(IN ULONG pid, IN PVOID target_address, IN int write_data)
{
    if (this->WriteToKernelByCR3NoAttach(pid, target_address, &write_data, sizeof(int)))
        return true;
    else
        return false;
}

BOOL Driver::WriteLongByCR3NoAttach(IN PVOID target_address, IN DWORD64 write_data)
{
    if (this->WriteToKernelByCR3NoAttach(this->m_pid, target_address, &write_data, sizeof(DWORD64)))
        return true;    else     return false;
}

BOOL Driver::WriteLongByCR3NoAttachEx(IN ULONG pid, IN PVOID target_address, IN DWORD64 write_data)
{
    if (this->WriteToKernelByCR3NoAttach(pid, target_address, &write_data, sizeof(DWORD64)))
        return true;    else     return false;
}

BOOL Driver::WriteFloatByCR3NoAttach(IN PVOID target_address, IN float write_data)
{
    if (this->WriteToKernelByCR3NoAttach(this->m_pid, target_address, &write_data, sizeof(float)))
        return true;    else     return false;
}

BOOL Driver::WriteFloatByCR3NoAttachEx(IN ULONG pid, IN PVOID target_address, IN float write_data)
{
    if (this->WriteToKernelByCR3NoAttach(pid, target_address, &write_data, sizeof(float)))
        return true;    else     return false;
}

BOOL Driver::WriteBytesByCR3NoAttach(IN PVOID target_address, IN PVOID write_data, IN SIZE_T write_size)
{
    if (this->WriteToKernelByCR3NoAttach(this->m_pid, target_address, write_data, write_size))
        return true;    else     return false;
}

BOOL Driver::WriteBytesByCR3NoAttachEx(IN ULONG pid, IN PVOID target_address, IN PVOID write_data, IN SIZE_T write_size)
{
    if (this->WriteToKernelByCR3NoAttach(pid, target_address, write_data, write_size))
        return true;    else     return false;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// DLL Injecter:
//////////////////////////////////////////////////////////////////////////////////////////////////////////
//private:
bool Driver::WriteSections(LPBYTE dll_buffer, LPBYTE target_base, IMAGE_SECTION_HEADER* section_header, IMAGE_FILE_HEADER* old_file_header)
{
    for (UINT i = 0; i != old_file_header->NumberOfSections; ++i, ++section_header)
    {
        if (section_header->SizeOfRawData)
        {
            if (!this->WriteBytesByMDL((PVOID)(target_base + section_header->VirtualAddress), (PVOID)(dll_buffer + section_header->PointerToRawData), section_header->SizeOfRawData))
                return false;
        }
    }
    return true;
}

bool Driver::WriteSectionsEx(ULONG pid, LPBYTE dll_buffer, LPBYTE target_base, IMAGE_SECTION_HEADER* section_header, IMAGE_FILE_HEADER* old_file_header)
{
    for (UINT i = 0; i != old_file_header->NumberOfSections; ++i, ++section_header)
    {
        if (section_header->SizeOfRawData)
        {
            if (!this->WriteBytesByMDLEx(pid, (PVOID)(target_base + section_header->VirtualAddress), (PVOID)(dll_buffer + section_header->PointerToRawData), section_header->SizeOfRawData))
                return false;
        }
    }
    return true;
}

void __stdcall Driver::Shellcode(MANUAL_MAPPING_DATA* lpData)
{
    // 检查参数
    if (!lpData)
    {
        lpData->hMod = (HINSTANCE)0x404040;
        return;
    }
    BYTE* pBase = lpData->pBase;
    auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

    auto _LoadLibraryA = lpData->pLoadLibraryA;
    auto _GetProcAddress = lpData->pGetProcAddress;
#ifdef _WIN64
    auto _RtlAddFunctionTable = lpData->pRtlAddFunctionTable;
#endif
    auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

    // 处理重定位表
    BYTE* LocationDelta = pBase - pOpt->ImageBase;
    if (LocationDelta)
    {
        if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        {
            auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
            while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock)
            {
                UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
                for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
                {
                    if (RELOC_FLAG(*pRelativeInfo))
                    {
                        UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                        *pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
                    }
                }
                pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
            }
        }
    }
    // 处理导入表
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDescr->Name) {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);
            ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);
            if (!pThunkRef)
                pThunkRef = pFuncRef;
            for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
            {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
                else
                {
                    auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDescr;
        }
    }
    // 处理tls
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback)
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }
    // 处理异常
    bool ExceptionSupportFailed = false;
#ifdef _WIN64
    if (lpData->SEHSupport)
    {
        auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excep.Size)
        {
            if (!_RtlAddFunctionTable
            (
                reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
                excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase))
            {
                ExceptionSupportFailed = true;
            }
        }
    }
#endif
    // 调用dllmain
    _DllMain(pBase, lpData->fdwReasonParam, lpData->reservedParam);
    if (ExceptionSupportFailed)
        lpData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
    else
        lpData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}

HINSTANCE Driver::GetReturnModule(LPBYTE lpParamBuff)
{
    HINSTANCE hModule = NULL;
    while (!hModule)
    {
        // 读取返回参数，由于GetExitCodeThread只能返回DWORD参数
        // 如果是64位返回QWORD类型会丢失内容
        // 所以这里使用之前的结构体来获取返回值
        MANUAL_MAPPING_DATA returnData{ 0 };
        BYTE* data = new BYTE[sizeof(MANUAL_MAPPING_DATA)];
        this->ReadBytesByMDL((PVOID)lpParamBuff, sizeof(MANUAL_MAPPING_DATA), data);
        memcpy(&returnData, data, sizeof(MANUAL_MAPPING_DATA));
        hModule = returnData.hMod;
        delete data;
        Sleep(0.5);
    }
    return hModule;
}

DWORD Driver::mManualMapInject(__int64 hook_point, int hook_byte_size, LPBYTE dll_buffer, DWORD dll_file_size, bool bClearHeader, bool bClearNonNeededSections, bool bAdjustProtections, bool bSEHExceptionSupport, DWORD fdwReason, LPVOID lpReserved)
{
    DWORD status = true;
    LPBYTE target_base = nullptr;
    LPBYTE param_buffer = nullptr;
    LPVOID shellcode = nullptr;
    LPBYTE empty_buffer = nullptr;

    //判断是否为正常的PE头 不是整成PE头返回0
    if (reinterpret_cast<IMAGE_DOS_HEADER*>(dll_buffer)->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    //获取PE结构
    IMAGE_NT_HEADERS* p_old_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(dll_buffer + reinterpret_cast<IMAGE_DOS_HEADER*>(dll_buffer)->e_lfanew);
    IMAGE_OPTIONAL_HEADER* p_old_optional_header = &p_old_nt_header->OptionalHeader;
    IMAGE_FILE_HEADER* p_old_file_header = &p_old_nt_header->FileHeader;

    //筛选环境 不是当前Machine返回2
    if (p_old_file_header->Machine != CURRENT_ARCH)
        return 2;

    //为反射注入做准备
    do
    {
        //只申请可读可写内存，后续修改可执行属性
        target_base = reinterpret_cast<BYTE*>(this->AllocMemory(p_old_optional_header->SizeOfImage, PAGE_READWRITE));//PAGE_READWRITE
        //申请内存失败返回 3
        if (!target_base) return 3;
        //向申请的地址前0x1000个字节写入dll头部PE数据，写入失败返回 4
        if (!this->WriteBytesByMDL(target_base, dll_buffer, 0x1000))
        {
            OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() failed", __FUNCTION__);
            status = 4;
            break;
        }
        //写入数据后修改内核层可执行属性，失败返回 5
        if (!this->SetExecutePage((ULONG64)target_base, p_old_optional_header->SizeOfImage))
        {
            OutputDebugStringA_1Param("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
            status = 5;
            break;
        }

        //写入节表，失败返回 6
        IMAGE_SECTION_HEADER* p_section_header = IMAGE_FIRST_SECTION(p_old_nt_header);
        if (!this->WriteSections(dll_buffer, target_base, p_section_header, p_old_file_header))
        {
            OutputDebugStringA_1Param("[GN]:%s-> WriteSections() failed", __FUNCTION__);
            status = 6;
            break;
        }
        OutputDebugStringA_1Param("[GN]:MyModulehandle：%p", target_base);

        //组装参数
        MANUAL_MAPPING_DATA data{ 0 };
        data.pLoadLibraryA = ::LoadLibraryA;
        data.pGetProcAddress = ::GetProcAddress;
#ifdef _WIN64
        data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else
        bSEHExceptionSupport = false;
#endif
        data.pBase = target_base;
        data.fdwReasonParam = fdwReason;
        data.reservedParam = lpReserved;
        data.SEHSupport = bSEHExceptionSupport;

        //将准备的参数映射到目标进程，只申请可读可写内存，为写入数据后做可执行属性做铺垫，申请失败返回 7
        param_buffer = reinterpret_cast<BYTE*>(this->AllocMemory(sizeof(MANUAL_MAPPING_DATA), PAGE_READWRITE));//PAGE_READWRITE
        if (!param_buffer)
        {
            OutputDebugStringA_1Param("[GN]:%s-> param_buffer is null", __FUNCTION__);
            status = 7;
            break;
        }
        //写入参数，写入参数失败返回 8
        if (!this->WriteBytesByMDL((PVOID)param_buffer, &data, sizeof(MANUAL_MAPPING_DATA)))//崩溃可疑
        {
            OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() failed", __FUNCTION__);
            status = 8;
            break;
        }
        //写入数据后修改内核层可执行属性，设置失败返回 9
        if (!this->SetExecutePage((ULONG64)param_buffer, sizeof(MANUAL_MAPPING_DATA)))
        {
            OutputDebugStringA_1Param("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
            status = 9;
            break;
        }
        //OutputDebugStringA_1Param("[GN]:申请的param_buffer地址：%p", param_buffer);

        //向目标进程申请写入shellcode的地址，只申请可读可写内存，后续修改可执行属性，申请失败返回 10
        shellcode = this->AllocMemory(0x1000, PAGE_READWRITE);
        if (!shellcode)
        {
            OutputDebugStringA_1Param("[GN]:%s-> shellcode is null", __FUNCTION__);
            status = 10;
            break;
        }
        if (!this->WriteBytesByMDL((PVOID)shellcode, Shellcode, 0x1000))
        {
            OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() failed", __FUNCTION__);
            break;
        }
        //写入数据后修改内核层可执行属性
        if (!this->SetExecutePage((ULONG64)shellcode, 0x1000))
        {
            OutputDebugStringA_1Param("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
            break;
        }
        //OutputDebugStringA_1Param("[GN]:申请的shellcode地址：%p", shellcode);

        //申请构造hook注入的地址，只申请可读可写内存，后续修改可执行属性
        DWORD64 hookcode_address = (DWORD64)this->AllocMemory(4096, PAGE_READWRITE);
        BYTE old_code[50] = { NULL };
        BYTE target_hook_code[1024] = { NULL };
        BYTE reduction_code[50] = { NULL };
        BYTE hook_code_one[63] = {
            0x54,0x50,0x53,0x51,0x52,0x55,0x56,0x57,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x9C,0x48,0x83,0xEC,0x40,0xE8,
            /*+0x1E Call shellcode偏移*/0x00,0x00,0x00,0x00,
            0x48,0x83,0xC4,0x40,0x9D,0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,0x5F,0x5E,0x5D,0x5A,0x59,0x5B,0x58,0x5C };
        BYTE hook_code_two[110] = {
            0x83,0x3D,0x57,0x00,0x00,0x00,0x00,0x75,0x4B,0xC7,0x05,0x4B,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x48,0x83,0xEC,0x38,0x31,0xC0,0x48,0xBA,
            /*+0x1B 参数地址*/0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x4C,0x8D,0x0A,0x36,0x48,0x89,0x44,0x24,0x28,0x48,0xBA,
            /*+0x2E 线程地址*/0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x4C,0x8D,0x02,0x31,0xD2,0x36,0x89,0x44,0x24,0x20,0x31,0xC9,0x48,0xB8,
            /*+0x44 CreateThread地址*/0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0xFF,0xD0,0x31,0xC0,0x48,0x83,0xC4,0x38,0xC3,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
        this->ReadBytesByMDL((PVOID)hook_point, hook_byte_size, old_code);                                                                          //保存hook点原始字节
        memcpy(reduction_code, old_code, hook_byte_size);                                                                                           //用来填充HOOK还原的代码
        memcpy((reduction_code + hook_byte_size), new BYTE[6]{ 0xFF,0x25,0x00,0x00,0x00,0x00 }, 6);                                                 //头部原始字节...+ 构造FF 25 00 00 00 00 跳回字节
        memcpy((reduction_code + hook_byte_size + 6), this->ToBytes(hook_point + hook_byte_size), 8);                                               //头部原始字节...+ 填充FF 25 00 00 00 00 跳回地址
        memcpy(target_hook_code, hook_code_one, sizeof(hook_code_one));                                                                             //向目标hook字节填充头部构造
        memcpy((target_hook_code + sizeof(hook_code_one)), reduction_code, (hook_byte_size + 14));                                                  //向目标hook字节中填充还原字节集
        memcpy((hook_code_two + 0x1B), this->ToBytes((DWORD64)param_buffer), 8);                                                                    //向hook_code_two中填充DLL启动参数
        memcpy((hook_code_two + 0x2E), this->ToBytes((DWORD64)shellcode), 8);                                                                       //向hook_code_two中填充DLL启动线程参数
        DWORD64 createthread_address = (DWORD64)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "CreateThread");
        memcpy((hook_code_two + 0x44), this->ToBytes(createthread_address), 8);                                                                     //向hook_code_two中填充CreateThread地址
        int call_offset = ((__int64)target_hook_code + sizeof(hook_code_one) + hook_byte_size + 14) - ((DWORD64)target_hook_code + 0x1D + 5);       //计算Call偏移
        memcpy((target_hook_code + 0x1E), &call_offset, 4);                                                                                         //向目标hook字节中填充Call偏移
        memcpy((target_hook_code + sizeof(hook_code_one) + (hook_byte_size + 14)), hook_code_two, sizeof(hook_code_two));                           //向目标hook字节中填充 call shellcode函数
        this->WriteBytesByMDL((PVOID)hookcode_address, (PVOID)target_hook_code, sizeof(target_hook_code));                                          //向目标进程中申请的地址写入构造完成的hook字节
        //写入数据后修改内核层可执行属性
        if (!this->SetExecutePage((ULONG64)hookcode_address, 4096))
        {
            OutputDebugStringA_1Param("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
            break;
        }
        BYTE init_hook_code[] = { 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };                                          //构造向hook_pointer下hook的字节
        memcpy((__int64*)&init_hook_code[0x06], this->ToBytes(hookcode_address), 8);                                                                //向init_hook_code中填充hook跳转地址
        this->WriteBytesByMDL((PVOID)hook_point, init_hook_code, sizeof(init_hook_code));                                                           //向目标进程中的hook_pointer写入hook跳转
        
        //等待检测注入状态
        int judgment_address = (hookcode_address + sizeof(hook_code_one) + (hook_byte_size + 14) + sizeof(hook_code_two) - 0x10);
        //OutputDebugStringA_1Param("[GN]:判断地址：%p", judgment_address);
        while (TRUE)
        {
            if (this->ReadIntByMDL((PVOID)judgment_address) == 0x01)
            {
                Sleep(30);
                this->WriteBytesByMDL((PVOID)hook_point, reduction_code, hook_byte_size);                                                           //判断dll启动后还原hook_point处的hook
                this->FreeMemory((DWORD64)hookcode_address, 4096);                                                                                  //释放申请的内存
                break;
            }
            Sleep(1);
        }
        
        status = TRUE;
    } while (0);

    Sleep(3000);
    if (shellcode)
        this->FreeMemory((ULONG64)shellcode, 0x1000);
    if (param_buffer)
        this->FreeMemory((ULONG64)param_buffer, sizeof(MANUAL_MAPPING_DATA));
    if (empty_buffer != nullptr)
        delete[] empty_buffer;
    return status;
}

//反射式注入
DWORD Driver::SeCreateBootstrap(IN LPBYTE Bootstrap, IN DWORD BootstrapLength, IN DWORD TargetArchitecture, IN ULONG_PTR ParameterData, IN ULONG_PTR RemoteBufferData, IN DWORD FunctionHashValue, IN ULONG_PTR UserData, IN DWORD UserDataLength, IN ULONG_PTR ReflectiveLoader)
{
    DWORD i = 0;
    if (BootstrapLength < 64)
        return 0;
#if defined(_WIN64)
    DWORD CurrentArchitecture = X64;
#elif defined(_WIN32)
    DWORD CurrentArchitecture = X86;
#else
#endif
    // mov rcx, <lpParameter>
    MoveMemory(Bootstrap + i, "\x48\xb9", 2);
    i += 2;
    MoveMemory(Bootstrap + i, &ParameterData, sizeof(ParameterData));
    i += sizeof(ParameterData);
    // mov rdx, <address of image base>
    MoveMemory(Bootstrap + i, "\x48\xba", 2);
    i += 2;
    MoveMemory(Bootstrap + i, &RemoteBufferData, sizeof(RemoteBufferData));
    i += sizeof(RemoteBufferData);
    // mov r8d, <hash of function>
    MoveMemory(Bootstrap + i, "\x41\xb8", 2);
    i += 2;
    MoveMemory(Bootstrap + i, &FunctionHashValue, sizeof(FunctionHashValue));
    i += sizeof(FunctionHashValue);
    // mov r9, <address of userdata>
    MoveMemory(Bootstrap + i, "\x49\xb9", 2);
    i += 2;
    MoveMemory(Bootstrap + i, &UserData, sizeof(UserData));
    i += sizeof(UserData);
    // push <size of userdata>
    Bootstrap[i++] = 0x68; // PUSH (word/dword)
    MoveMemory(Bootstrap + i, &UserDataLength, sizeof(UserDataLength));
    i += sizeof(UserDataLength);
    // sub rsp, 20
    MoveMemory(Bootstrap + i, "\x48\x83\xec\x20", 4);
    i += 4;
    // move rax, <address of reflective loader>
    MoveMemory(Bootstrap + i, "\x48\xb8", 2);
    i += 2;
    MoveMemory(Bootstrap + i, &ReflectiveLoader, sizeof(ReflectiveLoader));
    i += sizeof(ReflectiveLoader);
    // call rax
    Bootstrap[i++] = 0xFF; // CALL
    Bootstrap[i++] = 0xD0; // RAX
    return i;
}

DWORD Driver::RvaToOffset(OUT DWORD Rva, IN UINT_PTR ImageBaseAddress)   //ImageBaseAddress = ReadFile中的BufferData = "MZ     0x00004550 PE00"
{
    WORD i = 0;
    WORD NumberOfSections = 0;
    PIMAGE_SECTION_HEADER ImageSectionHeader = NULL;
    PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageBaseAddress + ((PIMAGE_DOS_HEADER)ImageBaseAddress)->e_lfanew);
    if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // PE32
    {
        PIMAGE_NT_HEADERS32 ImageNtHeaders32 = (PIMAGE_NT_HEADERS32)ImageNtHeaders;
        ImageSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&ImageNtHeaders32->OptionalHeader) + ImageNtHeaders32->FileHeader.SizeOfOptionalHeader);
        NumberOfSections = ImageNtHeaders32->FileHeader.NumberOfSections;
    }
    else if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // PE64
    {
        PIMAGE_NT_HEADERS64 ImageNtHeaders64 = (PIMAGE_NT_HEADERS64)ImageNtHeaders;
        ImageSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&ImageNtHeaders64->OptionalHeader) + ImageNtHeaders64->FileHeader.SizeOfOptionalHeader);
        NumberOfSections = ImageNtHeaders64->FileHeader.NumberOfSections;
    }
    else
        return 0;
    if (Rva < ImageSectionHeader[0].PointerToRawData)
        return Rva;
    for (i = 0; i < NumberOfSections; i++)
    {
        if (Rva >= ImageSectionHeader[i].VirtualAddress && Rva < (ImageSectionHeader[i].VirtualAddress + ImageSectionHeader[i].SizeOfRawData))
            return (Rva - ImageSectionHeader[i].VirtualAddress + ImageSectionHeader[i].PointerToRawData);
    }
    return 0;
}

DWORD Driver::SeGetReflectiveLoaderOffset(IN VOID* BufferData)
{
    UINT_PTR ImageBaseAddress = 0;
    PIMAGE_NT_HEADERS ImageNtHeaders = NULL;
    ULONG_PTR ImageDataDirectory = 0;
    ULONG_PTR ImageExportDirectory = NULL;
    ULONG_PTR AddressOfNames = 0;
    ULONG_PTR AddressOfFunctions = 0;
    ULONG_PTR AddressOfNameOrdinals = 0;
    DWORD     NumberOfNames = 0;
    ImageBaseAddress = (UINT_PTR)BufferData;
    // get the File Offset of the modules NT Header
    ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageBaseAddress + ((PIMAGE_DOS_HEADER)ImageBaseAddress)->e_lfanew);
    if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // PE32
        ImageDataDirectory = (UINT_PTR) & ((PIMAGE_NT_HEADERS32)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    else if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // PE64
        ImageDataDirectory = (UINT_PTR) & ((PIMAGE_NT_HEADERS64)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    else
        return 0;
    // get the File Offset of the export directory  //内存对齐转换为文件对齐
    ImageExportDirectory = ImageBaseAddress + RvaToOffset(((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress, ImageBaseAddress);
    // get the File Offset for the array of name pointers
    AddressOfNames = ImageBaseAddress + RvaToOffset(((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNames, ImageBaseAddress);
    // get the File Offset for the array of addresses
    AddressOfFunctions = ImageBaseAddress + RvaToOffset(((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfFunctions, ImageBaseAddress);
    // get the File Offset for the array of name ordinals
    AddressOfNameOrdinals = ImageBaseAddress + RvaToOffset(((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNameOrdinals, ImageBaseAddress);
    // get a counter for the number of exported functions...
    NumberOfNames = ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->NumberOfNames;
    // loop through all the exported functions to find the ReflectiveLoader
    while (NumberOfNames--)
    {
        char* FunctionName = (char*)(ImageBaseAddress + RvaToOffset(DEREFERENCE_32(AddressOfNames), ImageBaseAddress));
        if (strstr(FunctionName, "GuNianDLLLoader") != NULL)
        {
            // get the File Offset for the array of addresses
            AddressOfFunctions = ImageBaseAddress + RvaToOffset(((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfFunctions, ImageBaseAddress);
            // use the functions name ordinal as an index into the array of name pointers
            AddressOfFunctions += (DEREFERENCE_16(AddressOfNameOrdinals) * sizeof(DWORD));
            // return the File Offset to the ReflectiveLoader() functions code...
            return RvaToOffset(DEREFERENCE_32(AddressOfFunctions), ImageBaseAddress);
        }
        // get the next exported function name
        AddressOfNames += sizeof(DWORD);
        // get the next exported function name ordinal
        AddressOfNameOrdinals += sizeof(WORD);
    }
    return 0;
}

DWORD Driver::SeLoadRemoteLibrary(IN DWORD64 hook_point, IN int hook_byte_size, IN PVOID file_buffer, IN DWORD file_buffer_size, IN LPVOID parameter_data, IN DWORD function_hash, IN PVOID transfer_data, IN DWORD transfer_data_size)
{
    DWORD status = true;
    DWORD TargetArchitecture = X86;
    DWORD DllArchitecture = UNKNOWN;
#if defined(_WIN64)
    DWORD CurrentArchitecture = X64;
#elif defined (_WIN32)
    DWORD CurrentArchitecture = X86;
#else
#endif

    __try
    {
        //参数错误：返回0
        if (!file_buffer || !file_buffer_size)
            return false;

        // 获得目标进程的Architecture, 获取进程信息失败返回2
        SYSTEM_INFO SystemInfo = { 0 };
        GetNativeSystemInfo(&SystemInfo);
        if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
            TargetArchitecture = X64;
        else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
            TargetArchitecture = X86;
        else
            return 2;

        //获得DLL的框架信息
        PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(((PUINT8)file_buffer) + ((PIMAGE_DOS_HEADER)file_buffer)->e_lfanew);
        if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // PE32
            DllArchitecture = X86;
        else if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // PE64
            DllArchitecture = X64;
        if (DllArchitecture != TargetArchitecture)//检查dll是否x64框架
        {
            OutputDebugStringA("[GN]:Must Be Same Architecture");
            //运行架构不相同返回3
            return 3;
        }

        //检查dll是否有定义的GuNianDLLLoader()加载dll函数
        DWORD ReflectiveLoaderOffset = SeGetReflectiveLoaderOffset(file_buffer);
        if (!ReflectiveLoaderOffset)
        {
            OutputDebugStringA("[GN]:Could Not Get ReflectiveLoader Offset");
            //无法获取反射偏移返回4
            return 4;
        }

        //向目标进程申请DLL内存空间和shellcode空间
        LPVOID RemoteBufferData = this->AllocMemory(file_buffer_size + transfer_data_size, PAGE_EXECUTE_READWRITE);
        //申请地址失败返回5
        if (!RemoteBufferData)
            return 5;
        //向目标进程写入DLL数据
        this->WriteBytesByMDL(RemoteBufferData, file_buffer, file_buffer_size);
        OutputDebugStringA_1Param("[GN]:RemoteBufferData(DLL数据) 地址:%p", RemoteBufferData);

        ULONG_PTR ReflectiveLoader = (ULONG_PTR)RemoteBufferData + ReflectiveLoaderOffset;
        //得到用户数据地址 = DLL数据+DLL数据大小
        ULONG_PTR RemoteUserData = (ULONG_PTR)RemoteBufferData + file_buffer_size;
        //向目标进程写入用户数据
        this->WriteBytesByMDL((PVOID)RemoteUserData, transfer_data, transfer_data_size);

        //得到远程shellcode地址 = dll数据 + 用户数据 + transfer大小
        ULONG_PTR RemoteShellCode = RemoteUserData + transfer_data_size;
        BYTE Bootstrap[64] = { 0 };
        DWORD BootstrapLength = SeCreateBootstrap(Bootstrap, 64, TargetArchitecture, (ULONG_PTR)parameter_data, (ULONG_PTR)RemoteBufferData, function_hash, RemoteUserData, transfer_data_size, ReflectiveLoader);
        //启动参数长度为0 返回8
        if (BootstrapLength <= 0)
            return 8;
        //将启动dll的shellcode写入目标进程
        this->WriteBytesByMDL((PVOID)RemoteShellCode, Bootstrap, BootstrapLength);
        OutputDebugStringA_1Param("[GN]:RemoteShellCode address:%p\r\n", RemoteShellCode);

        //开始构造hook进行跳转注入
        DWORD64 hookcode_address = (DWORD64)this->AllocMemory(4096, PAGE_EXECUTE_READWRITE);
        BYTE old_code[50] = { NULL };
        BYTE target_hook_code[1024] = { NULL };
        BYTE reduction_code[50] = { NULL };
        BYTE hook_code_one[63] = {
            0x54,0x50,0x53,0x51,0x52,0x55,0x56,0x57,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x9C,0x48,0x83,0xEC,0x40,0xE8,
            /*+0x1E Call shellcode偏移*/0x00,0x00,0x00,0x00,
            0x48,0x83,0xC4,0x40,0x9D,0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,0x5F,0x5E,0x5D,0x5A,0x59,0x5B,0x58,0x5C };
        BYTE hook_code_two[110] = {
            0x83,0x3D,0x57,0x00,0x00,0x00,0x00,0x75,0x4B,0xC7,0x05,0x4B,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x48,0x83,0xEC,0x38,0x31,0xC0,0x48,0xBA,
            /*+0x1B 参数地址*/0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x4C,0x8D,0x0A,0x36,0x48,0x89,0x44,0x24,0x28,0x48,0xBA,
            /*+0x2E 线程地址*/0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x4C,0x8D,0x02,0x31,0xD2,0x36,0x89,0x44,0x24,0x20,0x31,0xC9,0x48,0xB8,
            /*+0x44 CreateThread地址*/0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0xFF,0xD0,0x31,0xC0,0x48,0x83,0xC4,0x38,0xC3,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
        this->ReadBytesByMDL((PVOID)hook_point, hook_byte_size, old_code);                                                                          //保存hook点原始字节
        memcpy(reduction_code, old_code, hook_byte_size);                                                                                           //用来填充HOOK还原的代码
        memcpy((reduction_code + hook_byte_size), new BYTE[6]{ 0xFF,0x25,0x00,0x00,0x00,0x00 }, 6);                                                 //头部原始字节...+ 构造FF 25 00 00 00 00 跳回字节
        memcpy((reduction_code + hook_byte_size + 6), this->ToBytes(hook_point + hook_byte_size), 8);                                               //头部原始字节...+ 填充FF 25 00 00 00 00 跳回地址
        memcpy(target_hook_code, hook_code_one, sizeof(hook_code_one));                                                                             //向目标hook字节填充头部构造
        memcpy((target_hook_code + sizeof(hook_code_one)), reduction_code, (hook_byte_size + 14));                                                  //向目标hook字节中填充还原字节集
        memcpy((hook_code_two + 0x1B), this->ToBytes((DWORD64)parameter_data), 8);                                                                  //向hook_code_two中填充DLL启动参数
        memcpy((hook_code_two + 0x2E), this->ToBytes((DWORD64)RemoteShellCode), 8);                                                                 //向hook_code_two中填充DLL启动线程参数
        DWORD64 createthread_address = (DWORD64)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "CreateThread");
        memcpy((hook_code_two + 0x44), this->ToBytes(createthread_address), 8);                                                                     //向hook_code_two中填充CreateThread地址
        int call_offset = ((__int64)target_hook_code + sizeof(hook_code_one) + hook_byte_size + 14) - ((DWORD64)target_hook_code + 0x1D + 5);       //计算Call偏移
        memcpy((target_hook_code + 0x1E), &call_offset, 4);                                                                                         //向目标hook字节中填充Call偏移
        memcpy((target_hook_code + sizeof(hook_code_one) + (hook_byte_size + 14)), hook_code_two, sizeof(hook_code_two));                           //向目标hook字节中填充 call shellcode函数
        this->WriteBytesByMDL((PVOID)hookcode_address, (PVOID)target_hook_code, sizeof(target_hook_code));                                          //向目标进程中申请的地址写入构造完成的hook字节
        BYTE init_hook_code[] = { 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };                                          //构造向hook_pointer下hook的字节
        memcpy((__int64*)&init_hook_code[0x06], this->ToBytes(hookcode_address), 8);                                                                //向init_hook_code中填充hook跳转地址
        this->WriteBytesByMDL((PVOID)hook_point, init_hook_code, sizeof(init_hook_code));                                                           //向目标进程中的hook_pointer写入hook跳转

        //等待检测注入状态
        int judgment_address = (hookcode_address + sizeof(hook_code_one) + (hook_byte_size + 14) + sizeof(hook_code_two) - 0x10);
        //OutputDebugStringA_1Param("[GN]:判断地址：%p", judgment_address);
        while (TRUE)
        {
            if (this->ReadIntByMDL((PVOID)judgment_address) == 0x01)
            {
                Sleep(30);
                this->WriteBytesByMDL((PVOID)hook_point, reduction_code, hook_byte_size);                                                           //判断dll启动后还原hook_point处的hook
                this->FreeMemory((DWORD64)hookcode_address, 4096);                                                                                  //释放申请的内存
                break;
            }
            Sleep(1);
        }
        Sleep(5000);
        this->FreeMemory((ULONG64)RemoteBufferData, file_buffer_size + transfer_data_size);
        status = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = 999;
    }
    return status;
}

DWORD Driver::SeLoadRemoteLibraryByInstCallback(IN PVOID file_buffer, IN DWORD file_buffer_size, IN LPVOID parameter_data, IN DWORD function_hash, IN PVOID transfer_data, IN DWORD transfer_data_size, IN LONG kernel_wait_millisecond, IN BOOL isclear_proccallback)
{
    DWORD status = true;
    DWORD TargetArchitecture = X86;
    DWORD DllArchitecture = UNKNOWN;
#if defined(_WIN64)
    DWORD CurrentArchitecture = X64;
#elif defined (_WIN32)
    DWORD CurrentArchitecture = X86;
#else
#endif

    __try
    {
        //参数错误：返回0
        if (!file_buffer || !file_buffer_size)
            return false;

        // 获得目标进程的Architecture, 获取进程信息失败返回2
        SYSTEM_INFO SystemInfo = { 0 };
        GetNativeSystemInfo(&SystemInfo);
        if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
            TargetArchitecture = X64;
        else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
            TargetArchitecture = X86;
        else
            return 2;

        //获得DLL的框架信息
        PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(((PUINT8)file_buffer) + ((PIMAGE_DOS_HEADER)file_buffer)->e_lfanew);
        if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // PE32
            DllArchitecture = X86;
        else if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // PE64
            DllArchitecture = X64;
        if (DllArchitecture != TargetArchitecture)//检查dll是否x64框架
        {
            OutputDebugStringA("[GN]:Must Be Same Architecture");
            //运行架构不相同返回3
            return 3;
        }

        //检查dll是否有定义的GuNianDLLLoader()加载dll函数
        DWORD ReflectiveLoaderOffset = SeGetReflectiveLoaderOffset(file_buffer);
        if (!ReflectiveLoaderOffset)
        {
            OutputDebugStringA("[GN]:Could Not Get ReflectiveLoader Offset");
            //无法获取反射偏移返回4
            return 4;
        }

        //向目标进程申请DLL内存空间和shellcode空间
        LPVOID RemoteBufferData = this->AllocMemory(file_buffer_size + transfer_data_size, PAGE_EXECUTE_READWRITE);
        //申请地址失败返回5
        if (!RemoteBufferData)
            return 5;
        //向目标进程写入DLL数据
        this->WriteBytesByMDL(RemoteBufferData, file_buffer, file_buffer_size);
        OutputDebugStringA_1Param("[GN]:Dll buffer address:%p", RemoteBufferData);

        ULONG_PTR ReflectiveLoader = (ULONG_PTR)RemoteBufferData + ReflectiveLoaderOffset;
        //得到用户数据地址 = DLL数据+DLL数据大小
        ULONG_PTR RemoteUserData = (ULONG_PTR)RemoteBufferData + file_buffer_size;
        //向目标进程写入用户数据
        this->WriteBytesByMDL((PVOID)RemoteUserData, transfer_data, transfer_data_size);

        //得到远程shellcode地址 = dll数据 + 用户数据 + transfer大小
        ULONG_PTR RemoteShellCode = RemoteUserData + transfer_data_size;
        BYTE Bootstrap[64] = { 0 };
        DWORD BootstrapLength = SeCreateBootstrap(Bootstrap, 64, TargetArchitecture, (ULONG_PTR)parameter_data, (ULONG_PTR)RemoteBufferData, function_hash, RemoteUserData, transfer_data_size, ReflectiveLoader);
        //启动参数长度为0 返回8
        if (BootstrapLength <= 0)
            return 8;
        //将启动dll的shellcode写入目标进程
        this->WriteBytesByMDL((PVOID)RemoteShellCode, Bootstrap, BootstrapLength);
        OutputDebugStringA_1Param("[GN]:LoaderShellCode address:%p\r\n", RemoteShellCode);

        //将启动参数传入内核回调函数
        if (!this->KernelCallback(this->m_pid, (ULONG64)parameter_data, (ULONG64)RemoteShellCode,
            (ULONG64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCaptureContext"),
            (ULONG64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtContinue"),
            kernel_wait_millisecond, isclear_proccallback))
        {
            OutputDebugStringA("[GN]:%s-> KernelCallback() error");
            this->FreeMemory((ULONG64)RemoteBufferData, file_buffer_size + transfer_data_size);
            return 999;
        }

        this->FreeMemory((ULONG64)RemoteBufferData, file_buffer_size + transfer_data_size);
        status = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = 999;
    }
    return status;
}

//源反射式注入
HANDLE Driver::Original_SeLoadRemoteLibrary(HANDLE ProcessHandle, LPVOID FileData, DWORD FileLength, LPVOID ParameterData, DWORD FunctionHash, LPVOID UserData, DWORD UserDataLength)
{
    HANDLE RemoteThreadHandle = NULL;
    DWORD  RemoteThreadID = 0;
    DWORD TargetArchitecture = X86;
    DWORD DllArchitecture = UNKNOWN;
#if defined(_WIN64)
    DWORD CurrentArchitecture = X64;
#elif defined (_WIN32)
    DWORD CurrentArchitecture = X86;
#else

#endif
    __try
    {
        do
        {
            if (!ProcessHandle || !FileData || !FileLength)
                break;
            // 获得目标进程的Architecture
            SYSTEM_INFO SystemInfo = { 0 };
            GetNativeSystemInfo(&SystemInfo);
            if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
                TargetArchitecture = X64;
            else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
                TargetArchitecture = X86;
            else
                break;
            // 获得Dll的Architecture
            PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(((PUINT8)FileData) + ((PIMAGE_DOS_HEADER)FileData)->e_lfanew);
            if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // PE32
                DllArchitecture = X86;
            else if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // PE64
                DllArchitecture = X64;
            // DLL and target process must be same architecture
            if (DllArchitecture != TargetArchitecture)
            {
                OutputDebugStringA("[GN]:Must Be Same Architecture");
                break;
            }
            // check if the library has a ReflectiveLoader...
            DWORD ReflectiveLoaderOffset = SeGetReflectiveLoaderOffset(FileData);
            if (!ReflectiveLoaderOffset)
            {
                OutputDebugStringA("[GN]:Could Not Get ReflectiveLoader Offset");
                break;
            }
            DWORD RemoteBufferLength = FileLength + UserDataLength + 64; //dll数据+shellcode的总长度
            // 申请地址写入dll数据+shellcode
            LPVOID RemoteBufferData = VirtualAllocEx(ProcessHandle, NULL, RemoteBufferLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!RemoteBufferData)
                break;
            //OutputDebugStringA_1Param("[GN]:映射加载器偏移：%p", ReflectiveLoaderOffset);
            //OutputDebugStringA_1Param("[GN]:RemoteBufferData(DLL数据) address:%p", RemoteBufferData);
            //向目标进程写入dll数据
            if (!WriteProcessMemory(ProcessHandle, RemoteBufferData, FileData, FileLength, NULL))
                break;
            //加载器的地址
            ULONG_PTR ReflectiveLoader = (ULONG_PTR)RemoteBufferData + ReflectiveLoaderOffset;
            //写入用户数据到目标进程的shellcode
            ULONG_PTR RemoteUserData = (ULONG_PTR)RemoteBufferData + FileLength;
            if (!WriteProcessMemory(ProcessHandle, (LPVOID)RemoteUserData, UserData, UserDataLength, NULL))
                break;
            ULONG_PTR RemoteShellCode = RemoteUserData + UserDataLength;
            BYTE Bootstrap[64] = { 0 };
            DWORD BootstrapLength = SeCreateBootstrap(Bootstrap, 64, TargetArchitecture, (ULONG_PTR)ParameterData, (ULONG_PTR)RemoteBufferData, FunctionHash, RemoteUserData, UserDataLength, ReflectiveLoader);
            if (BootstrapLength <= 0)
                break;
            //OutputDebugStringA_1Param("[GN]:RemoteShellCode address:%p", RemoteShellCode);
            //向目标进程写入shellcode
            if (!WriteProcessMemory(ProcessHandle, (LPVOID)RemoteShellCode, Bootstrap, BootstrapLength, NULL))
                break;
            // Make sure our changes are written right away
            FlushInstructionCache(ProcessHandle, RemoteBufferData, RemoteBufferLength);
            if (!WriteProcessMemory(ProcessHandle, (LPVOID)RemoteShellCode, Bootstrap, BootstrapLength, NULL))
                break;
            FlushInstructionCache(ProcessHandle, RemoteBufferData, RemoteBufferLength);
            if (CurrentArchitecture == X86 && TargetArchitecture == X64)
            {
                Wow64CreateRemoteThread(ProcessHandle, (LPVOID)RemoteShellCode, ParameterData, &RemoteThreadHandle);
                ResumeThread(RemoteThreadHandle);
            }
            else
                RemoteThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 1024 * 1024, (LPTHREAD_START_ROUTINE)RemoteShellCode, ParameterData, (DWORD)NULL, &RemoteThreadID);
        } while (0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        RemoteThreadHandle = NULL;
    }
    return RemoteThreadHandle;
}

DWORD Driver::Wow64CreateRemoteThread(HANDLE ProcessHandle, LPVOID ThreadProcedure, LPVOID ParameterData, HANDLE* ThreadHandle)
{
    DWORD dwResult = ERROR_SUCCESS;
    LPFN_EXECUTEX64  ExecuteX64 = NULL;
    LPFN_FUNCTIONX64 FunctionX64 = NULL;
    WOW64CONTEXT* Wow64Context = NULL;
    do
    {
        ExecuteX64 = (LPFN_EXECUTEX64)VirtualAlloc(NULL, sizeof(__ExecutexX64), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!ExecuteX64)
        {
            printf("VirtualAlloc() Error\r\n");
            break;
        }
        FunctionX64 = (LPFN_FUNCTIONX64)VirtualAlloc(NULL, sizeof(__FunctionX64) + sizeof(WOW64CONTEXT), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!FunctionX64)
        {
            printf("VirtualAlloc() Error\r\n");
            break;
        }
        // copy over the wow64->x64 stub
        memcpy(ExecuteX64, &__ExecutexX64, sizeof(__ExecutexX64));
        // copy over the native x64 function
        memcpy(FunctionX64, &__FunctionX64, sizeof(__FunctionX64));
        // set the context
        Wow64Context = (WOW64CONTEXT*)((BYTE*)FunctionX64 + sizeof(__FunctionX64));
        Wow64Context->u1.ProcessHandle = ProcessHandle;   //目标进程句柄
        Wow64Context->u2.ThreadProcedure = ThreadProcedure;
        Wow64Context->u3.ParameterData = ParameterData;
        Wow64Context->u4.ThreadHandle = NULL;
        //执行该代码的环境是32位
        if (!ExecuteX64(FunctionX64, (DWORD)Wow64Context))
        {
            printf("ExecuteX64() Error\r\n");
            break;
        }
        if (!Wow64Context->u4.ThreadHandle)
        {
            printf("ThreadHandle Is NULL\r\n");
            break;
        }
        // Success! grab the new thread handle from of the context
        *ThreadHandle = Wow64Context->u4.ThreadHandle;
    } while (0);
    if (ExecuteX64)
    {
        VirtualFree(ExecuteX64, 0, MEM_RELEASE);
        ExecuteX64 = NULL;
    }
    if (FunctionX64)
    {
        VirtualFree(FunctionX64, 0, MEM_RELEASE);
        FunctionX64 = NULL;
    }
    return dwResult;
}

//public:
//手动反射式注入
DWORD Driver::ManualMapInject(__int64 hook_point, int hook_byte_size, LPBYTE dll_buffer, DWORD dll_file_size)
{
    return this->mManualMapInject(hook_point, hook_byte_size, dll_buffer, dll_file_size);
}

//自动反射注入
DWORD Driver::ReflectiveInject(IN DWORD64 hook_point, IN int hook_byte_size, IN PVOID file_buffer, IN DWORD file_buffer_size, IN PVOID transfer_data, IN DWORD transfer_data_size)
{
    return this->SeLoadRemoteLibrary(hook_point, hook_byte_size, file_buffer, file_buffer_size, NULL, MYFUNCTION_HASH, transfer_data, transfer_data_size);
}

DWORD Driver::ReflectiveInjectByInstCallback(IN PVOID file_buffer, IN DWORD file_buffer_size, IN PVOID transfer_data, IN DWORD transfer_data_size, IN LONG kernel_wait_millisecond, IN BOOL isclear_proccallback)
{
    return this->SeLoadRemoteLibraryByInstCallback(file_buffer, file_buffer_size, NULL, MYFUNCTION_HASH, transfer_data, transfer_data_size, kernel_wait_millisecond, isclear_proccallback);
}

//原来的反射式注入
bool Driver::Original_ReflectiveInject(IN ULONG pid, IN PVOID file_buffer, IN DWORD file_buffer_size, IN PVOID transfer_data, IN DWORD transfer_data_size)
{
    HANDLE ProcessHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID Cid;
    //初始化
    InitializeObjectAttributes(&ObjectAttributes, 0, 0, 0, 0);
    Cid.UniqueProcess = (HANDLE)pid;
    Cid.UniqueThread = 0;
    pfnZwOpenProcess ZwOpenProcess = (pfnZwOpenProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwOpenProcess");
    ZwOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &Cid);
    if (!ProcessHandle)
    {
        OutputDebugStringA("[GN]:ZwOpenProcess() Error");
        return false;
    }
    HANDLE RemoteThreadHandle = this->Original_SeLoadRemoteLibrary(ProcessHandle, file_buffer, file_buffer_size, NULL, MYFUNCTION_HASH, transfer_data, transfer_data_size);
    if (!RemoteThreadHandle)
    {
        OutputDebugStringA("[GN]:Original_SeLoadRemoteLibrary() Error");
        return false;
    }
    WaitForSingleObject(RemoteThreadHandle, INFINITE);
    if (ProcessHandle)
    {
        CloseHandle(ProcessHandle);
        ProcessHandle = NULL;
    }
    return true;
}

bool Driver::InjectByRemoteThread(IN const wchar_t* dll_path)
{
    bool bRet = false;
    SIZE_T dWrited = 0;
    HANDLE hFile = CreateFile(dll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    UCHAR Code[] = { 0x40,  0x55,  0x53,  0x56,  0x57,  0x41,  0x54,  0x41,  0x56,  0x48,  0x8D,  0x6C,  0x24,
        0xD1,  0x48,  0x81,  0xEC,  0x88,  0x00,  0x00,  0x00,  0x48,  0x8B,  0x41,  0x20,  0x45,  0x33,  0xF6,
        0x44,  0x8B,  0x49,  0x08,  0x45,  0x8B,  0xC6,  0x48,  0x8B,  0x79,  0x28,  0x48,  0x8B,  0x19,  0x4C,
        0x8B,  0x61,  0x10,  0x48,  0x8B,  0x71,  0x18,  0x48,  0x89,  0x45,  0xE7,  0x48,  0x8B,  0x41,  0x30,
        0x48,  0x89,  0x45,  0xDF,  0x48,  0x8B,  0x41,  0x38,  0x48,  0x89,  0x45,  0xEF,  0x48,  0x89,  0x7D,
        0x7F,  0x4C,  0x89,  0x75,  0x67,  0x49,  0x83,  0xF9,  0x40,  0x0F,  0x86,  0xE3,  0x03,  0x00,  0x00,
        0xB8,  0x4D,  0x5A,  0x00,  0x00,  0x66,  0x39,  0x03,  0x0F,  0x85,  0xD5,  0x03,  0x00,  0x00,  0x48,
        0x63,  0x4B,  0x3C,  0x48,  0x8D,  0x81,  0x08,  0x01,  0x00,  0x00,  0x4C,  0x3B,  0xC8,  0x0F,  0x82,
        0xC1,  0x03,  0x00,  0x00,  0x81,  0x3C,  0x19,  0x50,  0x45,  0x00,  0x00,  0x4C,  0x89,  0xAC,  0x24,
        0x80,  0x00,  0x00,  0x00,  0x4C,  0x8D,  0x2C,  0x19,  0x0F,  0x85,  0xA0,  0x03,  0x00,  0x00,  0x41,
        0x0F,  0xB7,  0x45,  0x16,  0xB9,  0x02,  0x20,  0x00,  0x00,  0x66,  0x23,  0xC1,  0x66,  0x3B,  0xC1,
        0x0F,  0x85,  0x8A,  0x03,  0x00,  0x00,  0xB8,  0xF0,  0x00,  0x00,  0x00,  0x66,  0x41,  0x39,  0x45,
        0x14,  0x0F,  0x85,  0x7A,  0x03,  0x00,  0x00,  0x45,  0x0F,  0xB7,  0x55,  0x06,  0x41,  0x8B,  0xD6,
        0x45,  0x85,  0xD2,  0x0F,  0x84,  0x7E,  0x00,  0x00,  0x00,  0x49,  0x8D,  0x8D,  0x18,  0x01,  0x00,
        0x00,  0x8B,  0x41,  0x04,  0x03,  0x01,  0x41,  0x3B,  0xC1,  0x0F,  0x87,  0x54,  0x03,  0x00,  0x00,
        0xFF,  0xC2,  0x48,  0x83,  0xC1,  0x28,  0x41,  0x3B,  0xD2,  0x7C,  0xE7,  0x45,  0x8B,  0x5D,  0x38,
        0x33,  0xD2,  0x41,  0x8B,  0x45,  0x54,  0x49,  0x8B,  0xFA,  0xFF,  0xC8,  0x4D,  0x8D,  0x95,  0x18,
        0x01,  0x00,  0x00,  0x41,  0x03,  0xC3,  0x41,  0xF7,  0xF3,  0x44,  0x8B,  0xC8,  0x45,  0x0F,  0xAF,
        0xCB,  0x0F,  0x1F,  0x00,  0x41,  0x8B,  0x4A,  0xF8,  0x41,  0x8D,  0x43,  0xFF,  0x41,  0x39,  0x0A,
        0x41,  0x0F,  0x4F,  0x0A,  0x33,  0xD2,  0x41,  0x03,  0x4A,  0xFC,  0x4D,  0x8D,  0x52,  0x28,  0x03,
        0xC1,  0x41,  0xF7,  0xF3,  0x41,  0x0F,  0xAF,  0xC3,  0x44,  0x3B,  0xC8,  0x41,  0x0F,  0x4D,  0xC1,
        0x44,  0x8B,  0xC8,  0x48,  0x83,  0xEF,  0x01,  0x75,  0xCE,  0x48,  0x8B,  0x7D,  0x7F,  0xEB,  0x15,
        0x41,  0x8B,  0x4D,  0x38,  0x41,  0x8B,  0x45,  0x54,  0xFF,  0xC8,  0x03,  0xC1,  0xF7,  0xF1,  0x44,
        0x8B,  0xC8,  0x44,  0x0F,  0xAF,  0xC9,  0x45,  0x85,  0xC9,  0x0F,  0x84,  0xCD,  0x02,  0x00,  0x00,
        0x49,  0x63,  0xC1,  0x48,  0x8D,  0x55,  0x67,  0x4C,  0x8D,  0x4D,  0xD7,  0xC7,  0x44,  0x24,  0x28,
        0x40,  0x00,  0x00,  0x00,  0x48,  0xC7,  0xC1,  0xFF,  0xFF,  0xFF,  0xFF,  0x48,  0x89,  0x45,  0xD7,
        0xC7,  0x44,  0x24,  0x20,  0x00,  0x10,  0x00,  0x00,  0xFF,  0xD6,  0x4C,  0x8B,  0x45,  0x67,  0x4D,
        0x85,  0xC0,  0x0F,  0x84,  0x98,  0x02,  0x00,  0x00,  0x45,  0x0F,  0xB7,  0x4D,  0x06,  0x41,  0x8B,
        0x45,  0x54,  0x43,  0x8D,  0x0C,  0x89,  0x8D,  0x0C,  0xC8,  0x48,  0x63,  0xD1,  0x85,  0xC9,  0x7E,
        0x27,  0x49,  0x8B,  0xCE,  0x66,  0x66,  0x66,  0x0F,  0x1F,  0x84,  0x00,  0x00,  0x00,  0x00,  0x00,
        0x0F,  0xB6,  0x04,  0x19,  0x42,  0x88,  0x04,  0x01,  0x48,  0xFF,  0xC1,  0x4C,  0x8B,  0x45,  0x67,
        0x48,  0x3B,  0xCA,  0x7C,  0xEC,  0x45,  0x0F,  0xB7,  0x4D,  0x06,  0x45,  0x8B,  0xDE,  0x66,  0x45,
        0x3B,  0xF1,  0x73,  0x5B,  0x49,  0x8D,  0x95,  0x18,  0x01,  0x00,  0x00,  0x0F,  0x1F,  0x80,  0x00,
        0x00,  0x00,  0x00,  0x8B,  0x42,  0xFC,  0x85,  0xC0,  0x74,  0x35,  0x44,  0x8B,  0x12,  0x45,  0x85,
        0xD2,  0x74,  0x2D,  0x4D,  0x8D,  0x0C,  0x00,  0x49,  0x8B,  0xCE,  0x66,  0x66,  0x0F,  0x1F,  0x84,
        0x00,  0x00,  0x00,  0x00,  0x00,  0x8B,  0x42,  0x04,  0x48,  0x03,  0xC1,  0x0F,  0xB6,  0x04,  0x18,
        0x42,  0x88,  0x04,  0x09,  0x48,  0xFF,  0xC1,  0x8B,  0x02,  0x48,  0x3B,  0xC8,  0x72,  0xE8,  0x4C,
        0x8B,  0x45,  0x67,  0x41,  0x0F,  0xB7,  0x45,  0x06,  0x41,  0xFF,  0xC3,  0x48,  0x83,  0xC2,  0x28,
        0x44,  0x3B,  0xD8,  0x7C,  0xB3,  0x41,  0x8B,  0x85,  0xB0,  0x00,  0x00,  0x00,  0x4C,  0x89,  0x7C,
        0x24,  0x78,  0x85,  0xC0,  0x0F,  0x84,  0xB5,  0x00,  0x00,  0x00,  0x45,  0x39,  0xB5,  0xB4,  0x00,
        0x00,  0x00,  0x0F,  0x86,  0xA8,  0x00,  0x00,  0x00,  0x41,  0x8B,  0x0C,  0x00,  0x4D,  0x8D,  0x14,
        0x00,  0x45,  0x8B,  0x4A,  0x04,  0x49,  0x8B,  0xD8,  0x49,  0x2B,  0x5D,  0x30,  0x41,  0x03,  0xC9,
        0x0F,  0x84,  0x8C,  0x00,  0x00,  0x00,  0xB9,  0x00,  0x30,  0x00,  0x00,  0xBE,  0x00,  0xA0,  0x00,
        0x00,  0x41,  0xBF,  0x00,  0xF0,  0x00,  0x00,  0x66,  0x0F,  0x1F,  0x44,  0x00,  0x00,  0x41,  0x8B,
        0xC1,  0x49,  0x8B,  0xD6,  0x48,  0x83,  0xE8,  0x08,  0x48,  0xD1,  0xE8,  0x4C,  0x63,  0xD8,  0x85,
        0xC0,  0x7E,  0x4B,  0x0F,  0x1F,  0x40,  0x00,  0x0F,  0x1F,  0x84,  0x00,  0x00,  0x00,  0x00,  0x00,
        0x45,  0x0F,  0xB7,  0x4C,  0x52,  0x08,  0x41,  0x0F,  0xB7,  0xC1,  0x66,  0x41,  0x23,  0xC7,  0x66,
        0x3B,  0xC1,  0x74,  0x05,  0x66,  0x3B,  0xC6,  0x75,  0x1B,  0x41,  0x8B,  0x0A,  0x41,  0x81,  0xE1,
        0xFF,  0x0F,  0x00,  0x00,  0x4B,  0x8D,  0x04,  0x08,  0x48,  0x01,  0x1C,  0x01,  0xB9,  0x00,  0x30,
        0x00,  0x00,  0x4C,  0x8B,  0x45,  0x67,  0x48,  0xFF,  0xC2,  0x49,  0x3B,  0xD3,  0x7C,  0xC5,  0x45,
        0x8B,  0x4A,  0x04,  0x41,  0x8B,  0xC1,  0x4C,  0x03,  0xD0,  0x41,  0x8B,  0x0A,  0x45,  0x8B,  0x4A,
        0x04,  0x41,  0x03,  0xC9,  0xB9,  0x00,  0x30,  0x00,  0x00,  0x75,  0x8A,  0x41,  0x8B,  0x85,  0x90,
        0x00,  0x00,  0x00,  0x48,  0x85,  0xC0,  0x0F,  0x84,  0x18,  0x01,  0x00,  0x00,  0x4E,  0x8D,  0x3C,
        0x00,  0x42,  0x8B,  0x04,  0x00,  0x85,  0xC0,  0x0F,  0x84,  0xEB,  0x00,  0x00,  0x00,  0x33,  0xD2,
        0x0F,  0x1F,  0x84,  0x00,  0x00,  0x00,  0x00,  0x00,  0x45,  0x8B,  0x77,  0x10,  0x48,  0x8D,  0x4D,
        0xF7,  0x48,  0x89,  0x55,  0x6F,  0x4D,  0x03,  0xF0,  0x41,  0x8B,  0x57,  0x0C,  0x8B,  0xF0,  0x49,
        0x03,  0xD0,  0x49,  0x03,  0xF0,  0xFF,  0xD7,  0x41,  0xB0,  0x01,  0x48,  0x8D,  0x55,  0xF7,  0x48,
        0x8D,  0x4D,  0x07,  0xFF,  0x55,  0xDF,  0x4C,  0x8D,  0x4D,  0x6F,  0x33,  0xD2,  0x4C,  0x8D,  0x45,
        0x07,  0x33,  0xC9,  0xFF,  0x55,  0xE7,  0x48,  0x8D,  0x4D,  0x07,  0xFF,  0x55,  0xEF,  0x48,  0x8B,
        0x4D,  0x6F,  0x48,  0x85,  0xC9,  0x0F,  0x84,  0xAC,  0x00,  0x00,  0x00,  0x48,  0x8B,  0x06,  0x33,
        0xD2,  0x8B,  0xDA,  0x48,  0x85,  0xC0,  0x74,  0x73,  0x8B,  0xFA,  0x0F,  0x1F,  0x40,  0x00,  0x48,
        0x89,  0x55,  0x77,  0x48,  0x85,  0xC0,  0x79,  0x11,  0x66,  0x85,  0xC0,  0x0F,  0x84,  0x88,  0x00,
        0x00,  0x00,  0x44,  0x0F,  0xB7,  0xC0,  0x33,  0xD2,  0xEB,  0x1F,  0x4C,  0x8B,  0x45,  0x67,  0x49,
        0x8D,  0x50,  0x02,  0x48,  0x03,  0xD0,  0x74,  0x77,  0x48,  0x8D,  0x4D,  0xF7,  0xFF,  0x55,  0x7F,
        0x48,  0x8B,  0x4D,  0x6F,  0x48,  0x8D,  0x55,  0xF7,  0x45,  0x33,  0xC0,  0x4C,  0x8D,  0x4D,  0x77,
        0x41,  0xFF,  0xD4,  0x48,  0x8B,  0x45,  0x77,  0x48,  0x85,  0xC0,  0x74,  0x51,  0x48,  0xFF,  0xC3,
        0x4A,  0x89,  0x04,  0x37,  0x33,  0xD2,  0x48,  0x8D,  0x3C,  0xDD,  0x00,  0x00,  0x00,  0x00,  0x48,
        0x8B,  0x04,  0x37,  0x48,  0x85,  0xC0,  0x74,  0x06,  0x48,  0x8B,  0x4D,  0x6F,  0xEB,  0x97,  0x48,
        0x8B,  0x7D,  0x7F,  0x41,  0x8B,  0x47,  0x14,  0x49,  0x83,  0xC7,  0x14,  0x4C,  0x8B,  0x45,  0x67,
        0x85,  0xC0,  0x0F,  0x85,  0x1F,  0xFF,  0xFF,  0xFF,  0x41,  0x8B,  0x45,  0x28,  0xBA,  0x01,  0x00,
        0x00,  0x00,  0x4D,  0x89,  0x45,  0x30,  0x48,  0x8B,  0x4D,  0x67,  0x48,  0x03,  0xC1,  0x4C,  0x8B,
        0xC1,  0xFF,  0xD0,  0x4C,  0x8B,  0x45,  0x67,  0x4C,  0x8B,  0x7C,  0x24,  0x78,  0x4C,  0x8B,  0xAC,
        0x24,  0x80,  0x00,  0x00,  0x00,  0x49,  0x8B,  0xC0,  0x48,  0x81,  0xC4,  0x88,  0x00,  0x00,  0x00,
        0x41,  0x5E,  0x41,  0x5C,  0x5F,  0x5E,  0x5B,  0x5D,  0xC3 };
    ULONG_PTR fileSize2 = sizeof(Code);//shellcode的大小
    if (hFile)
    {
        //获取DLL数据
        DWORD fileSize = GetFileSize(hFile, NULL);
        DWORD RSize = 0;
        PVOID pBuffer = malloc(fileSize);
        ReadFile(hFile, pBuffer, fileSize, &RSize, NULL);

        HMODULE NTDLL = GetModuleHandleA("ntdll");
        PARAMX param;
        RtlZeroMemory(&param, sizeof(PARAMX));
        param.lpFileData = pBuffer;
        param.DataLength = fileSize;
        param.LdrGetProcedureAddress = GetProcAddress(NTDLL, "LdrGetProcedureAddress");
        param.dwNtAllocateVirtualMemory = GetProcAddress(NTDLL, "NtAllocateVirtualMemory");
        param.pLdrLoadDll = GetProcAddress(NTDLL, "LdrLoadDll");
        param.RtlInitAnsiString = GetProcAddress(NTDLL, "RtlInitAnsiString");
        param.RtlAnsiStringToUnicodeString = GetProcAddress(NTDLL, "RtlAnsiStringToUnicodeString");
        param.RtlFreeUnicodeString = GetProcAddress(NTDLL, "RtlFreeUnicodeString");

        //开始远程注入
        HANDLE hProcess;
        OBJECT_ATTRIBUTES ObjectAttributes;
        CLIENT_ID Cid;
        //初始化
        InitializeObjectAttributes(&ObjectAttributes, 0, 0, 0, 0);
        Cid.UniqueProcess = (HANDLE)m_pid;
        Cid.UniqueThread = 0;
        pfnZwOpenProcess ZwOpenProcess = (pfnZwOpenProcess)GetProcAddress(NTDLL, "ZwOpenProcess");
        ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &Cid);
        if (hProcess != NULL)
        {
            //申请内存,把shellcode和DLL数据,和参数复制到目标进程
            PBYTE  pAddress = (PBYTE)VirtualAllocEx(hProcess, 0, fileSize + fileSize2 + sizeof(PARAMX) + 0x100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//安全起见,大小多加0x100
            param.lpFileData = pAddress;//修成下DLL数据的地址
            WriteProcessMemory(hProcess, pAddress, pBuffer, fileSize, &dWrited);//DLL数据写入到目标
            WriteProcessMemory(hProcess, pAddress + fileSize, Code, fileSize2, &dWrited);//shellcode写入到目标
            WriteProcessMemory(hProcess, pAddress + fileSize + fileSize2, &param, sizeof(PARAMX), &dWrited);//参数写入到目标
            //启动注入线程=pAddress+ fileSize,参数=pAddress+ fileSize+ fileSize2;
            HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)(pAddress + fileSize), pAddress + fileSize + fileSize2, 0, 0);
            if (hThread)
            {
                DWORD dExecCode = 0;
                //printf("等待注入线程执行完毕....\n");
                WaitForSingleObject(hThread, -1);
                GetExitCodeThread(hThread, &dExecCode);
                bRet = true;
                CloseHandle(hThread);
                printf("注入成功,线程执行完毕，线程退出状态码%d\n", dExecCode);
                //释放掉申请的内存
                VirtualFreeEx(hProcess, pAddress, 0, MEM_FREE);
            }
            CloseHandle(hProcess);
        }
        CloseHandle(hFile);
        free(pBuffer);
    }
    return bRet;
}

bool Driver::InjectByRemoteThreadEx(IN ULONG pid, IN const wchar_t* dll_path)
{
    //OutputDebugStringA_1Param("[GN]:注入文件路径：%S", dll_path);
    bool bRet = false;
    SIZE_T dWrited = 0;
    HANDLE hFile = CreateFileW(dll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    UCHAR Code[] = { 0x40,  0x55,  0x53,  0x56,  0x57,  0x41,  0x54,  0x41,  0x56,  0x48,  0x8D,  0x6C,  0x24,
        0xD1,  0x48,  0x81,  0xEC,  0x88,  0x00,  0x00,  0x00,  0x48,  0x8B,  0x41,  0x20,  0x45,  0x33,  0xF6,
        0x44,  0x8B,  0x49,  0x08,  0x45,  0x8B,  0xC6,  0x48,  0x8B,  0x79,  0x28,  0x48,  0x8B,  0x19,  0x4C,
        0x8B,  0x61,  0x10,  0x48,  0x8B,  0x71,  0x18,  0x48,  0x89,  0x45,  0xE7,  0x48,  0x8B,  0x41,  0x30,
        0x48,  0x89,  0x45,  0xDF,  0x48,  0x8B,  0x41,  0x38,  0x48,  0x89,  0x45,  0xEF,  0x48,  0x89,  0x7D,
        0x7F,  0x4C,  0x89,  0x75,  0x67,  0x49,  0x83,  0xF9,  0x40,  0x0F,  0x86,  0xE3,  0x03,  0x00,  0x00,
        0xB8,  0x4D,  0x5A,  0x00,  0x00,  0x66,  0x39,  0x03,  0x0F,  0x85,  0xD5,  0x03,  0x00,  0x00,  0x48,
        0x63,  0x4B,  0x3C,  0x48,  0x8D,  0x81,  0x08,  0x01,  0x00,  0x00,  0x4C,  0x3B,  0xC8,  0x0F,  0x82,
        0xC1,  0x03,  0x00,  0x00,  0x81,  0x3C,  0x19,  0x50,  0x45,  0x00,  0x00,  0x4C,  0x89,  0xAC,  0x24,
        0x80,  0x00,  0x00,  0x00,  0x4C,  0x8D,  0x2C,  0x19,  0x0F,  0x85,  0xA0,  0x03,  0x00,  0x00,  0x41,
        0x0F,  0xB7,  0x45,  0x16,  0xB9,  0x02,  0x20,  0x00,  0x00,  0x66,  0x23,  0xC1,  0x66,  0x3B,  0xC1,
        0x0F,  0x85,  0x8A,  0x03,  0x00,  0x00,  0xB8,  0xF0,  0x00,  0x00,  0x00,  0x66,  0x41,  0x39,  0x45,
        0x14,  0x0F,  0x85,  0x7A,  0x03,  0x00,  0x00,  0x45,  0x0F,  0xB7,  0x55,  0x06,  0x41,  0x8B,  0xD6,
        0x45,  0x85,  0xD2,  0x0F,  0x84,  0x7E,  0x00,  0x00,  0x00,  0x49,  0x8D,  0x8D,  0x18,  0x01,  0x00,
        0x00,  0x8B,  0x41,  0x04,  0x03,  0x01,  0x41,  0x3B,  0xC1,  0x0F,  0x87,  0x54,  0x03,  0x00,  0x00,
        0xFF,  0xC2,  0x48,  0x83,  0xC1,  0x28,  0x41,  0x3B,  0xD2,  0x7C,  0xE7,  0x45,  0x8B,  0x5D,  0x38,
        0x33,  0xD2,  0x41,  0x8B,  0x45,  0x54,  0x49,  0x8B,  0xFA,  0xFF,  0xC8,  0x4D,  0x8D,  0x95,  0x18,
        0x01,  0x00,  0x00,  0x41,  0x03,  0xC3,  0x41,  0xF7,  0xF3,  0x44,  0x8B,  0xC8,  0x45,  0x0F,  0xAF,
        0xCB,  0x0F,  0x1F,  0x00,  0x41,  0x8B,  0x4A,  0xF8,  0x41,  0x8D,  0x43,  0xFF,  0x41,  0x39,  0x0A,
        0x41,  0x0F,  0x4F,  0x0A,  0x33,  0xD2,  0x41,  0x03,  0x4A,  0xFC,  0x4D,  0x8D,  0x52,  0x28,  0x03,
        0xC1,  0x41,  0xF7,  0xF3,  0x41,  0x0F,  0xAF,  0xC3,  0x44,  0x3B,  0xC8,  0x41,  0x0F,  0x4D,  0xC1,
        0x44,  0x8B,  0xC8,  0x48,  0x83,  0xEF,  0x01,  0x75,  0xCE,  0x48,  0x8B,  0x7D,  0x7F,  0xEB,  0x15,
        0x41,  0x8B,  0x4D,  0x38,  0x41,  0x8B,  0x45,  0x54,  0xFF,  0xC8,  0x03,  0xC1,  0xF7,  0xF1,  0x44,
        0x8B,  0xC8,  0x44,  0x0F,  0xAF,  0xC9,  0x45,  0x85,  0xC9,  0x0F,  0x84,  0xCD,  0x02,  0x00,  0x00,
        0x49,  0x63,  0xC1,  0x48,  0x8D,  0x55,  0x67,  0x4C,  0x8D,  0x4D,  0xD7,  0xC7,  0x44,  0x24,  0x28,
        0x40,  0x00,  0x00,  0x00,  0x48,  0xC7,  0xC1,  0xFF,  0xFF,  0xFF,  0xFF,  0x48,  0x89,  0x45,  0xD7,
        0xC7,  0x44,  0x24,  0x20,  0x00,  0x10,  0x00,  0x00,  0xFF,  0xD6,  0x4C,  0x8B,  0x45,  0x67,  0x4D,
        0x85,  0xC0,  0x0F,  0x84,  0x98,  0x02,  0x00,  0x00,  0x45,  0x0F,  0xB7,  0x4D,  0x06,  0x41,  0x8B,
        0x45,  0x54,  0x43,  0x8D,  0x0C,  0x89,  0x8D,  0x0C,  0xC8,  0x48,  0x63,  0xD1,  0x85,  0xC9,  0x7E,
        0x27,  0x49,  0x8B,  0xCE,  0x66,  0x66,  0x66,  0x0F,  0x1F,  0x84,  0x00,  0x00,  0x00,  0x00,  0x00,
        0x0F,  0xB6,  0x04,  0x19,  0x42,  0x88,  0x04,  0x01,  0x48,  0xFF,  0xC1,  0x4C,  0x8B,  0x45,  0x67,
        0x48,  0x3B,  0xCA,  0x7C,  0xEC,  0x45,  0x0F,  0xB7,  0x4D,  0x06,  0x45,  0x8B,  0xDE,  0x66,  0x45,
        0x3B,  0xF1,  0x73,  0x5B,  0x49,  0x8D,  0x95,  0x18,  0x01,  0x00,  0x00,  0x0F,  0x1F,  0x80,  0x00,
        0x00,  0x00,  0x00,  0x8B,  0x42,  0xFC,  0x85,  0xC0,  0x74,  0x35,  0x44,  0x8B,  0x12,  0x45,  0x85,
        0xD2,  0x74,  0x2D,  0x4D,  0x8D,  0x0C,  0x00,  0x49,  0x8B,  0xCE,  0x66,  0x66,  0x0F,  0x1F,  0x84,
        0x00,  0x00,  0x00,  0x00,  0x00,  0x8B,  0x42,  0x04,  0x48,  0x03,  0xC1,  0x0F,  0xB6,  0x04,  0x18,
        0x42,  0x88,  0x04,  0x09,  0x48,  0xFF,  0xC1,  0x8B,  0x02,  0x48,  0x3B,  0xC8,  0x72,  0xE8,  0x4C,
        0x8B,  0x45,  0x67,  0x41,  0x0F,  0xB7,  0x45,  0x06,  0x41,  0xFF,  0xC3,  0x48,  0x83,  0xC2,  0x28,
        0x44,  0x3B,  0xD8,  0x7C,  0xB3,  0x41,  0x8B,  0x85,  0xB0,  0x00,  0x00,  0x00,  0x4C,  0x89,  0x7C,
        0x24,  0x78,  0x85,  0xC0,  0x0F,  0x84,  0xB5,  0x00,  0x00,  0x00,  0x45,  0x39,  0xB5,  0xB4,  0x00,
        0x00,  0x00,  0x0F,  0x86,  0xA8,  0x00,  0x00,  0x00,  0x41,  0x8B,  0x0C,  0x00,  0x4D,  0x8D,  0x14,
        0x00,  0x45,  0x8B,  0x4A,  0x04,  0x49,  0x8B,  0xD8,  0x49,  0x2B,  0x5D,  0x30,  0x41,  0x03,  0xC9,
        0x0F,  0x84,  0x8C,  0x00,  0x00,  0x00,  0xB9,  0x00,  0x30,  0x00,  0x00,  0xBE,  0x00,  0xA0,  0x00,
        0x00,  0x41,  0xBF,  0x00,  0xF0,  0x00,  0x00,  0x66,  0x0F,  0x1F,  0x44,  0x00,  0x00,  0x41,  0x8B,
        0xC1,  0x49,  0x8B,  0xD6,  0x48,  0x83,  0xE8,  0x08,  0x48,  0xD1,  0xE8,  0x4C,  0x63,  0xD8,  0x85,
        0xC0,  0x7E,  0x4B,  0x0F,  0x1F,  0x40,  0x00,  0x0F,  0x1F,  0x84,  0x00,  0x00,  0x00,  0x00,  0x00,
        0x45,  0x0F,  0xB7,  0x4C,  0x52,  0x08,  0x41,  0x0F,  0xB7,  0xC1,  0x66,  0x41,  0x23,  0xC7,  0x66,
        0x3B,  0xC1,  0x74,  0x05,  0x66,  0x3B,  0xC6,  0x75,  0x1B,  0x41,  0x8B,  0x0A,  0x41,  0x81,  0xE1,
        0xFF,  0x0F,  0x00,  0x00,  0x4B,  0x8D,  0x04,  0x08,  0x48,  0x01,  0x1C,  0x01,  0xB9,  0x00,  0x30,
        0x00,  0x00,  0x4C,  0x8B,  0x45,  0x67,  0x48,  0xFF,  0xC2,  0x49,  0x3B,  0xD3,  0x7C,  0xC5,  0x45,
        0x8B,  0x4A,  0x04,  0x41,  0x8B,  0xC1,  0x4C,  0x03,  0xD0,  0x41,  0x8B,  0x0A,  0x45,  0x8B,  0x4A,
        0x04,  0x41,  0x03,  0xC9,  0xB9,  0x00,  0x30,  0x00,  0x00,  0x75,  0x8A,  0x41,  0x8B,  0x85,  0x90,
        0x00,  0x00,  0x00,  0x48,  0x85,  0xC0,  0x0F,  0x84,  0x18,  0x01,  0x00,  0x00,  0x4E,  0x8D,  0x3C,
        0x00,  0x42,  0x8B,  0x04,  0x00,  0x85,  0xC0,  0x0F,  0x84,  0xEB,  0x00,  0x00,  0x00,  0x33,  0xD2,
        0x0F,  0x1F,  0x84,  0x00,  0x00,  0x00,  0x00,  0x00,  0x45,  0x8B,  0x77,  0x10,  0x48,  0x8D,  0x4D,
        0xF7,  0x48,  0x89,  0x55,  0x6F,  0x4D,  0x03,  0xF0,  0x41,  0x8B,  0x57,  0x0C,  0x8B,  0xF0,  0x49,
        0x03,  0xD0,  0x49,  0x03,  0xF0,  0xFF,  0xD7,  0x41,  0xB0,  0x01,  0x48,  0x8D,  0x55,  0xF7,  0x48,
        0x8D,  0x4D,  0x07,  0xFF,  0x55,  0xDF,  0x4C,  0x8D,  0x4D,  0x6F,  0x33,  0xD2,  0x4C,  0x8D,  0x45,
        0x07,  0x33,  0xC9,  0xFF,  0x55,  0xE7,  0x48,  0x8D,  0x4D,  0x07,  0xFF,  0x55,  0xEF,  0x48,  0x8B,
        0x4D,  0x6F,  0x48,  0x85,  0xC9,  0x0F,  0x84,  0xAC,  0x00,  0x00,  0x00,  0x48,  0x8B,  0x06,  0x33,
        0xD2,  0x8B,  0xDA,  0x48,  0x85,  0xC0,  0x74,  0x73,  0x8B,  0xFA,  0x0F,  0x1F,  0x40,  0x00,  0x48,
        0x89,  0x55,  0x77,  0x48,  0x85,  0xC0,  0x79,  0x11,  0x66,  0x85,  0xC0,  0x0F,  0x84,  0x88,  0x00,
        0x00,  0x00,  0x44,  0x0F,  0xB7,  0xC0,  0x33,  0xD2,  0xEB,  0x1F,  0x4C,  0x8B,  0x45,  0x67,  0x49,
        0x8D,  0x50,  0x02,  0x48,  0x03,  0xD0,  0x74,  0x77,  0x48,  0x8D,  0x4D,  0xF7,  0xFF,  0x55,  0x7F,
        0x48,  0x8B,  0x4D,  0x6F,  0x48,  0x8D,  0x55,  0xF7,  0x45,  0x33,  0xC0,  0x4C,  0x8D,  0x4D,  0x77,
        0x41,  0xFF,  0xD4,  0x48,  0x8B,  0x45,  0x77,  0x48,  0x85,  0xC0,  0x74,  0x51,  0x48,  0xFF,  0xC3,
        0x4A,  0x89,  0x04,  0x37,  0x33,  0xD2,  0x48,  0x8D,  0x3C,  0xDD,  0x00,  0x00,  0x00,  0x00,  0x48,
        0x8B,  0x04,  0x37,  0x48,  0x85,  0xC0,  0x74,  0x06,  0x48,  0x8B,  0x4D,  0x6F,  0xEB,  0x97,  0x48,
        0x8B,  0x7D,  0x7F,  0x41,  0x8B,  0x47,  0x14,  0x49,  0x83,  0xC7,  0x14,  0x4C,  0x8B,  0x45,  0x67,
        0x85,  0xC0,  0x0F,  0x85,  0x1F,  0xFF,  0xFF,  0xFF,  0x41,  0x8B,  0x45,  0x28,  0xBA,  0x01,  0x00,
        0x00,  0x00,  0x4D,  0x89,  0x45,  0x30,  0x48,  0x8B,  0x4D,  0x67,  0x48,  0x03,  0xC1,  0x4C,  0x8B,
        0xC1,  0xFF,  0xD0,  0x4C,  0x8B,  0x45,  0x67,  0x4C,  0x8B,  0x7C,  0x24,  0x78,  0x4C,  0x8B,  0xAC,
        0x24,  0x80,  0x00,  0x00,  0x00,  0x49,  0x8B,  0xC0,  0x48,  0x81,  0xC4,  0x88,  0x00,  0x00,  0x00,
        0x41,  0x5E,  0x41,  0x5C,  0x5F,  0x5E,  0x5B,  0x5D,  0xC3 };

    ULONG_PTR fileSize2 = sizeof(Code);//shellcode的大小
    if (hFile)
    {
        //获取DLL数据
        DWORD fileSize = GetFileSize(hFile, NULL);
        DWORD RSize = 0;
        PVOID pBuffer = malloc(fileSize);
        ReadFile(hFile, pBuffer, fileSize, &RSize, NULL);

        HMODULE NTDLL = GetModuleHandleA("ntdll");
        PARAMX param;
        RtlZeroMemory(&param, sizeof(PARAMX));
        param.lpFileData = pBuffer;
        param.DataLength = fileSize;
        param.LdrGetProcedureAddress = GetProcAddress(NTDLL, "LdrGetProcedureAddress");
        param.dwNtAllocateVirtualMemory = GetProcAddress(NTDLL, "NtAllocateVirtualMemory");
        param.pLdrLoadDll = GetProcAddress(NTDLL, "LdrLoadDll");
        param.RtlInitAnsiString = GetProcAddress(NTDLL, "RtlInitAnsiString");
        param.RtlAnsiStringToUnicodeString = GetProcAddress(NTDLL, "RtlAnsiStringToUnicodeString");
        param.RtlFreeUnicodeString = GetProcAddress(NTDLL, "RtlFreeUnicodeString");

        //开始远程注入
        HANDLE hProcess;
        OBJECT_ATTRIBUTES ObjectAttributes;
        CLIENT_ID Cid;
        //初始化
        InitializeObjectAttributes(&ObjectAttributes, 0, 0, 0, 0);
        Cid.UniqueProcess = (HANDLE)pid;
        Cid.UniqueThread = 0;
        pfnZwOpenProcess ZwOpenProcess = (pfnZwOpenProcess)GetProcAddress(NTDLL, "ZwOpenProcess");
        ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &Cid);
        if (hProcess != NULL)
        {
            //申请内存,把shellcode和DLL数据,和参数复制到目标进程
            PBYTE  pAddress = (PBYTE)VirtualAllocEx(hProcess, 0, fileSize + fileSize2 + sizeof(PARAMX) + 0x100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//安全起见,大小多加0x100
            param.lpFileData = pAddress;//修成下DLL数据的地址
            WriteProcessMemory(hProcess, pAddress, pBuffer, fileSize, &dWrited);//DLL数据写入到目标
            WriteProcessMemory(hProcess, pAddress + fileSize, Code, fileSize2, &dWrited);//shellcode写入到目标
            WriteProcessMemory(hProcess, pAddress + fileSize + fileSize2, &param, sizeof(PARAMX), &dWrited);//参数写入到目标
            //启动注入线程=pAddress+ fileSize,参数=pAddress+ fileSize+ fileSize2;
            HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)(pAddress + fileSize), pAddress + fileSize + fileSize2, 0, 0);
            if (hThread)
            {
                DWORD dExecCode = 0;
                OutputDebugStringA("[GN]:等待注入线程执行完毕....\n");
                WaitForSingleObject(hThread, -1);
                GetExitCodeThread(hThread, &dExecCode);
                bRet = true;
                CloseHandle(hThread);
                printf("注入成功,线程执行完毕，线程退出状态码%d\n", dExecCode);
                //释放掉申请的内存
                VirtualFreeEx(hProcess, pAddress, 0, MEM_FREE);
            }
            else
                OutputDebugStringA("[GN]:CreateRemoteThread() error\n");
            CloseHandle(hProcess);
        }
        else
            OutputDebugStringA("[GN]:ZwOpenProcess() error\n");
        CloseHandle(hFile);
        free(pBuffer);
    }
    return bRet;
}

//内核劫持线程注入
bool Driver::KernelHackThread(IN ULONG pid, IN ULONG64 param_buffer_address, IN ULONG64 loader_shellcode_address, IN LONG kernel_wait_millisecond, IN int readwrite_modle)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    InjectByHackThreadStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = pid;
    data.param_buffer_address = param_buffer_address;
    data.loader_shellcode_address = loader_shellcode_address;
    data.createthread_address = (ULONG64)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "CreateThread");
    data.readwrite_modle = (ReadWriteModle)readwrite_modle;
    data.kernel_wait_millisecond = kernel_wait_millisecond;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

DWORD Driver::mInjectByKernelHackThread(IN ULONG pid, IN PVOID dll_file_buffer, IN DWORD dll_file_buffer_size, IN LONG kernel_wait_millisecond, IN PVOID transfer_data, IN DWORD transfer_data_size)
{
//    NTSTATUS status = false;
//    PVOID target_dll_buffer = NULL;
//    PVOID param_buffer = NULL;
//    PVOID loadershellcode = NULL;
//    //PVOID start_code_address = NULL;
//
//    //判断是否为正常的PE头 不是整成PE头返回0
//    if (reinterpret_cast<IMAGE_DOS_HEADER*>(dll_file_buffer)->e_magic != IMAGE_DOS_SIGNATURE)
//        return 0;
//
//    //获取PE结构
//    IMAGE_NT_HEADERS* p_old_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>((LPBYTE)dll_file_buffer + reinterpret_cast<IMAGE_DOS_HEADER*>(dll_file_buffer)->e_lfanew);
//    IMAGE_OPTIONAL_HEADER* p_old_optional_header = &p_old_nt_header->OptionalHeader;
//    IMAGE_FILE_HEADER* p_old_file_header = &p_old_nt_header->FileHeader;
//
//    //筛选环境 不是当前Machine返回2
//    if (p_old_file_header->Machine != CURRENT_ARCH)
//        return 2;
//
//    //为反射注入做准备
//    do
//    {
//        //向目标进程申请可读可写内存写入dll数据，后续修改可执行，申请内存失败返回3
//        target_dll_buffer = this->AllocMemoryEx(pid, p_old_optional_header->SizeOfImage, PAGE_READWRITE);
//        if (!target_dll_buffer)
//            return 3;
//        //向目标进程申请的地址写入dll前0x1000个字节的PE头数据，写入失败返回4
//        if (!this->WriteBytesByMDLEx(pid, target_dll_buffer, dll_file_buffer, 0x1000))
//        {
//            OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() failed", __FUNCTION__);
//            status = 4;
//            break;
//        }
//        //向进程目标地址写入数据后修改可执行数据，失败返回5
//        if (!this->SetExecutePageEx(pid, (ULONG64)target_dll_buffer, p_old_optional_header->SizeOfImage))
//        {
//            OutputDebugStringA_1Param("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
//            status = 5;
//            break;
//        }
//
//        //向目标地址写入节表，失败返回6
//        IMAGE_SECTION_HEADER* p_section_header = IMAGE_FIRST_SECTION(p_old_nt_header);
//        if (!this->WriteSectionsEx(pid, (LPBYTE)dll_file_buffer, (LPBYTE)target_dll_buffer, p_section_header, p_old_file_header))
//        {
//            OutputDebugStringA_1Param("[GN]:%s-> WriteSections() failed", __FUNCTION__);
//            status = 6;
//            break;
//        }
//        OutputDebugStringA_1Param("[GN]:申请的dll_buffer地址：%p", target_dll_buffer);
//
//        //组装参数
//        MANUAL_MAPPING_DATA data{ 0 };
//        data.pLoadLibraryA = ::LoadLibraryA;
//        data.pGetProcAddress = ::GetProcAddress;
//#ifdef _WIN64
//        data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
//#else
//        bSEHExceptionSupport = false;
//#endif
//        data.pBase = (LPBYTE)target_dll_buffer;
//        data.fdwReasonParam = DLL_PROCESS_ATTACH;
//        data.reservedParam = 0;
//        data.SEHSupport = true;
//
//        //将准备的参数映射到目标进程，只申请可读可写内存，为写入数据后做可执行属性做铺垫，申请失败返回 7
//        param_buffer = this->AllocMemoryEx(pid, sizeof(MANUAL_MAPPING_DATA), PAGE_READWRITE);
//        if (!param_buffer)
//        {
//            OutputDebugStringA_1Param("[GN]:%s-> param_buffer is null", __FUNCTION__);
//            status = 7;
//            break;
//        }
//        //向目标进程写入准备的参数，失败返回8
//        if (!this->WriteBytesByMDLEx(pid, param_buffer, &data, sizeof(MANUAL_MAPPING_DATA)))
//        {
//            OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() failed", __FUNCTION__);
//            status = 8;
//            break;
//        }
//        //向目标进程写入数据后修改内核可执行属性，失败返回9
//        if (!this->SetExecutePageEx(pid, (ULONG64)param_buffer, sizeof(MANUAL_MAPPING_DATA)))
//        {
//            OutputDebugStringA_1Param("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
//            status = 9;
//            break;
//        }
//        OutputDebugStringA_1Param("[GN]:申请的param_buffer地址：%p", param_buffer);
//
//        //向目标进程申请写入loadershellcode的可读可写地址，后续修改可执行，失败返回10
//        loadershellcode = this->AllocMemoryEx(pid, 0x1000, PAGE_READWRITE);
//        if (!loadershellcode)
//        {
//            OutputDebugStringA_1Param("[GN]:%s-> shellcode is null", __FUNCTION__);
//            status = 10;
//            break;
//        }
//        //向目标进程写入shellcode，失败返回12
//        if (!this->WriteBytesByMDLEx(pid, loadershellcode, Driver::Shellcode, 0x1000))
//        {
//            OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() failed", __FUNCTION__);
//            status = 12;
//            break;
//        }
//        //向目标进程写入shellcode数据后，修改可执行属性，失败返回13
//        if (!this->SetExecutePageEx(pid, (ULONG64)loadershellcode, 0x1000))
//        {
//            OutputDebugStringA_1Param("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
//            status = 13;
//            break;
//        }
//        OutputDebugStringA_1Param("[GN]:申请的loadershellcode地址：%p", loadershellcode);
//        Sleep(50);//添加延时，防止顺序错乱导致卡顿！！！
//
//        //将启动参数传入内核进行劫持线程
//        if (!this->KernelHackThread(pid, (ULONG64)param_buffer, (ULONG64)loadershellcode, kernel_wait_millisecond))
//        {
//            OutputDebugStringA_1Param("[GN]:%s-> KernelHackThread() error", __FUNCTION__);
//            if (loadershellcode)
//                this->FreeMemoryEx(pid, (ULONG64)loadershellcode, 0x1000);
//            if (param_buffer)
//                this->FreeMemoryEx(pid, (ULONG64)param_buffer, sizeof(MANUAL_MAPPING_DATA));
//            break;
//        }
//
//        status = 1;
//        break;
//    } while (true);
//
//    //Sleep(2000);
//    OutputDebugStringA("[GN]:应用层释放空间");
//    if (loadershellcode)
//        this->FreeMemoryEx(pid, (ULONG64)loadershellcode, 0x1000);
//    if (param_buffer)
//        this->FreeMemoryEx(pid, (ULONG64)param_buffer, sizeof(MANUAL_MAPPING_DATA));
//    return status;


    DWORD status = true;
    DWORD TargetArchitecture = X86;
    DWORD DllArchitecture = UNKNOWN;
#if defined(_WIN64)
    DWORD CurrentArchitecture = X64;
#elif defined (_WIN32)
    DWORD CurrentArchitecture = X86;
#else
#endif

    __try
    {
        //参数错误：返回0
        if (!dll_file_buffer || !dll_file_buffer_size)
            return false;

        // 获得目标进程的Architecture, 获取进程信息失败返回2
        SYSTEM_INFO SystemInfo = { 0 };
        GetNativeSystemInfo(&SystemInfo);
        if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
            TargetArchitecture = X64;
        else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
            TargetArchitecture = X86;
        else
            return 2;

        //获得DLL的框架信息
        PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(((PUINT8)dll_file_buffer) + ((PIMAGE_DOS_HEADER)dll_file_buffer)->e_lfanew);
        if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // PE32
            DllArchitecture = X86;
        else if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // PE64
            DllArchitecture = X64;
        if (DllArchitecture != TargetArchitecture)//检查dll是否x64框架
        {
            OutputDebugStringA("[GN]:Must Be Same Architecture");
            //运行架构不相同返回3
            return 3;
        }

        //检查dll是否有定义的GuNianDLLLoader()加载dll函数
        DWORD ReflectiveLoaderOffset = SeGetReflectiveLoaderOffset(dll_file_buffer);
        if (!ReflectiveLoaderOffset)
        {
            OutputDebugStringA("[GN]:Could Not Get ReflectiveLoader Offset");
            //无法获取反射偏移返回4
            return 4;
        }

        //向目标进程申请DLL内存空间和shellcode空间
        LPVOID RemoteBufferData = this->AllocMemory(dll_file_buffer_size + transfer_data_size, PAGE_EXECUTE_READWRITE);
        //申请地址失败返回5
        if (!RemoteBufferData)
            return 5;
        //向目标进程写入DLL数据
        this->WriteBytesByMDL(RemoteBufferData, dll_file_buffer, dll_file_buffer_size);
#ifdef _INFORELEASE
        OutputDebugStringA_2Param("[GN]:Dll buffer address:%p,Dll buffer size:%p", RemoteBufferData, dll_file_buffer_size);
#endif

        ULONG_PTR ReflectiveLoader = (ULONG_PTR)RemoteBufferData + ReflectiveLoaderOffset;
        //得到用户数据地址 = DLL数据+DLL数据大小
        ULONG_PTR RemoteUserData = (ULONG_PTR)RemoteBufferData + dll_file_buffer_size;
        //向目标进程写入用户数据
        this->WriteBytesByMDL((PVOID)RemoteUserData, transfer_data, transfer_data_size);

        //得到远程shellcode地址 = dll数据 + 用户数据 + transfer大小
        ULONG_PTR RemoteShellCode = RemoteUserData + transfer_data_size;
        BYTE Bootstrap[64] = { 0 };
        DWORD BootstrapLength = SeCreateBootstrap(Bootstrap, 64, TargetArchitecture, (ULONG_PTR)NULL, (ULONG_PTR)RemoteBufferData, MYFUNCTION_HASH, RemoteUserData, transfer_data_size, ReflectiveLoader);
        //启动参数长度为0 返回8
        if (BootstrapLength <= 0)
            return 8;
        //将启动dll的shellcode写入目标进程
this->WriteBytesByMDL((PVOID)RemoteShellCode, Bootstrap, BootstrapLength);
#ifdef _INFORELEASE
OutputDebugStringA_1Param("[GN]:LoaderShellCode address:%p\n", RemoteShellCode);
#endif

//将启动参数传入内核进行劫持线程
if (!this->KernelHackThread(pid, (ULONG64)NULL, (ULONG64)RemoteShellCode, kernel_wait_millisecond, _ReadWriteModle::MDL))
{
    OutputDebugStringA_1Param("[GN]:%s-> KernelHackThread() error", __FUNCTION__);

    this->FreeMemory((ULONG64)RemoteBufferData, dll_file_buffer_size + transfer_data_size);
    return 9999;
}

this->FreeMemory((ULONG64)RemoteBufferData, dll_file_buffer_size + transfer_data_size);
status = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = 999;
    }
    return status;
}

bool Driver::InjectByKernelHackThread(IN PVOID file_buffer, IN DWORD file_buffer_size, IN LONG kernel_wait_millisecond, IN PVOID transfer_data, IN DWORD transfer_data_size)
{
    DWORD status = this->mInjectByKernelHackThread(this->m_pid, file_buffer, file_buffer_size, kernel_wait_millisecond, transfer_data, transfer_data_size);
    if (status != true)
    {
        OutputDebugStringA_1Param("[GN]:mInjectByKernelHackThread() errorcode:%d", status);
        return false;
    }
    return status;
}

bool Driver::InjectByKernelHackThreadEx(IN ULONG pid, IN PVOID file_buffer, IN DWORD file_buffer_size, IN LONG kernel_wait_millisecond, IN PVOID transfer_data, IN DWORD transfer_data_size)
{
    DWORD status = this->mInjectByKernelHackThread(pid, file_buffer, file_buffer_size, kernel_wait_millisecond, transfer_data, transfer_data_size);
    if (status != true)
    {
        OutputDebugStringA_1Param("[GN]:mInjectByKernelHackThread() errorcode:%d", status);
        return false;
    }
    return status;
}

//拉伸PE
bool Driver::InitPELoader(IN ULONG pid, IN PVOID dll_file_buffer, IN PVOID* target_dll_file_buffer_address, OUT DWORD64* shellcode_address, OUT DWORD64* shellcode_param_address, IN int readwrite_modle)
{
    //解析DOS头
    PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)dll_file_buffer;
    if (p_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }
    //解析PE头
    PIMAGE_NT_HEADERS p_nt_header = (PIMAGE_NT_HEADERS)((DWORD64)dll_file_buffer + p_dos_header->e_lfanew);
    //获取节表
    PIMAGE_SECTION_HEADER p_section_header = IMAGE_FIRST_SECTION(p_nt_header);
    PIMAGE_OPTIONAL_HEADER p_optional_header = (PIMAGE_OPTIONAL_HEADER)&p_nt_header->OptionalHeader;
    PIMAGE_FILE_HEADER p_file_header = (PIMAGE_FILE_HEADER)&p_nt_header->FileHeader;

    //向目标进程申请拉伸后的DLL内存空间
    *target_dll_file_buffer_address = this->AllocMemoryEx(pid, p_optional_header->SizeOfImage + sizeof(MANUAL_MAPPING_DATA) + 0x1000, PAGE_READWRITE);
    if (!*(DWORD64*)target_dll_file_buffer_address)
    {
#if _INFORELEASE
        OutputDebugStringA_1Param("[GN]:%s-> p_target_dll_buffer is null!", __FUNCTION__);
#endif
        return false;
    }

    //向目标进程写入dll_buffer前0x1000个字节的PE头数据
    if ((_ReadWriteModle)readwrite_modle == _ReadWriteModle::MDL)
    {
        if (!this->WriteBytesByMDLEx(pid, (PVOID) * (DWORD64*)target_dll_file_buffer_address, dll_file_buffer, 0x1000))
        {
#if _INFORELEASE
            OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() dll_buffer PE header failed", __FUNCTION__);
#endif
            return false;
        }
    }
    else if ((_ReadWriteModle)readwrite_modle == _ReadWriteModle::CR3NOATTACH)
    {
        this->WriteBytesByCR3NoAttachEx(pid, (PVOID) * (DWORD64*)target_dll_file_buffer_address, dll_file_buffer, 0x1000);
//        if (!this->WriteBytesByCR3NoAttachEx(pid, (PVOID) * (DWORD64*)target_dll_file_buffer_address, dll_file_buffer, 0x1000))
//        {
//#if _INFORELEASE
//            OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByCR3NoAttachEx() dll_buffer PE header failed", __FUNCTION__);
//#endif
//            return false;
//        }
    }

    //向目标进程写入节表数据
    for (int i = 0; i != p_file_header->NumberOfSections; ++i, ++p_section_header)
    {
        if (p_section_header->SizeOfRawData)
        {
            if ((_ReadWriteModle)readwrite_modle == _ReadWriteModle::MDL)
            {
                if (!this->WriteBytesByMDLEx(pid, (PVOID)(*(DWORD64*)target_dll_file_buffer_address + p_section_header->VirtualAddress),
                    (PVOID)((DWORD64)dll_file_buffer + p_section_header->PointerToRawData),
                    p_section_header->SizeOfRawData))
                {
#if _INFORELEASE
                    OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() writesections failed", __FUNCTION__);
#endif
                    return false;
                }
            }
            else if ((_ReadWriteModle)readwrite_modle == _ReadWriteModle::CR3NOATTACH)
            {
                this->WriteBytesByCR3NoAttachEx(pid, (PVOID)(*(DWORD64*)target_dll_file_buffer_address + p_section_header->VirtualAddress),
                    (PVOID)((DWORD64)dll_file_buffer + p_section_header->PointerToRawData),
                    p_section_header->SizeOfRawData);
//                if (!this->WriteBytesByCR3NoAttachEx(pid, (PVOID)(*(DWORD64*)target_dll_file_buffer_address + p_section_header->VirtualAddress),
//                    (PVOID)((DWORD64)dll_file_buffer + p_section_header->PointerToRawData),
//                    p_section_header->SizeOfRawData))
//                {
//#if _INFORELEASE
//                    OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() writesections failed", __FUNCTION__);
//#endif
//                    return false;
//                }
            }
        }
    }

    //定位参数地址
    *shellcode_param_address = *(DWORD64*)target_dll_file_buffer_address + p_optional_header->SizeOfImage;
    //组装参数
    MANUAL_MAPPING_DATA mapping_data = { NULL };
    mapping_data.pLoadLibraryA = ::LoadLibraryA;
    mapping_data.pGetProcAddress = ::GetProcAddress;
#if _WIN64
    mapping_data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#endif
    mapping_data.pBase = (PBYTE)*(DWORD64*)target_dll_file_buffer_address;
    mapping_data.fdwReasonParam = DLL_PROCESS_ATTACH;
    mapping_data.reservedParam = NULL;
    mapping_data.SEHSupport = true;
    //将参数映射到目标进程
    if ((_ReadWriteModle)readwrite_modle == _ReadWriteModle::MDL)
    {
        if (!this->WriteBytesByMDLEx(pid, (PVOID) * (DWORD64*)shellcode_param_address, &mapping_data, sizeof(MANUAL_MAPPING_DATA)))
        {
#if _INFORELEASE
            OutputDebugStringA_1Param("[GN]:%s-> mapping_data write to target process error!", __FUNCTION__);
#endif
            return false;
        }
    }
    else if ((_ReadWriteModle)readwrite_modle == _ReadWriteModle::CR3NOATTACH)
    {
        if (!this->WriteBytesByCR3NoAttachEx(pid, (PVOID) * (DWORD64*)shellcode_param_address, &mapping_data, sizeof(MANUAL_MAPPING_DATA)))
        {
#if _INFORELEASE
            OutputDebugStringA_1Param("[GN]:%s-> mapping_data write to target process error!", __FUNCTION__);
#endif
            return false;
        }
    }

    //定位内存加载shellcode地址
    *shellcode_address = *(DWORD64*)target_dll_file_buffer_address + p_optional_header->SizeOfImage + sizeof(MANUAL_MAPPING_DATA);
    //向目标进程写入ShellCode数据
    if ((_ReadWriteModle)readwrite_modle == _ReadWriteModle::MDL)
    {
        if (!this->WriteBytesByMDLEx(pid, (PVOID) * (DWORD64*)shellcode_address, (PVOID)Driver::Shellcode, 0x1000))
        {
#if _INFORELEASE
            OutputDebugStringA_1Param("[GN]:%s-> write shellcode to target process is error!", __FUNCTION__);
#endif
            return false;
        }
    }
    else if ((_ReadWriteModle)readwrite_modle == _ReadWriteModle::CR3NOATTACH)
    {
        this->WriteBytesByCR3NoAttachEx(pid, (PVOID)* (DWORD64*)shellcode_address, (PVOID)Driver::Shellcode, 0x1000);
//        if (!this->WriteBytesByCR3NoAttachEx(pid, (PVOID) * (DWORD64*)shellcode_address, (PVOID)Driver::Shellcode, 0x1000))
//        {
//#if _INFORELEASE
//            OutputDebugStringA_1Param("[GN]:%s-> write shellcode to target process is error!", __FUNCTION__);
//#endif
//            return false;
//        }
    }

    //修改目标进程PE缓冲区可执行属性
    if (!this->SetExecutePageEx(pid, *(DWORD64*)target_dll_file_buffer_address, p_optional_header->SizeOfImage + sizeof(MANUAL_MAPPING_DATA) + 0x1000))
    {
#if _INFORELEASE
        OutputDebugStringA_1Param("[GN]:%s-> SetExecutePageEx() error!", __FUNCTION__);
#endif
        return false;
    }

    return true;
}

DWORD Driver::mInjectByKernelHackThreadMemoryLoad(IN ULONG pid, IN PVOID dll_file_buffer, IN DWORD dll_file_buffer_size, IN LONG kernel_wait_millisecond, IN int readwrite_modle)
{
    //参数检查
    if (!dll_file_buffer || !pid)
    {
#if _INFORELEASE
        OutputDebugStringA_1Param("[GN]:%s-> param check is error!", __FUNCTION__);
#endif
        return false;
    }

    //向目标进程申请的dll内存地址
    PVOID p_target_dll_buffer_address = NULL;
    //memory_loader_shellcode地址
    DWORD64 p_memory_loader_shellcode = NULL;
    //memory_loader_shellcode_param地址
    DWORD64 p_memory_loader_shellcode_param = NULL;
    //拉伸PE
    if (!this->InitPELoader(pid, dll_file_buffer, &p_target_dll_buffer_address, &p_memory_loader_shellcode, &p_memory_loader_shellcode_param, readwrite_modle))
    {
#if _INFORELEASE
        OutputDebugStringA_1Param("[GN]:%s-> InitPELoader() is error!", __FUNCTION__);
#endif
        return 2;
    }

#if _INFORELEASE
    OutputDebugStringA_1Param("[GN]:dll_base_address:%p", p_target_dll_buffer_address);
    OutputDebugStringA_1Param("[GN]:memory_loader_shellcode64_address:%p", p_memory_loader_shellcode);
    OutputDebugStringA_1Param("[GN]:memory_loader_shellcode64_param_address:%p", p_memory_loader_shellcode_param);
#endif

    //进入内核劫持线程
    bool return_value = this->KernelHackThread(pid, (ULONG64)p_memory_loader_shellcode_param, p_memory_loader_shellcode, kernel_wait_millisecond, readwrite_modle);

    //清除shellcode和shellcode_param
    if ((_ReadWriteModle)readwrite_modle == _ReadWriteModle::MDL)
    {
        this->WriteBytesByMDLEx(pid, (PVOID)p_memory_loader_shellcode_param, new BYTE[sizeof(MANUAL_MAPPING_DATA)]{ 0x00 }, sizeof(MANUAL_MAPPING_DATA));
        this->WriteBytesByMDLEx(pid, (PVOID)p_memory_loader_shellcode, new BYTE[0x1000]{ 0x00 }, 0x1000);
    }
    else if ((_ReadWriteModle)readwrite_modle == _ReadWriteModle::CR3NOATTACH)
    {
        this->WriteBytesByCR3NoAttachEx(pid, (PVOID)p_memory_loader_shellcode_param, new BYTE[sizeof(MANUAL_MAPPING_DATA)]{ 0x00 }, sizeof(MANUAL_MAPPING_DATA));
        this->WriteBytesByCR3NoAttachEx(pid, (PVOID)p_memory_loader_shellcode, new BYTE[0x1000]{ 0x00 }, 0x1000);
    }

    return return_value;
}

bool Driver::InjectByKernelHackThreadMemoryLoad(IN PVOID dll_file_buffer, IN DWORD dll_file_buffer_size, IN LONG kernel_wait_millisecond, IN _ReadWriteModle readwrite_modle)
{
    DWORD status = this->mInjectByKernelHackThreadMemoryLoad(this->m_pid, dll_file_buffer, dll_file_buffer_size, kernel_wait_millisecond, readwrite_modle);
    if (status != true)
    {
        OutputDebugStringA_1Param("[GN]:mInjectByKernelHackThreadMemoryLoad() errorcode:%d", status);
        return false;
    }
    return status;
}

bool Driver::InjectByKernelHackThreadMemoryLoadEx(IN ULONG pid, IN PVOID dll_file_buffer, IN DWORD dll_file_buffer_size, IN LONG kernel_wait_millisecond, IN _ReadWriteModle readwrite_modle)
{
    DWORD status = this->mInjectByKernelHackThreadMemoryLoad(pid, dll_file_buffer, dll_file_buffer_size, kernel_wait_millisecond, readwrite_modle);
    if (status != true)
    {
        //OutputDebugStringA_1Param("[GN]:mInjectByKernelHackThreadMemoryLoad() errorcode:%d", status);
        return false;
    }
    return status;
}

//内核创建线程注入
bool Driver::NtCreateThreadByKernel(IN ULONG pid, IN ULONG64 param_buffer_address, IN ULONG64 loader_shellcode_address, IN LONG kernel_wait_millisecond)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    InjectByHackThreadStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = pid;
    data.param_buffer_address = param_buffer_address;
    data.loader_shellcode_address = loader_shellcode_address;
    data.kernel_wait_millisecond = kernel_wait_millisecond;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

DWORD Driver::mInjectByKernelCreateThread(IN ULONG pid, IN PVOID dll_file_buffer, IN DWORD dll_file_buffer_size, IN LONG kernel_wait_millisecond)
{
    NTSTATUS status = false;
    PVOID target_dll_buffer = NULL;
    PVOID param_buffer = NULL;
    PVOID loadershellcode = NULL;
    //PVOID start_code_address = NULL;

    //判断是否为正常的PE头 不是整成PE头返回0
    if (reinterpret_cast<IMAGE_DOS_HEADER*>(dll_file_buffer)->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    //获取PE结构
    IMAGE_NT_HEADERS* p_old_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>((LPBYTE)dll_file_buffer + reinterpret_cast<IMAGE_DOS_HEADER*>(dll_file_buffer)->e_lfanew);
    IMAGE_OPTIONAL_HEADER* p_old_optional_header = &p_old_nt_header->OptionalHeader;
    IMAGE_FILE_HEADER* p_old_file_header = &p_old_nt_header->FileHeader;

    //筛选环境 不是当前Machine返回2
    if (p_old_file_header->Machine != CURRENT_ARCH)
        return 2;

    //为反射注入做准备
    do
    {
        //向目标进程申请可读可写内存写入dll数据，后续修改可执行，申请内存失败返回3
        target_dll_buffer = this->AllocMemoryEx(pid, p_old_optional_header->SizeOfImage, PAGE_READWRITE);
        if (!target_dll_buffer)
            return 3;
        //向目标进程申请的地址写入dll前0x1000个字节的PE头数据，写入失败返回4
        if (!this->WriteBytesByMDLEx(pid, target_dll_buffer, dll_file_buffer, 0x1000))
        {
            OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() failed", __FUNCTION__);
            status = 4;
            break;
        }
        //向进程目标地址写入数据后修改可执行数据，失败返回5
        if (!this->SetExecutePageEx(pid, (ULONG64)target_dll_buffer, p_old_optional_header->SizeOfImage))
        {
            OutputDebugStringA_1Param("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
            status = 5;
            break;
        }

        //向目标地址写入节表，失败返回6
        IMAGE_SECTION_HEADER* p_section_header = IMAGE_FIRST_SECTION(p_old_nt_header);
        if (!this->WriteSectionsEx(pid, (LPBYTE)dll_file_buffer, (LPBYTE)target_dll_buffer, p_section_header, p_old_file_header))
        {
            OutputDebugStringA_1Param("[GN]:%s-> WriteSections() failed", __FUNCTION__);
            status = 6;
            break;
        }
        //OutputDebugStringA_1Param("[GN]:申请的dll_buffer地址：%p", target_dll_buffer);

        //组装参数
        MANUAL_MAPPING_DATA data{ 0 };
        data.pLoadLibraryA = ::LoadLibraryA;
        data.pGetProcAddress = ::GetProcAddress;
#ifdef _WIN64
        data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
//#else
//        bSEHExceptionSupport = false;
#endif
        data.pBase = (LPBYTE)target_dll_buffer;
        data.fdwReasonParam = DLL_PROCESS_ATTACH;
        data.reservedParam = 0;
        data.SEHSupport = true;

        //将准备的参数映射到目标进程，只申请可读可写内存，为写入数据后做可执行属性做铺垫，申请失败返回 7
        param_buffer = this->AllocMemoryEx(pid, sizeof(MANUAL_MAPPING_DATA), PAGE_READWRITE);
        if (!param_buffer)
        {
            OutputDebugStringA_1Param("[GN]:%s-> param_buffer is null", __FUNCTION__);
            status = 7;
            break;
        }
        //向目标进程写入准备的参数，失败返回8
        if (!this->WriteBytesByMDLEx(pid, param_buffer, &data, sizeof(MANUAL_MAPPING_DATA)))
        {
            OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() failed", __FUNCTION__);
            status = 8;
            break;
        }
        //向目标进程写入数据后修改内核可执行属性，失败返回9
        if (!this->SetExecutePageEx(pid, (ULONG64)param_buffer, sizeof(MANUAL_MAPPING_DATA)))
        {
            OutputDebugStringA_1Param("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
            status = 9;
            break;
        }
        OutputDebugStringA_1Param("[GN]:申请的param_buffer地址：%p", param_buffer);

        //向目标进程申请写入loadershellcode的可读可写地址，后续修改可执行，失败返回10
        loadershellcode = this->AllocMemoryEx(pid, 0x1000, PAGE_READWRITE);
        if (!loadershellcode)
        {
            OutputDebugStringA_1Param("[GN]:%s-> shellcode is null", __FUNCTION__);
            status = 10;
            break;
        }
        //向目标进程写入shellcode，失败返回12
        if (!this->WriteBytesByMDLEx(pid, loadershellcode, Driver::Shellcode, 0x1000))
        {
            OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() failed", __FUNCTION__);
            status = 12;
            break;
        }
        //向目标进程写入shellcode数据后，修改可执行属性，失败返回13
        if (!this->SetExecutePageEx(pid, (ULONG64)loadershellcode, 0x1000))
        {
            OutputDebugStringA_1Param("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
            status = 13;
            break;
        }
        OutputDebugStringA_1Param("[GN]:申请的loadershellcode地址：%p", loadershellcode);
        Sleep(5);//添加延时，防止顺序错乱导致异常

        //将启动参数传入内核进行创建线程
        if (!this->NtCreateThreadByKernel(pid, (ULONG64)param_buffer, (ULONG64)loadershellcode, kernel_wait_millisecond))
        {
            OutputDebugStringA_1Param("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
            status = false;
            break;
        }

        status = 1;
        break;
    } while (true);

    Sleep(20000);
    OutputDebugStringA("[GN]:应用层释放空间");
    if (loadershellcode)
        this->FreeMemoryEx(pid, (ULONG64)loadershellcode, 0x1000);
    if (param_buffer)
        this->FreeMemoryEx(pid, (ULONG64)param_buffer, sizeof(MANUAL_MAPPING_DATA));
    return status;
}

bool Driver::InjectByKernelCreateThread(IN PVOID file_buffer, IN DWORD file_buffer_size, IN LONG kernel_wait_millisecond)
{
    DWORD status = this->mInjectByKernelCreateThread(this->m_pid, file_buffer, file_buffer_size, kernel_wait_millisecond);
    if (status != true)
    {
        OutputDebugStringA_1Param("[GN]:mInjectByKernelCreateThread() errorcode:%d", status);
        return false;
    }
    return status;
}

bool Driver::InjectByKernelCreateThreadEx(IN ULONG pid, IN PVOID file_buffer, IN DWORD file_buffer_size, IN LONG kernel_wait_millisecond)
{
    DWORD status = this->mInjectByKernelCreateThread(pid, file_buffer, file_buffer_size, kernel_wait_millisecond);
    if (status != true)
    {
        OutputDebugStringA_1Param("[GN]:mInjectByKernelCreateThread() errorcode:%d", status);
        return false;
    }
    return status;
}

//内核进程回调注入
bool Driver::KernelCallback(IN ULONG pid, IN ULONG64 param_buffer_address, IN ULONG64 loader_shellcode_address, IN ULONG64 rtlcapturecontext_address, IN ULONG64 ntcontinue_address, IN LONG kernel_wait_millisecond, IN BOOL isclear_proccallback)
{
    ULONG dwWrite;
    PVOID return_buffer = NULL;
    InjectByInstCallbackStruct data = { NULL };

    data.control_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS);
    data.pid = pid;
    data.param_buffer_address = param_buffer_address;
    data.loader_shellcode_address = loader_shellcode_address;
    data.createthread_address = (ULONG64)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "CreateThread");
    data.kernel_wait_millisecond = kernel_wait_millisecond;
    data.RtlCaptureContext = rtlcapturecontext_address;
    data.NtContinue = ntcontinue_address;
    data.isclear_proccallback = isclear_proccallback;

    HANDLE hDevice = CreateFile(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#if CURRENT_IO_DISPATCH==_HACK_IO_DISPATCH
    DeviceIoControl(hDevice, 0, &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#else
    DeviceIoControl(hDevice, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS), &data, sizeof(data), &return_buffer, sizeof(return_buffer), &dwWrite, NULL);
#endif
    CloseHandle(hDevice);

    if (NT_SUCCESS(return_buffer))
        return true;
    else
        return false;
}

DWORD Driver::mInjectByProcessCallback(IN ULONG pid, IN PVOID dll_file_buffer, IN DWORD dll_file_buffer_size, IN LONG kernel_wait_millisecond, IN BOOL isclear_proccallback)
{
    NTSTATUS status = false;
    PVOID target_dll_buffer = NULL;
    PVOID param_buffer = NULL;
    PVOID loadershellcode = NULL;
    //PVOID start_code_address = NULL;

    //判断是否为正常的PE头 不是整成PE头返回0
    if (reinterpret_cast<IMAGE_DOS_HEADER*>(dll_file_buffer)->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    //获取PE结构
    IMAGE_NT_HEADERS* p_old_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>((LPBYTE)dll_file_buffer + reinterpret_cast<IMAGE_DOS_HEADER*>(dll_file_buffer)->e_lfanew);
    IMAGE_OPTIONAL_HEADER* p_old_optional_header = &p_old_nt_header->OptionalHeader;
    IMAGE_FILE_HEADER* p_old_file_header = &p_old_nt_header->FileHeader;

    //筛选环境 不是当前Machine返回2
    if (p_old_file_header->Machine != CURRENT_ARCH)
        return 2;

    //为反射注入做准备
    do
    {
        //向目标进程申请可读可写内存写入dll数据，后续修改可执行，申请内存失败返回3
        target_dll_buffer = this->AllocMemoryEx(pid, p_old_optional_header->SizeOfImage, PAGE_READWRITE);
        if (!target_dll_buffer)
            return 3;
        //向目标进程申请的地址写入dll前0x1000个字节的PE头数据，写入失败返回4
        if (!this->WriteBytesByMDLEx(pid, target_dll_buffer, dll_file_buffer, 0x1000))
        {
            OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() failed", __FUNCTION__);
            status = 4;
            break;
        }
        //向进程目标地址写入数据后修改可执行数据，失败返回5
        if (!this->SetExecutePageEx(pid, (ULONG64)target_dll_buffer, p_old_optional_header->SizeOfImage))
        {
            OutputDebugStringA_1Param("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
            status = 5;
            break;
        }

        //向目标地址写入节表，失败返回6
        IMAGE_SECTION_HEADER* p_section_header = IMAGE_FIRST_SECTION(p_old_nt_header);
        if (!this->WriteSectionsEx(pid, (LPBYTE)dll_file_buffer, (LPBYTE)target_dll_buffer, p_section_header, p_old_file_header))
        {
            OutputDebugStringA_1Param("[GN]:%s-> WriteSections() failed", __FUNCTION__);
            status = 6;
            break;
        }
        //OutputDebugStringA_1Param("[GN]:申请的dll_buffer地址：%p", target_dll_buffer);

        //组装参数
        MANUAL_MAPPING_DATA data{ 0 };
        data.pLoadLibraryA = ::LoadLibraryA;
        data.pGetProcAddress = ::GetProcAddress;
#ifdef _WIN64
        data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
//#else
//        bSEHExceptionSupport = false;
#endif
        data.pBase = (LPBYTE)target_dll_buffer;
        data.fdwReasonParam = DLL_PROCESS_ATTACH;
        data.reservedParam = 0;
        data.SEHSupport = true;

        //将准备的参数映射到目标进程，只申请可读可写内存，为写入数据后做可执行属性做铺垫，申请失败返回 7
        param_buffer = this->AllocMemoryEx(pid, sizeof(MANUAL_MAPPING_DATA), PAGE_READWRITE);
        if (!param_buffer)
        {
            OutputDebugStringA_1Param("[GN]:%s-> param_buffer is null", __FUNCTION__);
            status = 7;
            break;
        }
        //向目标进程写入准备的参数，失败返回8
        if (!this->WriteBytesByMDLEx(pid, param_buffer, &data, sizeof(MANUAL_MAPPING_DATA)))
        {
            OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() failed", __FUNCTION__);
            status = 8;
            break;
        }
        //向目标进程写入数据后修改内核可执行属性，失败返回9
        if (!this->SetExecutePageEx(pid, (ULONG64)param_buffer, sizeof(MANUAL_MAPPING_DATA)))
        {
            OutputDebugStringA_1Param("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
            status = 9;
            break;
        }
        OutputDebugStringA_1Param("[GN]:申请的param_buffer地址：%p", param_buffer);

        //向目标进程申请写入loadershellcode的可读可写地址，后续修改可执行，失败返回10
        loadershellcode = this->AllocMemoryEx(pid, 0x1000, PAGE_READWRITE);
        if (!loadershellcode)
        {
            OutputDebugStringA_1Param("[GN]:%s-> shellcode is null", __FUNCTION__);
            status = 10;
            break;
        }
        //向目标进程写入shellcode，失败返回12
        if (!this->WriteBytesByMDLEx(pid, loadershellcode, Driver::Shellcode, 0x1000))
        {
            OutputDebugStringA_1Param("[GN]:%s-> WriteBytesByMDL() failed", __FUNCTION__);
            status = 12;
            break;
        }
        //向目标进程写入shellcode数据后，修改可执行属性，失败返回13
        if (!this->SetExecutePageEx(pid, (ULONG64)loadershellcode, 0x1000))
        {
            OutputDebugStringA_1Param("[GN]:%s-> SetExecutePage() failed", __FUNCTION__);
            status = 13;
            break;
        }
        OutputDebugStringA_1Param("[GN]:申请的loadershellcode地址：%p", loadershellcode);
        Sleep(50);//添加延时，防止顺序错乱导致异常

        //将启动参数传入内核回调函数
        if (!this->KernelCallback(pid, (ULONG64)param_buffer, (ULONG64)loadershellcode,
            (ULONG64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCaptureContext"),
            (ULONG64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtContinue"),
            kernel_wait_millisecond, isclear_proccallback))
        {
            OutputDebugStringA("[GN]:%s-> KernelCallback() error");
            status = 999;
            break;
        }

        status = 1;
        break;
    } while (true);

    //释放申请的内存
    if (loadershellcode)
        this->FreeMemoryEx(pid, (ULONG64)loadershellcode, 0x1000);
    if (param_buffer)
        this->FreeMemoryEx(pid, (ULONG64)param_buffer, sizeof(MANUAL_MAPPING_DATA));
    return status;
}

bool Driver::InjectByProcessCallback(IN PVOID file_buffer, IN DWORD file_buffer_size, IN LONG kernel_wait_millisecond, IN BOOL isclear_proccallback)
{
    DWORD status = this->mInjectByProcessCallback(this->m_pid, file_buffer, file_buffer_size, kernel_wait_millisecond, isclear_proccallback);
    if (status != true)
    {
        OutputDebugStringA_1Param("[GN]:mInjectByKernelCreateThread() errorcode:%d", status);
        return false;
    }
    return true;
}

bool Driver::InjectByProcessCallbackEx(IN ULONG pid, IN PVOID file_buffer, IN DWORD file_buffer_size, IN LONG kernel_wait_millisecond, IN BOOL isclear_proccallback)
{
    DWORD status = this->mInjectByProcessCallback(pid, file_buffer, file_buffer_size, kernel_wait_millisecond, isclear_proccallback);
    if (status != true)
    {
        OutputDebugStringA_1Param("[GN]:mInjectByProcessCallback() errorcode:%d", status);
        return false;
    }
    return true;
}


