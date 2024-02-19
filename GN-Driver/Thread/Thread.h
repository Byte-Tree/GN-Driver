#pragma once
#include "../pch.h"
#include <intrin.h>

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,// 0 Y N
	SystemProcessorInformation,// 1 Y N
	SystemPerformanceInformation,// 2 Y N
	SystemTimeOfDayInformation,// 3 Y N
	SystemNotImplemented1,// 4 Y N // SystemPathInformation
	SystemProcessesAndThreadsInformation,// 5 Y N
	SystemCallCounts,// 6 Y N
	SystemConfigurationInformation,// 7 Y N
	SystemProcessorTimes,// 8 Y N
	SystemGlobalFlag,// 9 Y Y
	SystemNotImplemented2,// 10 YN // SystemCallTimeInformation
	SystemModuleInformation,// 11 YN
	SystemLockInformation,// 12 YN
	SystemNotImplemented3,// 13 YN // SystemStackTraceInformation
	SystemNotImplemented4,// 14 YN // SystemPagedPoolInformation
	SystemNotImplemented5,// 15 YN // SystemNonPagedPoolInformation
	SystemHandleInformation,// 16 YN
	SystemObjectInformation,// 17 YN
	SystemPagefileInformation,// 18 YN
	SystemInstructionEmulationCounts,// 19 YN
	SystemInvalidInfoClass1,// 20
	SystemCacheInformation,// 21 YY
	SystemPoolTagInformation,// 22 YN
	SystemProcessorStatistics,// 23 YN
	SystemDpcInformation,// 24 YY
	SystemNotImplemented6,// 25 YN // SystemFullMemoryInformation
	SystemLoadImage,// 26 NY // SystemLoadGdiDriverInformation
	SystemUnloadImage,// 27 NY
	SystemTimeAdjustment,// 28 YY
	SystemNotImplemented7,// 29 YN // SystemSummaryMemoryInformation
	SystemNotImplemented8,// 30 YN // SystemNextEventIdInformation
	SystemNotImplemented9,// 31 YN // SystemEventIdsInformation
	SystemCrashDumpInformation,// 32 YN
	SystemExceptionInformation,// 33 YN
	SystemCrashDumpStateInformation,// 34 YY/N
	SystemKernelDebuggerInformation,// 35 YN
	SystemContextSwitchInformation,// 36 YN
	SystemRegistryQuotaInformation,// 37 YY
	SystemLoadAndCallImage,// 38 NY // SystemExtendServiceTableInformation
	SystemPrioritySeparation,// 39 NY
	SystemNotImplemented10,// 40 YN // SystemPlugPlayBusInformation
	SystemNotImplemented11,// 41 YN // SystemDockInformation
	SystemInvalidInfoClass2,// 42 // SystemPowerInformation
	SystemInvalidInfoClass3,// 43 // SystemProcessorSpeedInformation
	SystemTimeZoneInformation,// 44 YN
	SystemLookasideInformation,// 45 YN
	SystemSetTimeSlipEvent,// 46 NY
	SystemCreateSession,// 47 NY
	SystemDeleteSession,// 48 NY
	SystemInvalidInfoClass4,// 49
	SystemRangeStartInformation,// 50 YN
	SystemVerifierInformation,// 51 YY
	SystemAddVerifier,// 52 NY
	SystemSessionProcessesInformation// 53 YN
} SYSTEM_INFORMATION_CLASS;
typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG    WaitTime;
	PVOID    StartAddress;
	CLIENT_ID   ClientID;
	KPRIORITY   Priority;
	KPRIORITY   BasePriority;
	ULONG    ContextSwitchCount;
	ULONG    ThreadState;
	KWAIT_REASON  WaitReason;
	ULONG    Reserved; //Add
}SYSTEM_THREADS, * PSYSTEM_THREADS;
typedef struct _SYSTEM_PROCESSES
{
	ULONG    NextEntryDelta;//���ɽṹ���е�ƫ����
	ULONG    ThreadCount;//�߳���Ŀ
	ULONG    Reserved[6];
	LARGE_INTEGER  CreateTime;//����ʱ��;
	LARGE_INTEGER  UserTime;//�û�ģʽ(Ring3)����ʱ��
	LARGE_INTEGER  KernelTime;//�ں�ģʽ(Ring0)����ʱ��
	UNICODE_STRING  ProcessName;//������
	KPRIORITY   BasePriority;//��������Ȩ
	HANDLE   ProcessId;  //����ID
	HANDLE   InheritedFromProcessId;//������ID
	ULONG    HandleCount;//�����Ŀ
	ULONG    SessionId;
	ULONG_PTR  PageDirectoryBase;
	VM_COUNTERS VmCounters;//����Ĵ����ṹ
	SIZE_T    PrivatePageCount;//Add
	IO_COUNTERS  IoCounters; //windows 2000 only IO�������ṹ
	struct _SYSTEM_THREADS Threads[1];//��������̵߳Ľṹ����
}SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;
//typedef struct _SYSTEM_PROCESSES
//{
//	ULONG NextEntryDelta; //���ɽṹ���е�ƫ����;
//	ULONG ThreadCount; //�߳���Ŀ;
//	ULONG Reserved1[6];
//	LARGE_INTEGER CreateTime; //����ʱ��;
//	LARGE_INTEGER UserTime;//�û�ģʽ(Ring 3)��CPUʱ��;
//	LARGE_INTEGER KernelTime; //�ں�ģʽ(Ring 0)��CPUʱ��;
//	UNICODE_STRING ProcessName; //��������;
//	KPRIORITY BasePriority;//��������Ȩ;
//	ULONG ProcessId; //���̱�ʶ��;
//	ULONG InheritedFromProcessId; //�����̵ı�ʶ��;
//	ULONG HandleCount; //�����Ŀ;
//	ULONG Reserved2[2];
//	VM_COUNTERS  VmCounters; //����洢���Ľṹ������;
//	IO_COUNTERS IoCounters; //IO�����ṹ������;
//	SYSTEM_THREADS Threads[1]; //��������̵߳Ľṹ����
//}SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

typedef PVOID(*pfnPsGetThreadTeb)(IN PETHREAD Thread);
typedef NTSTATUS(*pfnNtSuspendThread)(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount OPTIONAL);
typedef NTSTATUS(*pfnNtResumeThread)(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount OPTIONAL); 
typedef NTSTATUS(*pfnNtGetContextThread)(IN HANDLE ThreadHandle, OUT PCONTEXT ThreadContext);
typedef NTSTATUS(*pfnNtSetContextThread)(IN HANDLE ThreadHandle, IN PCONTEXT ThreadContext);
typedef NTSTATUS(*pfnNtOpenThread)(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId);
typedef NTSTATUS(*pfnNtQueryInformationThread)(IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, OUT PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength);
typedef NTSTATUS(*pfnPsGetContextThread)(IN PETHREAD Thread, OUT PCONTEXT ThreadContext, IN KPROCESSOR_MODE Mode);
typedef NTSTATUS(*pfnPsSetContextThread)(IN PETHREAD Thread, OUT PCONTEXT ThreadContext, IN KPROCESSOR_MODE Mode);
typedef NTSTATUS(*pfnNtCreateThreadEx)(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID StartAddress, IN PVOID Parameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT PVOID ByteBuffer);
typedef NTSTATUS(*pfnZwGetNextThread)(IN HANDLE ProcessHandle, IN HANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN ULONG HandleAttributes, IN ULONG Flags, OUT PHANDLE NewThreadHandle);
typedef NTSTATUS(*pfnZwQuerySystemInformation)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength);
typedef NTSTATUS(*pfnZwQueryInformationThread)(IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, IN PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength);

class Thread
{
private:
	DWORD ktrap_frame_offset = 0x090;								//�Ĵ��������ETHREAD�ṹ�е�ƫ��  1909+ -> 0x090
	pfnPsGetThreadTeb mPsGetThreadTeb = NULL;
	pfnNtSuspendThread NtSuspendThread = NULL;
	pfnNtResumeThread NtResumeThread = NULL;
	pfnNtGetContextThread NtGetContextThread = NULL;
	pfnNtSetContextThread NtSetContextThread = NULL;
	pfnNtOpenThread NtOpenThread = NULL;
	pfnNtQueryInformationThread NtQueryInformationThread = NULL;
	pfnNtCreateThreadEx mNtCreateThreadEx = NULL;
	pfnPsGetContextThread mPsGetContextThread = NULL;
	pfnPsSetContextThread mPsSetContextThread = NULL;
	pfnZwGetNextThread mZwGetNextThread = NULL;						//Win7 �������˺���
	pfnZwQuerySystemInformation mZwQuerySystemInformation = NULL;
	pfnZwQueryInformationThread mZwQueryInformationThread = NULL;

public:
	void* operator new(size_t size, POOL_TYPE pool_type = NonPagedPool);
	void operator delete(void* pointer);
	DWORD GetTrapFrameOffset() { return this->ktrap_frame_offset; }

public:
	Thread();
	~Thread();
	PVOID PsGetThreadTeb(IN PETHREAD Thread);
	NTSTATUS SuspendThread(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount);
	NTSTATUS ResumeThread(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount);
	NTSTATUS GetContextThread(IN HANDLE ThreadHandle, OUT PCONTEXT ThreadContext);
	NTSTATUS SetContextThread(IN HANDLE ThreadHandle, IN PCONTEXT ThreadContext);
	KTRAP_FRAME GetContextByEThread(PETHREAD pethread);
	NTSTATUS SetContextByEThread(PETHREAD pethread, KTRAP_FRAME context);
	NTSTATUS OpenThread(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId);
	NTSTATUS PsGetContextThread(IN PETHREAD Thread, OUT PCONTEXT ThreadContext, IN KPROCESSOR_MODE Mode);
	NTSTATUS PsSetContextThread(IN PETHREAD Thread, OUT PCONTEXT ThreadContext, IN KPROCESSOR_MODE Mode);
	PETHREAD GetFirstThread(PEPROCESS tempep);
	DWORD GetThreadIdByModuleName(IN HANDLE pid, IN const wchar_t* module_name);
	NTSTATUS NtCreateThreadEx(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID StartAddress, IN PVOID Parameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT PVOID ByteBuffer);
	NTSTATUS ZwGetNextThread(IN HANDLE ProcessHandle, IN HANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN ULONG HandleAttributes, IN ULONG Flags, OUT PHANDLE NewThreadHandle);
	NTSTATUS ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength);
	NTSTATUS ZwQueryInformationThread(IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, IN PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength);
	bool SuspendKernelThread(const char* kernel_module_name, const char* judgment_tag);
	bool SuspendKernelThreadByID(const char* kernel_module_name, HANDLE tid);

	//void GetThread(int Pid);

};


