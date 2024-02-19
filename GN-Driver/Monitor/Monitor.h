#pragma once
#include "../pch.h"

#define MAX_STRING_LENGTH			512
#define MAX_PID_LENGTH				32
#define MAX_TIME_LENGTH				20
#define MEM_TAG 'MEM'

typedef struct _PROCESSINFO
{
	TIME_FIELDS			time;						// 时间
	BOOLEAN				bIsCreate;					// 是否是创建进程
	HANDLE				hParentProcessId;			// 父进程 ID
	ULONG				ulParentProcessLength;		// 父进程长度
	HANDLE				hProcessId;					// 子进程 ID
	ULONG				ulProcessLength;			// 子进程长度
	ULONG				ulCommandLineLength;		// 进程命令行参数长度
	UCHAR				uData[1];					// 数据域
} PROCESSINFO, * PPROCESSINFO;
typedef struct//储存进程的链表
{
	LIST_ENTRY		list_entry;
	PPROCESSINFO	pProcessInfo;
} PROCESSNODE, * PPROCESSNODE;

//NTSTATUS PsReferenceProcessFilePointer(IN PEPROCESS Process, OUT PVOID* pFilePointer);
extern "C" NTSTATUS PsReferenceProcessFilePointer(IN PEPROCESS Process, OUT PFILE_OBJECT * pFilePointer);


class Monitor
{
private:
	HANDLE m_pid;						//用于监视的进程id
	KSPIN_LOCK m_lock = NULL;			//用于链表的锁
	KEVENT m_event = { NULL };			//用于通知的事件
	LIST_ENTRY list_head = { NULL };	//链表头

public:
	void* operator new(size_t size, POOL_TYPE pool_type = NonPagedPool);
	void operator delete(void* pointer);

private:
	NTSTATUS InitMonitor();
	PPROCESSNODE InitListNode();
	void DestroyList();

public:
	Monitor(IN HANDLE pid);
	~Monitor();
	void SetPID(IN HANDLE pid) { this->m_pid = pid; }
	BOOLEAN GetPathByFileObject(PFILE_OBJECT FileObject, WCHAR* wzPath);
	BOOLEAN GetProcessPathBySectionObject(HANDLE ulProcessID, WCHAR* wzProcessPath);
	static void CreateProcessNotifyEx(IN PEPROCESS eprocess, IN HANDLE pid, IN PPS_CREATE_NOTIFY_INFO create_info);
	static void CreateProcessNotify(IN HANDLE parent_pid, IN HANDLE pid, IN BOOLEAN create);

};




