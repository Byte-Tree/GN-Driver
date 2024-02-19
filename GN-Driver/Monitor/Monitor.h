#pragma once
#include "../pch.h"

#define MAX_STRING_LENGTH			512
#define MAX_PID_LENGTH				32
#define MAX_TIME_LENGTH				20
#define MEM_TAG 'MEM'

typedef struct _PROCESSINFO
{
	TIME_FIELDS			time;						// ʱ��
	BOOLEAN				bIsCreate;					// �Ƿ��Ǵ�������
	HANDLE				hParentProcessId;			// ������ ID
	ULONG				ulParentProcessLength;		// �����̳���
	HANDLE				hProcessId;					// �ӽ��� ID
	ULONG				ulProcessLength;			// �ӽ��̳���
	ULONG				ulCommandLineLength;		// ���������в�������
	UCHAR				uData[1];					// ������
} PROCESSINFO, * PPROCESSINFO;
typedef struct//������̵�����
{
	LIST_ENTRY		list_entry;
	PPROCESSINFO	pProcessInfo;
} PROCESSNODE, * PPROCESSNODE;

//NTSTATUS PsReferenceProcessFilePointer(IN PEPROCESS Process, OUT PVOID* pFilePointer);
extern "C" NTSTATUS PsReferenceProcessFilePointer(IN PEPROCESS Process, OUT PFILE_OBJECT * pFilePointer);


class Monitor
{
private:
	HANDLE m_pid;						//���ڼ��ӵĽ���id
	KSPIN_LOCK m_lock = NULL;			//�����������
	KEVENT m_event = { NULL };			//����֪ͨ���¼�
	LIST_ENTRY list_head = { NULL };	//����ͷ

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




