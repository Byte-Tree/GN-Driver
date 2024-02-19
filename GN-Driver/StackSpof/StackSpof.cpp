#include "StackSpof.h"


StackSpof::StackSpof(void* ret_addr, unsigned short size, unsigned long long spof_addr) :
	m_ret_addr(ret_addr),	// ��ջ��ַ,Ĭ��ʹ��_AddressOfReturnAddress()
	m_size(size),			// ��ƭ���ö�ջ��ַ������
	m_spof_addr(spof_addr)	// ��Ҫα��ɵķ��ص�ַ
{
	if (m_spof_addr == 0) m_spof_addr = (unsigned long long)ret_addr + 1024;

	for (unsigned short i = 0; i < m_size; i++)
	{
		unsigned long long* value = ((unsigned long long*)m_ret_addr + i);

		m_data[i] = *value; // ����ԭʼ��ַ
		*value = m_spof_addr + (i * sizeof(unsigned long long)); // �޸ķ��ص�ַ
	}
}

StackSpof::~StackSpof()
{
	// ���������������뿪�������ʱ��ԭ�������ö�ջ��ַ
	for (unsigned short i = 0; i < m_size; i++) *((unsigned long long*)m_ret_addr + i) = m_data[i];
}