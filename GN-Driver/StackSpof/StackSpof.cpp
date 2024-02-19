#include "StackSpof.h"


StackSpof::StackSpof(void* ret_addr, unsigned short size, unsigned long long spof_addr) :
	m_ret_addr(ret_addr),	// 堆栈基址,默认使用_AddressOfReturnAddress()
	m_size(size),			// 欺骗调用堆栈地址的数量
	m_spof_addr(spof_addr)	// 需要伪造成的返回地址
{
	if (m_spof_addr == 0) m_spof_addr = (unsigned long long)ret_addr + 1024;

	for (unsigned short i = 0; i < m_size; i++)
	{
		unsigned long long* value = ((unsigned long long*)m_ret_addr + i);

		m_data[i] = *value; // 保存原始地址
		*value = m_spof_addr + (i * sizeof(unsigned long long)); // 修改返回地址
	}
}

StackSpof::~StackSpof()
{
	// 利用析构函数，离开作用域的时候还原函数调用堆栈地址
	for (unsigned short i = 0; i < m_size; i++) *((unsigned long long*)m_ret_addr + i) = m_data[i];
}