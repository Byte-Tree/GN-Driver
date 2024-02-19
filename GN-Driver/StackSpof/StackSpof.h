#pragma once
#include "../pch.h"


// 函数调用堆栈地址欺骗类
class StackSpof
{
private:
	unsigned short m_size = 1;
	unsigned long long m_data[100]{ 0 };
	unsigned long long m_spof_addr = 0;
	void* m_ret_addr = 0;

public:
	StackSpof(void* ret_addr, unsigned short size = 1, unsigned long long spof_addr = 0);
	~StackSpof();

};

//int main(int argc, char* argv[])
//{
//	//
//	StackSpof spof(_ReturnAddress(), 5);
//	return 0;
//}


