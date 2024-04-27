#include "WSKInterface.h"


void* WSKInterfaceError::operator new(size_t size, POOL_TYPE pool_type)
{
#pragma warning(disable : 4996)
	return ExAllocatePoolWithTag(pool_type, size, 'Wser');
#pragma warning(default : 4996)
}

void WSKInterfaceError::operator delete(void* pointer)
{
	ExFreePoolWithTag(pointer, 'Wser');
}

WSKInterfaceError::WSKInterfaceError(const char* error) :_error_str(error)
{
}

WSKInterfaceError::~WSKInterfaceError()
{
}

char const* WSKInterfaceError::what() const throw()
{
	return this->_error_str;
}


void* WSKInterface::operator new(size_t size, POOL_TYPE pool_type)
{
#pragma warning(disable : 4996)
	return ExAllocatePoolWithTag(pool_type, size, 'Wski');
#pragma warning(default : 4996)
}

void WSKInterface::operator delete(void* pointer)
{
	ExFreePoolWithTag(pointer, 'Wski');
}

WSKInterface::WSKInterface()
{

}

WSKInterface::~WSKInterface()
{
}

