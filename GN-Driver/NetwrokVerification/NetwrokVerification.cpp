#include "NetwrokVerification.h"


void* NetworkVerification::operator new(size_t size, POOL_TYPE pool_type)
{
#pragma warning(disable : 4996)
	return ExAllocatePoolWithTag(pool_type, size, 'netw');
#pragma warning(default : 4996)
}

void NetworkVerification::operator delete(void* pointer)
{
	ExFreePoolWithTag(pointer, 'netw');
}

NetworkVerification::NetworkVerification()
{
}

NetworkVerification::~NetworkVerification()
{
}

bool NetworkVerification::Verfication()
{



	return true;
}

