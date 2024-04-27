#pragma once
extern "C"
{
#include <ntddk.h>
#include <wsk.h>
}


class WSKInterfaceError
{
private:
	const char* _error_str = nullptr;

public:
	void* operator new(size_t size, POOL_TYPE pool_type = NonPagedPool);
	void operator delete(void* pointer);

public:
	WSKInterfaceError(const char* error);
	~WSKInterfaceError();

public:
	virtual char const* what() const throw();

};


class WSKInterface
{
private:


public:
	void* operator new(size_t size, POOL_TYPE pool_type = NonPagedPool);
	void operator delete(void* pointer);

public:
	WSKInterface();
	~WSKInterface();

public:

};

