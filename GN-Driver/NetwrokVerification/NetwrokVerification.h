#pragma once
#include <wdm.h>

#include "WSKInterface/WSKInterface.h"


class NetworkVerification
{
private:

public:
	void* operator new(size_t size, POOL_TYPE pool_type = NonPagedPool);
	void operator delete(void* pointer);

public:
	NetworkVerification();
	~NetworkVerification();

public:
	bool Verfication();

};

