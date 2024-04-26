#include <stdio.h>
#include <iostream>
#include <string>

#include "Server/Server.h"

std::shared_ptr<Server> server = nullptr;


template<typename T1, typename T2>
void OutPutLog(T1 title, T2 data)
{
#if _PRINT_INFORMATION
	std::cout << "[Server]-> " << title << " : " << data << std::endl;
#else
	return;
#endif
}

int main(int argc, char* argv[])
{
	//ÊµÀý»¯ServerÀà
	server = std::make_shared<Server>();

	SERVER_ERROR status = server->Running();

	server.~shared_ptr();

	return 0;
}

