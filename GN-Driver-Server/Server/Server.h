#pragma once
#include <stdio.h>
#include <iostream>
#include <string>

#include "ServerError.h"


class ServerError :public std::exception
{
private:
	std::string _error_str;

public:
	ServerError(std::string error);
	~ServerError();

public:
	virtual char const* what() const throw();

};


class Server
{
private:

public:
	Server();
	~Server();

public:
	SERVER_ERROR Running();

};

