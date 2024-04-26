#include "Server.h"


ServerError::ServerError(std::string error) :_error_str(error)
{
}

ServerError::~ServerError()
{
}

char const* ServerError::what() const throw()
{
	return this->_error_str.c_str();
}


Server::Server()
{
}

Server::~Server()
{
}

SERVER_ERROR Server::Running()
{
	SERVER_ERROR status = SERVER_SUCCESS;



	return status;
}

