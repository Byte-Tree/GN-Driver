#include "Server.h"


template<typename T1, typename T2>
void OutPutLog(T1 title, T2 data)
{
#if _PRINT_INFORMATION
	std::cout << "[Server]-> " << title << " : " << data << std::endl;
#else
	return;
#endif
}


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


Server::Server() :_tcp(this), _udp(this)
{
}

Server::~Server()
{
}

EnHandleResult Server::OnPrepareListen(ITcpServer* pSender, SOCKET soListen)
{
	//printf("Server key:hi!!girl!!gogogo\n");

	return HR_OK;
}

EnHandleResult Server::OnAccept(ITcpServer* pSender, CONNID dwConnID, UINT_PTR soClient)
{
	PClientNode client = nullptr;

	std::cout << __FUNCTION__ << ": connect id: " << dwConnID << std::endl;

	try
	{
		//实例化一个客户端节点
		client = new ClientNode;

		client->server = pSender;
		client->connect_id = dwConnID;
		client->login_time = this->Tools::GetSystemTime();

		pSender->SetConnectionExtra(dwConnID, client);
	}
	catch (const std::shared_ptr<ServerError>& e)
	{
		OutPutLog(__FUNCTION__ + std::string(" had exception"), e->what());
	}
	catch (const std::exception& e)
	{
		OutPutLog(__FUNCTION__ + std::string(" had exception"), e.what());
	}

	return HR_OK;
}

EnHandleResult Server::OnHandShake(ITcpServer* pSender, CONNID dwConnID)
{
	//printf("[GameServer][ConnID:%d]OnHandShake\n", dwConnID);
	return HR_IGNORE;
}

EnHandleResult Server::OnReceive(ITcpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength)
{
	PClientNode client = nullptr;
	std::string data((char*)pData, iLength);

	std::cout << __FUNCTION__ << ": connect id: " << dwConnID << std::endl;

	if (pSender->GetConnectionExtra(dwConnID, (PVOID*)&client))
	{
		try
		{
			////获取客户端发来的数据并派遣
			//PPcPacket p_packet = (PPcPacket)data.data();
			//std::cout << "command:" << p_packet->header.command << std::endl;
			//std::cout << "data len:" << p_packet->header.data_length << std::endl;

		}
		catch (const std::shared_ptr<ServerError>& e)
		{
			OutPutLog(__FUNCTION__ + std::string(" had exception"), e->what());
		}
		catch (const std::exception& e)
		{
			OutPutLog(__FUNCTION__ + std::string(" had exception"), e.what());
		}
	}

	return HR_OK;
}

EnHandleResult Server::OnSend(ITcpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength)
{
	//printf("[GameServer][ConnID:%d]OnSend\n", dwConnID);
	return HR_OK;
}

EnHandleResult Server::OnClose(ITcpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode)
{
	PClientNode client = nullptr;

	std::cout << __FUNCTION__ << ": connect id:" << dwConnID << std::endl;

	if (pSender->GetConnectionExtra(dwConnID, (PVOID*)&client))
	{
		try
		{
			//断开连接前的处理


			delete client;
		}
		catch (const std::shared_ptr<ServerError>& e)
		{
			OutPutLog(__FUNCTION__ + std::string(" had exception"), e->what());
		}
		catch (const std::exception& e)
		{
			OutPutLog(__FUNCTION__ + std::string(" had exception"), e.what());
		}
	}

	return HR_OK;
}

EnHandleResult Server::OnShutdown(ITcpServer* pSender)
{
	//printf("[GameServer]Close\n");

	return HR_OK;
}

CTcpServerPtr* Server::GetTcpServerPtr()
{
	return &this->_tcp;
}

EnHandleResult Server::OnPrepareListen(IUdpNode* pSender, SOCKET soListen)
{
	//SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN);
	//printf("[UDP]Start Success\n");
	//fflush(stdout);
	//SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
	return HR_OK;
}

EnHandleResult Server::OnSend(IUdpNode* pSender, LPCTSTR lpszRemoteAddress, USHORT usRemotePort, const BYTE* pData, int iLength)
{
	return HR_OK;
}

EnHandleResult Server::OnReceive(IUdpNode* pSender, LPCTSTR lpszRemoteAddress, USHORT usRemotePort, const BYTE* pData, int iLength)
{
	return HR_OK;
}

EnHandleResult Server::OnError(IUdpNode* pSender, EnSocketOperation enOperation, int iErrorCode, LPCTSTR lpszRemoteAddress, USHORT usRemotePort, const BYTE* pBuffer, int iLength)
{
	return HR_OK;
}

EnHandleResult Server::OnShutdown(IUdpNode* pSender)
{
	return HR_OK;
}

CUdpNodePtr* Server::GetUdpNodePtr()
{
	return &this->_udp;
}

SERVER_ERROR Server::Running()
{
	SERVER_ERROR status = SERVER_SUCCESS;

	if (!this->GetTcpServerPtr()->Get()->Start(L"0.0.0.0", 5999))
	{
		::MessageBoxA(::GetActiveWindow(), "start tcp error", "Error", MB_OK);
		return false;
	}
	OutPutLog(__FUNCTION__, "start tcp server success");

	while (true)
	{
		Sleep(1);
	}

	return status;
}

