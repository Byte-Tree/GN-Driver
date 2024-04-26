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
	std::cout << __FUNCTION__ << ": connect id:" << dwConnID << std::endl;

	PClientNode client = nullptr;
	if (pSender->GetConnectionExtra(dwConnID, (PVOID*)&client))
	{
		try
		{
			//断开连接前的处理


			delete client;
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
	//	try {
	//
	//		if (TransferModel == 1)
	//		{
	//			return HR_OK;
	//		}
	//
	//		TransferHead* ProtocolHead = (TransferHead*)pData;
	//		if (iLength < sizeof(TransferHead) && ntohs(ProtocolHead->TotalLength) > iLength)
	//		{
	//			return HR_OK;
	//		}
	//		ClientNode* Client = NULL;
	//		UINT Seq = ntohl(ProtocolHead->Seq);
	//		short DialogID = ntohs(ProtocolHead->DialogID);
	//		UINT Uin = ntohl(ProtocolHead->Uin);
	//
	//		short TransferCmd = ntohs(ProtocolHead->TransferCmd);
	//		UCHAR OptLength = ProtocolHead->OptLength;
	//
	//		//printf("[UDP:OnReceive]Uin:%d, TransferCmd:%d, OptLength:%d\n", Uin, TransferCmd, OptLength);
	//
	//		size_t len = 0;
	//		BYTE* p = PBYTE(ProtocolHead + 1);
	//		UCHAR option[1024];
	//
	//		int num = 0;
	//		switch (TransferCmd)
	//		{
	//		case UDP_CMD_LOGIN_SERVER:
	//		{
	//
	//			//udp服务器登录命令
	//			in_addr LocalIP;
	//			LocalIP.S_un.S_addr = Read32(p);
	//			USHORT LocalPort = Read16(p);
	//#
	//			//printf("lpszRemoteAddress:%s LocalIP:%s, LocalPort:%d\n", lpszRemoteAddress, inet_ntoa(LocalIP), LocalPort);
	//			p = option;
	//
	//			Write32(p, inet_addr(lpszRemoteAddress));
	//
	//			len = p - option;
	//			SendUdpData(lpszRemoteAddress, usRemotePort, UDP_CMD_LOGIN_SERVER, option, len, Seq, DialogID, Uin);
	//
	//
	//
	//			break;
	//		}
	//
	//		case UDP_CMD_P2P_GAME_DATA:
	//		{
	//			//UDP游戏数据 tcp传输
	//			Client = GetClient(Uin);
	//			if (!Client)
	//			{
	//				return HR_OK;
	//			}
	//			RoomNode* Room = NULL;
	//			if (Client->RoomID != 0)
	//			{
	//				Room = GetRoom(Client->RoomID);
	//			}
	//			else if (Client->BorderRoomID != 0)
	//			{
	//				Room = GetRoom(Client->BorderRoomID);
	//			}
	//			if (!Room)
	//			{
	//				return HR_OK;
	//			}
	//			len = iLength - sizeof(TransferHead) - OptLength;
	//			/*printf("TransferCmd:%d iLength:%d\n ", TransferCmd, iLength);
	//			for (int i = 0; i < iLength; i++)
	//			{
	//				printf("%02x ", *(pData + i));
	//			}
	//			printf("\n");*/
	//
	//			//BYTE* pDstInfo = p;
	//			//SHORT PlayerID = 0;
	//			//UINT DstUin = 0;
	//			BYTE* DataBuf = p + OptLength;
	//			/*while (OptLength >= 14)
	//			{
	//
	//			// 一个人占6个字节
	//				PlayerID = Read16(pDstInfo);
	//				DstUin = Read32(pDstInfo);
	//				//printf("PlayerID:%d, PlayerUin:%d  ",  PlayerID, PlayerUin);
	//				//DWORD dwStart = GetTickCount(); //取windows启动到现在的流逝时间(毫秒)
	//				for (char i2 = 0; i2 < 6; i2++)
	//				{
	//					ClientNode* RoomClient = Clients[DstUin];
	//					if (RoomClient)
	//					{
	//						NotifyTranferByTCP(RoomClient, Uin, 0, Seq, DataBuf, len);
	//					}
	//				}
	//
	//				//DWORD dwUsed = GetTickCount() - dwStart; //计算该函数所消耗的时间
	//				//printf("Clients Search lost:%d ms\n", dwUsed);
	//				OptLength -= 6;
	//			}*/
	//			//UINT Time = Read32(pDstInfo);
	//			//UINT Temp = Read32(pDstInfo);
	//			//printf("\n");
	//			for (char i2 = 0; i2 < 6; i2++)
	//			{
	//				ClientNode* RoomClient = Room->Player[i2];
	//				if (RoomClient && RoomClient != Client)
	//				{
	//					NotifyTranferByTCP(RoomClient, Uin, 0, Seq, DataBuf, len);
	//				}
	//			}
	//			break;
	//		}
	//		case UDP_CMD_SHOW_MY_IP_PORT:
	//		{
	//			short SrcPlayerID = Read16(p); //src player id
	//			UINT SrcUin = Read32(p); //src player uin
	//			in_addr LocalIP;
	//			LocalIP.S_un.S_addr = Read32(p);
	//			USHORT LocalPort = Read16(p);
	//
	//			//printf("SrcPlayerID:%d, SrcUin:%d\n", SrcPlayerID, SrcUin);
	//
	//			p = option;
	//			Write16(p, SrcPlayerID); //SrcPlayerID
	//			Write32(p, SrcUin); //SrcUin
	//			Write32(p, LocalIP.S_un.S_addr); //SrcOuterIP
	//			Write16(p, LocalPort); //SrcOuterPort
	//			Write32(p, inet_addr(lpszRemoteAddress)); //SrcInerIP
	//			Write16(p, usRemotePort); //SrcInnerPort
	//
	//
	//			len = p - option;
	//			SendUdpData(lpszRemoteAddress, usRemotePort, UDP_CMD_RECV_OTHER_IP_PORT, option, len, Seq, DialogID, Uin);
	//			break;
	//		}
	//		case UDP_CMD_HEART_BEAT:
	//		{
	//			//UDP心跳
	//			//p = option;
	//			//printf("TransferCmd:%d iLength:%d\n ", TransferCmd, iLength);
	//			len = iLength - sizeof(TransferHead);
	//			SendUdpData(lpszRemoteAddress, usRemotePort, UDP_CMD_HEART_BEAT, p, len, Seq, DialogID, Uin);
	//			break;
	//		}
	//		default:
	//			//printf("TransferCmd:%d iLength:%d\n ", TransferCmd , iLength);
	//			//len = iLength - sizeof(TransferHead);
	//			//SendUdpData(lpszRemoteAddress, usRemotePort, TransferCmd, p, len, Seq, DialogID, Uin);
	//
	//			break;
	//		}
	//
	//	}
	//	catch (...)
	//	{
	//		printf("UDP Receive Exception!!!\n");
	//		fflush(stdout);
	//	}

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



	return status;
}

