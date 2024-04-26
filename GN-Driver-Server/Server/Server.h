#pragma once
#include <stdio.h>
#include <iostream>
#include <string>

#include <HPSocket/HPSocket.h>

#include "ServerError.h"
#include "../Tools/Tools.h"


typedef struct _ClientNode
{
	ITcpServer* server;
	CONNID connect_id;

	systime login_time;
	systime online_time;
}ClientNode, * PClientNode;


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


class Server :public CTcpServerListener, public CUdpNodeListener, public Tools
{
private:
	CTcpServerPtr _tcp;
	CUdpNodePtr _udp;

public:
	Server();
	~Server();

public:
	//Tcp���Ӵ���ص�����
	virtual EnHandleResult OnPrepareListen(ITcpServer* pSender, SOCKET soListen);
	virtual EnHandleResult OnAccept(ITcpServer* pSender, CONNID dwConnID, UINT_PTR soClient);
	virtual EnHandleResult OnHandShake(ITcpServer* pSender, CONNID dwConnID);
	virtual EnHandleResult OnReceive(ITcpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength);
	virtual EnHandleResult OnSend(ITcpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength);
	virtual EnHandleResult OnClose(ITcpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode);
	virtual EnHandleResult OnShutdown(ITcpServer* pSender);

public:
	CTcpServerPtr* GetTcpServerPtr();

public:
	//Udp���Ӵ���ص�����
	virtual EnHandleResult OnPrepareListen(IUdpNode* pSender, SOCKET soListen);
	virtual EnHandleResult OnSend(IUdpNode* pSender, LPCTSTR lpszRemoteAddress, USHORT usRemotePort, const BYTE* pData, int iLength);
	virtual EnHandleResult OnReceive(IUdpNode* pSender, LPCTSTR lpszRemoteAddress, USHORT usRemotePort, const BYTE* pData, int iLength);
	virtual EnHandleResult OnError(IUdpNode* pSender, EnSocketOperation enOperation, int iErrorCode, LPCTSTR lpszRemoteAddress, USHORT usRemotePort, const BYTE* pBuffer, int iLength);
	virtual EnHandleResult OnShutdown(IUdpNode* pSender);

public:
	CUdpNodePtr* GetUdpNodePtr();

public:
	SERVER_ERROR Running();

};

