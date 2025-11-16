#pragma once
#include <winsock2.h>
#include <string>
#include <vector>
#include "DNSPacket.h"
class Socket {
private:
	SOCKET sock;
	struct sockaddr_in remote;
	struct sockaddr_in response;
	char m_buffer[DNSConstants::MAX_DNS_SIZE];
	int curPos;
public:
	Socket(const char* IP);
	SOCKET getSocket() { return sock; }
	const char* getPacketData() const { return m_buffer; }
	const int& getSize() const { return curPos; }
	
	bool Send(const char* packet, int size);
	int Read();
	bool Send_and_Recieve(const char* packet, int size);
	~Socket();
};