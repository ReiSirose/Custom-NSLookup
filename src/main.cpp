#include "pch.h"
#include "DNSPacket.h"
#include "Socket.h"

int main(int argc, char* argv [])
{
    if (argc != 3) {
        std::cout << "Usage: <name>.exe <Domain Name> <DNS server IP>\n" << std::endl;
		return -1;
    }
	char* host = argv[1];
	char* dnsServerIP = argv[2];
	uint16_t queryType{};
	if (inet_addr(host) == INADDR_NONE) {
		queryType = DNSConstants::DNS_A;
	}
	else {
		queryType = DNSConstants::DNS_PTR;
	}

	DNSPacket DNS{ host ,queryType };
	DNS.printQuerySummary(host, dnsServerIP, queryType);
	int querySize{ DNS.buildQueryPacket(host, DNSConstants::MAX_DNS_SIZE, queryType) };

	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}

	Socket socket{ dnsServerIP };
	if (!socket.Send_and_Recieve(DNS.getPacket(), querySize)) {
		WSACleanup();
		return -1;
	}
	DNS.parsePacket((char*)socket.getPacketData(), socket.getSize());
	DNS.printPacket();
	WSACleanup();
	return 0;

}