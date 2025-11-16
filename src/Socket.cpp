#include "pch.h"
#include "Socket.h"

constexpr int MAX_DNS_SIZE = 512;
constexpr int MAX_ATTEMPTS = 3;
constexpr int DNS_PORT = 53;
Socket::Socket(const char* IP) {
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET) {
		printf("Socket creation failed with error: %d\n", WSAGetLastError());
		return;
	}
	curPos = 0;
	memset(&remote, 0, sizeof(remote));
	memset(&response, 0, sizeof(response));
	memset(m_buffer, 0, (size_t)DNSConstants::MAX_DNS_SIZE);
	

	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = inet_addr(IP);
	remote.sin_port = htons(DNS_PORT);
	if (remote.sin_addr.s_addr == INADDR_NONE) {
		printf("Invalid IP address: %s\n", IP);
		closesocket(sock);
		return;
	}
}

bool Socket::Send(const char* packet, int size) {
	int bytes_sent = sendto(sock, packet, size, 0, (struct sockaddr*)&remote, sizeof(remote));
	if(bytes_sent == SOCKET_ERROR) {
		printf("socket error %d\n", WSAGetLastError());
	}
	return bytes_sent != SOCKET_ERROR;
	// TODO: add the time and how many bytes was attempted
}
int Socket::Read() {
	int response_size = sizeof(response);
	int bytes_recv = recvfrom(sock, m_buffer, DNSConstants::MAX_DNS_SIZE, 0, (struct sockaddr*)&response, &response_size);
	if(bytes_recv == SOCKET_ERROR) {
		printf("socket error %d\n", WSAGetLastError());
	}
	return bytes_recv;
}
bool Socket::Send_and_Recieve(const char* packet, int size) {
	// resource: https://learn.microsoft.com/en-us/cpp/standard-library/chrono?view=msvc-170
	for (int attempt = 0; attempt < DNSConstants::DNS_MAX_ATTEMPT; ++attempt) {
		printf("Attempt %d with %d bytes... ", attempt, size);
		auto start_time = std::chrono::steady_clock::now();
		if (!Send(packet, size)) {
			return false;
		}

		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(this->sock, &fds);

		struct timeval tv;
		tv.tv_sec = DNSConstants::TIMEOUT_SECONDS;
		tv.tv_usec = 0;
		int available = select(0, &fds, nullptr, nullptr, &tv);
		auto end_time1 = std::chrono::steady_clock::now();

		if (available > 0) {
			curPos = Read();
			if (curPos != SOCKET_ERROR) {
				auto end_time = std::chrono::steady_clock::now();
				auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
				if (remote.sin_addr.s_addr != response.sin_addr.s_addr || remote.sin_port != response.sin_port) {
					printf("++ invalid reply: received from a different IP/port\n");
					continue;
				}
				printf("response in %lld ms with %d bytes\n", duration.count(), curPos);
				return true;
			}
			return false;
		}
		else if (available == 0) {
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time1 - start_time);
			printf("timeout in %lld ms\n", duration.count());
			continue;
		}
		else {
			printf("select() failed with error %d\n", WSAGetLastError());
			break;
		}
	}
	return false;
}
Socket::~Socket() {
	if(sock != INVALID_SOCKET) {
		closesocket(sock);
	}
	WSACleanup();
}