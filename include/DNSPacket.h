#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <set>


namespace DNSConstants {
	constexpr int MAX_DNS_SIZE = 512;
	// --- DNS Header Flags ---
	constexpr uint16_t DNS_QUERY = (0 << 15); // 0 = query; 1 = response
	constexpr uint16_t DNS_RESPONSE = (1 << 15);
	constexpr uint16_t DNS_STDQUERY = (0 << 11); // opcode - 4 bits
	constexpr uint16_t DNS_AA = (1 << 10); // authoritative answer
	constexpr uint16_t DNS_TC = (1 << 9);  // truncated
	constexpr uint16_t DNS_RD = (1 << 8);  // recursion desired
	constexpr uint16_t DNS_RA = (1 << 7);  // recursion available

	// --- DNS Response Codes (RCODE) ---
	constexpr uint16_t DNS_OK = 0; // success
	constexpr uint16_t DNS_FORMAT = 1; // format error (unable to interpret)
	constexpr uint16_t DNS_SERVERFAIL = 2; // can�ft find authority nameserver
	constexpr uint16_t DNS_ERROR = 3; // no DNS entry
	constexpr uint16_t DNS_NOTIMPL = 4; // not implemented
	constexpr uint16_t DNS_REFUSED = 5; // server refused the query

	// --- DNS Query Types ---
	constexpr uint16_t DNS_A = 1;   // name -> IP
	constexpr uint16_t DNS_NS = 2;   // name server
	constexpr uint16_t DNS_CNAME = 5;   // canonical name
	constexpr uint16_t DNS_PTR = 12;  // IP -> name
	constexpr uint16_t DNS_HINFO = 13;  // host info
	constexpr uint16_t DNS_MX = 15;  // mail exchange
	constexpr uint16_t DNS_AXFR = 252; // request for zone transfer
	constexpr uint16_t DNS_ANY = 255; // all records

	// -- DNS Query Class ---
	constexpr uint16_t DNS_INET = 1;
	// -- Other constant ---
	constexpr uint16_t DNS_MAX_ATTEMPT = 3;
	constexpr uint16_t TIMEOUT_SECONDS = 10;
}
#pragma pack(push,1)
struct QueryHeader {
	USHORT qType;
	USHORT qClass;
};

struct DNSanswerHdr {
	u_short a_type;
	u_short a_class;
	u_int ttl;
	u_short len;
};

struct FixedDNSheader {
	USHORT TXID;
	USHORT flags;
	USHORT nQuestions;
	USHORT nAnswers;
	USHORT nAuthority;
	USHORT nAdditional;
};
#pragma pack(pop)

struct DnsQuestionHdr {
	std::string name;
	USHORT qType;
	USHORT qClass;
};

struct Resource {
	std::string name;
	USHORT a_type;
	USHORT a_class;
	u_int TTL;
	USHORT len;
	std::string data;
};

class DNSPacket {
private:
	std::vector<DnsQuestionHdr> m_questions;
	std::vector<Resource> m_answers;
	std::vector<Resource> m_authority;
	std::vector<Resource> m_additional;
	char m_packet[DNSConstants::MAX_DNS_SIZE];
	u_short m_TXID;
public:
	DNSPacket(char* host ,USHORT queryType);
	~DNSPacket();
	int buildQueryPacket(char* host, size_t size, USHORT queryType);
	bool parsePacket(char* buffer, int buffer_size);
	std::string ParseNameHelper(char*& currentPos, const char* buffer, int buffer_size, std::set<int>& visited_location);
	std::string ParseName(char*& currentPos, const char* buffer, int buffer_size);

	bool ParseRecord(char*& currentPos, const char* buffer, int buffer_size, Resource* Record);

	const char* recordTypeString(uint16_t type);
	void printPacket();
	int makeDNSQuestion(void* buffer_at_question, const char* host);
	char* getPacket() { return m_packet; }
	u_short& getTXID() { return m_TXID; }
	void printQuerySummary(const char* host, const char* serverIP, USHORT queryType);
	
};