#include "pch.h"
#include "DNSPacket.h"



DNSPacket::DNSPacket(char* host, USHORT queryType) {
	memset(getPacket(), 0, sizeof(DNSConstants::MAX_DNS_SIZE));
	srand(time(NULL));
	getTXID() = u_short(rand());
	size_t size{ strlen(host) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader) };

	buildQueryPacket(host, size, queryType);
}
void DNSPacket::printQuerySummary(const char* host, const char* serverIP, USHORT queryType) {
	printf("Lookup : %s\n", host);
	// IP reverse lookup
	if (queryType == DNSConstants::DNS_PTR) {
		unsigned char ip_bytes[4];
		sscanf_s(host, "%hhu.%hhu.%hhu.%hhu", &ip_bytes[0], &ip_bytes[1], &ip_bytes[2], &ip_bytes[3]);
		printf("Query  : %hhu.%hhu.%hhu.%hhu.in-addr.arpa, type %d, TXID 0x%.4X\n",
			ip_bytes[3], ip_bytes[2], ip_bytes[1], ip_bytes[0],
			queryType,
			m_TXID);
	}
	// DNS lookup
	else {
		printf("Query  : %s, type %d, TXID 0x%.4X\n",
			host,
			queryType,
			m_TXID);
	}
	printf("Server : %s\n", serverIP);
	printf("********************************\n");
}

int DNSPacket::buildQueryPacket(char* host, size_t size, USHORT queryType) {

	FixedDNSheader* fdh = (FixedDNSheader*)m_packet;
	
	fdh->TXID = htons(getTXID());
	fdh->flags = htons(DNSConstants::DNS_QUERY | DNSConstants::DNS_RD | DNSConstants::DNS_STDQUERY);
	fdh->nQuestions = htons(1);
	fdh->nAnswers = htons(0);
	fdh->nAuthority = htons(0);
	fdh->nAdditional = htons(0);

	int buffer_offset {};
	if (queryType == DNSConstants::DNS_A) {
		buffer_offset = makeDNSQuestion(fdh + 1, host);
	}
	else if (queryType == DNSConstants::DNS_PTR) {
		// resource: https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/sscanf-s-sscanf-s-l-swscanf-s-swscanf-s-l?view=msvc-170
		// resource: https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/sprintf-s-sprintf-s-l-swprintf-s-swprintf-s-l?view=msvc-170
		// revert the ip and add in-addr.arpa
		char reverse_ip[DNSConstants::MAX_DNS_SIZE];
		unsigned char ip_bytes[4];

		sscanf_s(host, "%hhu.%hhu.%hhu.%hhu", &ip_bytes[0], &ip_bytes[1], &ip_bytes[2], &ip_bytes[3]);
		sprintf_s(reverse_ip, sizeof(reverse_ip), "%hhu.%hhu.%hhu.%hhu.in-addr.arpa", ip_bytes[3], ip_bytes[2], ip_bytes[1], ip_bytes[0]);
		buffer_offset = makeDNSQuestion(fdh + 1, reverse_ip);
	}

	QueryHeader* qh = (QueryHeader*)((char*)(fdh + 1) + buffer_offset);
	qh->qType = htons(queryType);
	qh->qClass = htons(DNSConstants::DNS_INET);
	return sizeof(FixedDNSheader) + buffer_offset + sizeof(QueryHeader);
}

int DNSPacket::makeDNSQuestion(void* buffer_at_question, const char* host) {
	// resource: https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtok-s-strtok-s-l-wcstok-s-wcstok-s-l-mbstok-s-mbstok-s-l?view=msvc-170
	int buffer_offset = 0;
	char tempBuffer[DNSConstants::MAX_DNS_SIZE];
	strcpy_s(tempBuffer, sizeof(tempBuffer), host);
	char* token{ nullptr };
	char* next{ nullptr };
	char* buffer = (char*)buffer_at_question;

	token = strtok_s(tempBuffer, ".", &next);

	while (token != nullptr) {
		size_t token_length = strlen(token);
		buffer[buffer_offset] = static_cast<char>(token_length);
		++buffer_offset;
		memcpy(buffer + buffer_offset, token, token_length);
		buffer_offset += token_length;
		token = strtok_s(nullptr, ".", &next);
	}
	buffer[buffer_offset] = 0;
	++buffer_offset;
	return buffer_offset;
}

bool DNSPacket::parsePacket(char* buffer, int buffer_size) {
	if (buffer_size < sizeof(FixedDNSheader)) {
		printf("\t++ invalid reply: packet smaller than fixed DNS header\n");
		return false;
	}

	// Extract header
	FixedDNSheader* fdh = (FixedDNSheader*)buffer;
	
	USHORT r_TXID = ntohs(fdh->TXID);
	USHORT r_flags = ntohs(fdh->flags);
	USHORT r_nQuestion = ntohs(fdh->nQuestions);
	USHORT r_nAnswer = ntohs(fdh->nAnswers);
	USHORT r_nAuthority = ntohs(fdh->nAuthority);
	USHORT r_nAdditional = ntohs(fdh->nAdditional);
	printf("  TXID 0x%.4X, flags 0x%x, questions %d, answers %d, authority %d, additional %d\n",
		r_TXID,
		r_flags,
		r_nQuestion,
		r_nAnswer,
		r_nAuthority,
		r_nAdditional);
	if (r_TXID != m_TXID) {
		//  ++ invalid reply: TXID mismatch, sent 0x0871, received 0x0872  
		printf("  ++ invalid reply: TXID mismatch, sent 0x%.4X, received 0x%.4X\n",
		m_TXID,
		r_TXID);
		return false;
	}
	int rcode = r_flags & 0x000F;
	if (rcode != DNSConstants::DNS_OK) {
		printf("  failed with Rcode = %d", rcode);
		return false;
	}
	printf("  succeeded with Rcode = %d\n", rcode);
	char* current_pos = buffer + sizeof(FixedDNSheader);

	int questionParsed{};
	// ------------ [questions] ----------
	for (int i = 0; i < r_nQuestion; ++i) {
		DnsQuestionHdr question;
		try {
			question.name = ParseName(current_pos, buffer, buffer_size);
			QueryHeader* qh = (QueryHeader*)current_pos;
			if (current_pos + sizeof(QueryHeader) > buffer + buffer_size) {
				printf("\t++ invalid record: truncated question header");
				return false;
			}
			if (current_pos >= buffer + buffer_size) {
				break;
			}
			question.qClass = ntohs(qh->qClass);
			question.qType = ntohs(qh->qType);
			m_questions.push_back(question);
			current_pos += sizeof(QueryHeader);
			questionParsed++;
		}
		catch (const std::exception& e) {
			printf("%s\n", e.what());
			return false;
		}
	}
	if (questionParsed < r_nQuestion) {
		printf("++ invalid section: not enough records\n");
		return false;
	}
	int answerParsed{};
	// ------------ [answers] ------------
	for (int i = 0; i < r_nAnswer; ++i) {
		Resource record;
		if (current_pos >= buffer + buffer_size) {
			break;
		}
		if (!ParseRecord(current_pos, buffer, buffer_size, &record)) {
			return false;
		}
		m_answers.push_back(record);
		answerParsed++;
	}

	if (answerParsed < r_nAnswer) {
		printf("++ invalid section: not enough records\n");
		return false;
	}
	// ------------ [authority] ------------
	int authorityParsed{};
	for (int i = 0; i < r_nAuthority; ++i) {
		Resource record;
		if (current_pos >= buffer + buffer_size) {
			break;
		}
		if (!ParseRecord(current_pos, buffer, buffer_size, &record)) {
			return false;
		}
		m_authority.push_back(record);
		authorityParsed++;
	}
	if (authorityParsed < r_nAuthority) {
		printf("++ invalid section: not enough records\n");
		return false;
	}
	int additionParsed{};
	// ------------ [additional] ------------
	for (int i = 0; i < r_nAdditional; ++i) {
		Resource record;
		if (current_pos >= buffer + buffer_size) {
			break;
		}
		if (!ParseRecord(current_pos, buffer, buffer_size, &record)) {
			return false;
		}
		m_additional.push_back(record);
		additionParsed++;
	}
	if (additionParsed < r_nAdditional) {
		printf("++ invalid section: not enough records\n");
		return false;
	}
	return true;

}

std::string DNSPacket::ParseNameHelper(char*& currentPos, const char* buffer_start, int buffer_size, std::set<int>& visited_location) {
	std::string name{};
	bool isFirstSegment{ true }; // /3www/6google -> first segment is the /3
	while (true) {
		if (currentPos >= buffer_start + buffer_size) {
			// out of bound ( packet ended)
			throw std::runtime_error("\t++ invalid record: truncated name");
		}
		// compressed data
		if (static_cast<unsigned char>(*currentPos) >= 0xC) {
			// the jump offset out of bound (packet end)
			if (currentPos + 1 >= buffer_start + buffer_size) {
				throw std::runtime_error("  ++ invalid record: truncated jumped offset");
			}
			uint16_t offset = ntohs(*(uint16_t*)currentPos) & 0x3FFF;
			// sanitize offset
			if (offset >= buffer_size) {
				throw std::runtime_error("  ++invalid record : jump beyond packet boundary");
			}
			else if (offset < sizeof(FixedDNSheader)) {
				throw std::runtime_error("  ++ invalid record: jump into fixed DNS header");
			}
			else if (visited_location.count(offset) != 0) {
				throw std::runtime_error("  ++ invalid record: jump loop");
			}
			visited_location.insert(offset); // insert this to the list
			char* jumpedPos = (char*)(buffer_start + offset);
			name += ParseNameHelper(jumpedPos, buffer_start, buffer_size, visited_location);
			currentPos += 2; // skip 0xC0 0x0C
			return name;
		}
		// uncompressed data
		uint8_t wordLength = (uint8_t)(*currentPos);
		currentPos++;

		// quit recursive condition
		if (wordLength == 0) {
			return name;
		}
		//if not segment add a "."
		if (!isFirstSegment) {
			name += ".";
		}
		if (currentPos + wordLength > buffer_start + buffer_size) {
			throw std::runtime_error("++ invalid record: truncated name");
		}
		// resource: https://cplusplus.com/reference/string/string/append/
		name.append(currentPos, wordLength);
		currentPos += wordLength;
		isFirstSegment = false;
	}
}

std::string DNSPacket::ParseName(char*& currentPos, const char* buffer, int buffer_size) {
	std::set<int> visted_location;
	return ParseNameHelper(currentPos, buffer, buffer_size, visted_location);
}

bool DNSPacket::ParseRecord(char*& currentPos, const char* buffer, int buffer_size, Resource* Record) {
	try {
		Record->name = ParseName(currentPos, buffer, buffer_size);
		DNSanswerHdr* dah = (DNSanswerHdr*)currentPos;
		if (currentPos + sizeof(DNSanswerHdr) > buffer + buffer_size) {
			printf("++ invalid record: truncated RR header\n");
			return false;
		}
		Record->a_class = ntohs(dah->a_class);
		Record->a_type = ntohs(dah->a_type);
		Record->TTL = ntohl(dah->ttl);
		Record->len = ntohs(dah->len);
		
		currentPos += sizeof(DNSanswerHdr);
		char* recordataPos = currentPos;

		if (recordataPos + Record->len > buffer + buffer_size) {
			printf("++ invalid record: RR value length stretches the answer beyond packet\n");
			return false;
		}

		// it the its IP type, revert the ip
		if (Record->a_type == DNSConstants::DNS_A) {
			in_addr ip;
			ip.s_addr = *(uint32_t*)recordataPos;
			Record->data = inet_ntoa(ip);
		}
		// if it a string type, parseName
		else if (Record->a_type == DNSConstants::DNS_PTR || Record->a_type == DNSConstants::DNS_NS || Record->a_type == DNSConstants::DNS_CNAME) {
			Record->data = ParseName(recordataPos, buffer, buffer_size);
		}
		currentPos += Record->len;
	}
	catch (const std::exception& e) {
		// catch ParseName exception
		printf("%s\n", e.what());
		return false;
	}
	return true;
}
const char* DNSPacket::recordTypeString(uint16_t type) {
	switch (type) {
	case DNSConstants::DNS_A:     return "A";
	case DNSConstants::DNS_NS:    return "NS";
	case DNSConstants::DNS_CNAME: return "CNAME";
	case DNSConstants::DNS_PTR:   return "PTR";
	default:                      return "OTHER";
	}
}

void DNSPacket::printPacket() {
	if (!m_questions.empty()) {
		printf("------------ [questions] ----------\n");
		for (const auto& question : m_questions) {
			printf("\t%s type %d class %d\n",
				question.name.c_str(),
				question.qType,
				question.qClass);
		}
	}
	if (!m_questions.empty()) {
		printf("------------ [answers] ------------\n");
		for (const auto& record : m_answers) {
			printf("\t%s %s %s TTL = %d\n",
				record.name.c_str(),
				recordTypeString(record.a_type),
				record.data.c_str(),
				record.TTL);
		}
	}
	if (!m_authority.empty()) {
		printf("------------ [authority] ----------\n");
		for (const auto& record : m_authority) {
			printf("\t%s %s %s TTL = %d\n",
				record.name.c_str(),
				recordTypeString(record.a_type),
				record.data.c_str(),
				record.TTL);
		}
	}
	if (!m_additional.empty()) {
		printf("------------ [additional] ---------\n");
		for (const auto& record : m_additional) {
			printf("\t%s %s %s TTL = %d\n",
				record.name.c_str(),
				recordTypeString(record.a_type),
				record.data.c_str(),
				record.TTL);
		}
	}

}

DNSPacket::~DNSPacket() {

}