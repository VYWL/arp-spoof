#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include <vector>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#define ETHERNET_HEADER_SIZE 14
#define PCAP_GETERR 		 -1
#define PCAP_ERROR_CONTINUE	  0
#define FOR_RELAY			  1
#define FOR_REPLY			  0


typedef struct _addrInfo {
	Ip _ip;
	Mac _mac;
}AddrInfo;

typedef struct _addrInfoPair {
	AddrInfo _sender;
	AddrInfo _target;
}AddrInfoPair;

void usage();
void arpSpoofing(int len, char ** argv, char *dev, pcap_t *handle);

AddrInfoPair makeInitAddrInfo();
int isArpPacket(const u_char* packet);
int catchOnePacket(pcap_t *handle, pcap_pkthdr *header, u_char *packet);
void getMyIPMacAddr(char *ifname, uint8_t *mac_addr, uint32_t *ip_addr);
Mac getSMac(Mac smac, Mac dmac, Ip sip, Mac tmac, Ip tip, pcap_t *handle);
void replyOrRelay(AddrInfoPair AttackerInfo, std::vector<AddrInfoPair>& SenderTargetList, pcap_t *handle, int flag);
EthArpPacket useARPPacket(Mac smac, Mac dmac, Ip sip, Mac tmac, Ip tip, uint16_t op);