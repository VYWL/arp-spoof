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
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#define ETHERNET_HEADER_SIZE 20

void usage();
void arpSpoofing(char * senderIPString, char * targetIPString, char *dev, pcap_t *handle);

void GetInterfaceMacAddress(char *ifname, uint8_t *mac_addr, uint32_t *ip_addr);
void requestARPforMACAddr(Mac smac, Mac dmac, Ip sip, Mac tmac, Ip tip, Mac *replySmac, pcap_t *handle);
void replyARPforSpoofing(Mac smac, Mac dmac, Ip sip, Mac tmac, Ip tip, pcap_t *handle);