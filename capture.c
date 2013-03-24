/*
 * Original author: Martin Casado (https://github.com/lsanotes/libpcap-tutorial)
 * Refactored by: erdeszt (https://github.com/erdeszt)
 * Build with: `gcc capture.c -Wall -O3 -lpcap -o app` (or `make capture`)
 * Run with: sudo ./build/capture (or `make run_capture`)
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <time.h>

int main(int argc, char **argv) {
  int length;
  char error_buffer[PCAP_ERRBUF_SIZE];
  char* device;
  u_char* packet;    
  u_char* host;
  pcap_t* handler;    
  struct pcap_pkthdr packet_header;
  struct ether_header *ethernet_header;
    
  /* grab a device to peak into */
  if (argc > 1) {
    device = argv[1];
  }
  else {
    device = pcap_lookupdev(error_buffer);

    if (device == NULL) {
      fprintf(stderr, "pcap_loookupdev(): %s\n", error_buffer);
      exit(1);
    }
  }

  printf("DEV: %s\n",device);

  /* Open the device for sniffing. 

  pcap_t *pcap_open_live(char *device, int snaplen, int prmisc, int to_ms,
  char *ebuf);
  snaplen - maximum size of packets to capture in bytes
  promisc - set card in promiscuous mode?
  to_ms   - time to wait for packets in miliseconds before read times out
  errbuf  - if something happens, place error string here

  Note if you change "promisc" param to anything other than zero, you will
  get all packets your device sees, whether they are intended for you or
  not!! Be sure you know the rules of the network you are running on
  before you set your card in promiscuous mode!!  */

  handler = pcap_open_live(device, BUFSIZ, 0, -1, error_buffer);

  if(handler == NULL) {
    printf("pcap_open_live(): %s\n", error_buffer);
    exit(1);
  }

  /* Grab a packet from handler
   *
   * u_char *pcap_next(pcap_t *p,struct pcap_pkthdr *h)
   * so just pass in the descriptor we got from
   * our call to pcap_open_live and an allocated
   * struct pcap_pkthdr                               
   */

  packet = pcap_next(handler, &packet_header);

  if(packet == NULL) {
    /* Don't worry if you don't grab a packet at this point 
     * Try another example where we listen to the traffic and not just trying to 
     * grab a packet.
     */
    printf("Didn't grab packet\n"); 
    exit(1);
  }

  /* struct pcap_pkthdr {
   *   struct timeval ts;   time stamp
   *   bpf_u_int32 caplen;  length of portion present
   *   bpf_u_int32;         lebgth this packet (off wire)
   * }
   */

  printf("Grabbed packet of length . %d\n", packet_header.len);
  printf("Recieved at .............. %s\n", ctime((const time_t*)&packet_header.ts.tv_sec));
  printf("Ethernet address length is %d\n", ETHER_HDR_LEN);

  /* Lets start with the ether header */
  ethernet_header = (struct ether_header*)packet;

  /* Do a couple of checks to see what packet type we have */
  if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
    printf("Ethernet type hex: %x dec: %d is an IP packet\n",
            ntohs(ethernet_header->ether_type),
            ntohs(ethernet_header->ether_type));
  }
  else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP) {
    printf("Ethernet type hex: %x dec: %d is an ARP packet\n",
            ntohs(ethernet_header->ether_type),
            ntohs(ethernet_header->ether_type));
  }
  else {
    printf("Ethernet type %x not IP", ntohs(ethernet_header->ether_type));
    exit(1);
  }

  /* THANK YOU RICHARD STEVENS!!! RIP */
  host = ethernet_header->ether_dhost;
  length = ETHER_ADDR_LEN;

  printf(" Destination address: ");

  do {
    printf("%s%x",(length == ETHER_ADDR_LEN) ? " " : ":", *host++);
  } while (--length > 0);

  printf("\n");

  host = ethernet_header->ether_shost;
  length = ETHER_ADDR_LEN;
  
  printf(" Source address: ");

  do {
    printf("%s%x",(length == ETHER_ADDR_LEN) ? " " : ":", *host++);
  } while(--length > 0);

  printf("\n");

  return 0;
}
