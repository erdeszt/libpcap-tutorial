/*
 * Original author: Martin Casado (https://github.com/lsanotes/libpcap-tutorial)
 * Refactored by: erdeszt (https://github.com/erdeszt)
 * Build with: `gcc arp.c -Wall -O3 -lpcap -o app` (or `make arp`)
 * Run with: sudo ./build/arp (or `make run_arp`) 
 * Note: You may want to redirect the stderr to /dev/null in order to
 * get rid of the lot of Couldn't get packet. error, like this:  2>/dev/null 
 */

#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAX_BYTES_TO_CAPTURE 2048

typedef struct _arp_header {
  u_int16_t hw_type;
  u_int16_t protocol_type;
  u_char hw_len;
  u_char protocol_len;
  u_int16_t operation;
  u_char sender_hw_address[6];
  u_char sender_ip_address[4];
  u_char target_hw_address[6];
  u_char target_ip_address[4];
} arp_header_t;

int main(int argc, char** argv) {
  int i;
  char error_buffer[PCAP_ERRBUF_SIZE];
  char* device;
  char* filter_expression = "arp";
  bpf_u_int32 net = 0,
              mask = 0;
  struct bpf_program filter_program;
  pcap_t* handler;
  struct pcap_pkthdr packet_header;
  const unsigned char* packet;
  arp_header_t* arp_header;

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

  handler = pcap_open_live(device, MAX_BYTES_TO_CAPTURE, 0, -1, error_buffer);

  if (handler == NULL) {
    fprintf(stderr, "pcap_open_live(): %s\n", error_buffer);
    exit(1);
  }
  
  if (pcap_lookupnet(device, &net, &mask, error_buffer) == -1) {
    fprintf(stderr, "pcap_lookupnet(): %s\n", error_buffer);
    exit(1);
  }  

  if (pcap_compile(handler, &filter_program, filter_expression, 1, mask) == -1) {
    fprintf(stderr, "pcap_compile('%s'): %s\n", filter_expression, pcap_geterr(handler));
    exit(1);
  }

  if (pcap_setfilter(handler, &filter_program) == -1) {
    fprintf(stderr, "pcap_setfilter('%s'): %s\n", filter_expression, pcap_geterr(handler));
    exit(1);
  }

  while (1) {
    packet = pcap_next(handler, &packet_header);

    if (packet == NULL) {
      fprintf(stderr, "ERROR: Couldn't get packet.\n");
      continue;
    }

    arp_header = (arp_header_t*)(packet + 14);

    printf("\n\n Received packet size: %d\n", packet_header.len);
    printf("Hardware type: %s\n", (ntohs(arp_header->hw_type) == 1) ? "Ethernet" : "Unkown");
    printf("Protocol type: %s\n", (ntohs(arp_header->protocol_type) == 0x0800) ? "IPv4" : "Unkown");
    printf("Operation: %s\n", (ntohs(arp_header->operation) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");

    /* If ethernet and ipv4, print packet content */
    if (ntohs(arp_header->hw_type) == 1 && ntohs(arp_header->protocol_type) == 0x0800) {
      printf("Sender MAC: ");

      for (i = 0; i < 6; i++) { printf("%02X:", arp_header->sender_hw_address[i]); }

      printf("\nSender IP: ");

      for (i = 0; i < 4; i++) { printf("%d.", arp_header->sender_ip_address[i]); }

      printf("\nTarget MAC: ");

      for (i = 0; i < 6; i++) { printf("%02X:", arp_header->target_hw_address[i]); }

      printf("\nTarget IP: ");        

      for (i = 0; i < 4; i++) { printf("%d.", arp_header->target_ip_address[i]); }

      printf("\n");
    }    
  }
}
