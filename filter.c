/*
 * Original author: Martin Casado (https://github.com/lsanotes/libpcap-tutorial)
 * Refactored by: erdeszt (https://github.com/erdeszt)
 * Build with: `gcc filter.c -Wall -O3 -lpcap -o app` (or `make filter`)
 * Run with: sudo ./build/filter (or `make run_filter`)
 */

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define MAX_BYTES_TO_CAPTURE 2048

/* Callback function called by pcap_loop() everytime
 * a packet arrives to the network card.
 */
void process_packet(u_char* arg, const struct pcap_pkthdr* packet_header, const u_char* packet) {
  int i;
  int* counter = (int*)arg;

  printf("Packet count: %d\n", ++(*counter));
  printf("Received packet size: %d\n", packet_header->len);
  printf("Payload:\n");

  for (i = 0; i < packet_header->len; i++) {
    printf("%c ", isprint(packet[i]) ? packet[i] : '.');

    if ((i % 16 == 0 && i != 0) || i == packet_header->len -1) {
      printf("\n");
    }
  } 
}

int main(int argc, char** argv) {
  int count = 0;
  char error_buffer[PCAP_ERRBUF_SIZE];
  char* filter_expression = "port 80";
  char* device;
  pcap_t* handler;
  struct bpf_program filter_program;
  bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;

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

  printf("DEV: %s\n", device);

  handler = pcap_open_live(device, MAX_BYTES_TO_CAPTURE, 1, 512, error_buffer);

  if (handler == NULL) {
    fprintf(stderr, "pcap_open_live(): %s\n", error_buffer);
    exit(1);
  }

  /* Vars: fp, filter_exp, net */
  if (pcap_compile(handler, &filter_program, filter_expression, 0, net) == -1) {
    fprintf(stderr, "pcap_compile('%s'): %s\n", filter_expression, pcap_geterr(handler));
    exit(1);
  }

  if (pcap_setfilter(handler, &filter_program) == -1) {
    fprintf(stderr, "pcap_setfilter('%s'): %s\n", filter_expression, pcap_geterr(handler));
    exit(1);
  }

  if (pcap_loop(handler, -1, process_packet, (u_char*)&count) == -1) {
    fprintf(stderr, "pcap_loop(): %s\n", pcap_geterr(handler));
    exit(1);
  }

  return 0;
}