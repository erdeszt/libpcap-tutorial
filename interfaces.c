/*
 * Original author: Martin Casado (https://github.com/lsanotes/libpcap-tutorial)
 * Refactored by: erdeszt (https://github.com/erdeszt)
 * Build with: `gcc interfaces.c -Wall -O3 -lpcap -o app` (or `make interfaces`)
 * Run with: sudo ./build/interfaces (or `make interfaces`)
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char** argv) {
  char* device;
  char* net;
  char* mask;
  char error_buffer[PCAP_ERRBUF_SIZE];
  int result;
  bpf_u_int32 net_ptr;
  bpf_u_int32 mask_ptr;
  struct in_addr address;

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

  if (device == NULL) {
    fprintf(stderr, "pcap_lookupdev(): %s\n", error_buffer);
    exit(1);
  }

  printf("DEV: %s\n", device);

  result = pcap_lookupnet(device, &net_ptr, &mask_ptr, error_buffer);

  if (result == -1) {
    fprintf(stderr, "pcap_lookupnet(): %s\n", error_buffer);
    exit(1);
  }

  address.s_addr = net_ptr;
  net = inet_ntoa(address);

  if (net == NULL) {
    fprintf(stderr, "inet_ntoa(): %s\n", error_buffer);
    exit(1);
  }

  printf("NET: %s\n", net);

  address.s_addr = mask_ptr;
  mask = inet_ntoa(address);

  if (mask == NULL) {
    fprintf(stderr, "inet_ntoa(): %s\n", error_buffer);
    exit(1);
  }

  printf("MASK: %s\n", mask);

  return 0;
}