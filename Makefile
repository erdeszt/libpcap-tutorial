CC=gcc
CFLAGS=-Wall -O3 -lpcap

capture:
	$(CC) capture.c $(CFLAGS) -o build/capture

run_capture:
	sudo ./build/capture

sniffer:
	 $(CC) sniffer.c $(CFLAGS) -o build/sniffer

run_sniffer:
	sudo ./build/sniffer

interfaces:
	$(CC) interfaces.c $(CFLAGS) -o build/interfaces

run_interfaces:
	sudo ./build/interfaces

filter:
	$(CC) filter.c $(CFLAGS) -o build/filter

run_filter:
	sudo ./build/filter

arp:
	$(CC) arp.c $(CFLAGS) -o build/arp

run_arp:
	sudo ./build/arp

clean:
	rm build/*