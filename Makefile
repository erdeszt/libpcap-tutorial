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

clean:
	rm build/*