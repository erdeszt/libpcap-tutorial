CC=gcc
CFLAGS=-Wall -O3 -lpcap

capture:
	$(CC) capture.c $(CFLAGS) -o build/capture

run_capture:
	sudo ./build/capture

clean:
	rm build/*