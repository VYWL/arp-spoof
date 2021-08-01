#include "functions.h"

int main(int argc, char* argv[]) {
	if (argc <= 2) {
		usage();
		return -1;
	}

	// open
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// Do tasks
	arpSpoofing(argc, argv, dev, handle);

	// close
	pcap_close(handle);
}

