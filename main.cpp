#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ieee80211_radiotap.h"
#include "beacon_frame.h"
#include "mac.h"

#pragma pack(push, 1)
struct RdtBcnPacket final {
    struct _ieee80211_radiotap_header rdt_;
    struct beacon_frame_header bc_;
};
#pragma pack(pop)

void usage()
{
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_mac(const u_int8_t *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

int main(int argc, char** argv)
{
    if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
    int cnt = 1;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}  

        //raw hex
        printf("\n\n\n==========%d packet==========\n", cnt++);
        int i = 0;
        for (i = 0; i < header->len; i++) {
            printf("%02x ", packet[i]);
        }
        printf("total length: %d\n", i);
        printf("\n");
	}

	pcap_close(pcap);
    return 0;
}