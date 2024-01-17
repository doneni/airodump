#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <unordered_map>
#include "radiotap.h"
#include "beacon_frame.h"
#include "wireless.h"

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
	std::unordered_map<std::string, int> um;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}  

		struct _ieee80211_radiotap_header* rdt_hdr = (struct _ieee80211_radiotap_header*)packet;
		struct _ieee80211_beacon_frame_header* bc_hdr = (struct _ieee80211_beacon_frame_header*)(rdt_hdr->it_len + packet);
		struct _ieee80211_wireless_management_header* wire_hdr = (struct _ieee80211_wireless_management_header*)(rdt_hdr->it_len + sizeof(_ieee80211_beacon_frame_header) + packet);

		if(bc_hdr->frame_control != 0x80)
			continue;
		printf("\n\n\n==========%d packet==========\n", cnt++);
		printf("beacon type: %02x\n", bc_hdr->frame_control);
        printf("bssid: ");
		print_mac(bc_hdr->bssid);
		printf("\n");
		printf("essid: ");
		std::string ssid_str(reinterpret_cast<char*>(wire_hdr->ssid), wire_hdr->tag_length);
		printf("%s\n", ssid_str.c_str());
		if(um.find(ssid_str) != um.end())
			um[ssid_str]++;
		else
			um[ssid_str] = 1;
		printf("beacons: %d\n", um[ssid_str]);
		printf("\n");
		
	}

	pcap_close(pcap);
    return 0;
}