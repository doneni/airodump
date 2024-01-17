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

struct airodump_info{
	int beacons;
	std::string essid;
};

std::unordered_map<u_int8_t*, struct airodump_info> um;

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

void print_info()
{
	system("clear");
	printf("BSSID\t\t\t%-10s%-40s\n", "Beacons", "ESSID");
	printf("========================================================\n");
    // for (const auto& entry : um) {
	// 	print_mac(entry.first);
    //     printf("\t%-10d%-20s\n", entry.second.beacons, entry.second.essid.c_str());
    // }
	for(const auto& entry : um)
	{
		printf("%s\t%d\t%s\n", entry.first, entry.second.beacons,entry.second.essid.c_str());
	}
	return;
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

		struct _ieee80211_radiotap_header* rdt_hdr = (struct _ieee80211_radiotap_header*)packet;
		struct _ieee80211_beacon_frame_header* bc_hdr = (struct _ieee80211_beacon_frame_header*)(rdt_hdr->it_len + packet);
		struct _ieee80211_wireless_management_header* wire_hdr = (struct _ieee80211_wireless_management_header*)(rdt_hdr->it_len + sizeof(_ieee80211_beacon_frame_header) + packet);

		if(bc_hdr->frame_control != 0x80)
			continue;
		printf("\n\n\n==========%d packet==========\n", cnt++);
        printf("bssid: ");
		print_mac(bc_hdr->bssid);
		printf("\n");
		std::string ssid_str(reinterpret_cast<char*>(wire_hdr->ssid), wire_hdr->tag_length);
		if(um.find(bc_hdr->bssid) != um.end())
			um[bc_hdr->bssid].beacons++;
		else
		{
			printf("not found %s is added...\n", ssid_str.c_str());
			struct airodump_info info;
			info.beacons = 1;
			info.essid = ssid_str;
			um.insert({bc_hdr->bssid, info});
		}
		
   		for (const auto& entry : um) {
			print_mac(entry.first);
			printf("%-20d%-20s\n", entry.second.beacons, entry.second.essid.c_str());
    	}
		
		// print_info();		
	}

	pcap_close(pcap);
    return 0;
}