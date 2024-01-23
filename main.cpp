#include "main.h"

void usage()
{
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
}

struct airodump_info{
	int beacons;
	std::string essid;
};

std::unordered_map<std::string, struct airodump_info> um;

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
	for(const auto& entry : um)
		printf("%s\t%d\t%s\n", entry.first.c_str(), entry.second.beacons,entry.second.essid.c_str());
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	return;
}

int main(int argc, char** argv)
{
    if (!parse(&param, argc, argv))
		return -1;
	
	std::thread thrd(print_info);

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

		struct _ieee80211_radiotap_header* radiotap_hdr = (struct _ieee80211_radiotap_header*)packet;
		struct _ieee80211_beacon_frame_header* beacon_hdr = (struct _ieee80211_beacon_frame_header*)(radiotap_hdr->it_len + packet);
		struct _ieee80211_wireless_management_header* wireless_hdr = (struct _ieee80211_wireless_management_header*)(radiotap_hdr->it_len + sizeof(_ieee80211_beacon_frame_header) + packet);

		if(beacon_hdr->frame_control != 0x80 || wireless_hdr->tag_number != 0)
			continue;

		char bssid_str[18];
		std::sprintf(bssid_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                       beacon_hdr->bssid[0], beacon_hdr->bssid[1], beacon_hdr->bssid[2], beacon_hdr->bssid[3], beacon_hdr->bssid[4], beacon_hdr->bssid[5]);
		std::string essid_str(reinterpret_cast<char*>(wireless_hdr->ssid), wireless_hdr->tag_length);
		if(um.find(bssid_str) != um.end())
			um[bssid_str].beacons++;
		else
		{
			struct airodump_info info;
			info.beacons = 1;
			info.essid = essid_str;
			um[bssid_str] = info;
		}

		print_info();
	}

	thrd.join();
	pcap_close(pcap);
    return 0;
}