#pragma once

#include <arpa/inet.h>
#include <stdint.h>

#pragma pack(push, 1)
struct _ieee80211_wireless_management_header {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities_information;
    uint8_t tag_numger;
    uint8_t tag_length;
    uint8_t ssid[0];
};
#pragma pack(pop)
