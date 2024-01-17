#pragma once

#include <arpa/inet.h>
#include <stdint.h>

#pragma pack(push, 1)
struct _ieee80211_beacon_frame_header {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t receiver_address[6];
    uint8_t transmitter_address[6];
    uint8_t bssid[6];
    uint16_t sequence_control;
};
#pragma pack(pop)
