#pragma once

#include <arpa/inet.h>
#include "mac.h"

#pragma pack(push, 1)
struct beacon_frame_header final {

};
typedef beacon_frame_header *Pbeacon_frame_header;
#pragma pack(pop)

#include <stdint.h>

#pragma pack(push, 1)
struct ieee80211_beacon_frame {
    uint16_t frame_control;
    uint16_t duration;
    Mac receiver_address;
    Mac transmitter_address;
    Mac bssid;
    uint16_t sequence_control;
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities;

    uint8_t information_elements[256]; 
};
#pragma pack(pop)
