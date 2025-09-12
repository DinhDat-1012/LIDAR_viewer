#pragma once
//
// Created by ctf on 9/11/25.
//
#include "PCAP_capture.h"
#include <vector>

#ifndef LIDAR_VIEWER_PCAP_PARSE_H
#define LIDAR_VIEWER_PCAP_PARSE_H


class PCAP_parse {
    private:
    static constexpr float ROTATION_RESOLUTION = 0.01f;
    static constexpr float BLOCK_PER_PACKET = 12;
    static constexpr float SCANS_PER_BLOCK = 32;
    static constexpr float DISTANCE_RESOLUTION = 0.002f;
public:
    PCAP_parse() = default;

    std::vector<PCAP_capture> PCAP_parse_packet(const PCAP_capture& pcap_packet);
    std::vector<PCAP_capture> PCAP_parse_file(const PCAP_capture& pcap_file);
};

#endif //LIDAR_VIEWER_PCAP_PARSE_H