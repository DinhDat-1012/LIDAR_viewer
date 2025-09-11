#pragma once
//
// Created by ctf on 9/11/25.
//
#include "pcap.h"
#include "string"
#include <iostream>

#define Destination_IP "192.168.1.2"
#define Destination_Port "2368"
#define Source_IP "192.168.3.201"
#define Source_Port "2368"
#define Time_OUT 1000
#define SNAP_LEN 65535

#ifndef LIDAR_VIEWER_PCAP_CAPTURE_H
#define LIDAR_VIEWER_PCAP_CAPTURE_H

class PCAP_capture {
    private:
          pcap_t *pcap_handle;
          char errbuf[PCAP_ERRBUF_SIZE];
          bool is_open;
    public:
    PCAP_capture();
    ~PCAP_capture();
    bool open_device(const std::string &device, int snap_len = SNAP_LEN, int promisc = 1, int timeout_ms = Time_OUT);

    bool open_file(const std::string &filename_dir);
    bool close_device();
    bool close_file();

    bool isOpened() const{return is_open;};
};

#endif

#endif //LIDAR_VIEWER_PCAP_CAPTURE_H