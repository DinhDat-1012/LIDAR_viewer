#pragma once
//
// Created by ctf on 9/11/25.
//
// this header define the way to display pcap stream to screen using openCV library.
// created by Datdd9 in 11092025 for adas lv project
// if you have any confuse of this one you can contact me at dinhdat1012vn@gmail.com
#ifndef LIDAR_VIEWER_LIDAR2DVIEWER_H
#define LIDAR_VIEWER_LIDAR2DVIEWER_H

#include "vector"
#include "string"
#include "iostream"
#include "pcap.h"

#define SNAP_LEN 65535
#define PROMISC 1
#define NONE_PROMISC 0
#define TIME_OUT_MS 10000

#define UINT uint32_t
struct Pcap_packet {
    //uint => uint32_t
    UINT second;
    UINT microseconds;
    UINT capture_length;
    UINT len;
    const u_char *pcap_packet_data;
};
//=============
//a point data struct
//=============
struct Lidar_point_3D{
    float x;
    float y;
    float z;
    float intensity;
    Lidar_point_3D(float _x = 0, float _y = 0, float _z = 0, float _intensity =0) {
        this->x = _x;
        this->y = _y;
        this->z = _z;
        this->intensity = _intensity;
    }
};
struct Lidar_point_2D {
    float x;
    float y;
    Lidar_point_2D(float _x = 0, float _y = 0) {
        this->x = _x;
        this->y = _y;
    }
};
//====================
//a frame LIDAR
//====================
struct LIDAR_FRAME {
    uint64_t timestamp;
    std::vector<Lidar_point_3D> points;
};
struct LIDAR_FRAME2D {
    uint64_t timestamp;
    std::vector<Lidar_point_2D> points;
};
class PCAP_capture {
    private:
    pcap_t *pcap;
    char error_buffer[PCAP_ERRBUF_SIZE];
    bool isOpen;
    public:
    PCAP_capture();
    ~PCAP_capture();
};


#endif //LIDAR_VIEWER_LIDAR2DVIEWER_H