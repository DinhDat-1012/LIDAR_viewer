#pragma once
//
// Created by ctf on 9/11/25.
//
#ifndef LIDAR_VIEWER_LIDAR2DVIEWER_H
#define LIDAR_VIEWER_LIDAR2DVIEWER_H

#include<pcap/pcap.h>
#include<string>
#include<opencv4/opencv2/opencv.hpp>
class Lidar2DViewer {
    public: Lidar2DViewer(const std::string &pcapPath);
    ~Lidar2DViewer();
    void run();

    private:

};


#endif //LIDAR_VIEWER_LIDAR2DVIEWER_H