cmake_minimum_required(VERSION 4.0)
project(LIDAR_viewer)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(LIDAR_viewer
        main.cpp
        main.h
        include/Lidar2DViewer.cpp
        include/Lidar2DViewer.h
        include/PCAP_capture.cpp
        include/PcapLib/PCAP_capture.h
        include/PcapLib/PCAP_parse.h)
