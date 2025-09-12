cmake_minimum_required(VERSION 3.10)
project(LIDAR_viewer)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenCV REQUIRED)
find_library(PCAP_LIBRARY pcap)

include_directories(
        ${OpenCV_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/include
)

add_executable(LIDAR_viewer
        main.cpp
)

target_link_libraries(LIDAR_viewer
        ${OpenCV_LIBRARIES}  # với OpenCV>=4, dùng OpenCV_LIBRARIES
        ${PCAP_LIBRARY}
)
