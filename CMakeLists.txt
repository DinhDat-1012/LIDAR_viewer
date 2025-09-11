cmake_minimum_required(VERSION 4.0)
project(LIDAR_viewer)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(LIDAR_viewer
        main.cpp
        main.h)
