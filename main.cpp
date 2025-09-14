#include "PcapLib/Lidar2DViewer.h"
#include "main.h"
#include <vector>
#include <iostream>
#include "include/PcapLib/PCAP_parse.h"
#include "include/PcapLib/PCAP_capture.h"   // nhớ include thêm

int main(int argc, char** argv) {
    Lidar2DViewer viewer(SCEEN_WIDTH, SCEEN_HEIGHT);
    std::vector<cv::Point2f> points;

    //=============================================================
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return -1;
    }

    const char* filename = argv[1];
    PCAP_capture capture;
    if (!capture.open_file(filename)) {
        std::cerr << "Failed to open pcap file: " << filename << std::endl;
        return -1;
    }

    Pandar64Parser parser;

    // đọc tất cả packet từ file
    auto packets = capture.read_all_packets();
    int packet_count = 0;


    for (size_t i = 0; i < packets.size(); i++) {

        const auto& packet = packets[i];   // lấy packet theo index
        auto cloud = parser.parse_packet(packet);
        if (!cloud.empty()) {
            points.clear();  // reset point list cho packet mới
            for (size_t j = 0; j < cloud.size(); j++) {
                const auto& p = cloud[j];
                points.push_back(cv::Point2f(
                    (SCEEN_WIDTH /2) - p.x*SCALE,
                    (SCEEN_HEIGHT /2) - p.y*SCALE
                ));
            }
            viewer.update(points);
            viewer.show();
            cv::waitKey(1);   // xử lý GUI
        } else {
            std::cerr << "No points in packet #" << i << std::endl;
        }
        if (i%360==0) {
            viewer.clear_all_pixel();
        }
    }

    capture.close_device();
    return 0;
}
