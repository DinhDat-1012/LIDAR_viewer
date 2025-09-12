#include "include/PcapLib/PCAP_capture.h"
#include <pcap/pcap.h>
#include <iostream>

int main() {
    PCAP_capture cap;

    // Thay "eth0" bằng tên card mạng thực tế của bạn (ví dụ: ens33, enp3s0, ...)
    std::string device = "enx00e04c7405a7";

    if (!cap.open_device(device)) {
        std::cerr << "[ERR] Cannot open device: " << device << std::endl;
        return -1;
    }
    std::cout << "[OK] Opened live capture on device: " << device << std::endl;

    // -----------------------
    // Thiết lập filter: chỉ bắt UDP port 2368 (data của Hesai Pandar128)
    // -----------------------
    struct bpf_program fp;
    std::string filter_exp = "udp port 2368";

    if (pcap_compile(cap.get_handle(), &fp, filter_exp.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[ERR] Couldn't parse filter: " << pcap_geterr(cap.get_handle()) << std::endl;
        return -1;
    }

    if (pcap_setfilter(cap.get_handle(), &fp) == -1) {
        std::cerr << "[ERR] Couldn't install filter: " << pcap_geterr(cap.get_handle()) << std::endl;
        return -1;
    }

    std::cout << "[OK] Filter applied: " << filter_exp << std::endl;

    // -----------------------
    // Vòng lặp bắt gói tin
    // -----------------------
    int packet_count = 0;
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* data;

        int res = pcap_next_ex(cap.get_handle(), &header, &data);
        if (res == 1) {
            packet_count++;
            std::cout << "[Packet " << packet_count << "] "
                      << "len=" << header->len
                      << " caplen=" << header->caplen
                      << " ts=" << header->ts.tv_sec << "." << header->ts.tv_usec
                      << std::endl;

            // In vài byte đầu của packet
            for (int i = 0; i < 16 && i < header->caplen; i++) {
                printf("%02X ", data[i]);
            }
            printf("\n");

        } else if (res == 0) {
            // timeout
            continue;
        } else if (res == -1) {
            std::cerr << "[ERR] Error reading packet: " << pcap_geterr(cap.get_handle()) << std::endl;
            break;
        } else if (res == -2) {
            std::cout << "[OK] End of capture" << std::endl;
            break;
        }
    }

    cap.close_device();
    return 0;
}
