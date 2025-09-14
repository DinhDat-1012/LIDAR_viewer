#pragma once
//==============================================
// created by datdd9 20251109
//==============================================
#ifndef PCAP_CAPTURE_H
#define PCAP_CAPTURE_H

#include <pcap/pcap.h>
#include <string>
#include <vector>
#include <iostream>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#define SNAP_LEN     65535
#define PROMISC      1
#define NON_PROMISC  0
#define TIMEOUT_MS   1000

//================ STRUCTS ======================
struct PCAP_Header {
    uint32_t timestamp_second;
    uint32_t timestamp_microsecond;
    uint32_t capture_length;
    uint32_t length;
};

struct PCAP_Packet {
    PCAP_Header packet_header;
    std::vector<u_char> packet_data;   // copy an toàn dữ liệu
};

//================ CLASS ========================
class PCAP_capture {
private:
    pcap_t* handle {nullptr};
    char error_buffer[PCAP_ERRBUF_SIZE] = {};
    bool isOpen {false};

public:
    PCAP_capture() = default;

    ~PCAP_capture() {
        close_device();
    }

    //==========================================================================
    // Open device for live capture
    //==========================================================================
    bool open_device(const std::string& device,
                     int snaplen = SNAP_LEN,
                     int promisc = PROMISC,
                     int timeout_ms = TIMEOUT_MS)
    {
        handle = pcap_open_live(device.c_str(), snaplen, promisc, timeout_ms, error_buffer);
        if (!handle) {
            std::cerr << "Error when opening device: " << error_buffer << std::endl;
            return false;
        }
        isOpen = true;
        return true;
    }

    // Open file (offline mode)
    bool open_file(const std::string& pcap_file_dir) {
        handle = pcap_open_offline(pcap_file_dir.c_str(), error_buffer);
        if (!handle) {
            std::cerr << "Error when opening file:- " << error_buffer << std::endl;
            return false;
        }
        isOpen = true;
        return true;
    }

    // Read one packet
    bool read_packet(PCAP_Packet& packet) {
        if (!isOpen || !handle) return false;

        struct pcap_pkthdr* header;
        const u_char* data;

        int response = pcap_next_ex(handle, &header, &data);
        if (response <= 0) {
            if (response == -1)
                std::cerr << "Error when reading packet: " << pcap_geterr(handle) << std::endl;
            return false;
        }

        packet.packet_header = {
            static_cast<uint32_t>(header->ts.tv_sec),
            static_cast<uint32_t>(header->ts.tv_usec),
            header->caplen,
            header->len
        };
        packet.packet_data.assign(data, data + header->caplen);

        return true;
    }

    // Set non-blocking mode
    bool set_non_blocking(bool enable) {
        if (!isOpen || !handle) return false;

        int error = pcap_setnonblock(handle, enable, error_buffer);
        if (error < 0) {
            std::cerr << "Error when setting non-blocking: " << error_buffer << std::endl;
            return false;
        }
        return true;
    }

    // Apply a BPF filter
    bool apply_filter(const std::string& filter_exp) {
        if (!isOpen || !handle) return false;

        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter_exp.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Error when compiling filter: " << pcap_geterr(handle) << std::endl;
            return false;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Error when setting filter: " << pcap_geterr(handle) << std::endl;
            pcap_freecode(&fp);
            return false;
        }
        pcap_freecode(&fp);
        std::cout << "[OK] Applied filter: " << filter_exp << std::endl;
        return true;
    }

    // Capture live packets continuously
    void capture_live(int max_packets = 0) {
        if (!isOpen || !handle) {
            std::cerr << "Device is not open!" << std::endl;
            return;
        }

        int packet_count = 0;
        while (true) {
            struct pcap_pkthdr* header;
            const u_char* data;

            int res = pcap_next_ex(handle, &header, &data);
            if (res == 1) {
                packet_count++;
                for (int i = 0; i < std::min(16, (int)header->caplen); i++) {
                    printf("%02X ", data[i]);
                }
                printf("\n");

                if (max_packets > 0 && packet_count >= max_packets) break;
            }
            else if (res == 0) {
                continue; // timeout
            }
            else {
                if (res == -1) {
                    std::cerr << "Error when reading packet: " << pcap_geterr(handle) << std::endl;
                    continue;
                }else if (res == -2)
                    std::cout << "[OK] End of capture" << std::endl;

            }
        }
    }

    // Close
    void close_device() {
        if (isOpen && handle) {
            pcap_close(handle);
            handle = nullptr;
            isOpen = false;
        }
    }

    inline bool is_open() const {
        return isOpen;
    }

    // Read all packets from file/device
    std::vector<PCAP_Packet> read_all_packets() {
        std::vector<PCAP_Packet> all_packets;
        PCAP_Packet pkt;

        while (read_packet(pkt)) {
            all_packets.push_back(pkt);
        }
        return all_packets;
    }
};

#endif // PCAP_CAPTURE_H
