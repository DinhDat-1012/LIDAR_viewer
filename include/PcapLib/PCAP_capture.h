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
#include <exception>

#define SNAP_LEN     65535
#define PROMISC      1
#define NON_PROMISC  0
#define TIMEOUT_MS   10000

//================ STRUCTS ======================
struct PCAP_Header {
    uint32_t timestamp_second;
    uint32_t timestamp_microsecond;
    uint32_t capture_length;
    uint32_t length;
};

struct PCAP_Packet {
    PCAP_Header packet_header;
    const u_char* packet_data;
};

struct Pcap_packet_list {
    std::vector<PCAP_Packet> packets_list;
};

//================ CLASS ========================
class PCAP_capture {
private:
    pcap_t* handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    bool isOpen;

public:
    PCAP_capture() : handle(nullptr), isOpen(false) {
        memset(&error_buffer, 0, sizeof(error_buffer));
    }

    ~PCAP_capture() {
        close_device();
    }

    //==========================================================================
    // Open device for live capture
    //==========================================================================
    bool open_device(const std::string& device,
                     int snaplen = SNAP_LEN,
                     int promisc = PROMISC,
                     int timeout_ms = TIMEOUT_MS) {

        handle = pcap_open_live(device.c_str(), snaplen, promisc, timeout_ms, error_buffer);

        if (handle == nullptr) {
            std::cerr << "Error when opening device: " << error_buffer << std::endl;
            return false;
        }
        isOpen = true;
        return true;
    }

    // Open file (offline mode)
    bool open_file(const std::string& pcap_file_dir) {
        handle = pcap_open_offline(pcap_file_dir.c_str(), error_buffer);
        if (handle == nullptr) {
            std::cerr << "Error when opening file: " << error_buffer << std::endl;
            return false;
        }
        isOpen = true;
        return true;
    }

    // Read one packet
    bool read_packet(PCAP_Packet& packet) {
        if (!isOpen || handle == nullptr) {
            return false;
        }
        struct pcap_pkthdr* header;
        const u_char* packet_data;

        int response = pcap_next_ex(handle, &header, &packet_data);

        if (response == -1) {
            std::cerr << "Error when reading packet: " << pcap_geterr(handle) << std::endl;
            return false;
        } else if (response == 0) {
            // timeout
            return false;
        } else if (response == -2) {
            // EOF
            return false;
        }

        packet.packet_header.timestamp_second      = header->ts.tv_sec;
        packet.packet_header.timestamp_microsecond = header->ts.tv_usec;
        packet.packet_header.capture_length        = header->caplen;
        packet.packet_header.length                = header->len;
        packet.packet_data                         = packet_data;

        return true;
    }

    // Set non-blocking mode
    bool set_non_blocking(bool non_blocking_enable) {
        if (!isOpen || handle == nullptr) {
            return false;
        }
        int error = pcap_setnonblock(handle, non_blocking_enable, error_buffer);
        if (error < 0) {
            std::cerr << "Error when setting non-blocking: " << error_buffer << std::endl;
            return false;
        }
        return true;
    }

    // Apply a BPF filter (ví dụ: "udp port 2368" cho Hesai Pandar128)
    bool apply_filter(const std::string& filter_exp) {
        if (!isOpen || handle == nullptr) {
            return false;
        }
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

    // Capture live packets continuously (for Hesai Pandar128)
    void capture_live(int max_packets = 0) {
        if (!isOpen || handle == nullptr) {
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
                std::cout << "[Packet " << packet_count << "] "
                          << "len=" << header->len
                          << " caplen=" << header->caplen
                          << " ts=" << header->ts.tv_sec << "." << header->ts.tv_usec
                          << std::endl;

                // In 16 byte đầu để debug
                for (int i = 0; i < 16 && i < header->caplen; i++) {
                    printf("%02X ", data[i]);
                }
                printf("\n");

                if (max_packets > 0 && packet_count >= max_packets) break;

            } else if (res == 0) {
                // timeout
                continue;
            } else if (res == -1) {
                std::cerr << "Error when reading packet: " << pcap_geterr(handle) << std::endl;
                break;
            } else if (res == -2) {
                std::cout << "[OK] End of capture" << std::endl;
                break;
            }
        }
    }

    // Close
    void close_device() {
        if (isOpen && handle != nullptr) {
            pcap_close(handle);
            handle = nullptr;
            isOpen = false;
        }
    }

    bool is_open() const {
        return isOpen;
    }

    // Trả về raw handle (nếu cần dùng trực tiếp pcap_* API)
    pcap_t* get_handle() {
        return handle;
    }
};

#endif // PCAP_CAPTURE_H
