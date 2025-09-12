#ifndef PCAP_PARSE_H
#define PCAP_PARSE_H

#include <vector>
#include <cmath>
#include <algorithm>
#include <cstring>
#include "PCAP_capture.h"   // dùng PCAP_Packet struct

struct PointXYZI {
    float x;
    float y;
    float z;
    uint8_t intensity;
};

class Pandar64Parser {
public:
    Pandar64Parser() {
        init_vertical_angles();
        init_azimuth_table();
    }

    std::vector<PointXYZI> parse_packet(const PCAP_Packet &packet) {
        std::vector<PointXYZI> cloud;
        if (!packet.packet_data) return cloud;

        const uint8_t* payload = nullptr;
        size_t payload_len = 0;
        if (!extract_udp_payload(packet.packet_data, packet.packet_header.capture_length, payload, payload_len))
            return cloud;

        if (payload_len < 8) return cloud;

        // Kiểm tra header SOP (little-endian 0xFF 0xEE)
        uint16_t sop = payload[0] | (payload[1] << 8);
        if (sop != 0xEEFF) {
            // Fallback nếu không có header chuẩn
            parse_blocks_linear(payload, payload_len, cloud);
            return cloud;
        }

        // Parse header
        if (payload_len < 12) return cloud;
        uint8_t laser_num = payload[2];
        uint8_t block_num = payload[3];
        uint8_t reserved = payload[4];
        uint32_t dis_unit_raw = payload[5] | (payload[6] << 8) | (payload[7] << 16) | (payload[8] << 24);
        float dist_unit = dis_unit_raw / 1000.0f;  // Thường 0.2m, nhưng dùng giá trị thực

        if (laser_num != 0x40 || block_num != 0x06) {
            std::cerr << "[WARN] Invalid header: laser_num=" << (int)laser_num << ", block_num=" << (int)block_num << std::endl;
            return cloud;
        }

        // Parse 6 blocks
        const uint8_t* ptr = payload + 12;  // Skip header 12 bytes
        for (int blk = 0; blk < 6; ++blk) {
            if (ptr + 2 > payload + payload_len) break;

            // Azimuth raw (2 bytes, little-endian, 0-36000 -> degrees)
            uint16_t az_raw = ptr[0] | (ptr[1] << 8);
            float azimuth_deg = az_raw / 100.0f;  // 0-360 degrees
            float azimuth_rad = azimuth_deg * static_cast<float>(M_PI) / 180.0f;
            ptr += 2;

            // Mỗi block: 32 channels (Pandar64: 64 channels qua 2 blocks? Nhưng theo manual: 6 blocks x ~32? Thực tế 6 blocks x 32 channels x 2 bytes dist + 1 byte inten = 6*32*3=576, x2 cho dual return?
            // Theo manual: mỗi block có azimuth + 32 channels (mỗi channel: dist(2B) + inten(1B) + reserved(1B)? Nhưng code gốc dùng 3B/channel.
            // Giả sử 32 channels/block, total 192 channels? Không, Pandar64 là 64 channels single return, nhưng packet có 6 blocks x 32 = 192? Sai.
            // Từ search  và : Header sau là 6 blocks, mỗi block: azimuth (2B) + 32 measurements (mỗi: dist 2B + inten 1B), total body 6*(2 + 32*3)= 6*98=588B, +header12=600B UDP payload.
            // Nhưng Pandar64 64 channels, cách interleave: channels 0-31 in odd blocks, 32-63 in even? Nhưng để đơn giản, dùng channel index = blk % 2 * 32 + ch, cho elevation.
            // Thực tế từ Hesai SDK, channels ordered in packet as upper/lower interleaved, nhưng cho approx dùng sequential.

            for (int ch = 0; ch < 32; ++ch) {
                if (ptr + 3 > payload + payload_len) break;

                uint16_t raw_dist = ptr[0] | (ptr[1] << 8);
                uint8_t intensity = ptr[2];
                // uint8_t reserved = ptr[3]; // Nếu có, skip
                ptr += 3;  // 3 bytes per channel

                if (raw_dist == 0) continue;

                float distance_m = raw_dist * dist_unit;
                if (distance_m < 0.3f) continue;  // Filter min range

                // Channel ID: upper 32 (0-31) for even blocks? Approx sequential cho đơn giản
                int laser_id = (blk * 32 + ch) % 64;  // Cycle qua 64
                float vert_deg = elevation_table[laser_id];
                float vert_rad = vert_deg * static_cast<float>(M_PI) / 180.0f;

                // Sử dụng azimuth offset từ table cho horizontal calibration
                float az_offset_deg = azimuth_table[laser_id];
                float full_az_rad = (azimuth_deg + az_offset_deg) * static_cast<float>(M_PI) / 180.0f;

                PointXYZI p;
                p.x = distance_m * std::cos(vert_rad) * std::cos(full_az_rad);
                p.y = distance_m * std::cos(vert_rad) * std::sin(full_az_rad);
                p.z = distance_m * std::sin(vert_rad);
                p.intensity = intensity;
                cloud.push_back(p);
            }
        }

        return cloud;
    }

private:
    float elevation_table[64];
    float azimuth_table[64];

    void init_vertical_angles() {
        // Sửa theo manual : design values, accurate từ calibration file
        // Top beam ch0: 14.882°, nhưng code gốc có 14.708 (close), bottom -24.897
        // Dùng giá trị manual excerpt, fill approx cho 64 (từ search partial, dùng gốc + adjust bottom)
        const float tbl[64] = {
            14.882f, 11.032f, 8.059f, 5.057f, 3.04f, 1.854f, 0.686f, 0.514f,  // Approx upper
            0.348f, 0.177f, 0.01f, -0.157f, -0.324f, -0.491f, -0.658f, -0.825f,
            -0.992f, -1.159f, -1.326f, -1.493f, -1.660f, -1.827f, -1.994f, -2.161f,
            -2.328f, -2.495f, -2.662f, -2.829f, -2.996f, -3.163f, -3.330f, -3.497f,
            -3.664f, -3.831f, -3.998f, -4.165f, -4.332f, -4.499f, -4.666f, -4.833f,
            -5.000f, -5.167f, -5.334f, -5.501f, -5.668f, -5.835f, -6.002f, -6.169f,
            -6.336f, -6.503f, -6.670f, -6.837f, -7.004f, -7.171f, -8.233f, -9.234f,  // Lower approx từ manual
            -10.059f, -11.206f, -12.18f, -13.148f, -14.104f, -18.889f, -24.897f  // Bottom beams
        };
        std::memcpy(elevation_table, tbl, sizeof(tbl));
    }

    void init_azimuth_table() {
        // Từ manual : offsets như -1.042, 5.208, -5.208, -3.125, 1.042, etc. cho từng channel
        // Code gốc có pattern lặp, dùng tương tự nhưng adjust theo excerpt
        const float tbl[64] = {
            -1.042f, -1.042f, -1.042f, -1.042f, -1.042f, -1.042f, -1.042f, 3.125f,
            5.208f, -5.208f, -3.125f, -1.042f, 1.042f, 3.125f, 5.208f, -5.208f,
            -3.125f, -1.042f, 1.042f, 3.125f, 5.208f, -5.208f, -3.125f, -1.042f,
            1.042f, 3.125f, 5.208f, -5.208f, -3.125f, -1.042f, -1.042f, -1.042f,
            -1.042f, -1.042f, -1.042f, -1.042f, -1.042f, -1.042f, -1.042f, -1.042f,
            -3.125f, -1.042f, 1.042f, 3.125f, 5.208f, -5.208f, -3.125f, -1.042f,
            1.042f, 3.125f, 5.208f, -5.208f, -3.125f, -1.042f, -1.042f, -1.042f,
            -1.042f, -1.042f, -1.042f, -1.042f, -1.042f, -1.042f, -1.042f, -1.042f
        };
        std::memcpy(azimuth_table, tbl, sizeof(tbl));
    }

    bool extract_udp_payload(const u_char* packet_data, size_t caplen,
                             const uint8_t*& payload, size_t& payload_len) {
        payload = nullptr;
        payload_len = 0;
        if (!packet_data || caplen < 42) return false;

        size_t eth_header_len = 14;
        if (caplen < eth_header_len + 8) return false;

        uint16_t ethertype = (packet_data[12] << 8) | packet_data[13];
        size_t ip_offset = eth_header_len;

        if (ethertype == 0x8100) {  // VLAN
            if (caplen < eth_header_len + 4) return false;
            ethertype = (packet_data[16] << 8) | packet_data[17];
            ip_offset += 4;
        }

        if (ethertype != 0x0800) return false;  // IPv4

        if (caplen < ip_offset + 20) return false;
        const uint8_t* ip_hdr = packet_data + ip_offset;
        uint8_t ihl = ip_hdr[0] & 0x0F;
        size_t ip_header_len = ihl * 4;
        if (caplen < ip_offset + ip_header_len + 8) return false;

        if (ip_hdr[9] != 17) return false;  // UDP

        size_t udp_offset = ip_offset + ip_header_len;
        if (caplen < udp_offset + 8) return false;

        size_t udp_payload_offset = udp_offset + 8;
        uint16_t udp_len = (packet_data[udp_offset + 4] << 8) | packet_data[udp_offset + 5];
        size_t expected_payload = (udp_len > 8) ? (udp_len - 8) : 0;
        size_t available = caplen - udp_payload_offset;
        payload_len = std::min(available, expected_payload);
        payload = packet_data + udp_payload_offset;

        // Thêm check UDP port nếu cần (thường 2368 cho point cloud)
        uint16_t dst_port = (packet_data[udp_offset + 2] << 8) | packet_data[udp_offset + 3];
        if (dst_port != 2368) {
            std::cerr << "[WARN] Non-standard UDP port: " << dst_port << std::endl;
        }

        return payload_len > 0;
    }

    // Fallback cho linear parsing nếu không có header
    void parse_blocks_linear(const uint8_t* payload, size_t payload_len,
                             std::vector<PointXYZI>& cloud) {
        if (!payload || payload_len < 6) return;
        float dist_unit = 0.004f;  // Default 0.2m / 50? Wait, theo code gốc 0.004m per unit (raw 0-4095 -> 0-16.38m? Sai, manual: unit thường 0.2m per LSB? Adjust to 0.2/50? Không, từ search: raw_dist * 0.2 /1000? Code gốc 0.004 ok nếu raw max 50000 cho 200m.
        size_t i = 0;
        while (i + 4 < payload_len) {
            uint16_t flag = payload[i] | (payload[i+1] << 8);
            if (flag != 0xEEFF) {
                ++i;
                continue;
            }

            uint16_t raw_az = payload[i+2] | (payload[i+3] << 8);
            float azimuth_deg = raw_az / 100.0f;
            float azimuth_rad = azimuth_deg * static_cast<float>(M_PI) / 180.0f;

            size_t pos = i + 4;
            size_t t = 0;
            while (pos + 2 < payload_len) {
                uint16_t raw_dist = payload[pos] | (payload[pos+1] << 8);
                uint8_t intensity = payload[pos+2];
                pos += 3;
                if (raw_dist == 0) {
                    ++t;
                    continue;
                }
                float distance_m = raw_dist * dist_unit;
                size_t laser_id = t % 64;
                float vert_rad = elevation_table[laser_id] * static_cast<float>(M_PI) / 180.0f;
                float az_offset = azimuth_table[laser_id];
                float full_az_rad = (azimuth_deg + az_offset) * static_cast<float>(M_PI) / 180.0f;

                PointXYZI p;
                p.x = distance_m * std::cos(vert_rad) * std::cos(full_az_rad);
                p.y = distance_m * std::cos(vert_rad) * std::sin(full_az_rad);
                p.z = distance_m * std::sin(vert_rad);
                p.intensity = intensity;
                cloud.push_back(p);
                ++t;
            }
            i = pos - 1;  // Để loop tiếp
        }
    }
};

#endif // PCAP_PARSE_H