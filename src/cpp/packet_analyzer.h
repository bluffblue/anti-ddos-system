#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include <vector>
#include <string>
#include <ctime>

class PacketAnalyzer {
public:
    struct PacketInfo {
        std::string source_ip;
        uint32_t packet_count;
        double timestamp;
        uint32_t size;
    };

    PacketAnalyzer(uint32_t threshold, double window);
    bool analyze_packet(const std::string& ip, uint32_t size, double timestamp);
    double calculate_threat_score(const std::string& ip);
    void cleanup_old_packets(double current_time);

private:
    uint32_t packet_threshold;
    double time_window;
    std::vector<PacketInfo> packet_history;
};

#endif 