#include "packet_analyzer.h"
#include <algorithm>

PacketAnalyzer::PacketAnalyzer(uint32_t threshold, double window) 
    : packet_threshold(threshold), time_window(window) {}

bool PacketAnalyzer::analyze_packet(const std::string& ip, uint32_t size, double timestamp) {
    cleanup_old_packets(timestamp);
    
    packet_history.push_back({ip, 1, timestamp, size});
    
    uint32_t count = 0;
    for (const auto& packet : packet_history) {
        if (packet.source_ip == ip) {
            count++;
        }
    }
    
    return count > packet_threshold;
}

double PacketAnalyzer::calculate_threat_score(const std::string& ip) {
    uint32_t count = 0;
    uint32_t total_size = 0;
    
    for (const auto& packet : packet_history) {
        if (packet.source_ip == ip) {
            count++;
            total_size += packet.size;
        }
    }
    
    double packets_per_second = count / time_window;
    double bytes_per_second = total_size / time_window;
    
    return (packets_per_second * 0.7 + bytes_per_second * 0.3) / packet_threshold * 100;
}

void PacketAnalyzer::cleanup_old_packets(double current_time) {
    packet_history.erase(
        std::remove_if(
            packet_history.begin(),
            packet_history.end(),
            [&](const PacketInfo& packet) {
                return current_time - packet.timestamp > time_window;
            }
        ),
        packet_history.end()
    );
} 