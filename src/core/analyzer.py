import numpy as np
from collections import defaultdict
from .cpp_bridge import CPPBridge

class TrafficAnalyzer:
    def __init__(self):
        self.packet_threshold = 1000
        self.time_window = 1.0
        self.connection_tracker = defaultdict(list)
        self.cpp_analyzer = CPPBridge()
        
    def analyze_traffic(self, traffic_data):
        threats = []
        current_time = traffic_data.timestamp
        
        for packet in traffic_data.packets:
            is_threat = self.cpp_analyzer.analyze_packet(
                packet.source_ip,
                packet.size,
                current_time
            )
            
            if is_threat:
                threat_score = self.cpp_analyzer.get_threat_score(packet.source_ip)
                threats.append({
                    'ip': packet.source_ip,
                    'severity': int(threat_score),
                    'type': self.detect_attack_type(packet)
                })
                
        return threats
    
    def calculate_threat_level(self, connections):
        packet_rate = len(connections) / self.time_window
        return min(100, int(packet_rate / self.packet_threshold * 100))
    
    def detect_attack_type(self, packet):
        if packet.syn_flag and not packet.ack_flag:
            return "SYN_FLOOD"
        elif packet.udp:
            return "UDP_FLOOD"
        return "VOLUMETRIC" 