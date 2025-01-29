import asyncio
import socket
import psutil
import time
from dataclasses import dataclass
from typing import List

@dataclass
class Packet:
    source_ip: str
    destination_ip: str
    protocol: str
    size: int
    syn_flag: bool = False
    ack_flag: bool = False
    udp: bool = False

@dataclass
class TrafficData:
    timestamp: float
    packets: List[Packet]

class NetworkMonitor:
    def __init__(self):
        self.interfaces = psutil.net_if_addrs()
        self.baseline_traffic = self.calculate_baseline()
        
    def calculate_baseline(self):
        stats = psutil.net_io_counters()
        return {
            'bytes_sent': stats.bytes_sent,
            'bytes_recv': stats.bytes_recv,
            'packets_sent': stats.packets_sent,
            'packets_recv': stats.packets_recv
        }
        
    async def capture_traffic(self):
        current_stats = psutil.net_io_counters()
        packets = []
        
        connections = psutil.net_connections()
        for conn in connections:
            if conn.status == 'ESTABLISHED':
                packet = Packet(
                    source_ip=conn.raddr.ip if conn.raddr else "",
                    destination_ip=conn.laddr.ip,
                    protocol=conn.type,
                    size=0,
                    syn_flag='SYN' in conn.status,
                    ack_flag='ACK' in conn.status,
                    udp=conn.type == socket.SOCK_DGRAM
                )
                packets.append(packet)
        
        return TrafficData(
            timestamp=time.time(),
            packets=packets
        ) 