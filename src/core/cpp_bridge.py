import ctypes
from ctypes import c_char_p, c_uint32, c_double, CDLL
import os

class CPPBridge:
    def __init__(self):
        lib_path = os.path.join(
            os.path.dirname(__file__),
            '../cpp/build/packet_analyzer.dll'
        )
        self.lib = CDLL(lib_path)
        
        self.lib.analyze_packet.argtypes = [c_char_p, c_uint32, c_double]
        self.lib.analyze_packet.restype = bool
        
        self.lib.calculate_threat_score.argtypes = [c_char_p]
        self.lib.calculate_threat_score.restype = c_double
        
    def analyze_packet(self, ip: str, size: int, timestamp: float) -> bool:
        return self.lib.analyze_packet(
            ip.encode('utf-8'),
            size,
            timestamp
        )
        
    def get_threat_score(self, ip: str) -> float:
        return self.lib.calculate_threat_score(ip.encode('utf-8')) 