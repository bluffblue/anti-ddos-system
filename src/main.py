from core.analyzer import TrafficAnalyzer
from core.blocker import IPBlocker
from core.monitor import NetworkMonitor
from utils.config import load_config
import asyncio

class AntiDDOS:
    def __init__(self):
        self.config = load_config()
        self.monitor = NetworkMonitor()
        self.analyzer = TrafficAnalyzer()
        self.blocker = IPBlocker()
        
    async def start_protection(self):
        while True:
            traffic_data = await self.monitor.capture_traffic()
            threats = self.analyzer.analyze_traffic(traffic_data)
            
            if threats:
                await self.blocker.block_threats(threats)
            
            await asyncio.sleep(0.1)

if __name__ == "__main__":
    anti_ddos = AntiDDOS()
    asyncio.run(anti_ddos.start_protection()) 