import asyncio
import subprocess

class IPBlocker:
    def __init__(self):
        self.blocked_ips = set()
        self.block_duration = 3600
        
    async def block_threats(self, threats):
        for threat in threats:
            if threat['severity'] >= 80 and threat['ip'] not in self.blocked_ips:
                await self.block_ip(threat['ip'])
    async def block_ip(self, ip):
        if self.is_windows():
            cmd = f'netsh advfirewall firewall add rule name="BLOCK_IP_{ip}" dir=in action=block remoteip={ip}'
        else:
            cmd = f'iptables -A INPUT -s {ip} -j DROP'
                
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.communicate()
            self.blocked_ips.add(ip)
            asyncio.create_task(self.unblock_later(ip))
            
    async def unblock_later(self, ip):
        await asyncio.sleep(self.block_duration)
        await self.unblock_ip(ip)
        
    async def unblock_ip(self, ip):
        if self.is_windows():
            cmd = f'netsh advfirewall firewall delete rule name="BLOCK_IP_{ip}"'
        else:
            cmd = f'iptables -D INPUT -s {ip} -j DROP'
            
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        await process.communicate()
        self.blocked_ips.remove(ip)
        
    def is_windows(self):
        return subprocess.run('systeminfo', capture_output=True, text=True).returncode == 0 