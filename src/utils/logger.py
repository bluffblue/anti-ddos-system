import logging
import datetime

class SecurityLogger:
    def __init__(self):
        self.logger = logging.getLogger('AntiDDOS')
        self.logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        file_handler = logging.FileHandler(
            f'logs/antiddos_{datetime.datetime.now().strftime("%Y%m%d")}.log'
        )
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        
    def log_threat(self, threat):
        self.logger.warning(
            f'Threat detected - IP: {threat["ip"]}, '
            f'Severity: {threat["severity"]}, '
            f'Type: {threat["type"]}'
        )
        
    def log_block(self, ip):
        self.logger.info(f'Blocked IP: {ip}')
        
    def log_unblock(self, ip):
        self.logger.info(f'Unblocked IP: {ip}') 