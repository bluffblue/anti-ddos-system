import yaml
import os

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), '../config/settings.yaml')
    
    default_config = {
        'packet_threshold': 1000,
        'time_window': 1.0,
        'block_duration': 3600,
        'min_threat_level': 80,
        'monitoring': {
            'interval': 0.1,
            'interfaces': ['all']
        }
    }
    
    try:
        with open(config_path, 'r') as f:
            user_config = yaml.safe_load(f)
            return {**default_config, **user_config}
    except FileNotFoundError:
        return default_config 