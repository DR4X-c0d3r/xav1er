# config.py
import json
import os

CONFIG_FILE = 'waf_config.json'

def load_domains():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f).get('domains', [])
    return ['yourdomain.com']  # Default

def save_domains(domains):
    with open(CONFIG_FILE, 'w') as f:
        json.dump({'domains': domains}, f)

class Config:
    PROTECTED_DOMAINS = load_domains()