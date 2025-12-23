#!/bin/bash
#
# SamurEye Telemetry Service - Installation Script
# This script installs the telemetry service on SamurEye appliances
#
# Usage: sudo bash install_telemetry.sh <TOKEN> [API_URL]
#
# Example: sudo bash install_telemetry.sh abc123def456... https://app.samureye.com.br
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

TOKEN="${1}"
API_URL="${2:-https://app.samureye.com.br}"

if [ -z "$TOKEN" ]; then
    log_error "Usage: sudo bash install_telemetry.sh <TOKEN> [API_URL]"
    log_error "  TOKEN: Appliance token from SamurEye Cloud console"
    log_error "  API_URL: Optional. Default: https://app.samureye.com.br"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root (sudo bash install_telemetry.sh ...)"
    exit 1
fi

INSTALL_DIR="/opt/samureye"
CONFIG_DIR="/etc/samureye"
LOG_DIR="/var/log"
SERVICE_NAME="samureye-telemetry"

log_info "Starting SamurEye Telemetry Service installation..."

log_info "Installing system dependencies..."
apt-get update -y
apt-get install -y python3 python3-pip python3-venv curl

log_info "Creating directories..."
mkdir -p $INSTALL_DIR
mkdir -p $CONFIG_DIR

log_info "Creating Python virtual environment..."
python3 -m venv $INSTALL_DIR/venv
source $INSTALL_DIR/venv/bin/activate

log_info "Installing Python dependencies..."
pip install --upgrade pip
pip install requests psutil

log_info "Creating telemetry service script..."
cat > $INSTALL_DIR/samureye_telemetry.py << 'TELEMETRY_SCRIPT'
#!/usr/bin/env python3
"""
SamurEye Telemetry Service
Collects system metrics and sends to SamurEye Cloud Platform.
"""

import os
import sys
import json
import time
import logging
import requests
import psutil
from datetime import datetime, timedelta
from pathlib import Path

CONFIG_FILE = '/etc/samureye/telemetry.conf'
LICENSE_FILE = '/opt/samureye/license'
LOG_FILE = '/var/log/samureye-telemetry.log'

METRICS_INTERVAL = 300
LICENSE_CHECK_INTERVAL = 86400

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('samureye-telemetry')


class TelemetryService:
    def __init__(self):
        self.token = None
        self.api_url = None
        self.last_network_bytes_sent = 0
        self.last_network_bytes_recv = 0
        self.last_network_time = None
        self.last_license_check = None
        self.load_config()
    
    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.token = config.get('token')
                    self.api_url = config.get('api_url', 'https://app.samureye.com.br')
                    logger.info(f"Configuration loaded. API URL: {self.api_url}")
            else:
                logger.error(f"Configuration file not found: {CONFIG_FILE}")
        except Exception as e:
            logger.error(f"Error loading config: {e}")
    
    def get_headers(self):
        return {
            'X-Appliance-Token': self.token,
            'Content-Type': 'application/json'
        }
    
    def collect_metrics(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            
            current_time = time.time()
            network_bytes_sent_rate = 0
            network_bytes_recv_rate = 0
            
            if self.last_network_time:
                time_diff = current_time - self.last_network_time
                if time_diff > 0:
                    network_bytes_sent_rate = (network.bytes_sent - self.last_network_bytes_sent) / time_diff
                    network_bytes_recv_rate = (network.bytes_recv - self.last_network_bytes_recv) / time_diff
            
            self.last_network_bytes_sent = network.bytes_sent
            self.last_network_bytes_recv = network.bytes_recv
            self.last_network_time = current_time
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used_gb': memory.used / (1024 ** 3),
                'memory_total_gb': memory.total / (1024 ** 3),
                'disk_percent': disk.percent,
                'disk_used_gb': disk.used / (1024 ** 3),
                'disk_total_gb': disk.total / (1024 ** 3),
                'network_bytes_sent': network.bytes_sent,
                'network_bytes_recv': network.bytes_recv,
                'network_bytes_sent_rate': network_bytes_sent_rate,
                'network_bytes_recv_rate': network_bytes_recv_rate
            }
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            return None
    
    def send_metrics(self, metrics):
        if not self.token:
            return False
        
        try:
            url = f"{self.api_url}/api/v1/telemetry/metrics"
            response = requests.post(url, json=metrics, headers=self.get_headers(), timeout=30)
            
            if response.status_code == 200:
                logger.info("Metrics sent successfully")
                return True
            else:
                logger.error(f"Failed to send metrics: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error: {e}")
            return False
    
    def collect_login_logs(self):
        logs = []
        try:
            auth_log = '/var/log/auth.log'
            if os.path.exists(auth_log):
                with open(auth_log, 'r') as f:
                    for line in f.readlines()[-100:]:
                        if 'sshd' in line and ('Accepted' in line or 'Failed' in line):
                            log_entry = {
                                'login_type': 'SSH',
                                'success': 'Accepted' in line,
                                'details': line.strip()[:500]
                            }
                            if 'from' in line:
                                parts = line.split('from')
                                if len(parts) > 1:
                                    log_entry['source_ip'] = parts[1].strip().split()[0]
                            if 'for' in line:
                                parts = line.split('for')
                                if len(parts) > 1:
                                    log_entry['username'] = parts[1].strip().split()[0]
                            logs.append(log_entry)
        except Exception as e:
            logger.debug(f"Could not read auth.log: {e}")
        return logs[-20:]
    
    def send_login_logs(self, logs):
        if not self.token or not logs:
            return False
        
        try:
            url = f"{self.api_url}/api/v1/telemetry/login-logs"
            response = requests.post(url, json=logs, headers=self.get_headers(), timeout=30)
            if response.status_code == 200:
                logger.info(f"Login logs sent: {len(logs)} entries")
                return True
            return False
        except:
            return False
    
    def validate_license(self):
        if not self.token:
            return False
        
        try:
            url = f"{self.api_url}/api/v1/license/validate"
            response = requests.get(url, headers=self.get_headers(), timeout=30)
            
            if response.status_code == 200:
                license_data = response.json()
                
                license_dir = os.path.dirname(LICENSE_FILE)
                if not os.path.exists(license_dir):
                    os.makedirs(license_dir, mode=0o755)
                
                license_content = {
                    'valid': license_data.get('valid', False),
                    'appliance_name': license_data.get('appliance_name'),
                    'client_name': license_data.get('client_name'),
                    'contract_start': license_data.get('contract_start'),
                    'contract_end': license_data.get('contract_end'),
                    'validated_at': datetime.utcnow().isoformat(),
                    'expires_at': (datetime.utcnow() + timedelta(days=7)).isoformat()
                }
                
                with open(LICENSE_FILE, 'w') as f:
                    json.dump(license_content, f, indent=2)
                os.chmod(LICENSE_FILE, 0o644)
                
                logger.info(f"License validated. Valid: {license_data.get('valid')}")
                return license_data.get('valid', False)
            else:
                self._write_invalid_license(f"HTTP {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"License validation error: {e}")
            return False
    
    def _write_invalid_license(self, reason):
        try:
            license_dir = os.path.dirname(LICENSE_FILE)
            if not os.path.exists(license_dir):
                os.makedirs(license_dir, mode=0o755)
            
            with open(LICENSE_FILE, 'w') as f:
                json.dump({
                    'valid': False,
                    'reason': reason,
                    'validated_at': datetime.utcnow().isoformat()
                }, f, indent=2)
            os.chmod(LICENSE_FILE, 0o644)
        except:
            pass
    
    def should_check_license(self):
        if self.last_license_check is None:
            return True
        return (time.time() - self.last_license_check) >= LICENSE_CHECK_INTERVAL
    
    def run(self):
        logger.info("SamurEye Telemetry Service starting...")
        
        if not self.token:
            logger.error("No token configured!")
            sys.exit(1)
        
        self.validate_license()
        self.last_license_check = time.time()
        
        while True:
            try:
                if self.should_check_license():
                    logger.info("Daily license check...")
                    self.validate_license()
                    self.last_license_check = time.time()
                
                metrics = self.collect_metrics()
                if metrics:
                    self.send_metrics(metrics)
                
                login_logs = self.collect_login_logs()
                if login_logs:
                    self.send_login_logs(login_logs)
                
                time.sleep(METRICS_INTERVAL)
                
            except KeyboardInterrupt:
                logger.info("Service stopped")
                break
            except Exception as e:
                logger.error(f"Error: {e}")
                time.sleep(60)


if __name__ == '__main__':
    TelemetryService().run()
TELEMETRY_SCRIPT

chmod +x $INSTALL_DIR/samureye_telemetry.py

log_info "Creating configuration file..."
cat > $CONFIG_DIR/telemetry.conf << EOF
{
    "token": "$TOKEN",
    "api_url": "$API_URL"
}
EOF

chmod 600 $CONFIG_DIR/telemetry.conf

log_info "Creating systemd service..."
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=SamurEye Telemetry Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/bin"
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/samureye_telemetry.py
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

log_info "Starting service..."
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl start ${SERVICE_NAME}

sleep 2

if systemctl is-active --quiet ${SERVICE_NAME}; then
    log_info ""
    log_info "=============================================="
    log_info "  SamurEye Telemetry Service installed!"
    log_info "=============================================="
    log_info ""
    log_info "Service status: Running"
    log_info "Configuration: $CONFIG_DIR/telemetry.conf"
    log_info "License file: $INSTALL_DIR/license"
    log_info "Log file: /var/log/samureye-telemetry.log"
    log_info ""
    log_info "Commands:"
    log_info "  Check status: sudo systemctl status ${SERVICE_NAME}"
    log_info "  View logs: sudo tail -f /var/log/samureye-telemetry.log"
    log_info "  Restart: sudo systemctl restart ${SERVICE_NAME}"
    log_info ""
else
    log_error "Service failed to start. Check logs:"
    log_error "  sudo journalctl -u ${SERVICE_NAME} -n 50"
fi
