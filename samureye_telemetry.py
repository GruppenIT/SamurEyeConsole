#!/usr/bin/env python3
"""
SamurEye Telemetry Service
Collects system metrics and sends to SamurEye Cloud Platform.
Runs as a systemd service on SamurEye appliances.
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

API_BASE_URL = os.environ.get('SAMUREYE_API_URL', 'https://app.samureye.com.br')
METRICS_INTERVAL = 300
LICENSE_CHECK_INTERVAL = 86400

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE) if os.path.exists(os.path.dirname(LOG_FILE)) else logging.StreamHandler(),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('samureye-telemetry')

class TelemetryService:
    def __init__(self):
        self.token = None
        self.api_url = API_BASE_URL
        self.last_network_bytes_sent = 0
        self.last_network_bytes_recv = 0
        self.last_network_time = None
        self.last_license_check = None
        self.load_config()
    
    def load_config(self):
        """Load configuration from file."""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.token = config.get('token')
                    self.api_url = config.get('api_url', API_BASE_URL)
                    logger.info(f"Configuration loaded. API URL: {self.api_url}")
            else:
                logger.error(f"Configuration file not found: {CONFIG_FILE}")
                logger.info("Create config file with: echo '{\"token\": \"YOUR_TOKEN\", \"api_url\": \"https://app.samureye.com.br\"}' | sudo tee /etc/samureye/telemetry.conf")
        except Exception as e:
            logger.error(f"Error loading config: {e}")
    
    def get_headers(self):
        """Get API headers with token."""
        return {
            'X-Appliance-Token': self.token,
            'Content-Type': 'application/json'
        }
    
    def collect_metrics(self):
        """Collect system metrics."""
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
            
            metrics = {
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
            
            return metrics
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            return None
    
    def send_metrics(self, metrics):
        """Send metrics to SamurEye Cloud."""
        if not self.token:
            logger.warning("No token configured. Skipping metrics send.")
            return False
        
        try:
            url = f"{self.api_url}/api/v1/telemetry/metrics"
            response = requests.post(url, json=metrics, headers=self.get_headers(), timeout=30)
            
            if response.status_code == 200:
                logger.info("Metrics sent successfully")
                return True
            elif response.status_code == 401:
                logger.error("Invalid or inactive token")
                return False
            elif response.status_code == 403:
                logger.error("Contract expired or inactive")
                return False
            else:
                logger.error(f"Failed to send metrics: {response.status_code} - {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error sending metrics: {e}")
            return False
    
    def collect_login_logs(self):
        """Collect SSH and GUI login attempts from auth logs."""
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
                                    ip_part = parts[1].strip().split()[0]
                                    log_entry['source_ip'] = ip_part
                            if 'for' in line:
                                parts = line.split('for')
                                if len(parts) > 1:
                                    user_part = parts[1].strip().split()[0]
                                    log_entry['username'] = user_part
                            logs.append(log_entry)
        except Exception as e:
            logger.debug(f"Could not read auth.log: {e}")
        
        return logs[-20:] if logs else []
    
    def send_login_logs(self, logs):
        """Send login logs to SamurEye Cloud."""
        if not self.token or not logs:
            return False
        
        try:
            url = f"{self.api_url}/api/v1/telemetry/login-logs"
            response = requests.post(url, json=logs, headers=self.get_headers(), timeout=30)
            
            if response.status_code == 200:
                logger.info(f"Login logs sent: {len(logs)} entries")
                return True
            else:
                logger.error(f"Failed to send login logs: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error sending login logs: {e}")
            return False
    
    def validate_license(self):
        """Validate license with SamurEye Cloud and update local license file."""
        if not self.token:
            logger.warning("No token configured. Cannot validate license.")
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
                
                if license_data.get('valid'):
                    logger.info(f"License validated successfully. Valid until: {license_data.get('contract_end')}")
                else:
                    logger.warning("License is invalid or expired")
                
                return license_data.get('valid', False)
            elif response.status_code == 401:
                logger.error("Invalid token. License validation failed.")
                self._write_invalid_license("Invalid token")
                return False
            elif response.status_code == 403:
                logger.error("Contract expired or inactive.")
                self._write_invalid_license("Contract expired")
                return False
            else:
                logger.error(f"License validation failed: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error validating license: {e}")
            return False
    
    def _write_invalid_license(self, reason):
        """Write invalid license file."""
        try:
            license_dir = os.path.dirname(LICENSE_FILE)
            if not os.path.exists(license_dir):
                os.makedirs(license_dir, mode=0o755)
            
            license_content = {
                'valid': False,
                'reason': reason,
                'validated_at': datetime.utcnow().isoformat()
            }
            
            with open(LICENSE_FILE, 'w') as f:
                json.dump(license_content, f, indent=2)
            
            os.chmod(LICENSE_FILE, 0o644)
        except Exception as e:
            logger.error(f"Error writing invalid license: {e}")
    
    def should_check_license(self):
        """Check if it's time to validate license."""
        if self.last_license_check is None:
            return True
        
        time_since_check = time.time() - self.last_license_check
        return time_since_check >= LICENSE_CHECK_INTERVAL
    
    def run(self):
        """Main service loop."""
        logger.info("SamurEye Telemetry Service starting...")
        
        if not self.token:
            logger.error("No token configured. Please configure /etc/samureye/telemetry.conf")
            sys.exit(1)
        
        self.validate_license()
        self.last_license_check = time.time()
        
        while True:
            try:
                if self.should_check_license():
                    logger.info("Performing daily license check...")
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
                logger.info("Service stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(60)


def main():
    service = TelemetryService()
    service.run()


if __name__ == '__main__':
    main()
