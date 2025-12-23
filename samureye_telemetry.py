#!/usr/bin/env python3
"""
SamurEye Telemetry Service
Collects system metrics and sends to SamurEye Cloud Platform.
Runs as a systemd service on SamurEye appliances.
Includes reverse shell tunnel for remote management.
"""

import os
import sys
import json
import time
import pty
import select
import subprocess
import logging
import requests
import psutil
import threading
import socketio
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


class ShellSession:
    def __init__(self, sio, cols=80, rows=24):
        self.sio = sio
        self.master_fd = None
        self.slave_fd = None
        self.pid = None
        self.running = False
        self.cols = cols
        self.rows = rows
    
    def start(self):
        try:
            self.pid, self.master_fd = pty.fork()
            
            if self.pid == 0:
                os.environ['TERM'] = 'xterm-256color'
                os.environ['COLUMNS'] = str(self.cols)
                os.environ['LINES'] = str(self.rows)
                os.chdir(os.path.expanduser('~'))
                os.execvp('/bin/bash', ['/bin/bash', '-l'])
            else:
                self.running = True
                self._set_winsize(self.cols, self.rows)
                
                read_thread = threading.Thread(target=self._read_output)
                read_thread.daemon = True
                read_thread.start()
                
                logger.info("Shell session started")
                return True
        except Exception as e:
            logger.error(f"Failed to start shell: {e}")
            return False
    
    def _set_winsize(self, cols, rows):
        try:
            import fcntl
            import struct
            import termios
            winsize = struct.pack('HHHH', rows, cols, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
        except Exception as e:
            logger.debug(f"Could not set window size: {e}")
    
    def _read_output(self):
        while self.running:
            try:
                r, _, _ = select.select([self.master_fd], [], [], 0.1)
                if self.master_fd in r:
                    output = os.read(self.master_fd, 4096)
                    if output:
                        self.sio.emit('shell_output', {'output': output.decode('utf-8', errors='replace')}, namespace='/appliance')
                    else:
                        break
            except OSError:
                break
            except Exception as e:
                logger.debug(f"Read error: {e}")
                break
        
        self.running = False
        self.sio.emit('shell_closed', {'reason': 'Shell process ended'}, namespace='/appliance')
        logger.info("Shell session ended")
    
    def write(self, data):
        if self.running and self.master_fd:
            try:
                os.write(self.master_fd, data.encode('utf-8'))
            except Exception as e:
                logger.error(f"Write error: {e}")
    
    def resize(self, cols, rows):
        self.cols = cols
        self.rows = rows
        if self.running:
            self._set_winsize(cols, rows)
    
    def close(self):
        self.running = False
        if self.master_fd:
            try:
                os.close(self.master_fd)
            except:
                pass
        if self.pid:
            try:
                import signal
                os.kill(self.pid, signal.SIGTERM)
                os.waitpid(self.pid, os.WNOHANG)
            except:
                pass
        logger.info("Shell session closed")


class TelemetryService:
    def __init__(self):
        self.token = None
        self.api_url = API_BASE_URL
        self.last_network_bytes_sent = 0
        self.last_network_bytes_recv = 0
        self.last_network_time = None
        self.last_license_check = None
        self.sio = None
        self.shell_session = None
        self.tunnel_connected = False
        self.load_config()
    
    def load_config(self):
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
        return {
            'X-Appliance-Token': self.token,
            'Content-Type': 'application/json'
        }
    
    def setup_tunnel(self):
        ws_url = self.api_url.replace('https://', 'wss://').replace('http://', 'ws://')
        
        self.sio = socketio.Client(reconnection=True, reconnection_attempts=0, 
                                   reconnection_delay=5, reconnection_delay_max=60)
        
        @self.sio.on('connect', namespace='/appliance')
        def on_connect():
            self.tunnel_connected = True
            logger.info("[TUNNEL] Connected to cloud server")
        
        @self.sio.on('disconnect', namespace='/appliance')
        def on_disconnect():
            self.tunnel_connected = False
            logger.info("[TUNNEL] Disconnected from cloud server")
            if self.shell_session:
                self.shell_session.close()
                self.shell_session = None
        
        @self.sio.on('start_shell', namespace='/appliance')
        def on_start_shell(data):
            logger.info("[TUNNEL] Shell session requested")
            if self.shell_session:
                self.shell_session.close()
            
            cols = data.get('cols', 80)
            rows = data.get('rows', 24)
            self.shell_session = ShellSession(self.sio, cols, rows)
            if not self.shell_session.start():
                self.sio.emit('shell_closed', {'reason': 'Failed to start shell'}, namespace='/appliance')
                self.shell_session = None
        
        @self.sio.on('shell_input', namespace='/appliance')
        def on_shell_input(data):
            if self.shell_session and self.shell_session.running:
                self.shell_session.write(data.get('input', ''))
        
        @self.sio.on('resize_shell', namespace='/appliance')
        def on_resize_shell(data):
            if self.shell_session:
                self.shell_session.resize(data.get('cols', 80), data.get('rows', 24))
        
        @self.sio.on('close_shell', namespace='/appliance')
        def on_close_shell():
            if self.shell_session:
                self.shell_session.close()
                self.shell_session = None
        
        def connect_tunnel():
            while True:
                try:
                    if not self.tunnel_connected:
                        logger.info(f"[TUNNEL] Connecting to {ws_url}...")
                        self.sio.connect(ws_url, namespaces=['/appliance'], 
                                        auth={'token': self.token},
                                        transports=['websocket'])
                except Exception as e:
                    logger.error(f"[TUNNEL] Connection failed: {e}")
                time.sleep(30)
        
        tunnel_thread = threading.Thread(target=connect_tunnel)
        tunnel_thread.daemon = True
        tunnel_thread.start()
    
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
        if self.last_license_check is None:
            return True
        
        time_since_check = time.time() - self.last_license_check
        return time_since_check >= LICENSE_CHECK_INTERVAL
    
    def run(self):
        logger.info("SamurEye Telemetry Service starting...")
        
        if not self.token:
            logger.error("No token configured. Please configure /etc/samureye/telemetry.conf")
            sys.exit(1)
        
        self.setup_tunnel()
        
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
