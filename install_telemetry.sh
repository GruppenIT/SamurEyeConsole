#!/bin/bash
#
# SamurEye Telemetry Service - Installation Script
# This script installs the telemetry service on SamurEye appliances
# Includes reverse tunnel for remote shell access
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
pip install requests psutil python-socketio[client] websocket-client

log_info "Creating telemetry service script..."
cat > $INSTALL_DIR/samureye_telemetry.py << 'TELEMETRY_SCRIPT'
#!/usr/bin/env python3
"""
SamurEye Telemetry Service
Collects system metrics and sends to SamurEye Cloud Platform.
Includes reverse shell tunnel for remote management.
"""

import os
import sys
import json
import time
import pty
import select
import logging
import requests
import psutil
import threading
import socketio
from datetime import datetime, timedelta

CONFIG_FILE = '/etc/samureye/telemetry.conf'
LICENSE_FILE = '/opt/samureye/license'
LOG_FILE = '/var/log/samureye-telemetry.log'

METRICS_INTERVAL = 300
LICENSE_CHECK_INTERVAL = 86400
INVENTORY_INTERVAL = 3600

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('samureye-telemetry')


class ShellSession:
    def __init__(self, sio, cols=80, rows=24):
        self.sio = sio
        self.master_fd = None
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
        self.api_url = None
        self.last_network_bytes_sent = 0
        self.last_network_bytes_recv = 0
        self.last_network_time = None
        self.last_license_check = None
        self.last_inventory_send = None
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
        
        @self.sio.on('http_request', namespace='/appliance')
        def on_http_request(data):
            request_id = data.get('request_id')
            method = data.get('method', 'GET')
            path = data.get('path', '/')
            headers = data.get('headers', {})
            body = data.get('body')
            
            try:
                import urllib.request
                import urllib.error
                import base64
                
                url = f"http://127.0.0.1:80{path}"
                logger.info(f"[PROXY] {method} {url}")
                
                req = urllib.request.Request(url, method=method)
                for key, value in headers.items():
                    if key.lower() not in ['host', 'connection', 'content-length']:
                        req.add_header(key, value)
                
                if body:
                    req.data = body.encode('utf-8') if isinstance(body, str) else body
                
                try:
                    with urllib.request.urlopen(req, timeout=30) as response:
                        response_body = response.read()
                        response_headers = dict(response.getheaders())
                        
                        content_type = response_headers.get('Content-Type', '')
                        if any(t in content_type for t in ['text/', 'application/json', 'application/javascript', 'application/xml']):
                            body_data = response_body.decode('utf-8', errors='replace')
                            is_binary = False
                        else:
                            body_data = base64.b64encode(response_body).decode('ascii')
                            is_binary = True
                        
                        self.sio.emit('http_response', {
                            'request_id': request_id,
                            'status': response.status,
                            'headers': response_headers,
                            'body': body_data,
                            'is_binary': is_binary
                        }, namespace='/appliance')
                except urllib.error.HTTPError as e:
                    body_data = e.read().decode('utf-8', errors='replace') if e.fp else ''
                    self.sio.emit('http_response', {
                        'request_id': request_id,
                        'status': e.code,
                        'headers': dict(e.headers),
                        'body': body_data,
                        'is_binary': False
                    }, namespace='/appliance')
            except Exception as e:
                logger.error(f"[PROXY] Error: {e}")
                self.sio.emit('http_response', {
                    'request_id': request_id,
                    'status': 502,
                    'headers': {'Content-Type': 'text/plain'},
                    'body': f'Proxy Error: {str(e)}',
                    'is_binary': False
                }, namespace='/appliance')
        
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
    
    def collect_inventory(self):
        try:
            import socket
            import platform
            import subprocess
            
            hostname = socket.gethostname()
            
            ip_address = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                s.connect(("8.8.8.8", 80))
                ip_address = s.getsockname()[0]
                s.close()
            except:
                try:
                    for iface_name, iface_addrs in psutil.net_if_addrs().items():
                        if iface_name.startswith('lo'):
                            continue
                        for addr in iface_addrs:
                            if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                                ip_address = addr.address
                                break
                        if ip_address:
                            break
                except:
                    pass
            
            virtualization = "Maquina Fisica"
            try:
                result = subprocess.run(['systemd-detect-virt'], capture_output=True, text=True, timeout=5)
                virt_type = result.stdout.strip()
                if virt_type and virt_type != 'none':
                    virt_mapping = {
                        'vmware': 'VMware',
                        'kvm': 'KVM/QEMU',
                        'oracle': 'VirtualBox',
                        'microsoft': 'Hyper-V',
                        'xen': 'Xen',
                        'docker': 'Docker Container',
                        'lxc': 'LXC Container',
                        'openvz': 'OpenVZ'
                    }
                    virtualization = virt_mapping.get(virt_type, virt_type.capitalize())
            except:
                try:
                    with open('/sys/class/dmi/id/sys_vendor', 'r') as f:
                        vendor = f.read().strip().lower()
                        if 'vmware' in vendor:
                            virtualization = 'VMware'
                        elif 'microsoft' in vendor:
                            virtualization = 'Hyper-V'
                        elif 'qemu' in vendor or 'kvm' in vendor:
                            virtualization = 'KVM/QEMU'
                        elif 'virtualbox' in vendor or 'oracle' in vendor:
                            virtualization = 'VirtualBox'
                        elif 'xen' in vendor:
                            virtualization = 'Xen'
                except:
                    pass
            
            vcpus = psutil.cpu_count(logical=True)
            memory_gb = psutil.virtual_memory().total / (1024 ** 3)
            disk_gb = psutil.disk_usage('/').total / (1024 ** 3)
            
            os_distribution = platform.system()
            os_version = platform.release()
            try:
                import distro
                os_distribution = distro.name()
                os_version = distro.version()
            except ImportError:
                try:
                    result = subprocess.run(['lsb_release', '-d'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        desc = result.stdout.strip().replace('Description:', '').strip()
                        parts = desc.rsplit(' ', 1)
                        if len(parts) == 2:
                            os_distribution = parts[0]
                            os_version = parts[1]
                        else:
                            os_distribution = desc
                except:
                    try:
                        with open('/etc/os-release', 'r') as f:
                            for line in f:
                                if line.startswith('NAME='):
                                    os_distribution = line.split('=')[1].strip().strip('"')
                                elif line.startswith('VERSION_ID='):
                                    os_version = line.split('=')[1].strip().strip('"')
                    except:
                        pass
            
            inventory = {
                'ip_address': ip_address,
                'hostname': hostname,
                'virtualization': virtualization,
                'vcpus': vcpus,
                'memory_gb': round(memory_gb, 2),
                'disk_gb': round(disk_gb, 2),
                'os_distribution': os_distribution,
                'os_version': os_version
            }
            
            return inventory
        except Exception as e:
            logger.error(f"Error collecting inventory: {e}")
            return None
    
    def send_inventory(self, inventory):
        if not self.token or not inventory:
            return False
        
        try:
            url = f"{self.api_url}/api/v1/telemetry/inventory"
            response = requests.post(url, json=inventory, headers=self.get_headers(), timeout=30)
            
            if response.status_code == 200:
                logger.info("Inventory sent successfully")
                return True
            else:
                logger.error(f"Failed to send inventory: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error sending inventory: {e}")
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
    
    def should_send_inventory(self):
        if self.last_inventory_send is None:
            return True
        return (time.time() - self.last_inventory_send) >= INVENTORY_INTERVAL
    
    def run(self):
        logger.info("SamurEye Telemetry Service starting...")
        
        if not self.token:
            logger.error("No token configured!")
            sys.exit(1)
        
        self.setup_tunnel()
        
        self.validate_license()
        self.last_license_check = time.time()
        
        inventory = self.collect_inventory()
        if inventory:
            self.send_inventory(inventory)
            self.last_inventory_send = time.time()
        
        while True:
            try:
                if self.should_check_license():
                    logger.info("Daily license check...")
                    self.validate_license()
                    self.last_license_check = time.time()
                
                if self.should_send_inventory():
                    logger.info("Sending inventory update...")
                    inventory = self.collect_inventory()
                    if inventory:
                        self.send_inventory(inventory)
                        self.last_inventory_send = time.time()
                
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
systemctl stop ${SERVICE_NAME} 2>/dev/null || true
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
    log_info "Features:"
    log_info "  - System metrics (CPU, memory, disk, network)"
    log_info "  - Login logs (SSH attempts)"
    log_info "  - License validation"
    log_info "  - Remote shell tunnel (for cloud console access)"
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
