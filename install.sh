#!/bin/bash
#
# SamurEye Cloud Platform - Installation Script
# This script installs the SamurEye Cloud Platform on Ubuntu Server
#
# Usage: sudo bash install.sh
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

if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root (sudo bash install.sh)"
    exit 1
fi

APP_DIR="/opt/samureye-cloud"
APP_USER="samureye"
PYTHON_VERSION="3.11"

log_info "Starting SamurEye Cloud Platform installation..."

log_info "Updating system packages..."
apt-get update -y
apt-get upgrade -y

log_info "Installing system dependencies..."
apt-get install -y \
    python${PYTHON_VERSION} \
    python${PYTHON_VERSION}-venv \
    python3-pip \
    postgresql \
    postgresql-contrib \
    nginx \
    certbot \
    python3-certbot-nginx \
    git \
    curl \
    wget \
    ufw

log_info "Creating application user..."
if ! id "$APP_USER" &>/dev/null; then
    useradd -r -s /bin/false -d $APP_DIR $APP_USER
fi

log_info "Creating application directory..."
mkdir -p $APP_DIR
mkdir -p $APP_DIR/logs

log_info "Setting up PostgreSQL database..."
sudo -u postgres psql -c "CREATE USER samureye WITH PASSWORD 'samureye_secure_password_change_me';" 2>/dev/null || log_warn "Database user already exists"
sudo -u postgres psql -c "CREATE DATABASE samureye_cloud OWNER samureye;" 2>/dev/null || log_warn "Database already exists"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE samureye_cloud TO samureye;"

log_info "Creating Python virtual environment..."
python${PYTHON_VERSION} -m venv $APP_DIR/venv
source $APP_DIR/venv/bin/activate

log_info "Installing Python dependencies..."
pip install --upgrade pip
pip install flask flask-sqlalchemy flask-login psycopg2-binary gunicorn python-dotenv requests werkzeug

log_info "Copying application files..."
cp app.py $APP_DIR/
cp models.py $APP_DIR/
cp -r templates $APP_DIR/

log_info "Creating environment configuration..."
cat > $APP_DIR/.env << EOF
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
DATABASE_URL=postgresql://samureye:samureye_secure_password_change_me@localhost/samureye_cloud
FLASK_ENV=production
EOF

log_info "Setting file permissions..."
chown -R $APP_USER:$APP_USER $APP_DIR
chmod 600 $APP_DIR/.env

log_info "Creating systemd service..."
cat > /etc/systemd/system/samureye-cloud.service << EOF
[Unit]
Description=SamurEye Cloud Platform
After=network.target postgresql.service

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 4 --access-logfile $APP_DIR/logs/access.log --error-logfile $APP_DIR/logs/error.log app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

log_info "Configuring Nginx..."
cat > /etc/nginx/sites-available/samureye-cloud << 'EOF'
server {
    listen 80;
    server_name app.samureye.com.br;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        proxy_read_timeout 300;
    }

    location /static {
        alias $APP_DIR/static;
        expires 1d;
    }
}
EOF

ln -sf /etc/nginx/sites-available/samureye-cloud /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

log_info "Testing Nginx configuration..."
nginx -t

log_info "Configuring firewall..."
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

log_info "Starting services..."
systemctl daemon-reload
systemctl enable postgresql
systemctl start postgresql
systemctl enable samureye-cloud
systemctl start samureye-cloud
systemctl enable nginx
systemctl restart nginx

log_info "Initializing database..."
cd $APP_DIR
source venv/bin/activate
export $(cat .env | xargs)
python3 -c "from app import init_db; init_db()"

log_info ""
log_info "=============================================="
log_info "  SamurEye Cloud Platform installed!"
log_info "=============================================="
log_info ""
log_info "Application URL: http://app.samureye.com.br"
log_info "Default login: admin@samureye.com.br"
log_info "Default password: SamurEye@2024!"
log_info ""
log_info "IMPORTANT: Change the default password after first login!"
log_info ""
log_info "To enable HTTPS, run:"
log_info "  sudo certbot --nginx -d app.samureye.com.br"
log_info ""
log_info "Application logs: $APP_DIR/logs/"
log_info "Configuration: $APP_DIR/.env"
log_info ""
log_info "Database credentials are in $APP_DIR/.env"
log_info "CHANGE THE DATABASE PASSWORD IN PRODUCTION!"
log_info ""
