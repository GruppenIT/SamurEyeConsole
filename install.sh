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
REPO_URL="https://raw.githubusercontent.com/GruppenIT/SamurEyeConsole/main"

log_info "Starting SamurEye Cloud Platform installation..."

log_info "Updating system packages..."
apt-get update -y
apt-get upgrade -y

log_info "Installing system dependencies..."
apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    postgresql \
    postgresql-contrib \
    nginx \
    certbot \
    python3-certbot-nginx \
    git \
    curl \
    wget \
    ufw \
    dnsutils

log_info "Creating application user..."
if ! id "$APP_USER" &>/dev/null; then
    useradd -r -s /bin/false -d $APP_DIR $APP_USER
fi

log_info "Creating application directory..."
rm -rf $APP_DIR
mkdir -p $APP_DIR
mkdir -p $APP_DIR/logs
mkdir -p $APP_DIR/templates
mkdir -p $APP_DIR/static

log_info "Setting up PostgreSQL database..."
systemctl start postgresql
systemctl enable postgresql

sudo -u postgres psql -c "DROP DATABASE IF EXISTS samureye_cloud;" 2>/dev/null || true
sudo -u postgres psql -c "DROP USER IF EXISTS samureye;" 2>/dev/null || true
sudo -u postgres psql -c "CREATE USER samureye WITH PASSWORD 'samureye_secure_password_change_me';"
sudo -u postgres psql -c "CREATE DATABASE samureye_cloud OWNER samureye;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE samureye_cloud TO samureye;"

log_info "Creating Python virtual environment..."
python3 -m venv $APP_DIR/venv
source $APP_DIR/venv/bin/activate

log_info "Installing Python dependencies..."
pip install --upgrade pip
pip install flask flask-sqlalchemy flask-login psycopg2-binary gunicorn python-dotenv requests werkzeug

log_info "Downloading application files from GitHub..."
curl -sSL "$REPO_URL/app.py" -o $APP_DIR/app.py
curl -sSL "$REPO_URL/models.py" -o $APP_DIR/models.py

for template in base.html login.html dashboard.html contracts.html contract_form.html contract_view.html appliance_form.html appliance_view.html; do
    curl -sSL "$REPO_URL/templates/$template" -o $APP_DIR/templates/$template
done

log_info "Creating environment configuration..."
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
ADMIN_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')

cat > $APP_DIR/.env << ENVEOF
SECRET_KEY=$SECRET_KEY
DATABASE_URL=postgresql://samureye:samureye_secure_password_change_me@localhost/samureye_cloud
FLASK_ENV=production
ADMIN_PASSWORD=$ADMIN_PASSWORD
ENVEOF

log_info "Setting file permissions..."
chown -R $APP_USER:$APP_USER $APP_DIR
chmod 600 $APP_DIR/.env

log_info "Creating systemd service..."
cat > /etc/systemd/system/samureye-cloud.service << SERVICEEOF
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
SERVICEEOF

log_info "Configuring Nginx..."
cat > /etc/nginx/sites-available/samureye-cloud << 'NGINXEOF'
server {
    listen 80;
    server_name app.samureye.com.br _;

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
        alias /opt/samureye-cloud/static;
        expires 1d;
    }
}
NGINXEOF

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
systemctl enable samureye-cloud
systemctl stop samureye-cloud 2>/dev/null || true
systemctl restart nginx

log_info "Initializing database..."
cd $APP_DIR
source venv/bin/activate
export SECRET_KEY=$SECRET_KEY
export DATABASE_URL=postgresql://samureye:samureye_secure_password_change_me@localhost/samureye_cloud
export ADMIN_PASSWORD=$ADMIN_PASSWORD
python3 -c "from app import app, db, init_db; app.app_context().push(); db.create_all(); init_db()"

log_info "Starting application service..."
systemctl start samureye-cloud

sleep 3
if systemctl is-active --quiet samureye-cloud; then
    log_info "Service started successfully!"
else
    log_error "Service failed to start. Check logs with: journalctl -u samureye-cloud -n 50"
fi

log_info "Configuring SSL certificate with Let's Encrypt..."
DOMAIN="app.samureye.com.br"

if host $DOMAIN > /dev/null 2>&1; then
    SERVER_IP=$(hostname -I | awk '{print $1}')
    DOMAIN_IP=$(dig +short $DOMAIN | tail -1)
    
    if [ "$SERVER_IP" = "$DOMAIN_IP" ] || [ -n "$DOMAIN_IP" ]; then
        log_info "Requesting SSL certificate for $DOMAIN..."
        certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@samureye.com.br --redirect || {
            log_warn "Certbot failed. You can run manually later: sudo certbot --nginx -d $DOMAIN"
        }
    else
        log_warn "Domain $DOMAIN does not point to this server ($SERVER_IP)."
        log_warn "Configure DNS first, then run: sudo certbot --nginx -d $DOMAIN"
    fi
else
    log_warn "Could not resolve $DOMAIN. DNS may not be configured yet."
    log_warn "After configuring DNS, run: sudo certbot --nginx -d $DOMAIN"
fi

echo ""
echo -e "${GREEN}=============================================="
echo -e "  SamurEye Cloud Platform installed!"
echo -e "==============================================${NC}"
echo ""
echo -e "Application URL: https://app.samureye.com.br"
echo -e "              or http://$(hostname -I | awk '{print $1}')"
echo ""
echo -e "Default login: admin@samureye.com.br"
echo -e "Password: ${YELLOW}$ADMIN_PASSWORD${NC}"
echo ""
echo -e "Application logs: $APP_DIR/logs/"
echo -e "Configuration: $APP_DIR/.env"
echo ""
echo -e "${YELLOW}IMPORTANT: Save the admin password above!${NC}"
echo -e "${YELLOW}Change the database password in production!${NC}"
echo ""
