#!/bin/bash
#
# SamurEye Cloud Platform - Installation Script
# This script installs the SamurEye Cloud Platform on Ubuntu Server
#
# Usage: sudo bash install.sh
#

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
mkdir -p $APP_DIR
mkdir -p $APP_DIR/logs
mkdir -p $APP_DIR/templates
mkdir -p $APP_DIR/static

log_info "Setting up PostgreSQL database..."
systemctl start postgresql
systemctl enable postgresql

sudo -u postgres psql -c "DROP DATABASE IF EXISTS samureye_cloud;" 2>/dev/null || true
sudo -u postgres psql -c "DROP USER IF EXISTS samureye;" 2>/dev/null || true
sudo -u postgres psql -c "CREATE USER samureye WITH PASSWORD 'samureye_secure_password_change_me';" 2>/dev/null || log_warn "User already exists, updating password..."
sudo -u postgres psql -c "ALTER USER samureye WITH PASSWORD 'samureye_secure_password_change_me';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE samureye_cloud OWNER samureye;" 2>/dev/null || log_warn "Database already exists"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE samureye_cloud TO samureye;"

log_info "Creating Python virtual environment..."
python3 -m venv $APP_DIR/venv
source $APP_DIR/venv/bin/activate

log_info "Installing Python dependencies..."
pip install --upgrade pip
pip install flask flask-sqlalchemy flask-login psycopg2-binary gunicorn python-dotenv requests werkzeug flask-socketio eventlet

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
ExecStart=$APP_DIR/venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 1 --worker-class eventlet --access-logfile $APP_DIR/logs/access.log --error-logfile $APP_DIR/logs/error.log app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICEEOF

log_info "Configuring Nginx..."
DOMAIN="app.samureye.com.br"

if [ -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]; then
    log_info "SSL certificate found! Configuring Nginx with HTTPS..."
    cat > /etc/nginx/sites-available/samureye-cloud << 'NGINXEOF'
server {
    listen 80;
    server_name app.samureye.com.br _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name app.samureye.com.br _;

    ssl_certificate /etc/letsencrypt/live/app.samureye.com.br/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.samureye.com.br/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

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
else
    log_info "No SSL certificate found. Configuring Nginx with HTTP only..."
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
fi

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

log_info "Creating SSL setup script..."
cat > /opt/samureye-cloud/setup-ssl.sh << 'SSLSCRIPT'
#!/bin/bash
DOMAIN="app.samureye.com.br"
echo "Requesting SSL certificate using DNS challenge..."
echo "You will need to create a TXT record in your DNS when prompted."
echo ""

certbot certonly --manual --preferred-challenges dns -d $DOMAIN --agree-tos --email admin@samureye.com.br

if [ -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]; then
    echo "SSL certificate obtained! Configuring Nginx for HTTPS..."
    cat > /etc/nginx/sites-available/samureye-cloud << 'NGINXEOF'
server {
    listen 80;
    server_name app.samureye.com.br _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name app.samureye.com.br _;

    ssl_certificate /etc/letsencrypt/live/app.samureye.com.br/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.samureye.com.br/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

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
    nginx -t && systemctl restart nginx
    echo "HTTPS configured successfully!"
else
    echo "SSL certificate not found. Please try again."
fi
SSLSCRIPT

chmod +x /opt/samureye-cloud/setup-ssl.sh
log_info "SSL setup script created at /opt/samureye-cloud/setup-ssl.sh"

echo ""
echo -e "${GREEN}=============================================="
echo -e "  SamurEye Cloud Platform installed!"
echo -e "==============================================${NC}"
echo ""
echo -e "Application URL: http://$(hostname -I | awk '{print $1}')"
echo ""
echo -e "Default login: admin@samureye.com.br"
echo -e "Password: ${YELLOW}$ADMIN_PASSWORD${NC}"
echo ""
echo -e "${YELLOW}To enable HTTPS, run:${NC}"
echo -e "  sudo /opt/samureye-cloud/setup-ssl.sh"
echo ""
echo -e "Application logs: $APP_DIR/logs/"
echo -e "Configuration: $APP_DIR/.env"
echo ""
echo -e "${YELLOW}IMPORTANT: Save the admin password above!${NC}"
echo -e "${YELLOW}Change the database password in production!${NC}"
echo ""
