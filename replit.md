# SamurEye Cloud Platform

## Overview
Central management platform for SamurEye appliances - cyber threat assessment consoles deployed at client sites. This application runs at app.samureye.com.br and provides:

- Contract and client management
- Appliance registration with secure token authentication
- Health metrics monitoring (CPU, memory, disk, network) with Chart.js visualization
- SSH and GUI login logs tracking
- Threat metadata collection
- License validation for appliances
- Remote shell access via secure WebSocket tunnel

## Architecture

### Tech Stack
- **Backend**: Python 3.11 + Flask + Flask-SocketIO
- **Database**: PostgreSQL
- **Frontend**: HTML/CSS/JS with Bootstrap 5, Chart.js, xterm.js
- **Authentication**: Flask-Login with password hashing
- **Real-time**: Socket.IO with eventlet for WebSocket tunnel

### Database Models
- `User`: Admin users (admin@samureye.com.br)
- `Contract`: Client contracts with validity period
- `Appliance`: Devices with unique tokens and system inventory (IP, hostname, virtualization, vCPUs, memory, disk, OS)
- `Metric`: System health metrics (CPU, memory, disk, network)
- `LoginLog`: SSH/GUI login attempts
- `ThreatMetadata`: Threat information from appliances

### API Endpoints
All telemetry endpoints require `X-Appliance-Token` header:

- `POST /api/v1/telemetry/metrics` - Submit system metrics
- `POST /api/v1/telemetry/login-logs` - Submit login logs
- `POST /api/v1/telemetry/threats` - Submit threat metadata
- `POST /api/v1/telemetry/inventory` - Submit system inventory (IP, hostname, virtualization, specs)
- `GET /api/v1/license/validate` - Validate license and get contract info
- `GET /api/v1/appliances/<id>/tunnel-status` - Check if appliance tunnel is connected

### WebSocket Namespaces
- `/appliance` - Appliance connections (authenticated by token)
- `/console` - Admin console connections (authenticated by session)

## Project Structure
```
/
├── app.py                    # Main Flask + Socket.IO application
├── models.py                 # SQLAlchemy database models
├── templates/                # Jinja2 HTML templates
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── contracts.html
│   ├── contract_form.html
│   ├── contract_view.html
│   ├── appliance_form.html
│   └── appliance_view.html   # Includes xterm.js terminal
├── samureye_telemetry.py     # Telemetry service with tunnel support
├── install.sh                # Cloud platform installation script
├── install_telemetry.sh      # Appliance telemetry installation script
└── setup-ssl.sh              # SSL certificate setup (created by install.sh)
```

## Installation Scripts

### install.sh
Installs the cloud platform on Ubuntu server:
- System dependencies (Python, PostgreSQL, Nginx)
- Creates database and user
- Configures systemd service with eventlet worker
- Sets up Nginx reverse proxy
- Preserves SSL certificates on reinstall
- Creates setup-ssl.sh for HTTPS configuration

### install_telemetry.sh
Installs telemetry service on SamurEye appliances:
```bash
sudo bash install_telemetry.sh <TOKEN> [API_URL]
```
- Creates systemd service
- Sends metrics every 5 minutes
- Sends system inventory every hour (IP, hostname, virtualization type, hardware specs, OS)
- Validates license daily
- Generates /opt/samureye/license file
- Establishes persistent WebSocket tunnel for remote shell

## Remote Access Features

### Remote Shell
The platform provides secure remote shell access to appliances:

1. Appliance telemetry service maintains a persistent WebSocket connection
2. Admin clicks "Conectar Shell" on appliance page to start shell session
3. PTY-based shell session created on appliance
4. Terminal output streamed to xterm.js in browser
5. Full interactive bash shell with resize support

### GUI Proxy
The platform provides HTTP proxy access to the appliance's internal web interface:

1. Admin clicks "Conectar GUI" on appliance page (opens in new tab)
2. HTTP requests are tunneled through the WebSocket connection
3. Proxies to http://127.0.0.1:80 on the appliance
4. HTML responses have URLs rewritten to work through the /gui/<appliance_id>/ path
5. Binary content (images, etc.) is base64 encoded over WebSocket

### Security
- Token-based authentication for appliance connections
- Session-based authentication for admin console
- All traffic encrypted via HTTPS/WSS

## Credentials
- **Admin Login**: admin@samureye.com.br
- **Password**: Set via `ADMIN_PASSWORD` environment variable, or auto-generated on first run (check logs)

## Development
Run locally with:
```bash
python app.py
```
Access at http://localhost:5000

## License File Format
The telemetry service generates `/opt/samureye/license`:
```json
{
  "valid": true,
  "appliance_name": "SamurEye-001",
  "client_name": "Cliente XYZ",
  "contract_start": "2024-01-01",
  "contract_end": "2025-12-31",
  "validated_at": "2024-12-23T14:15:00",
  "expires_at": "2024-12-30T14:15:00"
}
```

## Data Retention
- Metrics, login logs, and threat metadata are retained for 90 days
- Automatic cleanup runs on application startup
- Manual cleanup available via POST /api/v1/cleanup

## Period Selection
Charts and data tables support multiple time periods:
- 1 hour, 6 hours, 24 hours (default)
- 7 days, 30 days, 90 days

## Recent Changes
- 2024-12-23: Initial implementation with full CRUD, API endpoints, and telemetry service
- 2024-12-23: Security improvement - removed hardcoded password, added Chart.js dashboard visualization
- 2024-12-23: Added SSL preservation on reinstall, created separate setup-ssl.sh script
- 2024-12-23: Implemented reverse shell tunnel via WebSocket/Socket.IO for remote appliance access
- 2024-12-26: Added period selection for charts (1h to 90 days) and 90-day data retention policy
- 2024-12-26: Added system inventory tracking (IP, hostname, virtualization type, vCPUs, memory, disk, OS) with hourly updates
- 2024-12-28: Added HTTP proxy via WebSocket tunnel to access appliance's internal GUI (http://127.0.0.1:80)
- 2024-12-28: Updated appliance interface with separate "Conectar Shell" and "Conectar GUI" buttons, GUI opens in new tab
