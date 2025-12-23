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
- `Appliance`: Devices with unique tokens
- `Metric`: System health metrics (CPU, memory, disk, network)
- `LoginLog`: SSH/GUI login attempts
- `ThreatMetadata`: Threat information from appliances

### API Endpoints
All telemetry endpoints require `X-Appliance-Token` header:

- `POST /api/v1/telemetry/metrics` - Submit system metrics
- `POST /api/v1/telemetry/login-logs` - Submit login logs
- `POST /api/v1/telemetry/threats` - Submit threat metadata
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
- Validates license daily
- Generates /opt/samureye/license file
- Establishes persistent WebSocket tunnel for remote shell

## Remote Shell Feature
The platform provides secure remote shell access to appliances:

1. Appliance telemetry service maintains a persistent WebSocket connection
2. Admin clicks "Conectar" on appliance page to start shell session
3. PTY-based shell session created on appliance
4. Terminal output streamed to xterm.js in browser
5. Full interactive bash shell with resize support

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

## Recent Changes
- 2024-12-23: Initial implementation with full CRUD, API endpoints, and telemetry service
- 2024-12-23: Security improvement - removed hardcoded password, added Chart.js dashboard visualization
- 2024-12-23: Added SSL preservation on reinstall, created separate setup-ssl.sh script
- 2024-12-23: Implemented reverse shell tunnel via WebSocket/Socket.IO for remote appliance access
