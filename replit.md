# SamurEye Cloud Platform

## Overview
Central management platform for SamurEye appliances - cyber threat assessment consoles deployed at client sites. This application runs at app.samureye.com.br and provides:

- Contract and client management
- Appliance registration with secure token authentication
- Health metrics monitoring (CPU, memory, disk, network)
- SSH and GUI login logs tracking
- Threat metadata collection
- License validation for appliances

## Architecture

### Tech Stack
- **Backend**: Python 3.11 + Flask
- **Database**: PostgreSQL
- **Frontend**: HTML/CSS/JS with Bootstrap 5, Chart.js
- **Authentication**: Flask-Login with password hashing

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

## Project Structure
```
/
├── app.py                    # Main Flask application
├── models.py                 # SQLAlchemy database models
├── templates/                # Jinja2 HTML templates
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── contracts.html
│   ├── contract_form.html
│   ├── contract_view.html
│   ├── appliance_form.html
│   └── appliance_view.html
├── samureye_telemetry.py     # Telemetry service for appliances
├── install.sh                # Cloud platform installation script
└── install_telemetry.sh      # Appliance telemetry installation script
```

## Installation Scripts

### install.sh
Installs the cloud platform on Ubuntu server:
- System dependencies (Python, PostgreSQL, Nginx)
- Creates database and user
- Configures systemd service
- Sets up Nginx reverse proxy
- Enables firewall rules

### install_telemetry.sh
Installs telemetry service on SamurEye appliances:
```bash
sudo bash install_telemetry.sh <TOKEN> [API_URL]
```
- Creates systemd service
- Sends metrics every 5 minutes
- Validates license daily
- Generates /opt/samureye/license file

## Credentials
- **Admin Login**: admin@samureye.com.br
- **Default Password**: SamurEye@2024!

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
