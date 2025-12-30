# Sentra Tunnel Server

Zentraler Management-Server für Remote-Zugriff auf Sentra Guard Türsteuerungssysteme.

## Features

- **WebSocket Tunnel**: Persistente Verbindung zu Raspberry Pi Geräten
- **Multi-Tenant**: Strikte Shop-/Mandanten-Trennung
- **Mobile-First UI**: Modernes, minimalistisches Design mit TailwindCSS
- **Sichere Authentifizierung**: Session-basierte Auth mit API-Keys für Geräte

## Quick Start

### Mit Docker

```bash
docker-compose up -d
```

### Ohne Docker

```bash
# Virtual Environment erstellen
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Abhängigkeiten installieren
pip install -r requirements.txt

# Server starten
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Erster Login

- URL: http://localhost:8000
- Username: `admin`
- Password: `admin`

**Wichtig: Passwort nach erstem Login ändern!**

## Architektur

```
sentra-tunnel-server/
├── app/
│   ├── main.py              # FastAPI App Entry
│   ├── models/              # Datenbank-Modelle
│   ├── routes/              # API & Web Routes
│   ├── tunnel/              # WebSocket Broker
│   └── templates/           # Jinja2 Templates (TailwindCSS)
├── data/
│   └── tunnel.db            # SQLite Database
├── Dockerfile
└── docker-compose.yml
```

## API Endpoints

### Authentication
- `POST /auth/login` - Login
- `POST /auth/logout` - Logout
- `GET /auth/me` - Current user

### Devices
- `GET /api/devices` - List devices
- `POST /api/devices/create` - Create device (generates token)
- `POST /api/devices/register` - Register device (Pi-side)
- `GET /api/devices/{id}/status` - Device status

### Commands
- `POST /api/commands/{id}/open` - Open door
- `POST /api/commands/{id}/status` - Get door status
- `GET /api/commands/{id}/config` - Get config
- `POST /api/commands/{id}/config` - Set config
- `POST /api/commands/{id}/override` - Set mode override

### WebSocket
- `ws://host/ws` - Device tunnel connection

## Gerät registrieren

1. **Admin**: Neues Gerät im Portal erstellen → Registration Token kopieren
2. **Pi**: Token eingeben:
   ```bash
   sudo sentra-register --token reg_xxx --server https://tunnel.example.com
   ```
3. Pi verbindet automatisch

## Sicherheit

- TLS für alle Verbindungen (wss://)
- API-Key pro Gerät (32 Bytes, kryptographisch sicher)
- Session-basierte Auth für Portal-Benutzer
- Audit-Log für alle Aktionen
- Rate Limiting

## Umgebungsvariablen

| Variable | Default | Beschreibung |
|----------|---------|--------------|
| `DATABASE_URL` | `sqlite:///data/tunnel.db` | Datenbank-Pfad |
| `SECRET_KEY` | (generiert) | Session-Encryption |
| `DEBUG` | `false` | Debug-Modus |

## Lizenz

Proprietary - Sentra GmbH
