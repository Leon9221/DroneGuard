# DroneGuard Command Center

Production-style FastAPI backend and dashboard for the DroneGuard mobile security platform.

## Capabilities

- Security Intelligence Center dashboard
- Tactical Detection System intake from Android field devices
- Restricted zone threat classification
- Personnel intelligence and face status classification
- Iraqi plate normalization and watchlist matching
- Evidence persistence with screenshots and video references
- Incident history search
- PDF incident report export
- Voice and Telegram alert hooks
- Fail-safe phone-to-PC connectivity model over local Wi-Fi

## Run

```powershell
cd C:\Users\lawan\AndroidStudioProjects\DroneGuard3\DroneGuard-Backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Open [http://localhost:8000/dashboard](http://localhost:8000/dashboard).

### MapTiler Toner map

The dashboard's geospatial incident map is optional. Before starting the server,
set the **replacement** MapTiler browser key in the current PowerShell window:

```powershell
$env:DRONEGUARD_MAPTILER_KEY = "paste-your-new-domain-restricted-key-here"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Keep the key out of source files. In MapTiler, restrict it to the dashboard
addresses you use, such as `http://localhost:8000/*` and your PC's local-Wi-Fi
address. The map displays the phone/field-terminal GPS coordinate attached to
each incident; it does not claim to independently locate an observed target.

## Android Connection

Set the Command Center host on the phone to the PC's local IP, for example `192.168.1.100`, with port `8000`.

## Environment Variables

- `DRONEGUARD_DB_URL` optional SQLAlchemy URL
- `DRONEGUARD_TELEGRAM_BOT_TOKEN` optional Telegram bot token
- `DRONEGUARD_TELEGRAM_CHAT_ID` optional Telegram chat id
- `DRONEGUARD_ENABLE_TTS` set `1` to enable voice alerts
- `DRONEGUARD_MAPTILER_KEY` optional browser key for the Toner incident map
