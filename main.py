from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import threading
from typing import Any
from urllib.parse import quote
import uuid
import xml.etree.ElementTree as ET

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from database import (
    BASE_DIR,
    ConnectedDevice,
    IncidentQuery,
    IncidentRecord,
    SessionLocal,
    init_db,
    search_incidents,
    seed_reference_data,
    serialize_incident,
)
from detection import DetectionCandidate, RestrictedZone, TacticalDetectionSystem
from face_recognition import PersonnelRecognitionEngine
from plate_reader import IraqiPlateRecognitionEngine
from threat_engine import THREAT_CRITICAL, THREAT_GREEN, THREAT_RED, THREAT_YELLOW, ThreatClassificationEngine
from yolo_service import YoloInferenceService


APP_TITLE = "DroneGuard Security Intelligence Center"
EVIDENCE_DIR = BASE_DIR / "evidence"
REPORT_DIR = BASE_DIR / "reports"
LOG_DIR = BASE_DIR / "logs"
CONFIG_PATH = BASE_DIR / "config" / "restricted_zones.json"


class DeviceConnectRequest(BaseModel):
    device_id: str | None = None
    device_name: str
    ip_address: str = ""
    connection_mode: str = "LOCAL_WIFI"


class DetectionBox(BaseModel):
    object_type: str
    label: str
    confidence: float
    left: float = 0.0
    top: float = 0.0
    right: float = 1.0
    bottom: float = 1.0
    identity_hint: str = ""
    plate_text_hint: str = ""
    sector: str = "Unspecified Sector"


class MobileDetectionRequest(BaseModel):
    device_id: str
    device_name: str
    ip_address: str = ""
    local_status: str = "MONITORING"
    local_alert_level: str = "GREEN"
    location_summary: str = ""
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    officer_notes: str = ""
    fail_safe_active: bool = False
    screenshot_base64: str = ""
    video_path: str = ""
    detections: list[DetectionBox] = Field(default_factory=list)


class AnalyzeFrameRequest(BaseModel):
    device_id: str
    device_name: str
    image_base64: str
    ip_address: str = ""
    local_status: str = "MONITORING"
    local_alert_level: str = "GREEN"
    location_summary: str = ""
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    officer_notes: str = ""
    fail_safe_active: bool = False
    video_path: str = ""
    sector_default: str = "Unspecified Sector"


class NightModeRequest(BaseModel):
    enabled: bool


class AssistantRequest(BaseModel):
    message: str
    device_id: str = ""
    local_status: str = "MONITORING"
    alert_level: str = "GREEN"
    audio_threat: bool = False
    audio_label: str = ""
    human_count: int = 0
    location_summary: str = ""


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def load_restricted_zones() -> list[RestrictedZone]:
    payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return [
        RestrictedZone(
            name=item["name"],
            zone_type=item["type"],
            x1=item["x1"],
            y1=item["y1"],
            x2=item["x2"],
            y2=item["y2"],
            restricted_objects=item["restricted_objects"],
            priority=item["priority"],
        )
        for item in payload
    ]


class VoiceAlertDispatcher:
    def __init__(self) -> None:
        self.enabled = os.getenv("DRONEGUARD_ENABLE_TTS", "0") == "1"
        self._engine = None
        self._lock = threading.Lock()

    def speak(self, message: str) -> None:
        if not self.enabled:
            return
        if self._engine is None:
            try:
                import pyttsx3

                self._engine = pyttsx3.init()
            except Exception:
                self.enabled = False
                return
        def _run() -> None:
            with self._lock:
                self._engine.say(message)
                self._engine.runAndWait()
        threading.Thread(target=_run, daemon=True).start()


class TelegramAlertDispatcher:
    def __init__(self) -> None:
        self.bot_token = os.getenv("DRONEGUARD_TELEGRAM_BOT_TOKEN", "")
        self.chat_id = os.getenv("DRONEGUARD_TELEGRAM_CHAT_ID", "")

    def send(self, message: str, screenshot_path: str = "") -> None:
        if not self.bot_token or not self.chat_id:
            return
        base_url = f"https://api.telegram.org/bot{self.bot_token}"
        try:
            image_path = BASE_DIR / screenshot_path.lstrip("/")
            if screenshot_path and image_path.exists():
                with open(image_path, "rb") as handle:
                    requests.post(
                        f"{base_url}/sendPhoto",
                        data={"chat_id": self.chat_id, "caption": message},
                        files={"photo": handle},
                        timeout=8,
                    )
            else:
                requests.post(
                    f"{base_url}/sendMessage",
                    data={"chat_id": self.chat_id, "text": message},
                    timeout=8,
                )
        except requests.RequestException:
            return


class DashboardHub:
    def __init__(self) -> None:
        self.connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.connections:
            self.connections.remove(websocket)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        stale: list[WebSocket] = []
        for websocket in self.connections:
            try:
                await websocket.send_json(payload)
            except RuntimeError:
                stale.append(websocket)
        for websocket in stale:
            self.disconnect(websocket)


app = FastAPI(title=APP_TITLE, version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
app.mount("/evidence", StaticFiles(directory=EVIDENCE_DIR), name="evidence")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
hub = DashboardHub()
voice_dispatcher = VoiceAlertDispatcher()
telegram_dispatcher = TelegramAlertDispatcher()
face_engine = PersonnelRecognitionEngine()
plate_engine = IraqiPlateRecognitionEngine()
threat_engine = ThreatClassificationEngine()
detection_system = TacticalDetectionSystem(load_restricted_zones(), night_mode_enabled=False)
yolo_service = YoloInferenceService()


@app.on_event("startup")
async def startup() -> None:
    init_db()
    seed_reference_data()
    LOG_DIR.mkdir(exist_ok=True)
    EVIDENCE_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)


def update_device(session: Session, request: DeviceConnectRequest) -> ConnectedDevice:
    device_id = request.device_id or f"DG-{uuid.uuid4().hex[:10].upper()}"
    device = session.scalar(select(ConnectedDevice).where(ConnectedDevice.device_id == device_id))
    if device is None:
        device = ConnectedDevice(
            device_id=device_id,
            device_name=request.device_name,
            ip_address=request.ip_address,
            connection_mode=request.connection_mode,
            status="ONLINE",
            last_alert_level=THREAT_GREEN,
        )
        session.add(device)
    else:
        device.device_name = request.device_name
        device.ip_address = request.ip_address
        device.connection_mode = request.connection_mode
        device.status = "ONLINE"
    device.last_seen_at = datetime.now(timezone.utc)
    return device


def save_screenshot(base64_payload: str, incident_code: str) -> str:
    if not base64_payload:
        return ""
    try:
        raw = base64.b64decode(base64_payload)
    except (ValueError, TypeError):
        return ""
    file_path = EVIDENCE_DIR / f"{incident_code}.jpg"
    file_path.write_bytes(raw)
    return f"/evidence/{file_path.name}"


def generate_incident_code() -> str:
    return f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"


def append_log(message: str) -> None:
    log_file = LOG_DIR / f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.log"
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(f"[{datetime.now(timezone.utc).isoformat()}] {message}\n")


def incident_snapshot(session: Session) -> dict[str, Any]:
    incidents = list(session.scalars(select(IncidentRecord).order_by(IncidentRecord.created_at.desc()).limit(20)))
    devices = list(session.scalars(select(ConnectedDevice).order_by(ConnectedDevice.last_seen_at.desc())))

    active_alerts = [serialize_incident(incident) for incident in incidents if incident.threat_level in {THREAT_RED, THREAT_CRITICAL, THREAT_YELLOW}][:6]
    top_threat = THREAT_GREEN
    for level in [THREAT_CRITICAL, THREAT_RED, THREAT_YELLOW]:
        if any(item["threat_level"] == level for item in active_alerts):
            top_threat = level
            break

    today = datetime.now(timezone.utc).date()
    incidents_today = sum(1 for incident in incidents if incident.created_at.date() == today)
    authorized_events = sum(1 for incident in incidents if incident.identity_result == "AUTHORIZED")

    return {
        "command_center": {
            "status": "ONLINE",
            "top_threat": top_threat,
            "night_mode_enabled": detection_system.night_mode_enabled,
        },
        "summary": {
            "active_alerts": len(active_alerts),
            "connected_devices": len(devices),
            "incidents_today": incidents_today,
            "authorized_events": authorized_events,
        },
        "active_alerts": active_alerts,
        "devices": [
            {
                "device_id": device.device_id,
                "device_name": device.device_name,
                "ip_address": device.ip_address,
                "connection_mode": device.connection_mode,
                "status": device.status,
                "last_seen_at": device.last_seen_at.isoformat(),
            }
            for device in devices
        ],
        "incidents": [serialize_incident(incident) for incident in incidents],
    }


async def broadcast_snapshot() -> None:
    with SessionLocal() as session:
        await hub.broadcast(incident_snapshot(session))


def create_incident_report(record: IncidentRecord) -> Path:
    report_path = REPORT_DIR / f"{record.incident_code}.pdf"
    report_canvas = canvas.Canvas(str(report_path), pagesize=A4)
    width, height = A4

    report_canvas.setTitle(f"DroneGuard Incident Report {record.incident_code}")
    report_canvas.setFont("Helvetica-Bold", 18)
    report_canvas.drawString(40, height - 50, "DroneGuard Incident Report")
    report_canvas.setFont("Helvetica", 11)

    lines = [
        f"Incident ID: {record.incident_code}",
        f"Timestamp: {record.created_at.isoformat()}",
        f"Threat Level: {record.threat_level}",
        f"Threat Title: {record.threat_title}",
        f"Threat Details: {record.threat_details}",
        f"Sector: {record.sector}",
        f"Object Type: {record.object_type}",
        f"Confidence: {record.confidence:.2%}",
        f"Identity Result: {record.identity_result}",
        f"Person: {record.person_name or 'N/A'}",
        f"Plate: {record.plate_number or 'N/A'}",
        f"Officer Notes: {record.officer_notes or 'N/A'}",
    ]

    y = height - 90
    for line in lines:
        report_canvas.drawString(40, y, line[:110])
        y -= 18

    if record.screenshot_path:
        image_path = BASE_DIR / record.screenshot_path.lstrip("/")
        if image_path.exists():
            report_canvas.drawImage(ImageReader(str(image_path)), 40, 120, width=260, height=180, preserveAspectRatio=True, mask="auto")

    report_canvas.showPage()
    report_canvas.save()
    return report_path


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            # MapTiler browser keys are intentionally public, but must be domain
            # restricted in MapTiler. Keep the actual key outside source control.
            "maptiler_key": os.getenv("DRONEGUARD_MAPTILER_KEY", ""),
        },
    )


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": APP_TITLE,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def local_assistant_reply(payload: AssistantRequest) -> str:
    message = payload.message.lower()
    if "status" in message or "report" in message:
        audio = payload.audio_label if payload.audio_threat else "none"
        return (
            f"Status report. Local state {payload.local_status}. "
            f"Alert level {payload.alert_level}. Humans visible {payload.human_count}. "
            f"Audio threat {audio}."
        )
    if "metal" in message or "knife" in message or "weapon" in message:
        return (
            "Use the metal detector after recalibrating away from metal. "
            "Knife warning means a stronger confirmed metal signature. "
            "Possible weapon means the signature is high enough to treat with caution."
        )
    if "help" in message or "what can you do" in message:
        return (
            "Jarvis can answer DroneGuard questions, summarize current status, "
            "and the mobile app can obey voice commands like open tools, open logs, "
            "open live view, and open command center."
        )
    return (
        "Jarvis is online. Ask for status, logs, tools, live view, "
        "or a DroneGuard safety question."
    )


def requested_city(message: str, fallback: str = "Baghdad") -> str:
    lowered = message.lower()
    match = re.search(r"weather\s+(?:in|for)\s+([a-zA-Z\s\-]+)", lowered)
    if match:
        return match.group(1).strip().title()
    return fallback


def weather_widgets(payload: AssistantRequest) -> tuple[str, list[dict[str, str]]]:
    city = requested_city(payload.message)
    try:
        geo = requests.get(
            "https://geocoding-api.open-meteo.com/v1/search",
            params={"name": city, "count": 1, "language": "en", "format": "json"},
            timeout=8,
        )
        geo.raise_for_status()
        result = (geo.json().get("results") or [])[0]
        latitude = result["latitude"]
        longitude = result["longitude"]
        display_city = ", ".join(
            value for value in [result.get("name"), result.get("country_code")] if value
        )

        weather = requests.get(
            "https://api.open-meteo.com/v1/forecast",
            params={
                "latitude": latitude,
                "longitude": longitude,
                "current": "temperature_2m,relative_humidity_2m,wind_speed_10m",
                "daily": "temperature_2m_max,temperature_2m_min,precipitation_probability_max",
                "timezone": "auto",
            },
            timeout=8,
        )
        weather.raise_for_status()
        data = weather.json()
        current = data.get("current", {})
        daily = data.get("daily", {})
        temp = current.get("temperature_2m")
        humidity = current.get("relative_humidity_2m")
        wind = current.get("wind_speed_10m")
        high = (daily.get("temperature_2m_max") or [""])[0]
        low = (daily.get("temperature_2m_min") or [""])[0]
        rain = (daily.get("precipitation_probability_max") or [""])[0]
        body = f"Now {temp} C. Humidity {humidity}%. Wind {wind} km/h. Today high {high} C, low {low} C. Rain chance {rain}%."
        reply = f"Weather for {display_city}: {body}"
        return reply, [
            {
                "type": "weather",
                "title": f"Weather: {display_city}",
                "subtitle": f"{temp} C now",
                "body": body,
                "url": "open-meteo.com",
            }
        ]
    except Exception:
        return "Weather feed is unavailable right now.", [
            {
                "type": "weather",
                "title": "Weather unavailable",
                "subtitle": city,
                "body": "The backend could not reach the weather feed.",
                "url": "",
            }
        ]


def news_widgets(payload: AssistantRequest) -> tuple[str, list[dict[str, str]]]:
    message = payload.message.lower()
    topic_match = re.search(r"(?:news about|news on|latest news about|latest news on)\s+(.+)", message)
    topic = topic_match.group(1).strip() if topic_match else ""
    rss_url = (
        f"https://news.google.com/rss/search?q={quote(topic)}&hl=en-US&gl=US&ceid=US:en"
        if topic
        else "https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en"
    )
    try:
        response = requests.get(rss_url, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.content)
        items: list[dict[str, str]] = []
        for item in root.findall("./channel/item")[:3]:
            title = item.findtext("title", default="News update")
            link = item.findtext("link", default="")
            published = item.findtext("pubDate", default="")
            items.append(
                {
                    "type": "news",
                    "title": title,
                    "subtitle": published,
                    "body": "Tap the link in a browser for the full article.",
                    "url": link,
                }
            )
        if not items:
            raise ValueError("No news items")
        scope = f" about {topic}" if topic else ""
        reply = f"Latest news{scope}: " + " ".join(item["title"] for item in items[:2])
        return reply, items
    except Exception:
        return "News feed is unavailable right now.", [
            {
                "type": "news",
                "title": "News unavailable",
                "subtitle": topic.title() if topic else "Global",
                "body": "The backend could not reach the news feed.",
                "url": "",
            }
        ]


def extract_gemini_text(response_payload: dict[str, Any]) -> str:
    parts: list[str] = []
    for candidate in response_payload.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        content = candidate.get("content", {})
        if not isinstance(content, dict):
            continue
        for part in content.get("parts", []):
            if not isinstance(part, dict):
                continue
            text = part.get("text")
            if isinstance(text, str) and text.strip():
                parts.append(text.strip())
    return " ".join(parts).strip()


def gemini_assistant_reply(payload: AssistantRequest) -> str | None:
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return None

    model = os.getenv("DRONEGUARD_GEMINI_MODEL", "gemini-1.5-flash")
    instructions = (
        "You are Jarvis inside DroneGuard, a concise military-style tactical assistant. "
        "Answer like a calm security co-pilot. Keep replies short enough for text-to-speech. "
        "You are integrated into the DroneGuard Field Terminal and can display UI widgets "
        "for news, weather, and tactical data. If asked for these, acknowledge that you "
        "are retrieving the data for the display. Do not claim to be just an AI; "
        "you are the system's tactical interface. "
        "Do not claim certainty about threats; advise caution and verification."
    )
    context = (
        f"Current app status: {payload.local_status}. "
        f"Alert level: {payload.alert_level}. "
        f"Humans visible: {payload.human_count}. "
        f"Audio threat active: {payload.audio_threat} {payload.audio_label}."
    )
    prompt = f"{instructions}\n\n{context}\n\nCommander asks: {payload.message}"
    body = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}],
            }
        ],
        "generationConfig": {
            "temperature": 0.7,
            "topP": 0.95,
            "maxOutputTokens": 512,
        },
    }

    try:
        response = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            headers={
                "x-goog-api-key": api_key,
                "Content-Type": "application/json",
            },
            json=body,
            timeout=12,
        )
        response.raise_for_status()
        text = extract_gemini_text(response.json())
        return text or None
    except requests.RequestException:
        return None


@app.post("/api/mobile/assistant")
def mobile_assistant(payload: AssistantRequest) -> dict[str, Any]:
    lowered = payload.message.lower()

    # Priority 1: Explicit keyword triggers
    if "weather" in lowered:
        reply, widgets = weather_widgets(payload)
        return {"reply": reply, "provider": "weather", "widgets": widgets}

    if "news" in lowered or "headlines" in lowered:
        reply, widgets = news_widgets(payload)
        return {"reply": reply, "provider": "news", "widgets": widgets}

    # Priority 2: Gemini intelligence
    gemini_enabled = bool(os.getenv("GEMINI_API_KEY", ""))
    reply = gemini_assistant_reply(payload) or local_assistant_reply(payload)

    # Check if Jarvis wants to show a widget via text trigger
    widgets = []
    reply_lower = reply.lower()
    if "displaying news" in reply_lower or "fetching news" in reply_lower:
        _, widgets = news_widgets(payload)
    elif "displaying weather" in reply_lower or "fetching weather" in reply_lower:
        _, widgets = weather_widgets(payload)
    else:
        widgets = [
            {
                "type": "info",
                "title": "Jarvis Intelligence" if gemini_enabled else "Local Protocol",
                "subtitle": payload.local_status,
                "body": reply,
                "url": "",
            }
        ]

    return {
        "reply": reply,
        "provider": "gemini" if gemini_enabled else "local",
        "widgets": widgets,
    }


@app.get("/api/command-center/status")
def command_center_status(db: Session = Depends(get_db)) -> dict[str, Any]:
    snapshot = incident_snapshot(db)
    return snapshot["command_center"] | {"connected_devices": snapshot["summary"]["connected_devices"]}


@app.post("/api/mobile/connect")
async def mobile_connect(payload: DeviceConnectRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    device = update_device(db, payload)
    db.commit()
    await broadcast_snapshot()
    return {
        "device_id": device.device_id,
        "status": "CONNECTED",
        "command_center": APP_TITLE,
        "message": "Field terminal linked to local command center",
    }


@app.post("/api/mobile/detections")
async def ingest_mobile_detections(payload: MobileDetectionRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    update_device(
        db,
        DeviceConnectRequest(
            device_id=payload.device_id,
            device_name=payload.device_name,
            ip_address=payload.ip_address,
            connection_mode="LOCAL_WIFI_FAIL_SAFE" if payload.fail_safe_active else "LOCAL_WIFI",
        ),
    )

    created: list[IncidentRecord] = []
    latest_alert: dict[str, Any] | None = None
    screenshot_path = ""
    # Avoid storing base64 screenshots in every incident row; this can explode memory/disk usage.
    sanitized_payload_json = json.dumps(
        payload.model_dump(exclude={"screenshot_base64"}),
        separators=(",", ":"),
    )

    for box in payload.detections:
        incident_code = generate_incident_code()
        if payload.screenshot_base64 and not screenshot_path:
            screenshot_path = save_screenshot(payload.screenshot_base64, incident_code)

        object_type = box.object_type.lower()
        center_x = max(0.0, min(1.0, (box.left + box.right) / 2))
        center_y = max(0.0, min(1.0, (box.top + box.bottom) / 2))
        assessment = detection_system.assess(
            DetectionCandidate(
                object_type=object_type,
                label=box.label,
                confidence=box.confidence,
                sector=box.sector,
                center_x=center_x,
                center_y=center_y,
                width=max(0.0, box.right - box.left),
                height=max(0.0, box.bottom - box.top),
                identity_hint=box.identity_hint,
                plate_text_hint=box.plate_text_hint,
                local_alert_level=payload.local_alert_level,
            )
        )

        face_result = face_engine.classify(db, box.identity_hint) if object_type == "human" else None
        plate_result = plate_engine.classify(db, box.plate_text_hint or box.label) if object_type == "vehicle" else None
        stability_key = (
            f"{payload.device_id}:{object_type}:{box.sector}:{assessment.zone_name or 'open'}"
        )
        decision = threat_engine.classify(
            assessment,
            face_result,
            plate_result,
            stability_key=stability_key,
        )

        incident = IncidentRecord(
            incident_code=incident_code,
            source_device_id=payload.device_id,
            object_type=object_type,
            object_label=box.label,
            confidence=box.confidence,
            threat_level=decision.level,
            threat_title=decision.title,
            threat_details=decision.details,
            identity_result=decision.identity_result,
            person_name=face_result.person_name if face_result else "",
            plate_number=plate_result.display_plate if plate_result else "",
            sector=box.sector,
            zone_name=assessment.zone_name,
            restricted_trigger=assessment.restricted_trigger,
            location_summary=payload.location_summary,
            latitude=payload.latitude,
            longitude=payload.longitude,
            screenshot_path=screenshot_path,
            video_path=payload.video_path,
            officer_notes=payload.officer_notes,
            detection_history=f"Local status {payload.local_status}; local fail-safe active={payload.fail_safe_active}",
            raw_payload_json=sanitized_payload_json,
        )
        db.add(incident)
        created.append(incident)

        if decision.level in {THREAT_RED, THREAT_CRITICAL}:
            voice_dispatcher.speak(decision.title)
            telegram_dispatcher.send(
                f"{decision.title}\nSector: {box.sector}\nTime: {datetime.now(timezone.utc).isoformat()}",
                screenshot_path,
            )
            latest_alert = {
                "threat_level": decision.level,
                "title": decision.title,
                "details": decision.details,
            }

        append_log(f"{incident.incident_code} | {incident.threat_level} | {incident.threat_title}")

    db.commit()
    await broadcast_snapshot()

    if latest_alert is None and created:
        newest = created[-1]
        latest_alert = {
            "threat_level": newest.threat_level,
            "title": newest.threat_title,
            "details": newest.threat_details,
        }

    return {
        "status": "accepted",
        "ingested": len(created),
        "latest_alert": latest_alert,
        "command_center_status": "ONLINE",
    }


def map_yolo_label_to_object_type(label: str) -> str:
    normalized = (label or "").strip().lower()
    if normalized == "person":
        return "human"
    if normalized in {"car", "truck", "bus", "motorcycle", "bicycle"}:
        return "vehicle"
    if normalized in {"drone", "uav", "quadcopter"}:
        return "drone"
    return normalized or "unknown"


@app.post("/api/mobile/analyze-frame")
async def analyze_mobile_frame(payload: AnalyzeFrameRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        encoded = payload.image_base64.split(",", 1)[1] if "," in payload.image_base64 else payload.image_base64
        image_bytes = base64.b64decode(encoded)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid image_base64 payload")

    yolo_detections = yolo_service.infer(image_bytes)
    detection_boxes = [
        DetectionBox(
            object_type=map_yolo_label_to_object_type(item.label),
            label=item.label,
            confidence=item.confidence,
            left=item.left,
            top=item.top,
            right=item.right,
            bottom=item.bottom,
            identity_hint="",
            plate_text_hint="",
            sector=payload.sector_default,
        )
        for item in yolo_detections
    ]

    mobile_payload = MobileDetectionRequest(
        device_id=payload.device_id,
        device_name=payload.device_name,
        ip_address=payload.ip_address,
        local_status=payload.local_status,
        local_alert_level=payload.local_alert_level,
        location_summary=payload.location_summary,
        latitude=payload.latitude,
        longitude=payload.longitude,
        officer_notes=payload.officer_notes,
        fail_safe_active=payload.fail_safe_active,
        screenshot_base64=payload.image_base64,
        video_path=payload.video_path,
        detections=detection_boxes,
    )

    result = await ingest_mobile_detections(mobile_payload, db)
    result["pipeline"] = "pc_yolo_heavy_inference"
    result["yolo_model"] = yolo_service.model_name
    return result


@app.get("/api/mobile/alerts/latest")
def latest_mobile_alert(device_id: str = Query(default=""), db: Session = Depends(get_db)) -> dict[str, Any]:
    stmt = select(IncidentRecord).order_by(IncidentRecord.created_at.desc())
    if device_id:
        stmt = stmt.where(IncidentRecord.source_device_id == device_id)
    incident = db.scalar(stmt.limit(1))
    if incident is None:
        return {"alert": None}
    return {"alert": serialize_incident(incident)}


@app.get("/api/dashboard/snapshot")
def dashboard_snapshot(db: Session = Depends(get_db)) -> dict[str, Any]:
    return incident_snapshot(db)


@app.get("/api/incidents")
def incidents(
    face: str | None = None,
    plate: str | None = None,
    date: str | None = None,
    threat_level: str | None = None,
    object_type: str | None = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    results = search_incidents(
        db,
        IncidentQuery(face=face, plate=plate, date=date, threat_level=threat_level, object_type=object_type),
    )
    return {"items": [serialize_incident(item) for item in results]}


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    record = db.get(IncidentRecord, incident_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return serialize_incident(record)


@app.post("/api/reports/incidents/{incident_id}/export")
def export_incident_report(incident_id: int, db: Session = Depends(get_db)) -> FileResponse:
    record = db.get(IncidentRecord, incident_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    report_path = create_incident_report(record)
    return FileResponse(path=report_path, filename=report_path.name, media_type="application/pdf")


@app.post("/api/settings/night-mode")
async def set_night_mode(payload: NightModeRequest) -> dict[str, Any]:
    detection_system.set_night_mode(payload.enabled)
    await broadcast_snapshot()
    return {"status": "updated", "night_mode_enabled": payload.enabled}


@app.websocket("/ws/dashboard")
async def dashboard_socket(websocket: WebSocket) -> None:
    await hub.connect(websocket)
    try:
        with SessionLocal() as session:
            await websocket.send_json(incident_snapshot(session))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        hub.disconnect(websocket)
