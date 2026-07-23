from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import os
from typing import Generator

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, create_engine, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


BASE_DIR = Path(__file__).resolve().parent
DB_URL = os.getenv("DRONEGUARD_DB_URL", f"sqlite:///{BASE_DIR / 'droneguard_command_center.db'}")


class Base(DeclarativeBase):
    pass


class PersonnelProfile(Base):
    __tablename__ = "personnel_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    profile_code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="AUTHORIZED")
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    face_signature: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class VehicleProfile(Base):
    __tablename__ = "vehicle_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    plate_number: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    display_plate: Mapped[str] = mapped_column(String(32), nullable=False)
    owner_name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="UNKNOWN")
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ConnectedDevice(Base):
    __tablename__ = "connected_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    device_name: Mapped[str] = mapped_column(String(120), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    connection_mode: Mapped[str] = mapped_column(String(40), nullable=False, default="LOCAL_WIFI")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="ONLINE")
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_alert_level: Mapped[str] = mapped_column(String(24), nullable=False, default="GREEN")


class IncidentRecord(Base):
    __tablename__ = "incident_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    source_device_id: Mapped[str] = mapped_column(String(80), nullable=False)
    object_type: Mapped[str] = mapped_column(String(24), nullable=False)
    object_label: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    threat_level: Mapped[str] = mapped_column(String(24), nullable=False, default="GREEN")
    threat_title: Mapped[str] = mapped_column(String(160), nullable=False, default="")
    threat_details: Mapped[str] = mapped_column(Text, nullable=False, default="")
    identity_result: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    person_name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    plate_number: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    sector: Mapped[str] = mapped_column(String(80), nullable=False, default="Unspecified Sector")
    zone_name: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    restricted_trigger: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    location_summary: Mapped[str] = mapped_column(String(160), nullable=False, default="")
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    screenshot_path: Mapped[str] = mapped_column(Text, nullable=False, default="")
    video_path: Mapped[str] = mapped_column(Text, nullable=False, default="")
    officer_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detection_history: Mapped[str] = mapped_column(Text, nullable=False, default="")
    raw_payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


engine = create_engine(DB_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    # Existing demo databases predate map coordinates. SQLite needs an explicit
    # additive migration because create_all() does not alter existing tables.
    with engine.begin() as connection:
        columns = {row[1] for row in connection.execute(text("PRAGMA table_info(incident_records)"))}
        if "latitude" not in columns:
            connection.execute(text("ALTER TABLE incident_records ADD COLUMN latitude FLOAT"))
        if "longitude" not in columns:
            connection.execute(text("ALTER TABLE incident_records ADD COLUMN longitude FLOAT"))


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@dataclass
class IncidentQuery:
    face: str | None = None
    plate: str | None = None
    date: str | None = None
    threat_level: str | None = None
    object_type: str | None = None


def serialize_incident(record: IncidentRecord) -> dict:
    return {
        "id": record.id,
        "incident_code": record.incident_code,
        "source_device_id": record.source_device_id,
        "object_type": record.object_type,
        "object_label": record.object_label,
        "confidence": round(record.confidence, 4),
        "threat_level": record.threat_level,
        "threat_title": record.threat_title,
        "threat_details": record.threat_details,
        "identity_result": record.identity_result,
        "person_name": record.person_name,
        "plate_number": record.plate_number,
        "sector": record.sector,
        "zone_name": record.zone_name,
        "restricted_trigger": record.restricted_trigger,
        "location_summary": record.location_summary,
        "latitude": record.latitude,
        "longitude": record.longitude,
        "screenshot_path": record.screenshot_path,
        "video_path": record.video_path,
        "officer_notes": record.officer_notes,
        "detection_history": record.detection_history,
        "created_at": record.created_at.isoformat(),
    }


def search_incidents(session: Session, query: IncidentQuery, limit: int = 50) -> list[IncidentRecord]:
    stmt = select(IncidentRecord).order_by(IncidentRecord.created_at.desc()).limit(limit)
    if query.face:
        stmt = stmt.where(IncidentRecord.person_name.ilike(f"%{query.face}%"))
    if query.plate:
        stmt = stmt.where(IncidentRecord.plate_number.ilike(f"%{query.plate}%"))
    if query.threat_level:
        stmt = stmt.where(IncidentRecord.threat_level == query.threat_level.upper())
    if query.object_type:
        stmt = stmt.where(IncidentRecord.object_type == query.object_type.lower())
    if query.date:
        stmt = stmt.where(IncidentRecord.created_at >= datetime.fromisoformat(query.date))
    return list(session.scalars(stmt))


def seed_reference_data() -> None:
    with session_scope() as session:
        if session.scalar(select(PersonnelProfile).limit(1)) is None:
            session.add_all(
                [
                    PersonnelProfile(
                        full_name="Captain Omar Al-Hadithi",
                        profile_code="DG-AUTH-001",
                        status="AUTHORIZED",
                        notes="Perimeter Defense commander",
                        face_signature="captain-omar",
                    ),
                    PersonnelProfile(
                        full_name="Faris Kareem",
                        profile_code="DG-BLK-911",
                        status="BLACKLISTED",
                        notes="Known hostile surveillance actor",
                        face_signature="faris-kareem",
                    ),
                ]
            )

        if session.scalar(select(VehicleProfile).limit(1)) is None:
            session.add_all(
                [
                    VehicleProfile(
                        plate_number="22K25901",
                        display_plate="22 K 25901",
                        owner_name="Rapid Logistics",
                        status="BLACKLISTED",
                        notes="High-risk watchlist vehicle",
                    ),
                    VehicleProfile(
                        plate_number="10B4421",
                        display_plate="10 B 4421",
                        owner_name="Security Intelligence Center Fleet",
                        status="AUTHORIZED",
                        notes="Authorized command vehicle",
                    ),
                ]
            )
