from __future__ import annotations

from dataclasses import dataclass
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from database import VehicleProfile


IRAQI_ARABIC_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")
IRAQI_PLATE_REGEX = re.compile(r"(\d{2,3})([A-Z]{1,2})(\d{3,5})")


def normalize_iraqi_plate(raw_text: str | None) -> str:
    if not raw_text:
        return ""
    translated = raw_text.translate(IRAQI_ARABIC_DIGITS).upper()
    cleaned = re.sub(r"[^A-Z0-9]", "", translated)
    match = IRAQI_PLATE_REGEX.search(cleaned)
    return match.group(0) if match else cleaned


def format_iraqi_plate(normalized: str) -> str:
    match = IRAQI_PLATE_REGEX.fullmatch(normalized)
    if not match:
        return normalized
    return f"{match.group(1)} {match.group(2)} {match.group(3)}"


@dataclass
class PlateRecognitionResult:
    normalized_plate: str
    display_plate: str
    classification: str
    confidence: float
    owner_name: str
    notes: str


class IraqiPlateRecognitionEngine:
    def classify(self, session: Session, plate_text_hint: str | None) -> PlateRecognitionResult:
        normalized = normalize_iraqi_plate(plate_text_hint)
        if not normalized:
            return PlateRecognitionResult("", "", "UNKNOWN", 0.18, "", "No plate text submitted")

        record = session.scalar(select(VehicleProfile).where(VehicleProfile.plate_number == normalized))
        if record is None:
            return PlateRecognitionResult(normalized, format_iraqi_plate(normalized), "UNKNOWN", 0.41, "", "Plate not enrolled")
        return PlateRecognitionResult(
            normalized_plate=record.plate_number,
            display_plate=record.display_plate,
            classification=record.status.upper(),
            confidence=0.93,
            owner_name=record.owner_name,
            notes=record.notes,
        )
