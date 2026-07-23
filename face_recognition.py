from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from database import PersonnelProfile


@dataclass
class FaceRecognitionResult:
    classification: str
    person_name: str
    confidence: float
    notes: str


class PersonnelRecognitionEngine:
    def classify(self, session: Session, identity_hint: str | None) -> FaceRecognitionResult:
        hint = (identity_hint or "").strip()
        if not hint:
            return FaceRecognitionResult("UNKNOWN", "", 0.22, "No biometric match submitted")

        record = session.scalar(
            select(PersonnelProfile).where(
                (PersonnelProfile.full_name.ilike(f"%{hint}%"))
                | (PersonnelProfile.profile_code.ilike(f"%{hint}%"))
                | (PersonnelProfile.face_signature.ilike(f"%{hint}%"))
            )
        )
        if record is None:
            return FaceRecognitionResult("UNKNOWN", hint, 0.31, "No personnel profile match")
        if record.status.upper() == "BLACKLISTED":
            return FaceRecognitionResult("BLACKLISTED", record.full_name, 0.94, record.notes)
        return FaceRecognitionResult("AUTHORIZED", record.full_name, 0.92, record.notes)
