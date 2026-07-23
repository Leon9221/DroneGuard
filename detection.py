from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass
class RestrictedZone:
    name: str
    zone_type: str
    x1: float
    y1: float
    x2: float
    y2: float
    restricted_objects: list[str]
    priority: str

    def contains(self, x: float, y: float) -> bool:
        return self.x1 <= x <= self.x2 and self.y1 <= y <= self.y2


@dataclass
class DetectionCandidate:
    object_type: str
    label: str
    confidence: float
    sector: str
    center_x: float
    center_y: float
    width: float
    height: float
    identity_hint: str = ""
    plate_text_hint: str = ""
    local_alert_level: str = "GREEN"


@dataclass
class DetectionAssessment:
    candidate: DetectionCandidate
    zone_name: str
    restricted_trigger: bool
    recommended_priority: str
    night_mode_boost: bool


class TacticalDetectionSystem:
    def __init__(self, restricted_zones: Iterable[RestrictedZone], night_mode_enabled: bool = False) -> None:
        self.restricted_zones = list(restricted_zones)
        self.night_mode_enabled = night_mode_enabled

    def set_night_mode(self, enabled: bool) -> None:
        self.night_mode_enabled = enabled

    def assess(self, candidate: DetectionCandidate) -> DetectionAssessment:
        matched_zone = ""
        restricted_trigger = False
        priority = "GREEN"

        for zone in self.restricted_zones:
            if zone.contains(candidate.center_x, candidate.center_y):
                matched_zone = zone.name
                if candidate.object_type in zone.restricted_objects:
                    restricted_trigger = True
                    priority = zone.priority
                break

        if candidate.object_type == "drone" and candidate.confidence >= 0.78:
            priority = "RED" if priority == "GREEN" else priority
        if candidate.object_type == "human" and candidate.confidence >= 0.82 and priority == "GREEN":
            priority = "YELLOW"
        if candidate.object_type == "vehicle" and candidate.confidence >= 0.86 and priority == "GREEN":
            priority = "YELLOW"

        return DetectionAssessment(
            candidate=candidate,
            zone_name=matched_zone,
            restricted_trigger=restricted_trigger,
            recommended_priority=priority,
            night_mode_boost=self.night_mode_enabled,
        )
