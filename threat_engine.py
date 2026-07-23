from __future__ import annotations

from dataclasses import dataclass
import time

from detection import DetectionAssessment
from face_recognition import FaceRecognitionResult
from plate_reader import PlateRecognitionResult


THREAT_GREEN = "GREEN"
THREAT_YELLOW = "YELLOW"
THREAT_RED = "RED"
THREAT_CRITICAL = "CRITICAL"


@dataclass
class ThreatDecision:
    level: str
    title: str
    details: str
    identity_result: str


@dataclass
class _StabilityState:
    level: str = THREAT_GREEN
    rise_streak: int = 0
    fall_streak: int = 0
    last_changed_at: float = 0.0
    last_seen_at: float = 0.0


class ThreatClassificationEngine:
    def __init__(self) -> None:
        self._rank = {
            THREAT_GREEN: 0,
            THREAT_YELLOW: 1,
            THREAT_RED: 2,
            THREAT_CRITICAL: 3,
        }
        self._states: dict[str, _StabilityState] = {}
        self.promote_frames = 2
        self.demote_frames = 4
        self.high_alert_hold_seconds = 4.0
        self.stale_state_seconds = 12.0

    def _apply_hysteresis(self, key: str | None, incoming_level: str) -> str:
        if not key:
            return incoming_level

        now = time.time()
        state = self._states.get(key)
        if state is None:
            state = _StabilityState(level=incoming_level, last_changed_at=now, last_seen_at=now)
            self._states[key] = state
            return incoming_level

        state.last_seen_at = now

        # Cleanup old keys opportunistically.
        stale_keys = [k for k, v in self._states.items() if now - v.last_seen_at > self.stale_state_seconds]
        for stale_key in stale_keys:
            self._states.pop(stale_key, None)

        current_rank = self._rank.get(state.level, 0)
        incoming_rank = self._rank.get(incoming_level, 0)

        if incoming_rank > current_rank:
            state.rise_streak += 1
            state.fall_streak = 0
            if state.rise_streak >= self.promote_frames:
                state.level = incoming_level
                state.last_changed_at = now
                state.rise_streak = 0
            return state.level

        if incoming_rank < current_rank:
            # Keep high alerts sticky for a short window to prevent frame-to-frame flicker.
            if current_rank >= self._rank[THREAT_RED] and (now - state.last_changed_at) < self.high_alert_hold_seconds:
                return state.level
            state.fall_streak += 1
            state.rise_streak = 0
            if state.fall_streak >= self.demote_frames:
                state.level = incoming_level
                state.last_changed_at = now
                state.fall_streak = 0
            return state.level

        state.rise_streak = 0
        state.fall_streak = 0
        return state.level

    def classify(
        self,
        assessment: DetectionAssessment,
        face_result: FaceRecognitionResult | None,
        plate_result: PlateRecognitionResult | None,
        stability_key: str | None = None,
    ) -> ThreatDecision:
        candidate = assessment.candidate

        if face_result and face_result.classification == "BLACKLISTED":
            decision = ThreatDecision(
                THREAT_CRITICAL,
                f"Blacklisted individual detected in {candidate.sector}",
                f"{face_result.person_name} matched a blacklist profile near {assessment.zone_name or candidate.sector}.",
                face_result.classification,
            )
            return decision if not stability_key else decision.__class__(
                level=self._apply_hysteresis(stability_key, decision.level),
                title=decision.title,
                details=decision.details,
                identity_result=decision.identity_result,
            )

        if plate_result and plate_result.classification == "BLACKLISTED":
            decision = ThreatDecision(
                THREAT_RED,
                f"Blacklisted vehicle detected in {candidate.sector}",
                f"Vehicle plate {plate_result.display_plate} matched a blacklist profile.",
                plate_result.classification,
            )
            return decision if not stability_key else decision.__class__(
                level=self._apply_hysteresis(stability_key, decision.level),
                title=decision.title,
                details=decision.details,
                identity_result=decision.identity_result,
            )

        if assessment.restricted_trigger:
            decision = ThreatDecision(
                THREAT_RED if assessment.recommended_priority != THREAT_CRITICAL else THREAT_CRITICAL,
                f"Restricted zone breach in {assessment.zone_name}",
                f"{candidate.object_type.title()} entered {assessment.zone_name}. Immediate perimeter response required.",
                face_result.classification if face_result else (plate_result.classification if plate_result else "UNKNOWN"),
            )
            return decision if not stability_key else decision.__class__(
                level=self._apply_hysteresis(stability_key, decision.level),
                title=decision.title,
                details=decision.details,
                identity_result=decision.identity_result,
            )

        if candidate.object_type == "drone":
            decision = ThreatDecision(
                THREAT_RED,
                f"Incoming drone detected in {candidate.sector}",
                "Aerial intrusion requires immediate verification and interception review.",
                "UNVERIFIED",
            )
            return decision if not stability_key else decision.__class__(
                level=self._apply_hysteresis(stability_key, decision.level),
                title=decision.title,
                details=decision.details,
                identity_result=decision.identity_result,
            )

        if face_result and face_result.classification == "AUTHORIZED":
            decision = ThreatDecision(
                THREAT_GREEN,
                f"Authorized personnel verified in {candidate.sector}",
                face_result.notes or "Personnel verification completed successfully.",
                face_result.classification,
            )
            return decision if not stability_key else decision.__class__(
                level=self._apply_hysteresis(stability_key, decision.level),
                title=decision.title,
                details=decision.details,
                identity_result=decision.identity_result,
            )

        if plate_result and plate_result.classification == "AUTHORIZED":
            decision = ThreatDecision(
                THREAT_GREEN,
                f"Authorized vehicle verified in {candidate.sector}",
                plate_result.notes or "Vehicle profile cleared by command registry.",
                plate_result.classification,
            )
            return decision if not stability_key else decision.__class__(
                level=self._apply_hysteresis(stability_key, decision.level),
                title=decision.title,
                details=decision.details,
                identity_result=decision.identity_result,
            )

        if face_result and face_result.classification == "UNKNOWN":
            decision = ThreatDecision(
                THREAT_YELLOW,
                f"Unknown person detected in {candidate.sector}",
                "No enrolled face profile match. Continue observation and escalate if zone breach occurs.",
                face_result.classification,
            )
            return decision if not stability_key else decision.__class__(
                level=self._apply_hysteresis(stability_key, decision.level),
                title=decision.title,
                details=decision.details,
                identity_result=decision.identity_result,
            )

        if plate_result and plate_result.classification in {"WATCHLIST", "UNKNOWN"}:
            level = THREAT_YELLOW if plate_result.classification == "WATCHLIST" else THREAT_YELLOW
            decision = ThreatDecision(
                level,
                f"Vehicle requires verification in {candidate.sector}",
                f"Plate read as {plate_result.display_plate or 'unresolved'} and requires officer review.",
                plate_result.classification,
            )
            return decision if not stability_key else decision.__class__(
                level=self._apply_hysteresis(stability_key, decision.level),
                title=decision.title,
                details=decision.details,
                identity_result=decision.identity_result,
            )

        decision = ThreatDecision(
            THREAT_YELLOW if assessment.recommended_priority != THREAT_GREEN else THREAT_GREEN,
            f"Suspicious {candidate.object_type} activity in {candidate.sector}",
            "Sensor confidence passed verification threshold. Continue tactical monitoring.",
            "UNKNOWN",
        )
        return decision if not stability_key else decision.__class__(
            level=self._apply_hysteresis(stability_key, decision.level),
            title=decision.title,
            details=decision.details,
            identity_result=decision.identity_result,
        )
