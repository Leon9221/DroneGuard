from __future__ import annotations

import os
from dataclasses import dataclass
import threading

import cv2
import numpy as np
from ultralytics import YOLO


@dataclass
class YoloDetection:
    label: str
    confidence: float
    left: float
    top: float
    right: float
    bottom: float


class YoloInferenceService:
    def __init__(self) -> None:
        self.model_name = os.getenv("DRONEGUARD_YOLO_MODEL", "yolo11n.pt")
        self.conf_threshold = float(os.getenv("DRONEGUARD_YOLO_CONF", "0.35"))
        self.max_side = int(os.getenv("DRONEGUARD_YOLO_MAX_SIDE", "640"))
        self._model: YOLO | None = None
        self._inference_lock = threading.Lock()

    def _ensure_model(self) -> YOLO:
        if self._model is None:
            self._model = YOLO(self.model_name)
        return self._model

    def infer(self, image_bytes: bytes) -> list[YoloDetection]:
        if not image_bytes:
            return []

        array = np.frombuffer(image_bytes, dtype=np.uint8)
        frame = cv2.imdecode(array, cv2.IMREAD_COLOR)
        if frame is None:
            return []

        height, width = frame.shape[:2]
        if width <= 0 or height <= 0:
            return []

        # Bound input size to keep CPU/GPU and RAM usage predictable.
        max_side = max(160, self.max_side)
        longest_side = max(width, height)
        if longest_side > max_side:
            scale = max_side / float(longest_side)
            frame = cv2.resize(
                frame,
                (int(width * scale), int(height * scale)),
                interpolation=cv2.INTER_AREA,
            )
            height, width = frame.shape[:2]

        model = self._ensure_model()
        # Drop overlapping requests while an inference is already running.
        if not self._inference_lock.acquire(blocking=False):
            return []
        try:
            results = model.predict(source=frame, conf=self.conf_threshold, verbose=False)
        finally:
            self._inference_lock.release()
        if not results:
            return []

        result = results[0]
        boxes = result.boxes
        if boxes is None:
            return []

        detections: list[YoloDetection] = []
        class_names = result.names
        for box in boxes:
            coords = box.xyxy[0].tolist()
            confidence = float(box.conf[0].item())
            class_idx = int(box.cls[0].item())
            label = str(class_names.get(class_idx, "unknown")).lower()

            left = max(0.0, min(1.0, coords[0] / width))
            top = max(0.0, min(1.0, coords[1] / height))
            right = max(0.0, min(1.0, coords[2] / width))
            bottom = max(0.0, min(1.0, coords[3] / height))

            detections.append(
                YoloDetection(
                    label=label,
                    confidence=confidence,
                    left=left,
                    top=top,
                    right=right,
                    bottom=bottom,
                )
            )
        return detections
