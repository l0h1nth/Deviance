from collections import defaultdict, deque
from statistics import mean, pstdev

from sqlalchemy.orm import Session

from app.database.models import DriftEventRecord


class DriftService:
    """Small rolling two-window detector suitable for the local demo."""
    _windows: dict[str, deque] = defaultdict(lambda: deque(maxlen=40))

    def __init__(self, db: Session): self.db = db

    def observe(self, subject_id: str, values: dict[str, float]) -> list[DriftEventRecord]:
        detected = []
        monitored = ["login_hour_deviation", "location_novelty_score", "new_device_score",
                     "download_volume_zscore", "session_duration_zscore", "anomaly_score"]
        for feature in monitored:
            key = f"{subject_id}:{feature}"; window = self._windows[key]; window.append(float(values[feature]))
            if len(window) < 40: continue
            old, new = list(window)[:20], list(window)[20:]
            magnitude = abs(mean(new) - mean(old)) / max(pstdev(old), .5)
            if magnitude >= 2.5:
                record = DriftEventRecord(subject_id=subject_id, feature=feature, magnitude=magnitude,
                    recommendation="Review trusted recent events before controlled retraining",
                    metadata_json={"old_mean": mean(old), "new_mean": mean(new), "detector": "rolling_two_window"})
                self.db.add(record); detected.append(record); window.clear()
        return detected
