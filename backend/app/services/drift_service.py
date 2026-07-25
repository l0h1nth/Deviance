from collections import defaultdict, deque
from statistics import mean, pstdev

from sqlalchemy.orm import Session

from app.database.models import DriftEventRecord


class DriftService:
    """Small rolling two-window detector suitable for the local demo."""
    _windows: dict[str, deque] = defaultdict(lambda: deque(maxlen=40))

    def __init__(self, db: Session): self.db = db

    @classmethod
    def window_status(cls) -> list[dict]:
        subjects: dict[str, list[int]] = defaultdict(list)
        for key, window in cls._windows.items():
            subject, _ = key.rsplit(":", 1)
            subjects[subject].append(len(window))
        result = []
        for subject, lengths in subjects.items():
            count = min(lengths) if lengths else 0
            result.append({
                "entity": subject,
                "reference_window": {"count": min(count, 20), "target": 20},
                "current_window": {"count": max(0, count - 20), "target": 20},
                "status": "collecting_reference" if count < 20 else "collecting_current" if count < 40 else "monitoring",
                "trusted_events_only": True,
            })
        return sorted(result, key=lambda item: item["entity"])

    def observe(self, subject_id: str, values: dict[str, float]) -> list[DriftEventRecord]:
        detected = []
        monitored = ["access_hour", "location_novelty_score", "new_device_score",
                     "download_volume_zscore", "resource_novelty_score", "privilege_expansion_score",
                     "sequence_anomaly_score", "anomaly_score"]
        for feature in monitored:
            key = f"{subject_id}:{feature}"; window = self._windows[key]; window.append(float(values.get(feature, 0.0)))
            if len(window) < 40: continue
            old, new = list(window)[:20], list(window)[20:]
            magnitude = abs(mean(new) - mean(old)) / max(pstdev(old), .5)
            if magnitude >= 2.5:
                record = DriftEventRecord(subject_id=subject_id, feature=feature, magnitude=magnitude,
                    recommendation="Review trusted recent events before controlled retraining",
                    metadata_json={"previous_distribution": {"mean": mean(old), "std": pstdev(old), "count": len(old)},
                                   "current_distribution": {"mean": mean(new), "std": pstdev(new), "count": len(new)},
                                   "drift_confidence": min(.999, .5 + magnitude / 10),
                                   "review_status": "pending", "detector": "rolling_two_window",
                                   "trusted_events_only": True})
                self.db.add(record); detected.append(record); window.clear()
        return detected
