from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from math import atan2, cos, exp, pi, sin
from statistics import mean, pstdev

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import DriftEventRecord, DriftWindowRecord


REFERENCE_SIZE = 20
CURRENT_SIZE = 20
EFFECT_THRESHOLD = 2.5
KS_THRESHOLD = 0.55

# Minimum meaningful changes prevent tiny movements in near-constant features
# from looking huge after division by a very small standard deviation.
MONITORED_SIGNALS = {
    "access_hour": {"label": "Access time", "domain": "identity", "floor": 1.5},
    "location_novelty_score": {"label": "Location novelty", "domain": "identity", "floor": .15},
    "new_device_score": {"label": "Device novelty", "domain": "device", "floor": .15},
    "download_volume_zscore": {"label": "Download volume", "domain": "access", "floor": .75},
    "resource_novelty_score": {"label": "Resource novelty", "domain": "access", "floor": .15},
    "privilege_expansion_score": {"label": "Privilege expansion", "domain": "access", "floor": .15},
    "sequence_anomaly_score": {"label": "Sequence residual", "domain": "sequence", "floor": .12},
    "anomaly_score": {"label": "Point anomaly score", "domain": "model", "floor": .12},
}

RECOMMENDATIONS = {
    "access_hour": "Validate the entity's new shift or working-hours assignment",
    "location_novelty_score": "Confirm travel, office reassignment, or approved remote-work location",
    "new_device_score": "Verify device enrollment and fingerprint ownership",
    "download_volume_zscore": "Review data-transfer purpose and expected workload change",
    "resource_novelty_score": "Validate role changes and newly authorized resources",
    "privilege_expansion_score": "Check approved privilege and responsibility changes",
    "sequence_anomaly_score": "Review the changed action sequence before adapting the sequence baseline",
    "anomaly_score": "Inspect the combined behavioral change before adapting the point baseline",
}


def _ks_distance(left: list[float], right: list[float]) -> float:
    """Two-sample empirical KS distance without adding a SciPy dependency."""
    values = sorted(set(left + right))
    if not values:
        return 0.0
    return max(abs(sum(item <= value for item in left) / len(left)
                   - sum(item <= value for item in right) / len(right)) for value in values)


def _circular_hour_mean(values: list[float]) -> float:
    angles = [value / 24 * 2 * pi for value in values]
    angle = atan2(mean([sin(value) for value in angles]), mean([cos(value) for value in angles]))
    return (angle % (2 * pi)) / (2 * pi) * 24


def _hour_distance(left: float, right: float) -> float:
    distance = abs(left - right) % 24
    return min(distance, 24 - distance)


def _feature_mean(feature: str, values: list[float]) -> float:
    return _circular_hour_mean(values) if feature == "access_hour" else mean(values)


def _feature_std(feature: str, values: list[float]) -> float:
    if feature == "access_hour":
        center = _circular_hour_mean(values)
        return (mean([_hour_distance(value, center) ** 2 for value in values])) ** .5
    return pstdev(values)


def _distribution(feature: str, values: list[float]) -> dict[str, float | int]:
    ordered = sorted(values)
    return {
        "mean": _feature_mean(feature, values), "std": _feature_std(feature, values), "count": len(values),
        "minimum": ordered[0], "maximum": ordered[-1],
        "p50": ordered[len(ordered) // 2], "p90": ordered[min(len(ordered) - 1, int(len(ordered) * .9))],
    }


class DriftService:
    """Persistent, trusted-only two-window concept-drift lifecycle.

    Detection freezes the affected signal until an analyst approves or rejects
    adaptation. Stable windows roll forward automatically; detected windows do not.
    """

    # Compatibility/debug mirror. Persistence and API reads use DriftWindowRecord.
    _windows: dict[str, deque] = defaultdict(lambda: deque(maxlen=REFERENCE_SIZE + CURRENT_SIZE))

    def __init__(self, db: Session):
        self.db = db

    @staticmethod
    def _key(subject_id: str, feature: str) -> str:
        return f"{subject_id}:{feature}"

    def _window(self, subject_id: str, feature: str) -> DriftWindowRecord:
        key = self._key(subject_id, feature)
        record = self.db.scalar(select(DriftWindowRecord).where(DriftWindowRecord.window_key == key))
        if record is None:
            record = DriftWindowRecord(window_key=key, subject_id=subject_id, feature=feature,
                                       reference_values=[], current_values=[])
            self.db.add(record)
            self.db.flush()
        return record

    def window_status(self) -> list[dict]:
        rows = list(self.db.scalars(select(DriftWindowRecord).order_by(DriftWindowRecord.subject_id,
                                                                       DriftWindowRecord.feature)))
        grouped: dict[str, list[DriftWindowRecord]] = defaultdict(list)
        for row in rows:
            grouped[row.subject_id].append(row)
        result = []
        for subject, signals in grouped.items():
            reference_count = min((len(row.reference_values or []) for row in signals), default=0)
            current_count = min((len(row.current_values or []) for row in signals), default=0)
            flagged = [row.feature for row in signals if row.status == "pending_review"]
            if flagged:
                status = "review_required"
            elif reference_count < REFERENCE_SIZE:
                status = "collecting_reference"
            elif current_count < CURRENT_SIZE:
                status = "collecting_current"
            else:
                status = "monitoring"
            result.append({
                "entity": subject,
                "reference_window": {"count": reference_count, "target": REFERENCE_SIZE},
                "current_window": {"count": current_count, "target": CURRENT_SIZE},
                "status": status, "trusted_events_only": True,
                "flagged_features": flagged,
                "baseline_version": max((row.baseline_version for row in signals), default=1),
                "last_observed_at": max((row.last_observed_at for row in signals), default=None),
            })
        return result

    def summary(self) -> dict:
        rows = list(self.db.scalars(select(DriftWindowRecord)))
        events = list(self.db.scalars(select(DriftEventRecord)))
        subjects = {row.subject_id for row in rows}
        trusted_by_subject: dict[str, int] = defaultdict(int)
        for row in rows:
            trusted_by_subject[row.subject_id] = max(trusted_by_subject[row.subject_id], row.trusted_observations)
        pending = sum(event.metadata_json.get("review_status", "pending") in {"pending", "investigating"}
                      for event in events)
        approved = sum(event.metadata_json.get("review_status") == "approved_adaptation" for event in events)
        rejected = sum(event.metadata_json.get("review_status") == "rejected_change" for event in events)
        collecting = sum(window["status"].startswith("collecting") for window in self.window_status())
        return {
            "state": "action_required" if pending else "learning" if collecting else "stable",
            "pending_reviews": pending, "approved_adaptations": approved, "rejected_changes": rejected,
            "monitored_entities": len(subjects), "trusted_events": sum(trusted_by_subject.values()),
            "signals_monitored": len(MONITORED_SIGNALS),
            "reference_size": REFERENCE_SIZE, "current_size": CURRENT_SIZE,
            "policy": "trusted_low_risk_only", "automatic_retraining": False,
        }

    def observe(self, subject_id: str, values: dict[str, float]) -> list[DriftEventRecord]:
        detected: list[DriftEventRecord] = []
        for feature, contract in MONITORED_SIGNALS.items():
            record = self._window(subject_id, feature)
            if record.status == "pending_review":
                continue
            value = float(values.get(feature, 0.0))
            reference = list(record.reference_values or [])
            current = list(record.current_values or [])
            record.trusted_observations += 1
            record.last_observed_at = datetime.now(timezone.utc)

            if len(reference) < REFERENCE_SIZE:
                reference.append(value)
                record.reference_values = reference
                record.status = "collecting_reference" if len(reference) < REFERENCE_SIZE else "collecting_current"
            else:
                current.append(value)
                record.current_values = current[-CURRENT_SIZE:]
                record.status = "collecting_current"

            mirror = self._windows[self._key(subject_id, feature)]
            mirror.clear(); mirror.extend([*record.reference_values, *record.current_values])
            if len(record.current_values) < CURRENT_SIZE:
                continue

            old, new = list(record.reference_values), list(record.current_values)
            old_mean, new_mean = _feature_mean(feature, old), _feature_mean(feature, new)
            absolute_shift = (_hour_distance(old_mean, new_mean) if feature == "access_hour"
                              else abs(new_mean - old_mean))
            pooled_scale = max((_feature_std(feature, old) + _feature_std(feature, new)) / 2,
                               float(contract["floor"]) / EFFECT_THRESHOLD)
            effect_size = absolute_shift / pooled_scale
            ks_distance = _ks_distance(old, new)
            significant = (absolute_shift >= contract["floor"] and effect_size >= EFFECT_THRESHOLD
                           and ks_distance >= KS_THRESHOLD)
            if not significant:
                # Trusted, statistically stable behavior becomes the next reference batch.
                record.reference_values = new
                record.current_values = []
                record.status = "collecting_current"
                record.baseline_version += 1
                continue

            confidence = min(.999, .5 + .28 * (1 - exp(-effect_size / 3)) + .2 * ks_distance)
            severity = "critical" if effect_size >= 6 else "high" if effect_size >= 4 else "medium"
            metadata = {
                "previous_distribution": _distribution(feature, old),
                "current_distribution": _distribution(feature, new),
                "absolute_shift": absolute_shift, "effect_size": effect_size, "ks_distance": ks_distance,
                "drift_confidence": confidence, "severity": severity, "review_status": "pending",
                "detector": "durable_two_window_effect_ks", "trusted_events_only": True,
                "window_key": record.window_key, "baseline_version": record.baseline_version,
                "domain": contract["domain"], "signal_label": contract["label"], "review_history": [],
            }
            event = DriftEventRecord(subject_id=subject_id, feature=feature, magnitude=effect_size,
                                     recommendation=RECOMMENDATIONS[feature], metadata_json=metadata)
            self.db.add(event)
            record.status = "pending_review"
            detected.append(event)
        return detected

    def review(self, event: DriftEventRecord, action: str, analyst: str, comment: str = "") -> DriftEventRecord:
        metadata = dict(event.metadata_json or {})
        current_status = metadata.get("review_status", "pending")
        if current_status in {"approved_adaptation", "rejected_change", "dismissed"}:
            raise ValueError("This drift finding already has a final disposition")
        window_key = metadata.get("window_key", self._key(event.subject_id, event.feature))
        window = self.db.scalar(select(DriftWindowRecord).where(DriftWindowRecord.window_key == window_key))
        if window is None:
            raise ValueError("The drift window is no longer available")

        if action == "investigate":
            review_status = "investigating"
        elif action == "approve_adaptation":
            window.reference_values = list(window.current_values or [])
            window.current_values = []
            window.status = "collecting_current"
            window.baseline_version += 1
            window.adapted_at = datetime.now(timezone.utc)
            review_status = "approved_adaptation"
        elif action in {"reject_change", "dismiss"}:
            # Preserve the previous known-good reference and discard the challenged batch.
            window.current_values = []
            window.status = "collecting_current"
            review_status = "rejected_change" if action == "reject_change" else "dismissed"
        else:
            raise ValueError(f"Unsupported drift review action: {action}")

        history = list(metadata.get("review_history", []))
        history.append({"action": action, "analyst": analyst, "comment": comment,
                        "created_at": datetime.now(timezone.utc).isoformat()})
        metadata.update(review_status=review_status, reviewed_by=analyst, review_comment=comment,
                        reviewed_at=datetime.now(timezone.utc).isoformat(), review_history=history,
                        resulting_baseline_version=window.baseline_version)
        event.metadata_json = metadata
        return event
