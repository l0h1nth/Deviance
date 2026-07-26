from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime
from math import exp

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


@dataclass
class DailyBehaviorBatch:
    vectors: np.ndarray
    labels: np.ndarray
    entities: np.ndarray
    days: np.ndarray
    event_counts: np.ndarray


def aggregate_daily(enriched: np.ndarray, labels: np.ndarray, entities: np.ndarray,
                    timestamps: np.ndarray) -> DailyBehaviorBatch:
    """Create one fixed-width p95 behavior vector per entity/calendar day."""
    groups: dict[tuple[str, date], list[int]] = defaultdict(list)
    for index, (entity, timestamp) in enumerate(zip(entities, timestamps)):
        day = timestamp.date() if isinstance(timestamp, datetime) else date.fromisoformat(str(timestamp)[:10])
        groups[(str(entity), day)].append(index)
    vectors, daily_labels, daily_entities, days, counts = [], [], [], [], []
    for (entity, day), indices in sorted(groups.items(), key=lambda item: (item[0][1], item[0][0])):
        rows = np.asarray(enriched[indices], dtype=float)
        labels_for_day = [str(labels[index]) for index in indices]
        attacks = [label for label in labels_for_day if label != "normal"]
        vectors.append(np.quantile(rows, .95, axis=0))
        daily_labels.append(attacks[0] if attacks else "normal")
        daily_entities.append(entity); days.append(day.isoformat()); counts.append(len(indices))
    return DailyBehaviorBatch(np.asarray(vectors), np.asarray(daily_labels), np.asarray(daily_entities),
                              np.asarray(days), np.asarray(counts, dtype=int))


def tune_daily_threshold(scores: np.ndarray, labels: np.ndarray, max_normal_fpr: float = .01) -> tuple[float, dict]:
    normal, attacks = labels == "normal", labels != "normal"
    candidates = []
    for threshold in np.unique(scores):
        flagged = scores >= threshold
        fp = int(np.sum(normal & flagged)); tn = int(np.sum(normal & ~flagged))
        tp = int(np.sum(attacks & flagged)); fn = int(np.sum(attacks & ~flagged))
        fpr = fp / max(fp + tn, 1)
        if fpr <= max_normal_fpr:
            candidates.append((tp / max(tp + fn, 1), tp / max(tp + fp, 1), -fpr, float(threshold)))
    threshold = max(candidates)[-1] if candidates else 1.0
    flagged = scores >= threshold
    tp, fp = int(np.sum(attacks & flagged)), int(np.sum(normal & flagged))
    fn, tn = int(np.sum(attacks & ~flagged)), int(np.sum(normal & ~flagged))
    return threshold, {"threshold": threshold, "precision": tp / max(tp + fp, 1),
                       "recall": tp / max(tp + fn, 1), "false_positive_rate": fp / max(fp + tn, 1)}


def identity_rankings(scores: np.ndarray, labels: np.ndarray, entities: np.ndarray, days: np.ndarray,
                      threshold: float) -> list[dict]:
    grouped: dict[str, list[int]] = defaultdict(list)
    for index, entity in enumerate(entities): grouped[str(entity)].append(index)
    latest_day = max((date.fromisoformat(str(day)) for day in days), default=date.today())
    result = []
    for entity, indices in grouped.items():
        ordered = sorted(indices, key=lambda index: str(days[index]))[-30:]
        values = np.asarray([scores[index] for index in ordered], dtype=float)
        flagged = values >= threshold
        maximum = float(np.max(values)) if len(values) else 0.0
        drift_days = int(np.sum(flagged))
        top_three = float(np.mean(np.sort(values)[-min(3, len(values)):])) if len(values) else 0.0
        consecutive = 0
        for value in values[::-1]:
            if value < threshold: break
            consecutive += 1
        flagged_indices = [index for index in ordered if scores[index] >= threshold]
        last_drift = date.fromisoformat(str(days[flagged_indices[-1]])) if flagged_indices else None
        recency = exp(-(latest_day - last_drift).days / 7) if last_drift else 0.0
        persistence = min(drift_days / 7, 1.0)
        rank_score = 100 * (.60 * maximum + .25 * persistence + .10 * top_three + .05 * recency)
        result.append({"entity_id": entity, "rank_score": float(rank_score), "maximum_drift_30d": maximum,
                       "drift_days_30d": drift_days, "consecutive_drift_days": consecutive,
                       "mean_top_3_drift": top_three, "last_drift_date": last_drift.isoformat() if last_drift else None,
                       "latest_score": float(values[-1]) if len(values) else 0.0,
                       "has_attack": bool(np.any(labels[ordered] != "normal"))})
    result.sort(key=lambda item: (-item["rank_score"], -item["maximum_drift_30d"], -item["drift_days_30d"]))
    for rank, item in enumerate(result, start=1): item["rank"] = rank
    return result


def daily_evaluation(scores: np.ndarray, batch: DailyBehaviorBatch, threshold: float) -> dict:
    binary = batch.labels != "normal"; flagged = scores >= threshold; normal = ~binary
    tp, fp = int(np.sum(binary & flagged)), int(np.sum(normal & flagged))
    fn, tn = int(np.sum(binary & ~flagged)), int(np.sum(normal & ~flagged))
    try:
        pr_auc = float(average_precision_score(binary, scores)); roc_auc = float(roc_auc_score(binary, scores))
    except ValueError:
        pr_auc = roc_auc = 0.0
    rankings = identity_rankings(scores, batch.labels, batch.entities, batch.days, threshold)
    attacked = {str(entity) for entity in batch.entities[binary]}
    top_count = max(1, int(np.ceil(len(rankings) * .01))); top = rankings[:top_count]
    return {"daily_count": len(scores), "attack_day_prevalence": float(np.mean(binary)),
            "pr_auc": pr_auc, "roc_auc": roc_auc, "threshold": threshold,
            "precision": tp / max(tp + fp, 1), "recall": tp / max(tp + fn, 1),
            "false_positive_rate": fp / max(fp + tn, 1),
            "ranked_entity_count": len(rankings), "attacked_entity_count": len(attacked),
            "top_1_percent_precision": sum(item["entity_id"] in attacked for item in top) / len(top),
            "rankings": rankings}
