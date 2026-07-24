from datetime import datetime, timedelta


def within_window(timestamp: datetime, reference: datetime, minutes: int) -> bool:
    delta = reference - timestamp
    return timedelta(0) <= delta <= timedelta(minutes=minutes)


def circular_hour_distance(hour: float, expected_hour: float) -> float:
    raw = abs(hour - expected_hour) % 24
    return min(raw, 24 - raw)

