from math import asin, cos, radians, sin, sqrt


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres."""
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return 6371.0088 * 2 * asin(sqrt(max(0.0, min(1.0, a))))


def required_speed_kmph(lat1: float, lon1: float, lat2: float, lon2: float, hours: float) -> float:
    if hours <= 0:
        return 20_000.0
    return min(20_000.0, haversine_km(lat1, lon1, lat2, lon2) / hours)

