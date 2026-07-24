from dataclasses import dataclass


@dataclass(frozen=True)
class Office:
    country: str
    city: str
    latitude: float
    longitude: float


@dataclass
class SyntheticUser:
    user_id: str
    role: str
    department: str
    office: Office
    remote: bool
    shift_hour: int
    devices: list[dict]


OFFICES = [
    Office("India", "Bengaluru", 12.9716, 77.5946), Office("United States", "New York", 40.7128, -74.0060),
    Office("United Kingdom", "London", 51.5074, -0.1278), Office("Singapore", "Singapore", 1.3521, 103.8198),
    Office("Germany", "Berlin", 52.5200, 13.4050), Office("Australia", "Sydney", -33.8688, 151.2093),
]

