from fastapi import APIRouter

from app.config import get_settings
from app.services.partitioning import partition_contract

router = APIRouter(prefix="/system", tags=["system design"])


@router.get("/design")
def design():
    settings = get_settings()
    return {
        "partitioning": partition_contract(settings.stream_partition_count),
        "runtime_state": {
            "sequence_history": "durable prediction rows keyed by entity_id and timestamp",
            "concept_drift": "durable drift_windows reference/current rows",
            "behavior_profiles": "durable entity/device/peer/global profile rows",
            "model_bundle": "read-only worker-local cache; contains no entity state",
        },
        "demo_backends": {"stream": "direct HTTP plus process-local SSE", "state": "SQLite WAL", "analytics": "SQLite"},
        "production_substitutions": {
            "stream": "Kafka or Redpanda keyed by entity_id",
            "hot_state": "Redis Cluster or online feature store",
            "transactional_store": "partitioned PostgreSQL",
            "analytics": "ClickHouse and object storage",
            "notifications": "durable pub/sub plus WebSocket gateway",
        },
    }
