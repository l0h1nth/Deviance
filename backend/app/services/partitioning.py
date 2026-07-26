"""Stable entity-keyed partition contract for ordered stream processing."""

from hashlib import blake2b


def partition_key(entity_id: str) -> str:
    if not entity_id:
        raise ValueError("entity_id is required for stream partitioning")
    return entity_id


def partition_for_entity(entity_id: str, partition_count: int) -> int:
    if partition_count < 1:
        raise ValueError("partition_count must be positive")
    digest = blake2b(partition_key(entity_id).encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big") % partition_count


def partition_contract(partition_count: int) -> dict:
    return {
        "key": "entity_id",
        "partition_count": partition_count,
        "local_algorithm": "blake2b-64 modulo partition_count",
        "ordering": "strict within an entity partition; parallel across partitions",
        "production": "send entity_id as the Kafka/Redpanda message key and use the broker partitioner",
    }
