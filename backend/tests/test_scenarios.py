import json

import numpy as np
import pytest

from app.synthetic.attack_generator import GENERATORS, credential_stuffing, generate_attacks
from app.synthetic.normal_generator import build_users, generate_normal, normal_event
from app.synthetic.simulation import build_simulation_events


@pytest.mark.parametrize("label",list(GENERATORS))
def test_every_attack_is_multi_event_and_multifield(label):
    rng=np.random.default_rng(42);user=build_users(1,rng)[0];base=normal_event(user,__import__('datetime').datetime.now(__import__('datetime').timezone.utc)-__import__('datetime').timedelta(days=1),1,rng)
    events=GENERATORS[label](user,base,1,rng)
    assert len(events)>=2 and all(row.label==label for row in events)
    changed=set()
    for row in events:
        for field in type(row.event).model_fields:
            if getattr(row.event,field)!=getattr(base,field):changed.add(field)
    assert len(changed)>=5


def test_credential_stuffing_spans_multiple_entities():
    rng=np.random.default_rng(8);users=build_users(8,rng)
    bases=[normal_event(user,__import__('datetime').datetime.now(__import__('datetime').timezone.utc)-__import__('datetime').timedelta(days=1),index,rng) for index,user in enumerate(users)]
    rows=credential_stuffing(users,bases,3,rng)
    assert len({row.event.entity_id for row in rows})>1 and all(row.label=="credential_stuffing" for row in rows)


def test_benign_and_attack_cold_start_simulations_use_fresh_subjects(tmp_path):
    rng = np.random.default_rng(21); entities = build_users(12, rng)
    normal = generate_normal(entities, 24, rng)
    rows = sorted(normal + generate_attacks(entities, normal, 1, rng, .03), key=lambda row: row.event.timestamp)
    stream = tmp_path / "demo_stream.jsonl"; labels = tmp_path / "demo_stream_labels.jsonl"
    stream.write_text("".join(json.dumps(row.event.model_dump(mode="json")) + "\n" for row in rows))
    labels.write_text("".join(json.dumps(row.sidecar().model_dump(mode="json")) + "\n" for row in rows))

    benign = build_simulation_events(stream, "cold_start_benign", 5, 500)
    compromised = build_simulation_events(stream, "cold_start_attack", 30, 500)
    assert {row.entity_id for row in benign} == {"usr-cold-start"}
    assert all(row.entity_id.startswith("cold-") and row.user_id == row.entity_id for row in compromised)
    assert all(row.device_id.startswith("cold-") and row.claimed_device_id.startswith("cold-") for row in compromised)
