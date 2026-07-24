import numpy as np
import pytest

from app.synthetic.attack_generator import GENERATORS, credential_stuffing
from app.synthetic.normal_generator import build_users, normal_event


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
