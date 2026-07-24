import numpy as np
import pytest

from app.synthetic.attack_generator import GENERATORS
from app.synthetic.normal_generator import build_users, normal_event


@pytest.mark.parametrize("label",list(GENERATORS))
def test_every_attack_is_multi_event_and_multifield(label):
    rng=np.random.default_rng(42);user=build_users(1,rng)[0];base=normal_event(user,__import__('datetime').datetime.now(__import__('datetime').timezone.utc)-__import__('datetime').timedelta(days=1),1,rng)
    events=GENERATORS[label](user,base,1)
    assert len(events)>=2 and all(e.ground_truth_label==label for e in events)
    changed=set()
    for attack in events:
        for field in type(attack).model_fields:
            if getattr(attack,field)!=getattr(base,field):changed.add(field)
    assert len(changed)>=5
