import json

import numpy as np

from app.ml.training import featurize_splits, train
from app.synthetic.attack_generator import generate_attacks
from app.synthetic.normal_generator import build_users, generate_normal


def test_training_pipeline(tmp_path):
    rng=np.random.default_rng(7);users=build_users(15,rng);normal=generate_normal(users,18,rng)
    attacks=generate_attacks(users,normal,4,rng);rows=sorted(normal+attacks,key=lambda e:e.timestamp)
    first,second=int(len(rows)*.65),int(len(rows)*.82)
    splits={"train":rows[:first],"validation":rows[first:second],"test":rows[second:]}
    processed=tmp_path/"processed";models=tmp_path/"models";processed.mkdir();models.mkdir()
    for name,events in splits.items():
        (processed/f"{name}.jsonl").write_text("".join(json.dumps(e.model_dump(mode="json"))+"\n" for e in events))
    bundle=train(tmp_path,models,seed=7)
    assert (models/"current.joblib").exists() and bundle.feature_schema_version=="1.0.0"
    assert bundle.metrics["test"]["sample_count"]==len(splits["test"])
    x_train,y_train=featurize_splits(splits)["train"]
    normal_mask=y_train=="normal"
    np.testing.assert_allclose(bundle.scaler.center_,np.median(x_train[normal_mask],axis=0))
    assert bundle.metrics["training_population"]=={
        "total_rows":len(y_train),"normal_rows":int(normal_mask.sum()),"attack_rows":int((~normal_mask).sum()),
        "preprocessor_fit":"normal_only","anomaly_detector_fit":"normal_only",
        "classifier_fit":"normal_and_attack",
    }
