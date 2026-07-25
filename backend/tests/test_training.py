import json
from datetime import datetime, timedelta, timezone

import numpy as np

from app.ml.training import featurize_splits, train
from app.synthetic.attack_generator import generate_attacks
from app.synthetic.normal_generator import build_users, generate_normal


def test_training_pipeline(tmp_path):
    rng=np.random.default_rng(7);entities=build_users(30,rng)
    groups={"train":entities[:18],"validation":entities[18:24],"test":entities[24:]}
    starts={"train":datetime.now(timezone.utc)-timedelta(days=390),
            "validation":datetime.now(timezone.utc)-timedelta(days=260),
            "test":datetime.now(timezone.utc)-timedelta(days=130)}
    splits={}
    for name,group in groups.items():
        normal=generate_normal(group,30,rng,start=starts[name])
        splits[name]=sorted(normal+generate_attacks(group,normal,None,rng,.03),key=lambda row:row.event.timestamp)
    processed=tmp_path/"processed";models=tmp_path/"models";processed.mkdir();models.mkdir()
    for name,rows in splits.items():
        (processed/f"{name}.jsonl").write_text("".join(json.dumps(row.event.model_dump(mode="json"))+"\n" for row in rows))
        (processed/f"{name}_labels.jsonl").write_text("".join(json.dumps(row.sidecar().model_dump(mode="json"))+"\n" for row in rows))
    bundle=train(tmp_path,models,seed=7)
    assert (models/"current.joblib").exists() and bundle.feature_schema_version=="3.0.0"
    assert bundle.metrics["test"]["sample_count"]==len(splits["test"])
    x_train,y_train,_,_,_,_=featurize_splits(splits)["train"];normal_mask=y_train=="normal"
    np.testing.assert_allclose(bundle.scaler.center_,np.median(x_train[normal_mask],axis=0))
    population=bundle.metrics["training_population"]
    assert population["normal_rows"]==int(normal_mask.sum())
    assert population["preprocessor_fit"]=="normal_only"
    assert population["sequence_detector_fit"]=="normal_sequences_only"
    assert "0.10% normal-event FPR" in bundle.metrics["threshold_selection"]["selection_method"]
    assert bundle.attack_classifier.model_kind in {"random_forest", "xgboost"}
    assert bundle.anomaly_detector.model_metadata()["type"] == "DomainIsolationForestEnsemble"
