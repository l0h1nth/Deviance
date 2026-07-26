import json
from datetime import datetime, timedelta, timezone

import numpy as np

from app.ml.training import featurize_splits, train, validation_partitions
from app.synthetic.attack_generator import ATTACK_TYPES, generate_attacks
from app.synthetic.normal_generator import build_users, generate_normal


def test_training_pipeline(tmp_path):
    rng=np.random.default_rng(7);entities=build_users(36,rng)
    groups={"train":entities[:18],"validation":entities[18:24],"test":entities[24:30],"audit":entities[30:]}
    starts={"train":datetime.now(timezone.utc)-timedelta(days=520),
            "validation":datetime.now(timezone.utc)-timedelta(days=390),
            "test":datetime.now(timezone.utc)-timedelta(days=260),
            "audit":datetime.now(timezone.utc)-timedelta(days=130)}
    splits={}
    for name,group in groups.items():
        normal=generate_normal(group,30,rng,start=starts[name])
        splits[name]=sorted(normal+generate_attacks(group,normal,3,rng,.03),key=lambda row:row.event.timestamp)
    processed=tmp_path/"processed";models=tmp_path/"models";processed.mkdir();models.mkdir()
    for name,rows in splits.items():
        (processed/f"{name}.jsonl").write_text("".join(json.dumps(row.event.model_dump(mode="json"))+"\n" for row in rows))
        (processed/f"{name}_labels.jsonl").write_text("".join(json.dumps(row.sidecar().model_dump(mode="json"))+"\n" for row in rows))
    bundle=train(tmp_path,models,seed=7)
    assert (models/"current.joblib").exists() and bundle.feature_schema_version=="3.0.0"
    assert bundle.metrics["test"]["sample_count"]==len(splits["test"])
    assert bundle.metrics["audit"]["sample_count"]==len(splits["audit"])
    x_train,y_train,_,_,_,_,_,_=featurize_splits(splits)["train"];normal_mask=y_train=="normal"
    np.testing.assert_allclose(bundle.scaler.center_,np.median(x_train[normal_mask],axis=0))
    population=bundle.metrics["training_population"]
    assert population["normal_rows"]==int(normal_mask.sum())
    assert population["preprocessor_fit"]=="normal_only"
    assert population["sequence_detector_fit"]=="normal_32_feature_sequences_only"
    assert population["entity_behavior_detector_fit"]=="normal_30_day_sequences_only"
    assert population["classifier_cold_start_attack_augmentation_rows"] > 0
    assert "0.10% normal-event FPR" in bundle.metrics["threshold_selection"]["selection_method"]
    assert bundle.attack_classifier.model_kind in {"random_forest", "xgboost"}
    assert bundle.anomaly_detector.model_metadata()["type"] == "DomainIsolationForestEnsemble"
    assert bundle.sequence_detector.source_input_size == 32
    assert bundle.sequence_detector.input_size == len(bundle.sequence_detector.feature_indices)
    assert bundle.sequence_detector.window_size == 12
    assert bundle.entity_behavior_detector.source_input_size == 42
    assert bundle.entity_behavior_detector.window_size == 30
    assert len(bundle.enriched_feature_names) == 42
    comparison = bundle.metrics["event_sequence_comparison"]
    assert set(comparison) >= {"active_32_feature_gru", "rejected_42_feature_gru"}
    assert comparison["selected"] == "active_32_feature_gru"
    assert "entity_behavior" in bundle.metrics
    test_metrics = bundle.metrics["test"]
    assert 0 <= test_metrics["classifier_accuracy"] <= 1
    assert "open_set_macro_f1" not in test_metrics
    assert "insider_drift_false_positive_rate" in test_metrics
    cold_start = test_metrics["cold_start_evaluation"]
    assert cold_start["maturity_threshold"] == 12
    assert set(cold_start["by_history_bucket"]) == {"0", "1-2", "3-11", "12+"}
    assert cold_start["overall"]["sample_count"] > 0
    assert 0 <= cold_start["overall"]["benign_false_positive_rate"] <= 1
    challenge = cold_start["attack_challenge"]
    assert challenge["event_count"] > 0 and challenge["scenario_count"] > 0
    assert set(challenge["by_attack_class"]) == set(ATTACK_TYPES)
    assert all(result["scenario_support"] > 0 for result in challenge["by_attack_class"].values())
    assert set(bundle.attack_classifier.classes_) == {"normal", *ATTACK_TYPES}


def test_insider_drift_is_a_benign_hard_negative():
    rng = np.random.default_rng(19)
    rows = generate_normal(build_users(24, rng), 180, rng)
    drift = [row for row in rows if row.scenario_id.startswith("insider_drift-")]
    assert drift and all(row.label == "normal" for row in drift)


def test_validation_purposes_are_scenario_disjoint():
    labels = np.asarray(["normal"] * 12 + ["brute_force"] * 6 + ["device_spoofing"] * 6)
    scenarios = np.asarray(
        [f"normal-{index}" for index in range(12)]
        + [f"brute-{index // 2}" for index in range(6)]
        + [f"spoof-{index // 2}" for index in range(6)]
    )
    partitions = validation_partitions(labels, scenarios, seed=11)
    assert sorted(np.concatenate(partitions).tolist()) == list(range(len(labels)))
    for left, right in ((0, 1), (0, 2), (1, 2)):
        assert set(scenarios[partitions[left]]).isdisjoint(scenarios[partitions[right]])
