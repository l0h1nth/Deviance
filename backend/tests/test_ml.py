from pathlib import Path

import numpy as np

from app.ml.anomaly_model import IsolationForestDetector
from app.ml.attack_classifier import AttackClassifier
from app.ml.feature_pipeline import FeaturePipeline
from app.ml.model_bundle import ModelBundle
from app.ml.preprocessing import build_scaler
from app.services.risk_service import RiskService
from helpers import event


def make_bundle():
    rng=np.random.default_rng(42);x=rng.normal(size=(100,12));y=np.array(["normal"]*70+["brute_force"]*15+["device_spoofing"]*15)
    scaler=build_scaler().fit(x);scaled=scaler.transform(x)
    anomaly=IsolationForestDetector(.05,42).fit(scaled[:70]);classifier=AttackClassifier(42).fit(scaled,y)
    return ModelBundle("test","1.0.0",FeaturePipeline.names,scaler,anomaly,classifier,50,{})


def test_model_save_load_and_inference(tmp_path:Path):
    bundle=make_bundle();path=tmp_path/"model.joblib";bundle.save(path);loaded=ModelBundle.load(path,tmp_path)
    loaded.validate(FeaturePipeline.names);result=loaded.infer(np.zeros(12));assert 0<=result["anomaly_score"]<=1


def test_risk_bounds():
    inference={"anomaly_score":5,"classifier_confidence":1,"class_probabilities":{"normal":0,"brute_force":1}}
    result=RiskService().score(inference,np.full(12,100),event(resource_sensitivity=1,is_privileged_action=True),.1)
    assert result["risk_score"]==100

