#!/usr/bin/env python3
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(BACKEND))
from app.config import get_settings
from app.ml.evaluation import load_metrics

if __name__ == "__main__": print(json.dumps(load_metrics(get_settings().model_dir), indent=2))

