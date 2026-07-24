#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(BACKEND))
from app.config import get_settings
from app.ml.training import train

if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--contamination", type=float, default=.03); args = parser.parse_args()
    settings = get_settings(); bundle = train(settings.data_dir, settings.model_dir, args.contamination, settings.random_seed)
    print(json.dumps({"version": bundle.version, "schema": bundle.feature_schema_version, "metrics": bundle.metrics}, indent=2))

