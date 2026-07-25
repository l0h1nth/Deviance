import os
import sys
from pathlib import Path
from uuid import uuid4

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("RANDOM_SEED", "42")
# API workflow tests must never write into the runtime/demo database. A unique
# database under the ignored pytest cache also prevents state leaking between runs.
TEST_DATABASE = BACKEND.parent / ".pytest_cache" / f"deviance-tests-{uuid4().hex}.db"
TEST_DATABASE.parent.mkdir(parents=True, exist_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DATABASE}"
