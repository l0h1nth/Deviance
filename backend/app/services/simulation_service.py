import asyncio
from datetime import datetime, timezone

from app.config import get_settings
from fastapi.concurrency import run_in_threadpool
from app.database.session import SessionLocal
from app.services.event_service import event_bus
from app.services.prediction_service import PredictionService
from app.synthetic.simulation import build_simulation_run


class SimulationManager:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._state = self._idle_state()

    @staticmethod
    def _idle_state() -> dict:
        return {
            "status": "idle", "scenario": None, "interval_ms": None, "event_count": 0,
            "processed_events": 0, "ground_truth_attack_events": 0, "ground_truth_normal_events": 0,
            "detected_attack_events": 0, "missed_attack_events": 0,
            "correct_attack_classifications": 0, "misclassified_attack_events": 0,
            "false_positive_events": 0, "new_incident_count": 0, "alert_count": 0,
            "started_at": None, "stopped_at": None, "telemetry_start": None, "telemetry_end": None,
            "last_event_id": None, "last_error": None,
        }

    def status(self) -> dict:
        return dict(self._state)

    async def start(self, scenario: str, interval_ms: int, event_count: int) -> dict:
        if self._task and not self._task.done():
            raise RuntimeError("A simulation is already running")
        settings = get_settings()
        events = build_simulation_run(settings.data_dir / "processed" / "demo_stream.jsonl",
                                      scenario, event_count, interval_ms)
        attack_count = sum(row.label != "normal" for row in events)
        self._stop = asyncio.Event()
        self._state = {
            "status": "running", "scenario": scenario, "interval_ms": interval_ms,
            "event_count": len(events), "processed_events": 0, "alert_count": 0,
            "ground_truth_attack_events": attack_count,
            "ground_truth_normal_events": len(events) - attack_count,
            "detected_attack_events": 0, "missed_attack_events": 0,
            "correct_attack_classifications": 0, "misclassified_attack_events": 0,
            "false_positive_events": 0, "new_incident_count": 0,
            "started_at": datetime.now(timezone.utc).isoformat(), "stopped_at": None,
            "telemetry_start": events[0].event.timestamp.isoformat(),
            "telemetry_end": events[-1].event.timestamp.isoformat(),
            "last_event_id": None, "last_error": None,
        }
        self._task = asyncio.create_task(self._run(events))
        await event_bus.publish({"type": "simulation_status", "data": self.status()})
        return self.status()

    async def stop(self) -> dict:
        if not self._task or self._task.done():
            return self.status()
        self._state["status"] = "stopping"
        self._stop.set()
        await event_bus.publish({"type": "simulation_status", "data": self.status()})
        try:
            await asyncio.wait_for(self._task, timeout=5)
        except asyncio.TimeoutError:
            self._task.cancel()
        return self.status()

    async def _run(self, events) -> None:
        try:
            for index, row in enumerate(events):
                if self._stop.is_set():
                    self._state.update(status="stopped", stopped_at=datetime.now(timezone.utc).isoformat())
                    break
                result = await run_in_threadpool(
                    self._process_event, row.event, self._state["scenario"] == "concept_drift"
                )
                is_attack = row.label != "normal"
                detected = result.get("alert_id") is not None
                correctly_classified = result.get("predicted_attack") == row.label
                self._state["processed_events"] += 1
                self._state["detected_attack_events"] += int(is_attack and detected)
                self._state["missed_attack_events"] += int(is_attack and not detected)
                self._state["correct_attack_classifications"] += int(is_attack and correctly_classified)
                self._state["misclassified_attack_events"] += int(is_attack and not correctly_classified)
                self._state["false_positive_events"] += int(not is_attack and detected)
                new_incident = int(detected and result.get("incident_event_count") == 1)
                self._state["new_incident_count"] += new_incident
                self._state["alert_count"] = self._state["new_incident_count"]  # compatibility alias
                self._state["last_event_id"] = result["event_id"]
                await event_bus.publish({"type": "scored_event", "data": result})
                await event_bus.publish({"type": "simulation_status", "data": self.status()})
                if index + 1 < len(events):
                    try:
                        await asyncio.wait_for(self._stop.wait(), timeout=self._state["interval_ms"] / 1000)
                    except asyncio.TimeoutError:
                        pass
            else:
                self._state.update(status="completed", stopped_at=datetime.now(timezone.utc).isoformat())
        except Exception as exc:
            self._state.update(status="failed", last_error=str(exc), stopped_at=datetime.now(timezone.utc).isoformat())
        await event_bus.publish({"type": "simulation_status", "data": self.status()})

    @staticmethod
    def _process_event(event, trusted_override: bool):
        with SessionLocal() as db:
            return PredictionService(db).process(event, trusted_override=trusted_override)


simulation_manager = SimulationManager()
