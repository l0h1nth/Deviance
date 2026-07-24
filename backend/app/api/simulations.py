from fastapi import APIRouter, HTTPException

from app.schemas.simulations import SimulationStart
from app.services.simulation_service import simulation_manager

router = APIRouter(prefix="/simulations", tags=["simulations"])


@router.post("/start", status_code=202)
async def start_simulation(payload: SimulationStart):
    try:
        return await simulation_manager.start(payload.scenario, payload.interval_ms, payload.event_count)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/status")
def simulation_status():
    return simulation_manager.status()


@router.post("/stop")
async def stop_simulation():
    return await simulation_manager.stop()
