import json

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database.session import SessionLocal
from app.schemas.events import AccessEvent, EventBatch
from app.schemas.predictions import PredictionResponse
from app.services.event_service import event_bus
from app.services.prediction_service import PredictionService

router = APIRouter(prefix="/events", tags=["events"])


def score_event(event: AccessEvent, db: Session) -> dict:
    try: return PredictionService(db).process(event)
    except FileNotFoundError as exc: raise HTTPException(503, str(exc)) from exc
    except ValueError as exc: raise HTTPException(409, str(exc)) from exc


def score_event_in_session(event: AccessEvent) -> dict:
    with SessionLocal() as db:
        return score_event(event, db)


@router.post("/ingest", response_model=PredictionResponse)
async def ingest(event: AccessEvent):
    result = await run_in_threadpool(score_event_in_session, event)
    await event_bus.publish({"type": "scored_event", "data": result}); return result


@router.post("/batch", response_model=list[PredictionResponse])
async def batch(payload: EventBatch):
    if len(payload.events) > get_settings().max_batch_size: raise HTTPException(413, "batch is too large")
    results = []
    for event in payload.events:
        result = await run_in_threadpool(score_event_in_session, event)
        results.append(result); await event_bus.publish({"type": "scored_event", "data": result})
    return results


@router.get("/stream")
async def stream():
    async def messages():
        yield "event: connected\ndata: {}\n\n"
        async for message in event_bus.subscribe(): yield f"data: {json.dumps(message)}\n\n"
    return StreamingResponse(messages(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})
