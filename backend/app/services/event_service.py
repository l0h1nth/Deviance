import asyncio
from collections import defaultdict


class EventBus:
    def __init__(self): self.subscribers: set[asyncio.Queue] = set()

    async def publish(self, message: dict) -> None:
        for queue in tuple(self.subscribers):
            try: queue.put_nowait(message)
            except asyncio.QueueFull: pass

    async def subscribe(self):
        queue = asyncio.Queue(maxsize=100); self.subscribers.add(queue)
        try:
            while True: yield await queue.get()
        finally: self.subscribers.discard(queue)


event_bus = EventBus()

