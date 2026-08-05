from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class HeartbeatRequest(BaseModel):
    cpu_usage_pct: float
    memory_usage_pct: float
    disk_usage_pct: Optional[float] = None
    active_monitors: int
    agent_version: str
    timestamp: datetime
