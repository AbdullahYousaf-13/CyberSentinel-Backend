from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class LogCreate(BaseModel):
    timestamp: datetime
    source: str = Field(..., description="Log source identifier")
    message: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    severity: Optional[str] = None


class LogResponse(BaseModel):
    id: str
    timestamp: datetime
    source: str
    message: str
    metadata: Dict[str, Any]
    severity: Optional[str] = None
