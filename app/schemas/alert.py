from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel


class AlertResponse(BaseModel):
    id: str
    created_at: datetime
    log_id: str
    alert_type: str
    severity: str
    classification: Optional[str] = None
    anomaly_score: Optional[float] = None
    model_version: str
    metadata: Dict[str, Any]
