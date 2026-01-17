from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class InvestigationPlanRequest(BaseModel):
    alert_id: str
    alert_type: str
    severity: str
    classification: Optional[str]
    metadata: Dict[str, Any]


class InvestigationStep(BaseModel):
    title: str
    description: str
    priority: str


class InvestigationPlanResponse(BaseModel):
    alert_id: str
    steps: List[InvestigationStep]
