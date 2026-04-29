from typing import Any, Dict, List, Optional

from app.db.repositories.suppression_repository import SuppressionRepository
from app.services.ml_promotion_service import MLPromotionService


class MLSuppressionService:
    def __init__(self) -> None:
        self._repo = SuppressionRepository()

    async def mark_false_positive(
        self,
        log_doc: Dict[str, Any],
        created_by: str,
        notes: Optional[str] = None,
    ) -> str:
        fingerprint = MLPromotionService.fingerprint_for_log(log_doc)
        if not fingerprint:
            raise ValueError("Cannot build fingerprint for this alert/log")
        await self._repo.upsert_suppression(
            fingerprint=fingerprint,
            reason="false_positive",
            created_by=created_by,
            notes=notes,
        )
        return fingerprint

    async def resolve_suppression(self, log_doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        fingerprint = MLPromotionService.fingerprint_for_log(log_doc)
        if not fingerprint:
            return None
        found = await self._repo.find_active(fingerprint)
        if not found:
            return None
        return {"fingerprint": fingerprint, "reason": found.get("reason") or "false_positive"}

    async def list_suppressions(self, limit: int = 200) -> List[Dict[str, Any]]:
        return await self._repo.list_suppressions(limit=limit)

    async def deactivate(self, fingerprint: str) -> None:
        ok = await self._repo.set_active(fingerprint, False)
        if not ok:
            raise ValueError("Suppression fingerprint not found")

    async def activate(self, fingerprint: str) -> None:
        ok = await self._repo.set_active(fingerprint, True)
        if not ok:
            raise ValueError("Suppression fingerprint not found")

