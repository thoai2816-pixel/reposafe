from enum import Enum
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}


class Finding(BaseModel):
    scanner: str
    severity: Severity
    message: str
    file: Optional[str] = None
    line: Optional[int] = None
    rule_id: Optional[str] = None
    recommendation: Optional[str] = None
    category: Optional[str] = None
    evidence: Optional[str] = None
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def sort_key(self):
        return (
            -SEVERITY_ORDER.get(self.severity, 0),
            self.scanner,
            self.file or "",
            self.line or 0,
            self.rule_id or "",
        )

    def as_dict(self) -> Dict[str, Any]:
        if hasattr(self, "model_dump"):
            return self.model_dump()
        return self.dict()


class ScanProfile(BaseModel):
    scanned_files: int = 0
    skipped_files: int = 0
    scanned_bytes: int = 0
    duration_seconds: float = 0.0
