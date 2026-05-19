from enum import Enum
from pydantic import BaseModel
from typing import Optional


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Finding(BaseModel):
    scanner: str
    severity: Severity
    message: str
    file: Optional[str] = None
    line: Optional[int] = None
    rule_id: Optional[str] = None
    recommendation: Optional[str] = None
