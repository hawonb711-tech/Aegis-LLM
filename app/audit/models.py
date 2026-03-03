"""
Pydantic models for audit events returned by the API.
The `ts` field is stored/returned as an ISO-8601 string to avoid timezone
ambiguity in SQLite.
"""
from typing import List
from pydantic import BaseModel


class AuditEvent(BaseModel):
    id: str
    ts: str           # ISO-8601 UTC timestamp, e.g. "2024-06-01T12:00:00.000000"
    endpoint: str
    request_json: str
    response_json: str
    decision: str
    reason_codes: List[str]
    risk_score: int
