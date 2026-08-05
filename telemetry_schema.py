from pydantic import BaseModel, UUID4, Field, field_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum

class ThreatClassification(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    RANSOMWARE = "RANSOMWARE"

class ThreatLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ResponseStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    
class RecommendedAction(str, Enum):
    MONITOR = "MONITOR"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    ISOLATE_NETWORK = "ISOLATE_NETWORK"

class IncidentStatus(str, Enum):
    NEW = "NEW"
    DETECTED = "DETECTED"
    ANALYZING = "ANALYZING"
    CONFIRMED = "CONFIRMED"
    RESPONDING = "RESPONDING"
    QUARANTINED = "QUARANTINED"
    RECOVERING = "RECOVERING"
    RECOVERED = "RECOVERED"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"

class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IncidentSchema(BaseModel):
    id: UUID4
    status: IncidentStatus
    severity: Optional[IncidentSeverity] = None
    description: Optional[str] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None

class PredictionSchema(BaseModel):
    id: UUID4
    incident_id: Optional[UUID4] = None
    model_id: UUID4
    feature_version: str
    threat_classification: ThreatClassification
    confidence: float = Field(..., ge=0.0, le=1.0)
    processing_time_ms: float
    created_at: datetime

class DecisionSchema(BaseModel):
    id: UUID4
    prediction_id: UUID4
    incident_id: Optional[UUID4] = None
    threat_level: ThreatLevel
    risk_score: float = Field(..., ge=0.0, le=100.0)
    recommended_action: RecommendedAction
    reason_codes: str
    created_at: datetime

class ResponseSchema(BaseModel):
    id: UUID4
    decision_id: UUID4
    incident_id: Optional[UUID4] = None
    executed_action: str
    status: ResponseStatus
    details: Optional[str] = None
    error_message: Optional[str] = None
    duration_ms: float
    created_at: datetime

class RecoverySchema(BaseModel):
    id: UUID4
    response_id: UUID4
    incident_id: Optional[UUID4] = None
    original_path: str
    quarantine_path: str
    sha256: str
    status: ResponseStatus
    details: Optional[str] = None
    duration_ms: float
    created_at: datetime

class TelemetrySyncRequest(BaseModel):
    # Incidents are the correlation root and are synced first so dependent
    # records never violate their foreign keys.
    incidents: List[IncidentSchema] = []
    predictions: List[PredictionSchema] = []
    decisions: List[DecisionSchema] = []
    responses: List[ResponseSchema] = []
    recoveries: List[RecoverySchema] = []

    @field_validator('incidents', 'predictions', 'decisions', 'responses', 'recoveries', mode="before")
    @classmethod
    def validate_batch_size(cls, v):
        if len(v) > 500:
            raise ValueError("Batch size exceeds 500 records")
        return v
