from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
from enum import Enum

class ScanLevel(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    AGGRESSIVE = "aggressive"

class AuthType(str, Enum):
    NONE = "none"
    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"

class ScanOptions(BaseModel):
    scan_level: ScanLevel = ScanLevel.ACTIVE
    auth_type: AuthType = AuthType.NONE
    auth_token: Optional[str] = None
    api_key: Optional[str] = None
    custom_headers: Optional[Dict[str, str]] = {}
    timeout: int = 10
    max_endpoints: int = 50
    check_owasp_mobile: bool = True
    check_owasp_api: bool = True
    check_ssl: bool = True
    check_auth: bool = True
    check_injection: bool = True
    check_broken_auth: bool = True

class ScanRequest(BaseModel):
    target_url: str
    options: ScanOptions = ScanOptions()
    description: Optional[str] = None

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class ScanResult(BaseModel):
    scan_id: str
    target_url: str
    status: ScanStatus
    vulnerabilities: List[Dict[str, Any]] = []
    endpoints_tested: int = 0
    risk_score: float = 0.0
    summary: Dict[str, Any] = {}
