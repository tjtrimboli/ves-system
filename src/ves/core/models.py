"""Core data models for VES system"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(Enum):
    """CVSS Severity Levels"""
    NONE = "NONE"
    LOW = "LOW" 
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class VulnerabilityMetrics:
    """Container for all vulnerability metrics"""
    cve_id: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev_status: bool = False
    lev_score: Optional[float] = None
    ves_score: Optional[float] = None
    severity: Severity = Severity.NONE
    priority_level: int = 4
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    description: Optional[str] = None
