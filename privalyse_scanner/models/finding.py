"""Data models for scan findings and classifications"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class Severity(str, Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ClassificationResult:
    """Structured result for PII classification"""
    pii_types: List[str]
    sectors: List[str]
    severity: str
    article: Optional[str]
    legal_basis_required: bool
    category: str
    confidence: float
    reasoning: str = ""
    gdpr_articles: List[str] = field(default_factory=list)  # NEW: Support multiple GDPR articles
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "pii_types": self.pii_types,
            "sectors": self.sectors,
            "severity": self.severity,
            "article": self.article,
            "gdpr_articles": self.gdpr_articles,
            "legal_basis_required": self.legal_basis_required,
            "category": self.category,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
        }


@dataclass
class Finding:
    """Represents a single scan finding"""
    rule: str
    severity: Severity
    file: str
    line: int
    snippet: str
    classification: ClassificationResult
    
    # Optional metadata
    data_flow_type: Optional[str] = None
    tainted_variables: List[str] = field(default_factory=list)
    taint_sources: List[str] = field(default_factory=list)
    url: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {
            "rule": self.rule,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "classification": self.classification.to_dict() if hasattr(self.classification, 'to_dict') else self.classification,
        }
        
        # Add optional fields if present
        if self.data_flow_type:
            result["data_flow_type"] = self.data_flow_type
        if self.tainted_variables:
            result["tainted_variables"] = self.tainted_variables
        if self.taint_sources:
            result["taint_sources"] = self.taint_sources
        if self.url:
            result["url"] = self.url
        if self.metadata:
            result["metadata"] = self.metadata
        
        return result
