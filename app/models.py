from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class SecurityFindingModel:
    """
    Internal finding model used by all scanners.

    We normalize every scanner result into this structure before creating
    SecurityFinding and SecurityRemediation CRs.
    """
    name: str
    severity: str
    category: str
    namespace: str
    resource_kind: str
    resource_name: str
    issue: str
    recommendation: str
    reason: List[str] = field(default_factory=list)
    remediation_type: str = "documentation"
    remediation_patch: Optional[Dict] = None
    remediation_command: Optional[str] = None


@dataclass
class NamespaceReportModel:
    """
    Summary model for one namespace.

    This becomes NamespaceSecurityReport.status.
    """
    namespace: str
    score: int
    posture: str
    total_findings: int
    findings_by_severity: Dict[str, int]
    top_recommendations: List[str]
    drift: Dict