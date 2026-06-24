from typing import List
from app.models import SecurityFindingModel


SEVERITY_POINTS = {
    "critical": 20,
    "high": 12,
    "medium": 6,
    "low": 2,
    "info": 0,
}


def calculate_namespace_score(findings: List[SecurityFindingModel]) -> int:
    """
    Start from 100 and subtract points for findings.

    The score is intentionally simple and explainable for interview/demo.
    """
    risk = sum(SEVERITY_POINTS.get(f.severity, 1) for f in findings)
    return max(0, 100 - risk)


def classify_posture(score: int) -> str:
    if score >= 85:
        return "Healthy"
    if score >= 65:
        return "Moderate"
    if score >= 40:
        return "Risky"
    return "Critical"


def count_by_severity(findings: List[SecurityFindingModel]) -> dict:
    result = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        result[finding.severity] = result.get(finding.severity, 0) + 1

    return result