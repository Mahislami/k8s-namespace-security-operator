from typing import List, Dict
from app.models import SecurityFindingModel


SEVERITY_PENALTIES = {
    "critical": 25,
    "high": 10,
    "medium": 3,
    "low": 1,
    "info": 0,
}


CATEGORY_CAPS = {
    "namespace-security": 15,
    "network-security": 25,
    "deployment-security": 20,
    "daemonset-security": 20,
    "statefulset-security": 20,
    "replicaset-security": 12,
    "job-security": 10,
    "cronjob-security": 10,
    "pod-security": 15,
    "service-account": 10,
    "image-security": 8,
    "secret-security": 12,
    "configmap-security": 8,
    "storage-security": 12,
    "rbac": 25,
    "attack-path": 30,
}


def calculate_namespace_score(findings: List[SecurityFindingModel]) -> int:
    penalties_by_category = {}
    has_critical = any(f.severity == "critical" for f in findings)

    for finding in findings:
        category = finding.category
        penalty = SEVERITY_PENALTIES.get(finding.severity, 0)
        penalties_by_category[category] = penalties_by_category.get(category, 0) + penalty

    total_penalty = 0

    for category, penalty in penalties_by_category.items():
        cap = CATEGORY_CAPS.get(category, 15)
        total_penalty += min(penalty, cap)

    score = 100 - total_penalty

    if has_critical:
        return max(score, 0)

    return max(score, 20)


def classify_posture(score: int) -> str:
    if score >= 85:
        return "Healthy"
    if score >= 70:
        return "Moderate"
    if score >= 40:
        return "Risky"
    return "Critical"


def count_by_severity(findings: List[SecurityFindingModel]) -> Dict[str, int]:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1

    return counts