"""
Graders for the SOC Alert Triage Environment.

Each grader scores agent performance on a task from 0.0 to 1.0.
Graders are deterministic given the same triage history and alert data.
"""

from typing import Any, Dict, List


def _field_accuracy(history: List[Dict[str, Any]], alerts: List[Dict[str, Any]], field: str) -> float:
    """Compute accuracy for a single field across all triaged alerts."""
    if not history:
        return 0.0
    alert_map = {a["alert_id"]: a for a in alerts}
    correct = 0
    total = 0
    for entry in history:
        alert = alert_map.get(entry["alert_id"])
        if alert and "ground_truth" in alert:
            total += 1
            if entry.get(field) == alert["ground_truth"].get(field):
                correct += 1
    return correct / total if total > 0 else 0.0


def _severity_closeness(history: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> float:
    """Score severity with partial credit for adjacent levels."""
    if not history:
        return 0.0
    severity_order = ["low", "medium", "high", "critical"]
    alert_map = {a["alert_id"]: a for a in alerts}
    score_sum = 0.0
    total = 0
    for entry in history:
        alert = alert_map.get(entry["alert_id"])
        if alert and "ground_truth" in alert:
            total += 1
            gt_sev = alert["ground_truth"]["severity"]
            act_sev = entry.get("severity", "")
            if gt_sev == act_sev:
                score_sum += 1.0
            elif gt_sev in severity_order and act_sev in severity_order:
                diff = abs(severity_order.index(gt_sev) - severity_order.index(act_sev))
                if diff == 1:
                    score_sum += 0.5
    return score_sum / total if total > 0 else 0.0


def grade_easy(triage_history: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> float:
    """
    Grade Task 1: Single Alert Classification.

    Weights: classification 30%, severity 20%, category 20%, team 15%, action 15%
    Returns: 0.0 - 1.0
    """
    if not triage_history:
        return 0.0

    classification_acc = _field_accuracy(triage_history, alerts, "classification")
    severity_score = _severity_closeness(triage_history, alerts)
    category_acc = _field_accuracy(triage_history, alerts, "category")
    team_acc = _field_accuracy(triage_history, alerts, "assigned_team")
    action_acc = _field_accuracy(triage_history, alerts, "recommended_action")

    score = (
        0.30 * classification_acc
        + 0.20 * severity_score
        + 0.20 * category_acc
        + 0.15 * team_acc
        + 0.15 * action_acc
    )
    return round(min(max(score, 0.0), 1.0), 4)


def grade_medium(triage_history: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> float:
    """
    Grade Task 2: Queue Triage.

    Same field-level grading as easy, plus:
    - Coverage bonus: percentage of alerts triaged
    - Priority bonus: critical true positives triaged early get extra credit

    Returns: 0.0 - 1.0
    """
    if not triage_history:
        return 0.0

    total_alerts = len(alerts)

    # Field-level accuracy (60% of score)
    classification_acc = _field_accuracy(triage_history, alerts, "classification")
    severity_score = _severity_closeness(triage_history, alerts)
    category_acc = _field_accuracy(triage_history, alerts, "category")
    team_acc = _field_accuracy(triage_history, alerts, "assigned_team")
    action_acc = _field_accuracy(triage_history, alerts, "recommended_action")

    field_score = (
        0.30 * classification_acc
        + 0.20 * severity_score
        + 0.20 * category_acc
        + 0.15 * team_acc
        + 0.15 * action_acc
    )

    # Coverage (20% of score)
    coverage = len(triage_history) / total_alerts if total_alerts > 0 else 0.0

    # Priority ordering (20% of score): reward for triaging critical alerts first
    alert_map = {a["alert_id"]: a for a in alerts}
    critical_tp_ids = {
        a["alert_id"]
        for a in alerts
        if a["ground_truth"]["classification"] == "true_positive"
        and a["ground_truth"]["severity"] in ("critical", "high")
    }

    if critical_tp_ids:
        # Check how many critical/high TPs were triaged in the first half of actions
        first_half = triage_history[: max(len(triage_history) // 2, 1)]
        critical_early = sum(1 for e in first_half if e["alert_id"] in critical_tp_ids)
        priority_score = critical_early / len(critical_tp_ids)
    else:
        priority_score = 1.0  # No critical alerts to prioritize

    score = 0.60 * field_score + 0.20 * coverage + 0.20 * priority_score
    return round(min(max(score, 0.0), 1.0), 4)


def grade_hard(triage_history: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> float:
    """
    Grade Task 3: Campaign Detection.

    Same as medium grading, plus:
    - Campaign identification: correctly grouping the 5 campaign alerts
    - Kill chain ordering: correct attack_chain_position for campaign alerts

    Returns: 0.0 - 1.0
    """
    if not triage_history:
        return 0.0

    total_alerts = len(alerts)
    alert_map = {a["alert_id"]: a for a in alerts}

    # Field-level accuracy (40% of score)
    classification_acc = _field_accuracy(triage_history, alerts, "classification")
    severity_score = _severity_closeness(triage_history, alerts)
    category_acc = _field_accuracy(triage_history, alerts, "category")
    team_acc = _field_accuracy(triage_history, alerts, "assigned_team")
    action_acc = _field_accuracy(triage_history, alerts, "recommended_action")

    field_score = (
        0.30 * classification_acc
        + 0.20 * severity_score
        + 0.20 * category_acc
        + 0.15 * team_acc
        + 0.15 * action_acc
    )

    # Coverage (15% of score)
    coverage = len(triage_history) / total_alerts if total_alerts > 0 else 0.0

    # Campaign identification (25% of score)
    campaign_alerts = [a for a in alerts if a.get("is_campaign")]
    campaign_ids_in_history: Dict[str, List[str]] = {}  # campaign_id → list of alert_ids

    for entry in triage_history:
        cid = entry.get("campaign_id")
        if cid is not None:
            campaign_ids_in_history.setdefault(cid, []).append(entry["alert_id"])

    # Score: what fraction of actual campaign alerts did the agent correctly group?
    actual_campaign_alert_ids = {a["alert_id"] for a in campaign_alerts}
    best_campaign_score = 0.0

    for cid, grouped_ids in campaign_ids_in_history.items():
        grouped_set = set(grouped_ids)
        # True positives: correctly grouped campaign alerts
        tp = len(grouped_set & actual_campaign_alert_ids)
        # False positives: non-campaign alerts incorrectly grouped
        fp = len(grouped_set - actual_campaign_alert_ids)
        # Precision and recall
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / len(actual_campaign_alert_ids) if actual_campaign_alert_ids else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        best_campaign_score = max(best_campaign_score, f1)

    # Kill chain ordering (20% of score)
    chain_score = 0.0
    if campaign_alerts:
        correct_positions = 0
        total_campaign_triaged = 0
        for entry in triage_history:
            alert = alert_map.get(entry["alert_id"])
            if alert and alert.get("is_campaign"):
                total_campaign_triaged += 1
                if entry.get("attack_chain_position") == alert.get("chain_position"):
                    correct_positions += 1
        chain_score = correct_positions / len(campaign_alerts) if campaign_alerts else 0.0

    score = (
        0.40 * field_score
        + 0.15 * coverage
        + 0.25 * best_campaign_score
        + 0.20 * chain_score
    )
    return round(min(max(score, 0.0), 1.0), 4)


# Map task IDs to grader functions
GRADERS = {
    "easy_single_alert": grade_easy,
    "medium_queue_triage": grade_medium,
    "hard_campaign_detection": grade_hard,
}
