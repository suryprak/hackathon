# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
SOC Alert Triage Environment Implementation.

Simulates a Security Operations Center where an AI agent triages
incoming security alerts from a SIEM system.
"""

from typing import Any, Dict, List, Optional
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment

try:
    from ..alerts import generate_easy_scenario, generate_hard_scenario, generate_medium_scenario
    from ..models import (
        CATEGORIES,
        CLASSIFICATIONS,
        RESPONSE_ACTIONS,
        SEVERITIES,
        TEAMS,
        SocAlertAction,
        SocAlertObservation,
        SocAlertState,
    )
except ImportError:
    from alerts import generate_easy_scenario, generate_hard_scenario, generate_medium_scenario
    from models import (
        CATEGORIES,
        CLASSIFICATIONS,
        RESPONSE_ACTIONS,
        SEVERITIES,
        TEAMS,
        SocAlertAction,
        SocAlertObservation,
        SocAlertState,
    )


TASK_DEFINITIONS = {
    "easy_single_alert": {
        "description": (
            "Triage a single security alert. Classify it as true_positive, "
            "false_positive, benign, or suspicious. Assign the correct severity, "
            "threat category, responsible team, and recommended response action."
        ),
        "max_steps": 1,
        "generator": generate_easy_scenario,
    },
    "medium_queue_triage": {
        "description": (
            "Triage a queue of 10 security alerts. For each alert, classify it, "
            "assign severity, category, responsible team, and recommended action. "
            "Prioritize critical true positives first. You have 12 steps to triage "
            "as many alerts as possible."
        ),
        "max_steps": 12,
        "generator": generate_medium_scenario,
    },
    "hard_campaign_detection": {
        "description": (
            "Triage 15 security alerts. Among the noise, 5 alerts form a coordinated "
            "attack campaign (phishing → execution → credential theft → lateral movement "
            "→ data exfiltration). Triage each alert AND identify which alerts belong to "
            "the campaign by assigning them the same campaign_id and correct "
            "attack_chain_position (1-5). You have 20 steps."
        ),
        "max_steps": 20,
        "generator": generate_hard_scenario,
    },
}


class SocAlertEnvironment(Environment):
    """
    SOC Alert Triage Environment.

    An agent acts as a Tier 1 SOC analyst triaging security alerts from a SIEM.
    Supports 3 tasks with increasing difficulty.
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self):
        self._state = SocAlertState(episode_id=str(uuid4()), step_count=0)
        self._alerts: List[Dict[str, Any]] = []
        self._pending_alert_ids: List[str] = []
        self._triage_history: List[Dict[str, Any]] = []
        self._task_id: str = "easy_single_alert"
        self._seed: int = 42
        self._done: bool = False
        self._cumulative_reward: float = 0.0

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        task_id: Optional[str] = None,
        **kwargs: Any,
    ) -> SocAlertObservation:
        """Reset the environment, optionally selecting a task."""
        self._seed = seed if seed is not None else 42
        self._task_id = task_id if task_id and task_id in TASK_DEFINITIONS else "easy_single_alert"
        self._done = False
        self._triage_history = []
        self._cumulative_reward = 0.0

        task_def = TASK_DEFINITIONS[self._task_id]
        self._alerts = task_def["generator"](self._seed)
        self._pending_alert_ids = [a["alert_id"] for a in self._alerts]

        self._state = SocAlertState(
            episode_id=episode_id or str(uuid4()),
            step_count=0,
            task_id=self._task_id,
            alerts_total=len(self._alerts),
            alerts_triaged=0,
            cumulative_reward=0.0,
            max_steps=task_def["max_steps"],
        )

        return SocAlertObservation(
            alerts=self._sanitize_alerts(self._alerts),
            alert_count=len(self._alerts),
            time_elapsed=0.0,
            triage_history=[],
            task_id=self._task_id,
            task_description=task_def["description"],
            feedback=None,
            done=False,
            reward=0.0,
        )

    def step(self, action: SocAlertAction) -> SocAlertObservation:  # type: ignore[override]
        """Execute a triage action on an alert."""
        self._state.step_count += 1
        task_def = TASK_DEFINITIONS[self._task_id]

        # Check if episode is already done
        if self._done:
            return self._make_observation("Episode is already complete. Call reset().", reward=0.0)

        # Validate alert_id exists
        alert = self._find_alert(action.alert_id)
        if alert is None:
            return self._make_observation(
                f"Alert '{action.alert_id}' not found in queue. Valid IDs: {self._pending_alert_ids}",
                reward=-0.1,
            )

        # Validate enum fields
        validation_error = self._validate_action_fields(action)
        if validation_error:
            return self._make_observation(validation_error, reward=-0.05)

        # Already triaged?
        if action.alert_id not in self._pending_alert_ids:
            return self._make_observation(
                f"Alert '{action.alert_id}' has already been triaged.",
                reward=-0.05,
            )

        # Score the triage decision
        reward, feedback_parts = self._score_action(action, alert)

        # Record triage
        self._pending_alert_ids.remove(action.alert_id)
        triage_entry = {
            "alert_id": action.alert_id,
            "classification": action.classification,
            "severity": action.severity,
            "category": action.category,
            "assigned_team": action.assigned_team,
            "recommended_action": action.recommended_action,
            "campaign_id": action.campaign_id,
            "attack_chain_position": action.attack_chain_position,
            "reward": reward,
            "step": self._state.step_count,
        }
        self._triage_history.append(triage_entry)

        self._cumulative_reward += reward
        self._state.alerts_triaged += 1
        self._state.cumulative_reward = self._cumulative_reward

        # Check done conditions
        all_triaged = len(self._pending_alert_ids) == 0
        max_steps_reached = self._state.step_count >= task_def["max_steps"]
        self._done = all_triaged or max_steps_reached

        feedback = " | ".join(feedback_parts)
        return self._make_observation(feedback, reward=reward)

    @property
    def state(self) -> SocAlertState:
        return self._state

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sanitize_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove ground truth from alerts before showing to the agent."""
        sanitized = []
        for a in alerts:
            clean = {k: v for k, v in a.items() if k not in ("ground_truth", "campaign_id", "chain_position", "chain_label", "is_campaign")}
            sanitized.append(clean)
        return sanitized

    def _find_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        for a in self._alerts:
            if a["alert_id"] == alert_id:
                return a
        return None

    def _validate_action_fields(self, action: SocAlertAction) -> Optional[str]:
        errors = []
        if action.classification not in CLASSIFICATIONS:
            errors.append(f"Invalid classification '{action.classification}'. Must be one of {CLASSIFICATIONS}")
        if action.severity not in SEVERITIES:
            errors.append(f"Invalid severity '{action.severity}'. Must be one of {SEVERITIES}")
        if action.category not in CATEGORIES:
            errors.append(f"Invalid category '{action.category}'. Must be one of {CATEGORIES}")
        if action.assigned_team not in TEAMS:
            errors.append(f"Invalid team '{action.assigned_team}'. Must be one of {TEAMS}")
        if action.recommended_action not in RESPONSE_ACTIONS:
            errors.append(f"Invalid action '{action.recommended_action}'. Must be one of {RESPONSE_ACTIONS}")
        return "; ".join(errors) if errors else None

    def _score_action(self, action: SocAlertAction, alert: Dict[str, Any]) -> tuple:
        """Score a triage action against ground truth. Returns (reward, feedback_parts)."""
        gt = alert["ground_truth"]
        reward = 0.0
        feedback = []

        # Classification (most important)
        if action.classification == gt["classification"]:
            reward += 0.25
            feedback.append("Classification: CORRECT")
        else:
            # Harsh penalty for missing a true positive critical
            if gt["classification"] == "true_positive" and gt["severity"] == "critical" and action.classification == "false_positive":
                reward -= 0.3
                feedback.append("Classification: WRONG — Critical true positive misclassified as false positive!")
            else:
                feedback.append(f"Classification: WRONG (expected {gt['classification']})")

        # Severity
        if action.severity == gt["severity"]:
            reward += 0.15
            feedback.append("Severity: CORRECT")
        else:
            # Partial credit for adjacent severity levels
            severity_order = ["low", "medium", "high", "critical"]
            gt_idx = severity_order.index(gt["severity"])
            act_idx = severity_order.index(action.severity)
            if abs(gt_idx - act_idx) == 1:
                reward += 0.05
                feedback.append(f"Severity: CLOSE (expected {gt['severity']})")
            else:
                feedback.append(f"Severity: WRONG (expected {gt['severity']})")

        # Category
        if action.category == gt["category"]:
            reward += 0.15
            feedback.append("Category: CORRECT")
        else:
            feedback.append(f"Category: WRONG (expected {gt['category']})")

        # Team routing
        if action.assigned_team == gt["assigned_team"]:
            reward += 0.15
            feedback.append("Team: CORRECT")
        else:
            feedback.append(f"Team: WRONG (expected {gt['assigned_team']})")

        # Recommended action
        if action.recommended_action == gt["recommended_action"]:
            reward += 0.15
            feedback.append("Action: CORRECT")
        else:
            feedback.append(f"Action: WRONG (expected {gt['recommended_action']})")

        # Campaign detection (Task 3 only)
        if alert.get("is_campaign") and self._task_id == "hard_campaign_detection":
            if action.campaign_id is not None:
                reward += 0.10
                feedback.append("Campaign ID: ASSIGNED (correct — this is a campaign alert)")
                if action.attack_chain_position == alert.get("chain_position"):
                    reward += 0.15
                    feedback.append("Chain position: CORRECT")
                elif action.attack_chain_position is not None:
                    reward += 0.05
                    feedback.append(f"Chain position: WRONG (expected {alert['chain_position']})")
            else:
                feedback.append("Campaign ID: MISSED — this alert is part of a campaign")
        elif not alert.get("is_campaign") and self._task_id == "hard_campaign_detection":
            if action.campaign_id is not None:
                reward -= 0.05
                feedback.append("Campaign ID: FALSE ALARM — this alert is NOT part of a campaign")

        # Small time pressure penalty per step
        step_penalty = 0.01 * self._state.step_count
        reward -= step_penalty

        return round(reward, 4), feedback

    def _make_observation(self, feedback: str, reward: float) -> SocAlertObservation:
        task_def = TASK_DEFINITIONS[self._task_id]
        return SocAlertObservation(
            alerts=self._sanitize_alerts([a for a in self._alerts if a["alert_id"] in self._pending_alert_ids]),
            alert_count=len(self._pending_alert_ids),
            time_elapsed=self._state.step_count * 30.0,
            triage_history=self._triage_history,
            task_id=self._task_id,
            task_description=task_def["description"],
            feedback=feedback,
            done=self._done,
            reward=reward,
        )
