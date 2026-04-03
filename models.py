"""
Data models for the SOC Alert Triage Environment.

Defines typed Pydantic models for actions, observations, and state
used by a SOC analyst agent triaging security alerts from a SIEM.
"""

from typing import Any, Dict, List, Optional

from openenv.core.env_server.types import Action, Observation, State
from pydantic import Field


# Valid choices for action fields
CLASSIFICATIONS = ["true_positive", "false_positive", "benign", "suspicious"]
SEVERITIES = ["low", "medium", "high", "critical"]
CATEGORIES = [
    "malware",
    "phishing",
    "brute_force",
    "data_exfiltration",
    "lateral_movement",
    "reconnaissance",
    "insider_threat",
    "denial_of_service",
]
TEAMS = [
    "malware_ops",
    "network_security",
    "identity_security",
    "data_protection",
    "threat_intel",
]
RESPONSE_ACTIONS = [
    "escalate",
    "isolate_host",
    "block_ip",
    "reset_credentials",
    "monitor",
    "close",
]


class SocAlertAction(Action):
    """Action taken by the SOC analyst agent to triage an alert."""

    alert_id: str = Field(..., description="ID of the alert being triaged")
    classification: str = Field(
        ...,
        description=f"Alert classification: {CLASSIFICATIONS}",
    )
    severity: str = Field(
        ...,
        description=f"Assessed severity level: {SEVERITIES}",
    )
    category: str = Field(
        ...,
        description=f"Threat category: {CATEGORIES}",
    )
    assigned_team: str = Field(
        ...,
        description=f"Team to route the alert to: {TEAMS}",
    )
    recommended_action: str = Field(
        ...,
        description=f"Recommended response action: {RESPONSE_ACTIONS}",
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Agent's self-assessed confidence (0.0-1.0)",
    )
    notes: str = Field(
        default="",
        description="Free-text reasoning or justification for the triage decision",
    )
    # Task 3 (campaign detection) fields
    campaign_id: Optional[str] = Field(
        default=None,
        description="Optional campaign identifier to group related alerts",
    )
    attack_chain_position: Optional[int] = Field(
        default=None,
        ge=1,
        description="Position of this alert in the attack kill chain (1-based)",
    )


class SocAlertObservation(Observation):
    """Observation returned by the SOC Alert Triage environment."""

    alerts: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of security alerts currently in the triage queue",
    )
    alert_count: int = Field(
        default=0,
        description="Number of alerts remaining in the queue",
    )
    time_elapsed: float = Field(
        default=0.0,
        description="Simulated time elapsed in seconds since episode start",
    )
    triage_history: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="History of triage decisions made this episode",
    )
    task_id: str = Field(
        default="",
        description="Current task identifier",
    )
    task_description: str = Field(
        default="",
        description="Human-readable description of the current task objective",
    )
    feedback: Optional[str] = Field(
        default=None,
        description="Feedback on the last triage action taken",
    )


class SocAlertState(State):
    """Extended state for the SOC Alert Triage environment."""

    task_id: str = Field(default="", description="Active task identifier")
    alerts_total: int = Field(default=0, description="Total alerts in this episode")
    alerts_triaged: int = Field(default=0, description="Number of alerts triaged so far")
    cumulative_reward: float = Field(default=0.0, description="Total reward accumulated")
    max_steps: int = Field(default=1, description="Maximum steps allowed for this task")
