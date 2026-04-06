# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""SOC Alert Triage Environment Client."""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult

try:
    from .models import SocAlertAction, SocAlertObservation, SocAlertState
except ImportError:
    from models import SocAlertAction, SocAlertObservation, SocAlertState


class SocAlertEnv(
    EnvClient[SocAlertAction, SocAlertObservation, SocAlertState]
):
    """
    Client for the SOC Alert Triage Environment.

    Example:
        >>> with SocAlertEnv(base_url="http://localhost:8000").sync() as client:
        ...     result = client.reset(task_id="easy_single_alert")
        ...     print(result.observation.alerts)
        ...     result = client.step(SocAlertAction(
        ...         alert_id="ALERT-...",
        ...         classification="true_positive",
        ...         severity="critical",
        ...         category="malware",
        ...         assigned_team="malware_ops",
        ...         recommended_action="isolate_host",
        ...     ))
        ...     print(result.observation.feedback)
    """

    def _step_payload(self, action: SocAlertAction) -> Dict:
        return action.model_dump(exclude_none=True)

    def _parse_result(self, payload: Dict) -> StepResult[SocAlertObservation]:
        obs_data = payload.get("observation", {})
        observation = SocAlertObservation(**obs_data)
        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> SocAlertState:
        return SocAlertState(**payload)
