# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
FastAPI application for the SOC Alert Triage Environment.

Exposes OpenEnv core endpoints plus hackathon-required custom endpoints:
  /tasks   — list tasks and action schema
  /grader  — score a completed episode
  /baseline — run baseline inference and return scores
"""

import os
from typing import Any, Dict, List, Optional

# Enable OpenEnv's built-in web interface (Playground) at /web
os.environ["ENABLE_WEB_INTERFACE"] = "true"

from fastapi import Body, HTTPException
from pydantic import BaseModel

try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:
    raise ImportError(
        "openenv is required. Install with: pip install openenv-core"
    ) from e

try:
    from ..graders import GRADERS
    from ..models import SocAlertAction, SocAlertObservation
    from .soc_alert_env_environment import TASK_DEFINITIONS, SocAlertEnvironment
except ImportError:
    from graders import GRADERS
    from models import SocAlertAction, SocAlertObservation
    from server.soc_alert_env_environment import TASK_DEFINITIONS, SocAlertEnvironment


# Create the core OpenEnv app
app = create_app(
    SocAlertEnvironment,
    SocAlertAction,
    SocAlertObservation,
    env_name="soc_alert_env",
    max_concurrent_envs=4,
)


# ---------------------------------------------------------------------------
# Custom endpoints required by hackathon
# ---------------------------------------------------------------------------


class TaskInfo(BaseModel):
    task_id: str
    description: str
    difficulty: str
    max_steps: int
    action_schema: Dict[str, Any]


class TasksResponse(BaseModel):
    tasks: List[TaskInfo]


class GraderRequest(BaseModel):
    task_id: str
    triage_history: List[Dict[str, Any]]
    seed: int = 42


class GraderResponse(BaseModel):
    task_id: str
    score: float
    details: Dict[str, Any]


class BaselineResponse(BaseModel):
    scores: Dict[str, float]
    details: Dict[str, Any]


DIFFICULTY_MAP = {
    "easy_single_alert": "easy",
    "medium_queue_triage": "medium",
    "hard_campaign_detection": "hard",
}


@app.get("/tasks", response_model=TasksResponse, tags=["Hackathon"])
async def get_tasks():
    """Return the list of tasks and the action schema."""
    action_schema = SocAlertAction.model_json_schema()
    tasks = []
    for task_id, task_def in TASK_DEFINITIONS.items():
        tasks.append(
            TaskInfo(
                task_id=task_id,
                description=task_def["description"],
                difficulty=DIFFICULTY_MAP.get(task_id, "unknown"),
                max_steps=task_def["max_steps"],
                action_schema=action_schema,
            )
        )
    return TasksResponse(tasks=tasks)


@app.post("/grader", response_model=GraderResponse, tags=["Hackathon"])
async def grade_episode(request: GraderRequest = Body(...)):
    """Grade a completed episode given the triage history."""
    if request.task_id not in GRADERS:
        raise HTTPException(status_code=400, detail=f"Unknown task_id: {request.task_id}")

    # Regenerate alerts with same seed for deterministic grading
    task_def = TASK_DEFINITIONS[request.task_id]
    alerts = task_def["generator"](request.seed)

    grader = GRADERS[request.task_id]
    score = grader(request.triage_history, alerts)

    return GraderResponse(
        task_id=request.task_id,
        score=score,
        details={
            "alerts_total": len(alerts),
            "alerts_triaged": len(request.triage_history),
            "seed": request.seed,
        },
    )


@app.post("/baseline", response_model=BaselineResponse, tags=["Hackathon"])
async def run_baseline():
    """Run the baseline inference script and return scores for all tasks."""
    try:
        from baseline import run_baseline
    except ImportError:
        try:
            from soc_alert_env.baseline import run_baseline
        except ImportError:
            raise HTTPException(
                status_code=500,
                detail="Baseline script not found. Ensure baseline.py is in the package.",
            )

    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("HF_TOKEN")
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="API key not set. Set OPENAI_API_KEY or HF_TOKEN environment variable.",
        )

    model_name = "gpt-4o-mini"
    if api_key.startswith("hf_"):
        model_name = os.environ.get("MODEL_NAME", "meta-llama/Llama-3.3-70B-Instruct")

    scores = run_baseline(api_key=api_key, model=model_name)
    return BaselineResponse(
        scores=scores,
        details={"model": model_name, "note": "Baseline scores"},
    )


def main(host: str = "0.0.0.0", port: int = 8000):
    """Entry point for running the server directly."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
