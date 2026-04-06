"""
Baseline inference script for the SOC Alert Triage Environment.

Uses the OpenAI API to run a model against all 3 tasks and produce
reproducible baseline scores.

Usage:
    # Set your API key
    export OPENAI_API_KEY=sk-...

    # Run standalone
    python -m soc_alert_env.baseline

    # Or trigger via /baseline endpoint
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional

from openai import OpenAI

# Allow running from multiple import contexts
try:
    from .alerts import generate_easy_scenario, generate_hard_scenario, generate_medium_scenario
    from .graders import GRADERS
    from .models import CATEGORIES, CLASSIFICATIONS, RESPONSE_ACTIONS, SEVERITIES, TEAMS
except ImportError:
    from alerts import generate_easy_scenario, generate_hard_scenario, generate_medium_scenario
    from graders import GRADERS
    from models import CATEGORIES, CLASSIFICATIONS, RESPONSE_ACTIONS, SEVERITIES, TEAMS


TASKS = {
    "easy_single_alert": {
        "generator": generate_easy_scenario,
        "max_steps": 1,
        "description": "Classify a single security alert: assign classification, severity, category, team, and recommended action.",
    },
    "medium_queue_triage": {
        "generator": generate_medium_scenario,
        "max_steps": 12,
        "description": "Triage a queue of 10 alerts. Classify each and prioritize critical true positives first.",
    },
    "hard_campaign_detection": {
        "generator": generate_hard_scenario,
        "max_steps": 20,
        "description": "Triage 15 alerts. 5 form a hidden attack campaign — identify and order them.",
    },
}

SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) Tier 1 analyst.
You are triaging security alerts from a SIEM system.

For each alert, you must provide a JSON response with these fields:
- alert_id: the ID of the alert you are triaging
- classification: one of {classifications}
- severity: one of {severities}
- category: one of {categories}
- assigned_team: one of {teams}
- recommended_action: one of {actions}
- confidence: float 0.0-1.0
- notes: brief reasoning

For the hard task (campaign detection), also include:
- campaign_id: a string to group related campaign alerts (null if not part of campaign)
- attack_chain_position: integer 1-5 for campaign alerts (null if not part of campaign)

Respond ONLY with a valid JSON object. No markdown, no explanation outside JSON.""".format(
    classifications=CLASSIFICATIONS,
    severities=SEVERITIES,
    categories=CATEGORIES,
    teams=TEAMS,
    actions=RESPONSE_ACTIONS,
)


def _sanitize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Remove ground truth before sending to the model."""
    return {k: v for k, v in alert.items() if k not in ("ground_truth", "campaign_id", "chain_position", "chain_label", "is_campaign")}


def _call_llm(client: OpenAI, task_id: str, alerts: List[Dict[str, Any]], model: str = "gpt-4o-mini") -> List[Dict[str, Any]]:
    """Call the LLM to triage alerts and return parsed triage decisions."""
    sanitized = [_sanitize_alert(a) for a in alerts]
    task_info = TASKS[task_id]

    user_message = f"""Task: {task_info['description']}

You have {task_info['max_steps']} steps to triage the following {len(sanitized)} alerts.
Triage each alert by providing a JSON response. Respond with a JSON array of triage decisions.

Alerts:
{json.dumps(sanitized, indent=2)}

Respond with a JSON array of triage objects, one per alert you want to triage."""

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.0,
            max_tokens=4000,
        )
        content = response.choices[0].message.content.strip()

        # Strip markdown code fences if present
        if content.startswith("```"):
            lines = content.split("\n")
            # Remove first and last lines (```json and ```)
            lines = [l for l in lines if not l.strip().startswith("```")]
            content = "\n".join(lines)

        parsed = json.loads(content)

        # Normalize: if the model returned a single object, wrap in list
        if isinstance(parsed, dict):
            parsed = [parsed]

        return parsed[:task_info["max_steps"]]

    except Exception as e:
        print(f"LLM call failed for task {task_id}: {e}", file=sys.stderr)
        return []


def run_baseline(api_key: Optional[str] = None, model: str = "gpt-4o-mini", seed: int = 42) -> Dict[str, float]:
    """
    Run baseline inference on all 3 tasks and return scores.

    Args:
        api_key: OpenAI API key or HF token (falls back to OPENAI_API_KEY or HF_TOKEN env vars)
        model: Model to use
        seed: Random seed for reproducible alert generation

    Returns:
        Dict mapping task_id to score (0.0-1.0)
    """
    key = api_key or os.environ.get("OPENAI_API_KEY") or os.environ.get("HF_TOKEN")
    if not key:
        raise ValueError("API key not provided. Set OPENAI_API_KEY or HF_TOKEN.")

    # Detect HF token and route through HF Inference API
    base_url = None
    if key.startswith("hf_"):
        base_url = "https://router.huggingface.co/v1"
        model = os.environ.get("MODEL_NAME", "meta-llama/Llama-3.3-70B-Instruct")

    client = OpenAI(api_key=key, base_url=base_url) if base_url else OpenAI(api_key=key)
    scores = {}

    for task_id, task_info in TASKS.items():
        print(f"\n{'='*60}")
        print(f"Running baseline for: {task_id}")
        print(f"{'='*60}")

        alerts = task_info["generator"](seed)
        triage_history = _call_llm(client, task_id, alerts, model=model)

        print(f"  Alerts: {len(alerts)}, Triaged: {len(triage_history)}")

        grader = GRADERS[task_id]
        score = grader(triage_history, alerts)
        scores[task_id] = score

        print(f"  Score: {score:.4f}")

    print(f"\n{'='*60}")
    print("BASELINE RESULTS:")
    for tid, s in scores.items():
        print(f"  {tid}: {s:.4f}")
    print(f"{'='*60}")

    return scores


if __name__ == "__main__":
    scores = run_baseline()
    print(json.dumps(scores, indent=2))
