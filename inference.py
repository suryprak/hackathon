"""
Inference Script — SOC Alert Triage Environment
================================================
MANDATORY environment variables:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.
    LOCAL_IMAGE_NAME The name of the local Docker image (when using from_docker_image()).

STDOUT FORMAT:
    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> rewards=<r1,r2,...,rn>
"""

import asyncio
import json
import os
import textwrap
from typing import Any, Dict, List, Optional

from openai import OpenAI

from client import SocAlertEnv
from models import (
    CATEGORIES,
    CLASSIFICATIONS,
    RESPONSE_ACTIONS,
    SEVERITIES,
    TEAMS,
    SocAlertAction,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME")  # Docker image name
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
API_BASE_URL = os.getenv("API_BASE_URL") or "https://router.huggingface.co/v1"
MODEL_NAME = os.getenv("MODEL_NAME") or "Qwen/Qwen2.5-72B-Instruct"

TASK_NAME = os.getenv("SOC_TASK", "easy_single_alert")
BENCHMARK = "soc_alert_env"
SEED = int(os.getenv("SOC_SEED", "42"))
TEMPERATURE = 0.3
MAX_TOKENS = 1024
SUCCESS_SCORE_THRESHOLD = 0.5  # normalised score in [0, 1]

# Per-task max steps (mirrors environment definitions)
TASK_MAX_STEPS = {
    "easy_single_alert": 1,
    "medium_queue_triage": 12,
    "hard_campaign_detection": 20,
}
MAX_STEPS = TASK_MAX_STEPS.get(TASK_NAME, 12)

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = textwrap.dedent(
    f"""\
    You are an expert SOC (Security Operations Center) analyst performing alert triage.
    You will receive security alerts from a SIEM system. For each alert you must decide:

    1. classification: one of {CLASSIFICATIONS}
    2. severity: one of {SEVERITIES}
    3. category: one of {CATEGORIES}
    4. assigned_team: one of {TEAMS}
    5. recommended_action: one of {RESPONSE_ACTIONS}
    6. confidence: a float between 0.0 and 1.0
    7. notes: brief reasoning for your decision
    8. campaign_id: (optional) if alerts are part of a coordinated campaign, group them with the same campaign_id string
    9. attack_chain_position: (optional) integer position in the kill chain (1-based)

    Respond ONLY with a JSON object containing these fields plus "alert_id".
    Do NOT include any other text, explanation, or markdown formatting.
    Example:
    {{"alert_id": "ALERT-ABC123", "classification": "true_positive", "severity": "critical", "category": "malware", "assigned_team": "malware_ops", "recommended_action": "isolate_host", "confidence": 0.95, "notes": "EDR detected known malware hash"}}
    """
)


# ---------------------------------------------------------------------------
# Logging helpers (mandatory stdout format)
# ---------------------------------------------------------------------------
def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}",
        flush=True,
    )


# ---------------------------------------------------------------------------
# Alert formatting
# ---------------------------------------------------------------------------
def format_alerts_for_llm(alerts: List[Dict[str, Any]]) -> str:
    """Format alerts into a readable prompt block for the LLM."""
    parts = []
    for i, alert in enumerate(alerts, 1):
        parts.append(
            f"--- Alert {i} ---\n"
            f"  ID: {alert.get('alert_id', 'N/A')}\n"
            f"  Type: {alert.get('alert_type', 'N/A')}\n"
            f"  Source: {alert.get('source', 'N/A')}\n"
            f"  MITRE Tactic: {alert.get('mitre_tactic', 'N/A')}\n"
            f"  MITRE Technique: {alert.get('mitre_technique', 'N/A')}\n"
            f"  Timestamp: {alert.get('timestamp', 'N/A')}\n"
            f"  Description: {alert.get('description', 'N/A')}\n"
            f"  Raw Log: {alert.get('raw_log', 'N/A')}"
        )
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------
def get_triage_decision(
    client: OpenAI,
    alerts: List[Dict[str, Any]],
    triage_history: List[str],
    task_name: str,
) -> Dict[str, Any]:
    """Ask the LLM to triage the next alert and return parsed JSON."""
    alerts_block = format_alerts_for_llm(alerts)
    history_block = "\n".join(triage_history[-6:]) if triage_history else "None yet."

    is_campaign = task_name == "hard_campaign_detection"
    campaign_hint = (
        "\nIMPORTANT: Some of these alerts may be part of a coordinated attack campaign. "
        "If you detect related alerts, assign them the same campaign_id and set "
        "attack_chain_position to indicate ordering in the kill chain."
        if is_campaign
        else ""
    )

    user_prompt = textwrap.dedent(
        f"""\
        Current alerts in queue:
        {alerts_block}

        Previous triage decisions:
        {history_block}
        {campaign_hint}
        Triage the next untriaged alert. Respond with a single JSON object."""
    )

    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
            stream=False,
        )
        text = (completion.choices[0].message.content or "").strip()
        # Strip markdown code fences if present
        if text.startswith("```"):
            text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()
        return json.loads(text)
    except (json.JSONDecodeError, Exception) as exc:
        print(f"[DEBUG] LLM parse error: {exc}", flush=True)
        # Fallback: triage first alert with safe defaults
        alert_id = alerts[0].get("alert_id", "UNKNOWN") if alerts else "UNKNOWN"
        return {
            "alert_id": alert_id,
            "classification": "suspicious",
            "severity": "medium",
            "category": "malware",
            "assigned_team": "malware_ops",
            "recommended_action": "monitor",
            "confidence": 0.1,
            "notes": "Fallback decision due to LLM error",
        }


def build_action(decision: Dict[str, Any]) -> SocAlertAction:
    """Build a validated SocAlertAction from the LLM's JSON decision."""
    return SocAlertAction(
        alert_id=str(decision.get("alert_id", "UNKNOWN")),
        classification=decision.get("classification", "suspicious"),
        severity=decision.get("severity", "medium"),
        category=decision.get("category", "malware"),
        assigned_team=decision.get("assigned_team", "malware_ops"),
        recommended_action=decision.get("recommended_action", "monitor"),
        confidence=float(decision.get("confidence", 0.5)),
        notes=str(decision.get("notes", "")),
        campaign_id=decision.get("campaign_id"),
        attack_chain_position=decision.get("attack_chain_position"),
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main() -> None:
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    # Connect to environment via Docker image
    env = await SocAlertEnv.from_docker_image(IMAGE_NAME)

    triage_history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0
    score = 0.0
    success = False

    log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)

    try:
        result = await env.reset(task_id=TASK_NAME, seed=SEED)
        alerts = result.observation.alerts

        for step in range(1, MAX_STEPS + 1):
            if result.done:
                break

            # Get LLM triage decision
            decision = get_triage_decision(client, alerts, triage_history, TASK_NAME)
            action = build_action(decision)

            # Execute step
            result = await env.step(action)
            obs = result.observation

            reward = result.reward or 0.0
            done = result.done
            error = None

            rewards.append(reward)
            steps_taken = step
            alerts = obs.alerts  # updated queue

            action_str = f"triage({action.alert_id},{action.classification},{action.severity})"
            log_step(step=step, action=action_str, reward=reward, done=done, error=error)

            triage_history.append(
                f"Step {step}: {action.alert_id} -> {action.classification} "
                f"({action.severity}/{action.category}) reward={reward:+.2f}"
            )

            if done:
                break

        total_reward = sum(rewards)
        max_possible = float(MAX_STEPS)  # each step can yield up to 1.0
        score = total_reward / max_possible if max_possible > 0 else 0.0
        score = min(max(score, 0.0), 1.0)
        success = score >= SUCCESS_SCORE_THRESHOLD

    finally:
        try:
            await env.close()
        except Exception as e:
            print(f"[DEBUG] env.close() error: {e}", flush=True)
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)


if __name__ == "__main__":
    asyncio.run(main())
