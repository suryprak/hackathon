"""
Inference Script — SOC Alert Triage Environment
================================================
MANDATORY environment variables:
    API_BASE_URL     The API endpoint for the LLM.
    MODEL_NAME       The model identifier to use for inference.
    HF_TOKEN         Your Hugging Face / API key.
    LOCAL_IMAGE_NAME The name of the local Docker image (when using from_docker_image()).

Runs ALL 3 tasks (easy, medium, hard) and reports per-task grader scores.

STDOUT FORMAT:
    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<0.000> rewards=<r1,r2,...,rn>
"""

import asyncio
import json
import os
import textwrap
from typing import Any, Dict, List, Optional

from openai import OpenAI

try:
    from soc_alert_env.alerts import (
        generate_easy_scenario,
        generate_hard_scenario,
        generate_medium_scenario,
    )
    from soc_alert_env.client import SocAlertEnv
    from soc_alert_env.graders import GRADERS
    from soc_alert_env.models import (
        CATEGORIES,
        CLASSIFICATIONS,
        RESPONSE_ACTIONS,
        SEVERITIES,
        TEAMS,
        SocAlertAction,
    )
except ImportError:
    from alerts import (
        generate_easy_scenario,
        generate_hard_scenario,
        generate_medium_scenario,
    )
    from client import SocAlertEnv
    from graders import GRADERS
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
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3.3-70B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")

# Optional — if you use from_docker_image():
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME")

# Optional — connect to a running server instead of Docker
LOCAL_SERVER_URL = os.getenv("LOCAL_SERVER_URL")

BENCHMARK = "soc_alert_env"
SEED = int(os.getenv("SOC_SEED", "42"))
TEMPERATURE = 0.1
MAX_TOKENS = 1024
SUCCESS_SCORE_THRESHOLD = 0.5  # normalised score in [0, 1]

# All tasks to run (mirrors environment definitions)
TASKS = {
    "easy_single_alert": {
        "max_steps": 1,
        "generator": generate_easy_scenario,
    },
    "medium_queue_triage": {
        "max_steps": 12,
        "generator": generate_medium_scenario,
    },
    "hard_campaign_detection": {
        "max_steps": 20,
        "generator": generate_hard_scenario,
    },
}

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

    CLASSIFICATION GUIDANCE:
    - true_positive: Real threat requiring action (malware execution, active brute force, data exfiltration, lateral movement)
    - false_positive: The detection rule fired INCORRECTLY — what was flagged is NOT actually malicious. Examples: approved internal tools flagged by EDR, legitimate software triggering a malware signature, known safe binaries being treated as suspicious, scheduled security scans mistaken for attacks.
    - benign: The detected activity IS what it appears to be, but it is authorized and expected. Examples: a sysadmin running nmap for authorized testing, a scheduled backup process, legitimate bulk data download.
    - suspicious: Uncertain — not enough evidence to classify definitively, needs further investigation

    TEAM ROUTING:
    - malware_ops: malware, ransomware, trojans
    - network_security: network-based attacks, DoS, scanning, lateral movement
    - identity_security: credential attacks, brute force, account compromise
    - data_protection: data exfiltration, DLP alerts, insider threats
    - threat_intel: reconnaissance, advanced persistent threats, campaign analysis

    IMPORTANT: You must triage ONLY alerts from the current queue. Pick the alert_id from the alerts shown. Do NOT repeat an alert_id you have already triaged.

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
    triage_log: List[str],
    task_name: str,
) -> Dict[str, Any]:
    """Ask the LLM to triage the next alert and return parsed JSON."""
    alerts_block = format_alerts_for_llm(alerts)
    history_block = "\n".join(triage_log[-6:]) if triage_log else "None yet."

    is_campaign = task_name == "hard_campaign_detection"
    campaign_hint = (
        "\nIMPORTANT: Some of these alerts may be part of a coordinated attack campaign. "
        "If you detect related alerts, assign them the same campaign_id and set "
        "attack_chain_position to indicate ordering in the kill chain."
        if is_campaign
        else ""
    )

    priority_hint = ""
    if task_name == "medium_queue_triage":
        priority_hint = (
            "\nPrioritize critical and high-severity true positive alerts first. "
            "Triage the most urgent alert from the queue."
        )

    # Build list of valid alert IDs for the LLM to choose from
    valid_ids = [a.get("alert_id", "") for a in alerts]
    valid_ids_str = ", ".join(valid_ids) if valid_ids else "(none)"

    user_prompt = textwrap.dedent(
        f"""\
        Current alerts in queue ({len(alerts)} remaining):
        {alerts_block}

        Valid alert IDs to triage: {valid_ids_str}

        Previous triage decisions:
        {history_block}
        {campaign_hint}{priority_hint}
        Pick ONE alert from the valid IDs above and triage it. Respond with a single JSON object."""
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
# Run a single task
# ---------------------------------------------------------------------------
async def run_task(
    env: SocAlertEnv,
    llm_client: OpenAI,
    task_name: str,
    task_info: Dict[str, Any],
    seed: int,
) -> float:
    """Run one task end-to-end and return the grader score."""
    max_steps = task_info["max_steps"]
    triage_history: List[Dict[str, Any]] = []  # action dicts for grader
    triage_log: List[str] = []  # human-readable log for LLM context
    rewards: List[float] = []
    steps_taken = 0
    score = 0.0
    success = False

    log_start(task=task_name, env=BENCHMARK, model=MODEL_NAME)
    triaged_ids: set = set()  # track already-triaged alert IDs

    try:
        result = await env.reset(task_id=task_name, seed=seed)
        alerts = result.observation.alerts

        for step in range(1, max_steps + 1):
            if result.done:
                break

            # Filter out already-triaged alerts before sending to LLM
            untriaged = [a for a in alerts if a.get("alert_id") not in triaged_ids]
            if not untriaged:
                break  # nothing left to triage

            decision = get_triage_decision(llm_client, untriaged, triage_log, task_name)
            action = build_action(decision)

            # If LLM still picks a triaged ID, force-pick the first untriaged one
            if action.alert_id in triaged_ids:
                action.alert_id = untriaged[0]["alert_id"]

            result = await env.step(action)
            reward = result.reward or 0.0
            rewards.append(reward)
            steps_taken = step
            alerts = result.observation.alerts

            action_str = f"triage({action.alert_id},{action.classification},{action.severity})"
            log_step(step=step, action=action_str, reward=reward, done=result.done, error=None)

            # Collect action dict for grader
            triaged_ids.add(action.alert_id)
            triage_history.append(action.model_dump(exclude_none=True))

            triage_log.append(
                f"Step {step}: {action.alert_id} -> {action.classification} "
                f"({action.severity}/{action.category}) reward={reward:+.2f}"
            )

            if result.done:
                break

        # Grade with the official grader (regenerate alerts with ground truth)
        ground_truth_alerts = task_info["generator"](seed)
        grader = GRADERS[task_name]
        score = grader(triage_history, ground_truth_alerts)
        success = score >= SUCCESS_SCORE_THRESHOLD

    except Exception as e:
        print(f"[DEBUG] Error in task {task_name}: {e}", flush=True)

    log_end(success=success, steps=steps_taken, score=score, rewards=rewards)
    return score


# ---------------------------------------------------------------------------
# Main — run all 3 tasks
# ---------------------------------------------------------------------------
async def main() -> None:
    llm_client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)

    # Connect to environment — prefer local server URL for testing, else Docker
    if LOCAL_SERVER_URL:
        env = SocAlertEnv(base_url=LOCAL_SERVER_URL)
        await env.connect()
    elif LOCAL_IMAGE_NAME:
        env = await SocAlertEnv.from_docker_image(LOCAL_IMAGE_NAME)
    else:
        raise RuntimeError(
            "Set LOCAL_SERVER_URL or LOCAL_IMAGE_NAME to connect to the environment"
        )

    all_scores: Dict[str, float] = {}

    try:
        for task_name, task_info in TASKS.items():
            score = await run_task(env, llm_client, task_name, task_info, SEED)
            all_scores[task_name] = score
    finally:
        try:
            await env.close()
        except Exception as e:
            print(f"[DEBUG] env.close() error: {e}", flush=True)

    # Final summary
    print(f"\n{'='*60}", flush=True)
    print("FINAL SCORES:", flush=True)
    for task_name, score in all_scores.items():
        print(f"  {task_name}: {score:.4f}", flush=True)
    avg = sum(all_scores.values()) / len(all_scores) if all_scores else 0.0
    print(f"  average: {avg:.4f}", flush=True)
    print(f"{'='*60}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
