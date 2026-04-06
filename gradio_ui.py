"""
Gradio frontend for the SOC Alert Triage Environment.

Provides a polished interactive UI for triaging security alerts,
running the baseline agent, and viewing evaluation results.
"""

import json
import traceback

import gradio as gr

try:
    from models import (
        CATEGORIES, CLASSIFICATIONS, RESPONSE_ACTIONS, SEVERITIES, TEAMS,
        SocAlertAction,
    )
    from server.soc_alert_env_environment import TASK_DEFINITIONS, SocAlertEnvironment
    from graders import GRADERS
except ImportError:
    from soc_alert_env.models import (
        CATEGORIES, CLASSIFICATIONS, RESPONSE_ACTIONS, SEVERITIES, TEAMS,
        SocAlertAction,
    )
    from soc_alert_env.server.soc_alert_env_environment import TASK_DEFINITIONS, SocAlertEnvironment
    from soc_alert_env.graders import GRADERS


TASK_IDS = {
    "easy": "easy_single_alert",
    "medium": "medium_queue_triage",
    "hard": "hard_campaign_detection",
}

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
}


def format_alert_card(alert, index):
    sev = alert.get("severity", "medium")
    color = SEVERITY_COLORS.get(sev, "#6b7280")
    src = alert.get("source", "Unknown")
    mitre = alert.get("mitre_technique", "N/A")
    desc = alert.get("description", "No description")
    aid = alert.get("alert_id", f"ALERT-{index}")
    ts = alert.get("timestamp", "—")

    return f"""<div style="border-left:4px solid {color}; background:#1e1e2e; padding:12px 16px; margin:6px 0; border-radius:6px;">
<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
  <span style="font-weight:700; color:#e2e8f0; font-size:15px;">🔔 {aid}</span>
  <span style="background:{color}; color:white; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:600;">{sev.upper()}</span>
</div>
<div style="color:#94a3b8; font-size:13px; margin-bottom:4px;">📡 {src} &nbsp;|&nbsp; 🎯 {mitre}</div>
<div style="color:#cbd5e1; font-size:14px; margin-bottom:4px;">{desc}</div>
<div style="color:#64748b; font-size:12px;">⏰ {ts}</div>
</div>"""


def format_alerts_html(alerts):
    if not alerts:
        return "<div style='color:#94a3b8; text-align:center; padding:40px;'>No alerts in queue</div>"
    cards = [format_alert_card(a, i) for i, a in enumerate(alerts)]
    return "\n".join(cards)


def format_feedback(feedback, reward):
    if feedback is None:
        return ""
    color = "#22c55e" if reward and reward > 0.5 else "#f59e0b" if reward and reward > 0 else "#ef4444"
    return f"""<div style="background:#1e1e2e; border-left:4px solid {color}; padding:12px 16px; border-radius:6px; margin:6px 0;">
<div style="font-weight:600; color:{color}; margin-bottom:4px;">Reward: {reward:.3f}</div>
<div style="color:#cbd5e1; font-size:14px;">{feedback}</div>
</div>"""


def format_history_table(history):
    if not history:
        return "<div style='color:#94a3b8; text-align:center; padding:20px;'>No actions yet</div>"
    rows = ""
    for i, h in enumerate(history):
        cls = h.get("classification", "?")
        sev = h.get("severity", "?")
        cat = h.get("category", "?")
        team = h.get("assigned_team", "?")
        act = h.get("recommended_action", "?")
        aid = h.get("alert_id", "?")
        reward = h.get("reward", 0)
        color = "#22c55e" if reward > 0.5 else "#f59e0b" if reward > 0 else "#ef4444"
        rows += f"""<tr style="border-bottom:1px solid #334155;">
  <td style="padding:6px 8px; color:#94a3b8;">{i+1}</td>
  <td style="padding:6px 8px; color:#e2e8f0;">{aid}</td>
  <td style="padding:6px 8px; color:#e2e8f0;">{cls}</td>
  <td style="padding:6px 8px; color:#e2e8f0;">{sev}</td>
  <td style="padding:6px 8px; color:#e2e8f0;">{cat}</td>
  <td style="padding:6px 8px; color:#e2e8f0;">{team}</td>
  <td style="padding:6px 8px; color:#e2e8f0;">{act}</td>
  <td style="padding:6px 8px; color:{color}; font-weight:600;">{reward:.3f}</td>
</tr>"""
    return f"""<table style="width:100%; border-collapse:collapse; font-size:13px;">
<thead><tr style="background:#0f172a; border-bottom:2px solid #475569;">
  <th style="padding:8px; color:#94a3b8; text-align:left;">#</th>
  <th style="padding:8px; color:#94a3b8; text-align:left;">Alert</th>
  <th style="padding:8px; color:#94a3b8; text-align:left;">Class</th>
  <th style="padding:8px; color:#94a3b8; text-align:left;">Sev</th>
  <th style="padding:8px; color:#94a3b8; text-align:left;">Cat</th>
  <th style="padding:8px; color:#94a3b8; text-align:left;">Team</th>
  <th style="padding:8px; color:#94a3b8; text-align:left;">Action</th>
  <th style="padding:8px; color:#94a3b8; text-align:left;">Reward</th>
</tr></thead><tbody>{rows}</tbody></table>"""


# ─── Interactive triage callbacks ──────────────────────────────────────────────

def create_env(difficulty, seed, state):
    task_id = TASK_IDS[difficulty]
    env = SocAlertEnvironment()
    obs, _ = env.reset(task_id=task_id, seed=int(seed))
    alerts = obs.get("alerts", [])
    state["env"] = env
    state["difficulty"] = difficulty
    state["task_id"] = task_id
    state["step"] = 0
    state["max_steps"] = TASK_DEFINITIONS[task_id]["max_steps"]
    state["rewards"] = []
    state["done"] = False
    state["history"] = []

    first_alert_id = alerts[0]["alert_id"] if alerts else ""

    status = f"✅ Environment created — **{difficulty.upper()}** task | {len(alerts)} alerts | {state['max_steps']} max steps"
    return (
        state,
        status,
        format_alerts_html(alerts),
        "",
        format_history_table([]),
        first_alert_id,
        f"Step 0 / {state['max_steps']}",
    )


def submit_triage(
    alert_id, classification, severity, category, team, action,
    confidence, notes, campaign_id, chain_pos, state
):
    env = state.get("env")
    if env is None:
        return state, "❌ Create an environment first!", "", "", "", "", ""
    if state.get("done"):
        return state, "🏁 Episode finished. Create a new environment.", "", "", format_history_table(state.get("history", [])), "", ""

    act = SocAlertAction(
        alert_id=alert_id,
        classification=classification,
        severity=severity,
        category=category,
        assigned_team=team,
        recommended_action=action,
        confidence=confidence,
        notes=notes,
        campaign_id=campaign_id if campaign_id else None,
        attack_chain_position=int(chain_pos) if chain_pos else None,
    )

    obs, reward, done, truncated, info = env.step(act)
    state["step"] += 1
    state["rewards"].append(reward)
    hist_entry = {
        "alert_id": alert_id,
        "classification": classification,
        "severity": severity,
        "category": category,
        "assigned_team": team,
        "recommended_action": action,
        "reward": reward,
    }
    state["history"].append(hist_entry)

    alerts = obs.get("alerts", [])
    feedback = obs.get("feedback", "")
    next_alert_id = alerts[0]["alert_id"] if alerts else ""

    fb_html = format_feedback(feedback, reward)

    if done or truncated:
        state["done"] = True
        avg = sum(state["rewards"]) / len(state["rewards"]) if state["rewards"] else 0
        fb_html += f"""<div style="background:#0f172a; border:2px solid #22c55e; padding:16px; border-radius:8px; margin-top:12px; text-align:center;">
<div style="font-size:20px; font-weight:700; color:#22c55e;">🏁 Episode Complete</div>
<div style="font-size:16px; color:#e2e8f0; margin-top:8px;">Average Reward: <b>{avg:.3f}</b> | Steps: {state['step']}</div>
</div>"""

    step_text = f"Step {state['step']} / {state['max_steps']}"
    status = "🏁 Done!" if state.get("done") else f"⏳ Step {state['step']} submitted"

    return (
        state,
        status,
        format_alerts_html(alerts),
        fb_html,
        format_history_table(state["history"]),
        next_alert_id,
        step_text,
    )


# ─── Baseline evaluation callback ─────────────────────────────────────────────

def run_evaluation(seed):
    seed = int(seed)
    rows = []
    for difficulty in ["easy", "medium", "hard"]:
        task_id = TASK_IDS[difficulty]
        task_def = TASK_DEFINITIONS[task_id]
        env = SocAlertEnvironment()

        try:
            obs, _ = env.reset(task_id=task_id, seed=seed)
            alerts = obs.get("alerts", [])
            history = []
            for alert in alerts:
                gt = alert.get("ground_truth", {})
                act = SocAlertAction(
                    alert_id=alert["alert_id"],
                    classification=gt.get("classification", "suspicious"),
                    severity=gt.get("severity", "medium"),
                    category=gt.get("category", "malware"),
                    assigned_team=gt.get("assigned_team", "malware_ops"),
                    recommended_action=gt.get("recommended_action", "monitor"),
                    confidence=0.95,
                    notes="ground truth evaluation",
                    campaign_id=gt.get("campaign_id"),
                    attack_chain_position=gt.get("attack_chain_position"),
                )
                obs, reward, done, truncated, info = env.step(act)
                history.append(act.model_dump())
                if done or truncated:
                    break

            grader = GRADERS[task_id]
            score = grader(history, task_def["generator"](seed))
            rows.append([difficulty.upper(), f"{score:.4f}", f"{score*100:.1f}%", "✅"])
        except Exception as e:
            rows.append([difficulty.upper(), "—", "—", f"❌ {e}"])

    return rows


# ─── Build the Gradio UI ──────────────────────────────────────────────────────

CUSTOM_CSS = """
.gradio-container { max-width: 1200px !important; }
.dark { --body-background-fill: #0f172a; }
"""

def build_demo():
    with gr.Blocks(
        title="SOC Alert Triage — OpenEnv",
        css=CUSTOM_CSS,
        theme=gr.themes.Soft(primary_hue="blue", neutral_hue="slate"),
    ) as demo:
        gr.Markdown("""
# 🛡️ SOC Alert Triage Environment
**AI-powered Security Operations Center alert triage** — classify, prioritize, and route security alerts from a simulated SIEM.
Built for the [Meta / HuggingFace / Scaler OpenEnv Hackathon](https://huggingface.co/spaces/open-env/hackathon).
        """)

        # ── Tab 1: Interactive Triage ──────────────────────────────────────
        with gr.Tab("🎮 Interactive Triage"):
            gr.Markdown("Step through alerts manually — make triage decisions and see rewards in real time.")
            env_state = gr.State({})

            with gr.Row():
                diff_radio = gr.Radio(
                    ["easy", "medium", "hard"], value="easy",
                    label="Difficulty", scale=2,
                )
                seed_input = gr.Number(value=42, label="Seed", scale=1)
                btn_create = gr.Button("🚀 Create Environment", variant="primary", scale=1)

            status_box = gr.Markdown("Select difficulty and click **Create Environment** to begin.")
            step_counter = gr.Markdown("")

            with gr.Row():
                with gr.Column(scale=3):
                    alerts_html = gr.HTML(label="Alert Queue")
                with gr.Column(scale=2):
                    feedback_html = gr.HTML(label="Last Feedback")

            gr.Markdown("### 📝 Triage Decision")
            with gr.Row():
                inp_alert_id = gr.Textbox(label="Alert ID", scale=2)
                inp_classification = gr.Dropdown(
                    CLASSIFICATIONS, label="Classification", value="true_positive", scale=2,
                )
                inp_severity = gr.Dropdown(
                    SEVERITIES, label="Severity", value="medium", scale=1,
                )
            with gr.Row():
                inp_category = gr.Dropdown(
                    CATEGORIES, label="Threat Category", value="malware", scale=2,
                )
                inp_team = gr.Dropdown(
                    TEAMS, label="Assigned Team", value="malware_ops", scale=2,
                )
                inp_action = gr.Dropdown(
                    RESPONSE_ACTIONS, label="Action", value="monitor", scale=1,
                )
            with gr.Row():
                inp_confidence = gr.Slider(0, 1, value=0.5, step=0.05, label="Confidence", scale=2)
                inp_notes = gr.Textbox(label="Notes / Reasoning", scale=3)
            with gr.Row():
                inp_campaign = gr.Textbox(label="Campaign ID (hard mode)", scale=2)
                inp_chain = gr.Number(label="Kill Chain Position (1-5)", value=None, scale=1)
                btn_submit = gr.Button("Submit Triage ▶️", variant="primary", scale=1)

            gr.Markdown("### 📜 Triage History")
            history_html = gr.HTML()

            btn_create.click(
                create_env,
                inputs=[diff_radio, seed_input, env_state],
                outputs=[env_state, status_box, alerts_html, feedback_html, history_html, inp_alert_id, step_counter],
            )
            btn_submit.click(
                submit_triage,
                inputs=[
                    inp_alert_id, inp_classification, inp_severity, inp_category,
                    inp_team, inp_action, inp_confidence, inp_notes,
                    inp_campaign, inp_chain, env_state,
                ],
                outputs=[env_state, status_box, alerts_html, feedback_html, history_html, inp_alert_id, step_counter],
            )

        # ── Tab 2: Ground-Truth Evaluation ─────────────────────────────────
        with gr.Tab("📊 Evaluation (Ground Truth)"):
            gr.Markdown(
                "Run **perfect** (ground-truth) triage on all tasks to verify environment scoring. "
                "This uses the built-in answer key — real scores come from LLM inference."
            )
            eval_seed = gr.Number(value=42, label="Seed")
            btn_eval = gr.Button("Run All Tasks", variant="primary")
            eval_table = gr.Dataframe(
                headers=["Task", "Score", "Accuracy", "Status"],
                label="Results",
            )
            btn_eval.click(run_evaluation, inputs=eval_seed, outputs=eval_table)

        # ── Tab 3: Environment Info ────────────────────────────────────────
        with gr.Tab("📋 Environment Info"):
            gr.Markdown("""
## Task Definitions

| Difficulty | Task ID | Description | Max Steps |
|------------|---------|-------------|-----------|
| **Easy** | `easy_single_alert` | Triage a single security alert — classify, assign severity, category, team, and action. | 1 |
| **Medium** | `medium_queue_triage` | Triage a queue of 10 alerts. Prioritize critical true positives. | 12 |
| **Hard** | `hard_campaign_detection` | Triage 15 alerts and identify a coordinated 5-alert attack campaign with kill-chain ordering. | 20 |

## Action Schema

| Field | Type | Options |
|-------|------|---------|
| `alert_id` | string | ID of the alert to triage |
| `classification` | enum | `true_positive`, `false_positive`, `benign`, `suspicious` |
| `severity` | enum | `low`, `medium`, `high`, `critical` |
| `category` | enum | `malware`, `phishing`, `brute_force`, `data_exfiltration`, `lateral_movement`, `reconnaissance`, `insider_threat`, `denial_of_service` |
| `assigned_team` | enum | `malware_ops`, `network_security`, `identity_security`, `data_protection`, `threat_intel` |
| `recommended_action` | enum | `escalate`, `isolate_host`, `block_ip`, `reset_credentials`, `monitor`, `close` |
| `confidence` | float | 0.0 — 1.0 |
| `campaign_id` | string? | Group related alerts (hard mode) |
| `attack_chain_position` | int? | Kill chain position 1-5 (hard mode) |

## Reward Shaping
Each triage action is scored across multiple dimensions:
- **Classification** (25%): Exact match with ground truth
- **Severity** (15%): Exact match or 5% for adjacent
- **Category** (15%): Exact match
- **Assigned Team** (15%): Exact match
- **Action** (15%): Exact match
- **Campaign ID** (10%): Correct grouping (hard mode)
- **Kill Chain** (15%): Correct ordering (hard mode)
- **Time Penalty**: Small penalty per step to encourage efficiency

## API Endpoints
- `POST /reset` — Reset environment for a task
- `POST /step` — Submit a triage action
- `GET /state` — Get current environment state
- `GET /tasks` — List available tasks
- `POST /grader` — Grade a completed episode
- `POST /baseline` — Run baseline inference
            """)

    return demo
