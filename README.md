---
title: SOC Alert Triage Environment
emoji: 🛡
colorFrom: red
colorTo: blue
sdk: docker
pinned: false
app_port: 8000
base_path: /web
tags:
  - openenv
---

# SOC Alert Triage Environment

An OpenEnv RL environment simulating a **Security Operations Center (SOC)** where an AI agent acts as a Tier 1 analyst triaging incoming security alerts from a SIEM system.

## Overview

The agent receives security alerts with MITRE ATT&CK annotations, raw log excerpts, and contextual descriptions. It must classify each alert, assess severity, identify the threat category, route to the correct team, and recommend a response action. Advanced tasks require identifying coordinated attack campaigns across multiple correlated alerts.

## Tasks

| Task ID | Difficulty | Alerts | Max Steps | Description |
|---------|-----------|--------|-----------|-------------|
| `easy_single_alert` | Easy | 1 | 1 | Triage a single alert: classify, assign severity, category, team, and action |
| `medium_queue_triage` | Medium | 10 | 12 | Triage a queue of 10 alerts with mixed true/false positives. Prioritize critical alerts |
| `hard_campaign_detection` | Hard | 15 | 20 | Triage 15 alerts and identify a 5-alert coordinated attack campaign with kill chain ordering |

## Action Space

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `alert_id` | string | Yes | ID of the alert being triaged |
| `classification` | string | Yes | `true_positive`, `false_positive`, `benign`, `suspicious` |
| `severity` | string | Yes | `low`, `medium`, `high`, `critical` |
| `category` | string | Yes | `malware`, `phishing`, `brute_force`, `data_exfiltration`, `lateral_movement`, `reconnaissance`, `insider_threat`, `denial_of_service` |
| `assigned_team` | string | Yes | `malware_ops`, `network_security`, `identity_security`, `data_protection`, `threat_intel` |
| `recommended_action` | string | Yes | `escalate`, `isolate_host`, `block_ip`, `reset_credentials`, `monitor`, `close` |
| `confidence` | float | No | Agent's self-assessed confidence (0.0-1.0) |
| `notes` | string | No | Reasoning or justification |
| `campaign_id` | string | No | Campaign identifier to group related alerts (hard task) |
| `attack_chain_position` | int | No | Position in attack kill chain, 1-based (hard task) |

## Observation Space

Each observation contains:
- **alerts**: List of alert objects with `alert_id`, `timestamp`, `alert_type`, `source`, `mitre_tactic`, `mitre_technique`, `description`, and `raw_log`
- **alert_count**: Number of alerts in the current queue
- **time_elapsed**: Simulated time elapsed
- **triage_history**: History of previous triage decisions
- **task_id** / **task_description**: Current task info
- **feedback**: Natural language feedback on the last action

## Scoring

Grading is deterministic and based on field-level accuracy against ground truth:

- **Easy**: 30% classification + 20% severity + 20% category + 15% team + 15% action
- **Medium**: 60% field accuracy + 20% coverage + 20% priority ordering (critical alerts first)
- **Hard**: 40% field accuracy + 15% coverage + 25% campaign detection F1 + 20% kill chain ordering

## Quick Start

```python
import requests

BASE = "http://localhost:8000"

# List available tasks
tasks = requests.get(f"{BASE}/tasks").json()

# Reset environment with a specific task
obs = requests.post(f"{BASE}/reset", json={
    "seed": 42,
    "task_id": "easy_single_alert"
}).json()

# Triage the alert
alert = obs["observation"]["alerts"][0]
result = requests.post(f"{BASE}/step", json={
    "action": {
        "alert_id": alert["alert_id"],
        "classification": "false_positive",
        "severity": "low",
        "category": "malware",
        "assigned_team": "malware_ops",
        "recommended_action": "close"
    }
}).json()

# Grade an episode
score = requests.post(f"{BASE}/grader", json={
    "task_id": "easy_single_alert",
    "seed": 42,
    "triage_history": [{
        "alert_id": alert["alert_id"],
        "classification": "false_positive",
        "severity": "low",
        "category": "malware",
        "assigned_team": "malware_ops",
        "recommended_action": "close"
    }]
}).json()
print(f"Score: {score['score']}")
```

## API Endpoints

### Core OpenEnv Endpoints
- `GET /health` — Server health check
- `GET /metadata` — Environment metadata
- `GET /schema` — Action/Observation/State JSON schemas
- `POST /reset` — Reset environment (accepts `seed`, `task_id`)
- `POST /step` — Submit a triage action
- `GET /state` — Current environment state
- `WS /ws` — WebSocket for stateful sessions

### Custom Hackathon Endpoints
- `GET /tasks` — List all tasks with action schema
- `POST /grader` — Deterministic grading of an episode
- `POST /baseline` — Run baseline LLM inference (requires OPENAI_API_KEY)

## Local Development

```bash
# Install dependencies
pip install openenv-core[core] openai

# Start server
cd soc_alert_env
PYTHONPATH=. uvicorn server.app:app --host 127.0.0.1 --port 8000

# Validate
openenv validate
openenv validate --url http://localhost:8000
```

## Docker

```bash
docker build -t soc-alert-env:latest -f server/Dockerfile .
docker run -p 8000:8000 soc-alert-env:latest
```

## Deploy to Hugging Face Spaces

```bash
openenv push
```

## Project Structure

```
soc_alert_env/
├── __init__.py            # Module exports
├── README.md              # This file
├── openenv.yaml           # OpenEnv manifest
├── pyproject.toml         # Project metadata and dependencies
├── uv.lock                # Locked dependencies
├── client.py              # SocAlertEnv client
├── models.py              # Action, Observation, State models
├── alerts.py              # Alert templates and scenario generators
├── graders.py             # Deterministic grading functions
├── baseline.py            # LLM baseline inference script
├── inference.py           # Mandatory LLM inference script
├── Dockerfile             # Root-level container image definition
└── server/
    ├── __init__.py
    ├── soc_alert_env_environment.py  # Core environment logic
    ├── app.py             # FastAPI application
    ├── Dockerfile         # Container image (used by openenv push)
    └── requirements.txt   # Server dependencies
```
