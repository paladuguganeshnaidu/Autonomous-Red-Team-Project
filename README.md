# Autonomous Red Team

Autonomous Red Team is a Python-based reconnaissance and vulnerability intelligence agent for authorized security assessments.
It automates reconnaissance, prioritizes actions with a planner, enriches findings with LLM analysis, and produces a practical human-readable report.

## Features

- Autonomous planning loop (`planner -> executor -> analyzer`)
- Recon collection for:
  - subdomains
  - open ports/services
  - web endpoints/technology signals
- LLM-assisted vulnerability reasoning (Ollama-compatible)
- Actionable report generation with:
  - vulnerability breakdown
  - security weakness mapping
  - practical next steps
- Persistent session state for iterative runs

## Architecture (Text Diagram)

```
main.py
  |
  +--> core/config.py          (runtime configuration)
  +--> core/logger.py          (session logging)
  +--> core/state_manager.py   (state persistence)
  +--> agent/planner.py        (next action selection)
  +--> agent/executor.py       (tool execution wrapper)
  +--> agent/analyzer.py       (state merge + vuln enrichment)
  +--> tools/subdomain_tool.py (subfinder wrapper)
  +--> tools/nmap_tool.py      (nmap wrapper)
  +--> tools/httpx_tool.py     (httpx + header posture checks)
  +--> tools/dirsearch_tool.py (ffuf-based directory discovery)
  +--> reporting/report_generator.py (final actionable report)
```

## Project Layout

```
autonomous_red_team/
|
|-- core/
|   |-- config.py
|   |-- logger.py
|   |-- llm.py
|   |-- state_manager.py
|
|-- agent/
|   |-- planner.py
|   |-- executor.py
|   |-- analyzer.py
|
|-- tools/
|   |-- nmap_tool.py
|   |-- subdomain_tool.py
|   |-- httpx_tool.py
|   |-- dirsearch_tool.py
|
|-- reporting/
|   |-- report_generator.py
|
|-- memory/
|   `-- session.json
|
|-- logs/
|   `-- session.log
|
|-- reports/
|   `-- final_report.txt
|
|-- wordlists/
|   `-- fuzz_wordlist.txt
|
|-- main.py
|-- requirements.txt
|-- .gitignore
`-- README.md
```

## Setup

1. Create and activate a Python environment.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies.

```powershell
pip install -r requirements.txt
```

3. Ensure external tools are installed and available in PATH:

- `subfinder`
- `nmap`
- `httpx`
- `ffuf`

4. Optional LLM setup (for vulnerability enrichment):

- Start Ollama locally
- Pull the configured model (default: `mistral`)

5. Run the agent:

```powershell
python main.py example.com
```

## Example Report Output

```text
==============================
AUTONOMOUS RED TEAM REPORT
==========================

Target: example.com

--- Recon Summary ---
Subdomains: 2
Open Ports: 4
Services: 5
Endpoints: 3

--- Vulnerabilities Found ---
[MEDIUM] Sensitive path exposure candidate
Target: example.com
Evidence: Discovered path 'admin?param' with status 200
...
```

## Configuration Notes

Runtime settings are controlled in `core/config.py` and by environment variables.
Common settings:

- `MAX_ITERATIONS`
- `COMMAND_TIMEOUT`
- `COMMAND_RETRIES`
- `OLLAMA_URL`
- `OLLAMA_MODEL`
- `LLM_TIMEOUT`
- `DIRSEARCH_WORDLIST`

## Disclaimer

This project is for educational use and authorized security testing only.
Do not scan or test systems without explicit written permission.
The authors and users are responsible for legal and ethical usage.
