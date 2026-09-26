# Autonomous Red Team

A Python reconnaissance and vulnerability-intelligence agent for authorized security assessments. It coordinates discovery tools, maintains session state, enriches findings with an optional Ollama-compatible model, and writes human-readable reports.

## Capabilities

- Subdomain, service, endpoint, and technology discovery.
- Planner → executor → analyzer workflow.
- Optional LLM-assisted finding enrichment.
- Persistent session state and structured reports.
- Configurable timeouts, retries, and iteration limits.

## Architecture

```text
main.py
 ├─ core/       configuration, logging, state, LLM adapter
 ├─ agent/      planner, executor, analyzer
 ├─ tools/      subfinder, nmap, httpx, and ffuf wrappers
 └─ reporting/  final report generation
```

## Setup

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
```

Install the external tools used by the configured workflow (`subfinder`, `nmap`, `httpx`, and `ffuf`) and ensure they are available on `PATH`.

## Run

```powershell
python main.py example.com
```

Optional Ollama settings are controlled through `core/config.py` and environment variables such as `OLLAMA_URL`, `OLLAMA_MODEL`, `MAX_ITERATIONS`, and `COMMAND_TIMEOUT`.

## Safety

Use only against systems you own or are explicitly authorized to test. Keep scans within written scope, avoid disruptive options against production systems, and treat collected findings and logs as sensitive.

## License

See [LICENSE](LICENSE) if present.
