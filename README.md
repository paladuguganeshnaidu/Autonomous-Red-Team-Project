# Autonomous Red Team

A Python reconnaissance and vulnerability-intelligence agent for **authorized security assessments**. The project coordinates reconnaissance tools, maintains state, optionally enriches findings with an Ollama-compatible model, and produces human-readable reports.

> **Authorized-use only:** run the project only against systems you own or are explicitly authorized to test.

## Capabilities

- Subdomain discovery.
- Service and endpoint discovery.
- Technology discovery.
- Planner → executor → analyzer workflow.
- Optional LLM-assisted finding enrichment.
- Persistent session state.
- Structured reporting.
- Configurable command timeouts, retries and iteration limits.

## Architecture

```text
main.py
 ├── core/       configuration, logging, state, LLM adapter
 ├── agent/      planner, executor, analyzer
 ├── tools/      subfinder, nmap, httpx and ffuf wrappers
 └── reporting/  report generation
```

## Requirements

- Python virtual environment.
- Python dependencies from requirements.txt.
- External tools used by the configured workflow: subfinder, nmap, httpx and ffuf.
- Ollama is optional for LLM-assisted enrichment.

Install Python dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

The checked requirements.txt currently contains requests, FastAPI, Uvicorn and WebSockets. The external security tools are installed separately.

## Configuration

The repository documents settings including OLLAMA_URL, OLLAMA_MODEL, MAX_ITERATIONS and COMMAND_TIMEOUT.

Inspect core/config.py for authoritative configuration names and defaults.

Do not commit credentials or private assessment data.

## Usage

The documented entry point is:

```powershell
python main.py example.com
```

Only substitute a target that is within your written authorization scope.

## Safety

This project can invoke security-reconnaissance tooling. Safe operation therefore depends on target authorization and scan configuration.

Before an engagement:

- Define target scope and excluded hosts in writing.
- Prefer non-disruptive scan modes against production.
- Restrict timeouts and iteration limits.
- Treat reports, logs and discovered endpoints as sensitive.
- Do not use collected credentials or secrets outside the authorized assessment.

## Testing and performance

No formal coverage percentage, P95/P99 latency, throughput or production availability claim is made because those measurements are not established in the repository.

## Limitations

- Required external tools must be installed on the host.
- LLM enrichment is optional.
- Additional sandboxing, authorization, auditability and safety testing would be required before treating this as a production autonomous-security platform.
- No guarantee is made that discovery or vulnerability classification is complete or correct.

## License

No explicit open-source license is currently declared for this repository.

Until a license is added by the copyright holder, reuse remains subject to applicable copyright law.

## Author

Paladugu Ganesh Naidu

Repository: https://github.com/paladuguganeshnaidu/Autonomous-Red-Team-Project
