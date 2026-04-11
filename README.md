# Autonomous Recon Agent

Autonomous reconnaissance pipeline for a target IP/domain:
1. LLM plans a powerful command batch for the iteration
2. All commands run automatically
3. All responses are aggregated and analyzed by LLM
4. LLM plans deeper commands for the next round
5. Repeat for exactly 4 iterations
6. Generate final intelligence report and vulnerability text summary

## Features

- Autonomous iterative workflow (no per-step manual input)
- AI-planned command batches per iteration (not single-command loop)
- Tool planner powered by local Ollama model
- Per-iteration analysis over combined command evidence
- Run-scoped SQLite memory (history isolated per run)
- Fixed 4-iteration autonomous depth
- In-scope URL/host filtering to avoid drifting to unrelated external domains
- Final synthesized report plus clear vulnerabilities text file

## Requirements

- Windows
- Python 3.9+
- Ollama running locally
- Installed tools:
	- nmap
	- ffuf
	- nuclei
	- subfinder

## Install

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
ollama pull mistral
```

## Configure

Edit [config.py](config.py) and verify:
- `OLLAMA_URL`
- `OLLAMA_MODEL`
- `REQUIRE_LLM` (default: True)
- `NMAP_PATH`
- `FFUF_PATH`
- `NUCLEI_PATH`
- `SUBFINDER_PATH`
- `MAX_ITERATIONS` (default: 4)
- `MIN_ITERATIONS` (default: 4)

The project auto-selects a valid wordlist from [wordlists/Wordlists](wordlists/Wordlists).

## Run

```bash
python main.py testphp.vulnweb.com
```

Or run without arguments and type target interactively:

```bash
python main.py
```

## Output

- SQLite database: `redteam.db`
- Markdown report: [output](output)
- Vulnerability text summary: `output/vulns_<target>.txt`

Each run gets a unique run ID. Reports and memory are generated only from that run, not mixed with old runs.

Reports now include:
- Tool usage summary (success/failure/timeout)
- Consolidated risk signals
- Confidence and overall risk rating
- Structured vulnerability candidates with severity, evidence, and recommendation

## Project Flow

- [main.py](main.py): orchestrates full autonomous loop
- [decision_engine.py](decision_engine.py): LLM batch planning, aggregated analysis, final synthesis
- [executor.py](executor.py): command execution with timeout and output capture
- [recon.py](recon.py): target normalization helpers
- [memory.py](memory.py): run-scoped persistence
- [reporter.py](reporter.py): final markdown + vulnerability text report generation