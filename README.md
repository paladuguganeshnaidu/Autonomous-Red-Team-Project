# Autonomous Red Team Project

Autonomous, iteration-based reconnaissance and analysis framework for authorized security testing.

This project runs a structured 4-iteration loop where an LLM plans command batches, executes them, aggregates evidence, and refines the next step. The result is a clean intelligence report plus vulnerability candidates and remediation guidance.

## Why This Project

- Reduces repetitive manual recon work.
- Keeps run history isolated with a run ID.
- Adds context-aware reasoning with local RAG.
- Produces report-ready output for triage and follow-up testing.

## Safety and Scope

Use this only on localhost systems or targets where you have explicit written authorization.

- No destructive testing.
- No unauthorized scanning.
- Keep scans rate-limited and evidence-based.

## Workflow at a Glance

1. Initialize run context and normalize target.
2. Perform passive recon first (when enabled).
3. Let the LLM plan a bounded command batch.
4. Execute commands with timeout and capture output.
5. Analyze combined evidence and update scan state.
6. Repeat for a fixed number of iterations (default: 4).
7. Generate final markdown report + vulnerabilities text summary.

## Core Capabilities

- Autonomous multi-step scanning loop.
- AI-planned command batches (not single-command chat loops).
- In-scope host and URL filtering to prevent drift.
- Passive-first recon mode.
- Structured findings and risk signals per iteration.
- Run-scoped memory in SQLite.
- Optional local RAG context retrieval with FAISS.

## Requirements

- Windows
- Python 3.9+
- Ollama running locally
- Installed external tools:
	- nmap
	- ffuf
	- nuclei
	- subfinder

## Quick Start

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
ollama pull mistral
python main.py
```

You can also provide a target directly:

```bash
python main.py example.com
```

## Configuration

Main runtime settings live in [config.py](config.py).

Most important values to review:

- LLM:
	- OLLAMA_URL
	- OLLAMA_MODEL
	- REQUIRE_LLM
	- ALLOW_LLM_FALLBACK
- Iteration and runtime policy:
	- MAX_ITERATIONS
	- TOOL_TIMEOUT
	- MAX_COMMANDS_PER_ITERATION
	- MAX_COMMAND_TIMEOUT
- Tool paths:
	- NMAP_PATH
	- FFUF_PATH
	- NUCLEI_PATH
	- SUBFINDER_PATH
- Scope and recon behavior:
	- PASSIVE_RECON_FIRST
	- PASSIVE_RECON_ENABLED
	- SHODAN_API_KEY (optional)
- Proxy and operational safety:
	- ENABLE_PROXY
	- PROXY_URL
	- NMAP_TIMING_TEMPLATE
- Security and data handling:
	- ENCRYPTION_ENABLED
	- REDTEAM_MASTER_KEY (via environment)
- RAG:
	- RAG_ENABLED
	- RAG_TOP_K
	- RAG_MIN_SIMILARITY
	- RAG_CHUNK_MIN_WORDS
	- RAG_CHUNK_MAX_WORDS

The project automatically picks an available wordlist from [wordlists/Wordlists](wordlists/Wordlists).

## Output

Each run creates isolated artifacts:

- Database: redteam.db
- Markdown report: [output](output)
- Vulnerability summary text: output/vulns_<target>.txt

Reports include:

- Iteration-by-iteration command chain
- Success and failure signals
- Confidence and overall risk
- Vulnerability candidates with evidence and recommendations

## RAG (Context-Aware Reasoning)

RAG helps improve planning and analysis quality by retrieving relevant local context.

Flow:

1. Chunk curated or historical text into segments.
2. Embed segments using sentence-transformers.
3. Store vectors in FAISS.
4. Retrieve top-k relevant context for planning/analysis.
5. Inject context into prompts.
6. Ingest fresh scan outputs back into the index.

RAG paths:

- Data: [rag/data](rag/data)
- Index: [rag/index](rag/index)
- Pipeline code: [rag](rag)

## Docker

```bash
docker build -t autonomous-recon .
docker run --rm autonomous-recon example.com
```

## Code Map

- [main.py](main.py): Orchestrates autonomous loop and run lifecycle.
- [decision_engine.py](decision_engine.py): Planning, analysis, and final synthesis.
- [executor.py](executor.py): Command execution, timeout, and output capture.
- [passive_recon.py](passive_recon.py): Passive intelligence collection.
- [recon.py](recon.py): Target normalization and recon helpers.
- [memory.py](memory.py): Run-scoped persistence layer.
- [reporter.py](reporter.py): Final markdown and vulnerability summary generation.
- [trace_logger.py](trace_logger.py): Trace events and run diagnostics.
- [rag/embedder.py](rag/embedder.py): Embedding service.
- [rag/vector_store.py](rag/vector_store.py): FAISS index operations.
- [rag/ingest.py](rag/ingest.py): Data ingestion and chunk pipeline.
- [rag/retriever.py](rag/retriever.py): Retrieval and relevance filtering.
- [rag/update_loop.py](rag/update_loop.py): Runtime RAG bootstrap and updates.

## Troubleshooting

- Ollama not reachable:
	- Start Ollama and verify the configured model is pulled.
- Tool access denied:
	- Re-check executable path and permissions in [config.py](config.py).
- Empty findings:
	- Increase timeout, improve wordlists, and validate target scope.
- Weak analysis quality:
	- Seed better RAG content under [rag/data](rag/data).

## How to Elevate This Repo Online

Use this checklist to make the project stand out on GitHub and in security communities.

1. Improve first impression
	 - Keep this README concise at the top with a strong one-line value proposition.
	 - Add a short demo section with one real run screenshot from [output](output).
	 - Pin this repository on your GitHub profile.
2. Increase discoverability (SEO inside GitHub)
	 - Add repository topics: autonomous-security, red-team, recon, ollama, rag, cybersecurity.
	 - Use a clear repository description in settings.
	 - Keep section headings keyword-rich (recon, vulnerability analysis, RAG).
3. Build trust and professionalism
	 - Add LICENSE, CONTRIBUTING.md, and SECURITY.md.
	 - Add a Responsible Use section with authorization requirements.
	 - Publish a roadmap with near-term milestones.
4. Show engineering quality
	 - Add unit tests for parser and state update logic.
	 - Add CI (lint + test) so visitors see passing checks.
	 - Include sample config and sample report artifacts.
5. Create momentum
	 - Post a launch thread with architecture + sample output.
	 - Share one weekly update: feature, bug fix, or benchmark.
	 - Cut versioned releases with changelog notes.

## Suggested Next Additions

- LICENSE
- CONTRIBUTING.md
- SECURITY.md
- CHANGELOG.md
- .github/workflows/ci.yml

These files substantially improve credibility for recruiters, collaborators, and open-source users.
