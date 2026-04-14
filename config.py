import os
import shutil

BASE_DIR = os.path.dirname(__file__)

# LLM / Ollama
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "mistral"   # or "llama3.2:3b"
REQUIRE_LLM = True
ALLOW_LLM_FALLBACK = True
OLLAMA_TIMEOUT = 240

# Runtime policy
MAX_ITERATIONS = 4
TOOL_TIMEOUT = 120
DELAY_BETWEEN_ACTIONS = 2
HISTORY_LIMIT = 8
MAX_COMMANDS_PER_ITERATION = 3
MAX_COMMAND_TIMEOUT = 300

# Adaptive timing
ENABLE_JITTER = True
JITTER_MIN_SEC = 0.5
JITTER_MAX_SEC = 2.5
JITTER_BETWEEN_COMMANDS = True
JITTER_BETWEEN_ITERATIONS = True

# Passive-first recon
PASSIVE_RECON_FIRST = True
PASSIVE_RECON_ENABLED = True
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")

# Scan intensity
NMAP_TIMING_TEMPLATE = "T3"  # T2 polite, T3 normal, T4 aggressive

# Proxy
ENABLE_PROXY = False
PROXY_URL = ""
PROXY_NMAP_FLAG = "--proxies"
PROXY_FFUF_FLAG = "-x"
PROXY_NUCLEI_FLAG = "--proxy"
PROXY_SUBFINDER_FLAG = "-proxy"

# Verification / feedback
VERIFY_BEFORE_LLM = True
DEAD_END_THRESHOLD = 1

# Encryption / cleanup
ENCRYPTION_ENABLED = False
MASTER_KEY_ENV = "REDTEAM_MASTER_KEY"
ENCRYPT_OUTPUTS = True
CLEANUP_AFTER_REPORT = False

# Tool resolution
def _resolve_tool(name, default_path, env_key):
    env_value = os.environ.get(env_key, "").strip()
    if env_value and os.path.exists(env_value):
        return env_value
    if default_path and os.path.exists(default_path):
        return default_path
    found = shutil.which(name) or shutil.which(f"{name}.exe")
    return found or default_path


NMAP_PATH = _resolve_tool("nmap", "C:\\Users\\ganes\\nmap.exe", "NMAP_PATH")
FFUF_PATH = _resolve_tool("ffuf", "C:\\Users\\ganes\\go\\bin\\ffuf.exe", "FFUF_PATH")
NUCLEI_PATH = _resolve_tool("nuclei", "C:\\Users\\ganes\\go\\bin\\nuclei.exe", "NUCLEI_PATH")
SUBFINDER_PATH = _resolve_tool("subfinder", "C:\\Users\\ganes\\go\\bin\\subfinder.exe", "SUBFINDER_PATH")

TOOL_PATHS = {
    "nmap": NMAP_PATH,
    "ffuf": FFUF_PATH,
    "nuclei": NUCLEI_PATH,
    "subfinder": SUBFINDER_PATH,
}

# Wordlists
WORDLIST_CANDIDATES = [
    os.path.join(BASE_DIR, "wordlists", "Wordlists", "wordlist.txt"),
    os.path.join(BASE_DIR, "wordlists", "Wordlists", "fuzz_wordlist.txt"),
    os.path.join(BASE_DIR, "wordlists", "Wordlists", "dicc.txt"),
]
WORDLIST = next((path for path in WORDLIST_CANDIDATES if os.path.exists(path)), WORDLIST_CANDIDATES[0])
FAST_WORDLIST_CANDIDATES = [
    os.path.join(BASE_DIR, "wordlists", "Wordlists", "fuzz_wordlist.txt"),
    os.path.join(BASE_DIR, "wordlists", "Wordlists", "dicc.txt"),
    WORDLIST,
]
FAST_WORDLIST = next((path for path in FAST_WORDLIST_CANDIDATES if os.path.exists(path)), FAST_WORDLIST_CANDIDATES[-1])
DEEP_WORDLIST = WORDLIST

OUTPUT_PREVIEW_CHARS = 4000
ANALYSIS_INPUT_CHARS = 24000

# RAG (Retrieval Augmented Generation)
RAG_ENABLED = True
RAG_BOOTSTRAP_ON_START = True
RAG_UPDATE_AFTER_ITERATION = True
RAG_UPDATE_AFTER_RUN = True

RAG_DIR = os.path.join(BASE_DIR, "rag")
RAG_DATA_DIR = os.path.join(RAG_DIR, "data")
RAG_INDEX_DIR = os.path.join(RAG_DIR, "index")
RAG_FAISS_INDEX_PATH = os.path.join(RAG_INDEX_DIR, "faiss.index")
RAG_METADATA_PATH = os.path.join(RAG_INDEX_DIR, "metadata.json")
RAG_INGEST_MANIFEST_PATH = os.path.join(RAG_INDEX_DIR, "manifest.json")

RAG_EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
RAG_EMBED_BATCH_SIZE = 32

RAG_CHUNK_MIN_WORDS = 200
RAG_CHUNK_MAX_WORDS = 500
RAG_CHUNK_OVERLAP_WORDS = 60

RAG_TOP_K = 5
RAG_MIN_SIMILARITY = 0.35
RAG_MAX_CONTEXT_CHARS = 6000

RAG_SOURCE_GLOBS = [
    os.path.join(BASE_DIR, "output", "*.md"),
    os.path.join(BASE_DIR, "output", "*.txt"),
    os.path.join(BASE_DIR, "output", "*.json"),
    os.path.join(BASE_DIR, "wordlists", "Wordlists", "README.md"),
    os.path.join(RAG_DATA_DIR, "**", "*.md"),
    os.path.join(RAG_DATA_DIR, "**", "*.txt"),
    os.path.join(RAG_DATA_DIR, "**", "*.json"),
]

# Trace JSON
TRACE_JSON_ENABLED = True
TRACE_OUTPUT_DIR = os.path.join(BASE_DIR, "output")
TRACE_CAPTURE_SCAN_STATE = True
TRACE_CAPTURE_ANALYSIS_INPUT = True
TRACE_CAPTURE_STDOUT_STDERR = True
