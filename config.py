# config.py
import os

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "mistral"   # or "llama3.2:3b"
REQUIRE_LLM = True
ALLOW_LLM_FALLBACK = True
OLLAMA_TIMEOUT = 240

MAX_ITERATIONS = 4
MIN_ITERATIONS = 4
TOOL_TIMEOUT = 120
DELAY_BETWEEN_ACTIONS = 2
HISTORY_LIMIT = 8
MAX_COMMANDS_PER_ITERATION = 3
MAX_COMMAND_TIMEOUT = 300

NMAP_PATH = "C:\\Users\\ganes\\nmap.exe"
FFUF_PATH = "C:\\Users\\ganes\\go\\bin\\ffuf.exe"
NUCLEI_PATH = "C:\\Users\\ganes\\go\\bin\\nuclei.exe"
SUBFINDER_PATH = "C:\\Users\\ganes\\go\\bin\\subfinder.exe"

BASE_DIR = os.path.dirname(__file__)

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

TOOL_PATHS = {
	"nmap": NMAP_PATH,
	"ffuf": FFUF_PATH,
	"nuclei": NUCLEI_PATH,
	"subfinder": SUBFINDER_PATH,
}

OUTPUT_PREVIEW_CHARS = 4000
ANALYSIS_INPUT_CHARS = 24000

TRACE_JSON_ENABLED = True
TRACE_OUTPUT_DIR = os.path.join(BASE_DIR, "output")
TRACE_CAPTURE_SCAN_STATE = True
TRACE_CAPTURE_ANALYSIS_INPUT = True
TRACE_CAPTURE_STDOUT_STDERR = True
