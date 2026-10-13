"""Maps a local project's LLM attack surface, before anything is scanned.

Why this runs first
-------------------
"Scan my app for LLM vulnerabilities" is not actionable on its own. The scanner
needs a reachable target and a target type, and firing 51 adversarial payloads at
a project that has no LLM in it is pure waste. So the skill's first step is to
read the repository and answer three questions:

- Is there an LLM component at all?
- What shape is it (chatbot, RAG, tool-using agent, MCP server, batch pipeline)?
- Which OWASP LLM categories are actually relevant to *that* shape?

The result is evidence-based: every signal carries the file and line that produced
it, so an agent reports "LLM06 matters here because `agent.py:42` binds a shell
tool" rather than guessing.

This is static, read-only detection by design. It never imports or executes
project code -- the project is untrusted input.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AttackSurface",
    "Signal",
    "SurfaceFeature",
    "inspect_project",
]

# Directories never worth reading: vendored code, build output, VCS metadata.
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "target",
        "vendor",
        ".terraform",
        ".tox",
        "site-packages",
        ".gradle",
        ".idea",
        ".vscode",
        "coverage",
        ".cache",
        ".worktrees",
    }
)

_TEXT_SUFFIXES: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".mjs",
        ".cjs",
        ".go",
        ".rs",
        ".rb",
        ".java",
        ".kt",
        ".cs",
        ".php",
        ".yaml",
        ".yml",
        ".toml",
        ".json",
        ".md",
        ".txt",
        ".env",
        ".sh",
        ".ipynb",
        ".tf",
        ".prompt",
        ".jinja",
        ".j2",
    }
)

# Files bigger than this are skipped: a multi-megabyte lockfile or data dump has
# no signal worth the read cost.
_MAX_FILE_BYTES = 512_000
_MAX_FILES = 4000


class SurfaceFeature(BaseModel):
    """One detected capability of the target application."""

    model_config = ConfigDict(extra="forbid")

    name: str
    present: bool = False
    signals: list[str] = Field(default_factory=list)


class Signal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feature: str
    file: str
    line: int
    excerpt: str


# (feature, regex, note). Patterns are deliberately conservative -- a false
# positive here sends an agent down the wrong remediation path.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "llm_sdk",
        re.compile(
            r"\b(?:from|import)\s+(?:openai|anthropic|ollama|cohere|mistralai|google\.generativeai|google\.genai)\b|\bfrom\s+['\"](?:openai|@anthropic-ai/sdk|ollama)['\"]|require\(['\"](?:openai|ollama)['\"]\)"
        ),
    ),
    (
        "llm_framework",
        re.compile(
            r"\b(?:from|import)\s+(?:langchain|langchain_\w+|llama_index|llamaindex|haystack|semantic_kernel|dspy|autogen|crewai|langgraph|pydantic_ai)\b|from\s+['\"](?:langchain|llamaindex|@langchain/\w+|ai)['\"]"
        ),
    ),
    (
        "chat_completion_call",
        re.compile(
            r"\.(?:chat\.completions\.create|messages\.create|generate_content|chat)\s*\(|\bgenerateText\s*\(|\bstreamText\s*\("
        ),
    ),
    (
        "http_llm_endpoint",
        re.compile(
            r"@(?:app|router)\.(?:post|route)\s*\(\s*['\"][^'\"]*(?:chat|completion|ask|query|prompt|message|generate|agent|rag)|app\.post\s*\(\s*['\"][^'\"]*(?:chat|completion|ask|query|prompt|message|generate|agent)"
        ),
    ),
    (
        "system_prompt",
        re.compile(
            r"['\"]role['\"]\s*:\s*['\"]system['\"]|\bSYSTEM_PROMPT\b|\bsystem_prompt\b|\bsystemPrompt\b|\bSystemMessage\s*\("
        ),
    ),
    (
        "user_controlled_prompt",
        re.compile(
            r"""(
                  (?:request|req)\s*\.\s*(?:get_json|json)\b          # Flask/FastAPI body read
                | (?:request|req|body|params|query|form|args|data|payload)
                  \s*(?:\.|\[\s*['"])
                  (?:prompt|message|question|query|input|text|q|content|user_input)\b
                | \.get\(\s*['"](?:prompt|message|question|query|input|text|user_input)['"]
                | \bawait\s+(?:req|request)\.json\(\)
            )""",
            re.VERBOSE,
        ),
    ),
    (
        "rag_retrieval",
        re.compile(
            r"\b(?:similarity_search|as_retriever|RetrievalQA|VectorStoreIndex|query_engine|retrieve|rerank|embed_query|embeddings\.create)\b|\bRAG\b"
        ),
    ),
    (
        "vector_db",
        re.compile(
            r"\b(?:chromadb|pinecone|weaviate|qdrant|milvus|faiss|pgvector|lancedb|opensearchpy|elasticsearch)\b|\bCREATE\s+EXTENSION\s+vector\b"
        ),
    ),
    (
        "document_ingestion",
        re.compile(
            r"\b(?:PyPDFLoader|UnstructuredFileLoader|WebBaseLoader|DirectoryLoader|SimpleDirectoryReader|TextLoader|RecursiveCharacterTextSplitter|load_and_split)\b|\bpdfplumber\b|\bPyPDF2\b"
        ),
    ),
    (
        "tool_calling",
        # NOTE: the `@tool` decorator must NOT sit behind a \b. At the start of a line
        # the preceding character is a newline and `@` is itself a non-word character,
        # so there is no word boundary between them and `\b@tool` can never match --
        # which silently missed every LangChain `@tool` definition.
        re.compile(
            r"""(
                  \b(?:tool_choice|function_call|tool_calls|StructuredTool|FunctionTool
                      |bind_tools|ToolNode|tool_registry)\b
                | \btools\s*=\s*\[
                | (?:^|[^\w.])@tool\b
                | \bfrom\s+langchain_core\.tools\s+import\b
                | ['"]type['"]\s*:\s*['"]function['"]
            )""",
            re.VERBOSE | re.MULTILINE,
        ),
    ),
    (
        "mcp_integration",
        re.compile(
            r"\b(?:mcp\.server|FastMCP|ClientSession|modelcontextprotocol|@modelcontextprotocol/sdk|StdioServerParameters)\b|['\"]mcpServers['\"]"
        ),
    ),
    (
        "agent_loop",
        re.compile(
            r"\b(?:AgentExecutor|create_react_agent|initialize_agent|create_tool_calling_agent|StateGraph|CrewAI|Crew\s*\(|AssistantAgent|ReActAgent)\b"
        ),
    ),
    (
        "multi_agent",
        re.compile(
            r"\b(?:GroupChat|CrewAI|Crew\s*\(|multi_agent|handoff|swarm|AgentTeam|delegate_to)\b"
        ),
    ),
    (
        "memory",
        re.compile(
            r"\b(?:ConversationBufferMemory|ConversationSummaryMemory|ChatMessageHistory|checkpointer|MemorySaver|conversation_history|chat_history)\b"
        ),
    ),
    (
        "file_upload",
        re.compile(
            r"\b(?:UploadFile|request\.files|multer|FormData|multipart/form-data|files\.create)\b"
        ),
    ),
    (
        "autonomous_action",
        re.compile(
            r"\b(?:subprocess\.(?:run|Popen|call)|os\.system|exec\s*\(|eval\s*\(|child_process|shell=True)\b"
        ),
    ),
    (
        "external_data_access",
        re.compile(
            r"\b(?:requests\.get|httpx\.(?:get|post)|urllib\.request|fetch\s*\(|axios\.(?:get|post))\b"
        ),
    ),
    (
        "database_access",
        re.compile(
            r"\b(?:psycopg2?|sqlalchemy|asyncpg|pymongo|mysql\.connector|sqlite3|prisma|knex|mongoose)\b|\bSELECT\s+.+\s+FROM\b"
        ),
    ),
    (
        "output_rendered_raw",
        re.compile(
            r"\b(?:dangerouslySetInnerHTML|innerHTML\s*=|\|\s*safe\b|\{\{\{|markdown\.markdown|render_template_string|v-html)\b"
        ),
    ),
    (
        "secrets_in_scope",
        re.compile(
            r"\b(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|GOOGLE_API_KEY|DATABASE_URL|STRIPE_(?:SECRET|API)_KEY|GITHUB_TOKEN|SLACK_TOKEN|JWT_SECRET)\b"
        ),
    ),
    (
        "auth_present",
        re.compile(
            r"\b(?:Depends\s*\(\s*(?:get_current_user|oauth2_scheme)|@login_required|verify_jwt|requireAuth|passport\.authenticate|Authorization['\"]?\s*\]|HTTPBearer)\b"
        ),
    ),
    (
        "rate_limiting",
        re.compile(
            r"\b(?:slowapi|Limiter|rate_limit|RateLimiter|express-rate-limit|@limiter\.limit|throttle)\b"
        ),
    ),
    (
        "output_validation",
        re.compile(
            r"\b(?:bleach\.clean|DOMPurify|sanitize_html|escape\s*\(|output_parser|PydanticOutputParser|model_validate)\b"
        ),
    ),
)

# Which OWASP LLM categories a detected feature makes relevant, and why.
_FEATURE_TO_CATEGORIES: dict[str, tuple[tuple[str, str], ...]] = {
    "user_controlled_prompt": (
        ("LLM01", "User text reaches the model, so direct prompt injection is in scope."),
    ),
    "http_llm_endpoint": (
        ("LLM01", "A reachable HTTP endpoint accepts prompts -- the primary injection surface."),
    ),
    "system_prompt": (("LLM07", "A system prompt exists and can be targeted for extraction."),),
    "rag_retrieval": (
        ("LLM01", "Retrieved documents are concatenated into the prompt: indirect injection."),
        ("LLM08", "Retrieval means embedding/vector weaknesses and cross-tenant leakage apply."),
    ),
    "vector_db": (("LLM08", "A vector store is present; check tenant isolation on retrieval."),),
    "document_ingestion": (
        ("LLM01", "Ingested documents are attacker-controllable: indirect prompt injection."),
        ("LLM04", "Untrusted documents entering the index is a data-poisoning path."),
    ),
    "tool_calling": (("LLM06", "The model can invoke tools, so excessive agency is a live risk."),),
    "agent_loop": (("LLM06", "An autonomous agent loop can chain actions without human review."),),
    "multi_agent": (
        ("LLM06", "Agent-to-agent handoff propagates a single injection across the system."),
    ),
    "mcp_integration": (
        ("LLM06", "MCP tools extend the model's reach; each server is a privilege boundary."),
        ("LLM03", "Third-party MCP servers are a supply-chain dependency."),
    ),
    "autonomous_action": (
        ("LLM06", "Shell/eval reachable from model output means injection becomes execution."),
        ("LLM05", "Model output flowing into an interpreter is improper output handling."),
    ),
    "output_rendered_raw": (
        ("LLM05", "Model output is rendered unescaped -- XSS from a generated response."),
    ),
    "secrets_in_scope": (
        ("LLM02", "Credentials are in the process environment the model code can read."),
        ("LLM07", "Secrets near the system prompt can leak through prompt extraction."),
    ),
    "database_access": (
        ("LLM02", "The model's code path can reach a database holding real data."),
    ),
    "external_data_access": (
        ("LLM01", "Fetched remote content enters the prompt: indirect injection."),
    ),
    "memory": (("LLM01", "Persisted history lets an injection survive into later turns."),),
    "file_upload": (("LLM01", "Uploaded files are untrusted prompt content."),),
    "llm_framework": (("LLM03", "Framework and model dependencies are a supply-chain surface."),),
}

# Protections whose ABSENCE raises a category's priority.
_MISSING_CONTROL_NOTES: dict[str, tuple[str, str]] = {
    "rate_limiting": ("LLM10", "No rate limiting or token budget was detected."),
    "output_validation": ("LLM05", "No output sanitization or schema validation was detected."),
    "auth_present": ("LLM02", "No authentication was detected on the LLM entry point."),
}


class AttackSurface(BaseModel):
    """The inspection result an agent reasons over before configuring a scan."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    root: str
    is_llm_application: bool = False
    application_kind: str = "unknown"
    confidence: str = "low"
    features: dict[str, bool] = Field(default_factory=dict)
    signals: list[Signal] = Field(default_factory=list)
    recommended_categories: list[str] = Field(default_factory=list)
    category_rationale: dict[str, list[str]] = Field(default_factory=dict)
    missing_controls: list[str] = Field(default_factory=list)
    candidate_endpoints: list[str] = Field(default_factory=list)
    scan_readiness: str = ""
    next_steps: list[str] = Field(default_factory=list)
    files_scanned: int = 0
    notes: list[str] = Field(default_factory=list)

    def to_json(self, indent: int | None = 2) -> str:
        return self.model_dump_json(indent=indent)


_ENDPOINT_RE = re.compile(
    r"""(?:@(?:app|router)\.(?:post|route)|app\.post|router\.post)\s*\(\s*['"]([^'"]{1,120})['"]""",
)
_PORT_RE = re.compile(
    r"(?:port\s*[=:]\s*|PORT\s*[=:]\s*|localhost:|0\.0\.0\.0:|127\.0\.0\.1:)(\d{2,5})"
)


def _iter_files(root: Path) -> list[Path]:
    """Walk *root*, skipping vendored/build directories and oversized files."""
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".venv")]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() not in _TEXT_SUFFIXES:
                continue
            try:
                if p.stat().st_size > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            out.append(p)
            if len(out) >= _MAX_FILES:
                return out
    return out


def _classify_kind(features: dict[str, bool]) -> tuple[str, str]:
    """Name the application shape, which drives which workflow the skill follows."""
    if features.get("mcp_integration"):
        return "mcp_server_or_client", "high"
    if features.get("multi_agent"):
        return "multi_agent_system", "high"
    if features.get("agent_loop") or (
        features.get("tool_calling") and features.get("autonomous_action")
    ):
        return "tool_using_agent", "high"
    if features.get("rag_retrieval") or features.get("vector_db"):
        return "rag_application", "high"
    if features.get("http_llm_endpoint") and features.get("user_controlled_prompt"):
        return "chatbot_or_llm_api", "high"
    if features.get("http_llm_endpoint"):
        return "llm_api", "medium"
    if features.get("chat_completion_call") or features.get("llm_sdk"):
        return "llm_integration", "medium"
    return "unknown", "low"


def inspect_project(root: str | Path) -> AttackSurface:
    """Statically inspect *root* and return its LLM attack surface.

    Read-only: files are opened as text and pattern-matched. Nothing is imported,
    installed, or executed.
    """
    root_path = Path(root).resolve()
    surface = AttackSurface(root=str(root_path))

    if not root_path.is_dir():
        surface.notes.append(f"{root_path} is not a directory.")
        surface.scan_readiness = "not_ready"
        surface.next_steps.append("Point the inspection at a project directory.")
        return surface

    files = _iter_files(root_path)
    surface.files_scanned = len(files)
    if len(files) >= _MAX_FILES:
        surface.notes.append(
            f"Stopped after {_MAX_FILES} files; inspection may be incomplete on a repo this large."
        )

    hits: dict[str, list[Signal]] = {}
    endpoints: set[str] = set()
    ports: set[str] = set()

    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root_path))
        lines: list[str] | None = None

        for feature, pattern in _PATTERNS:
            match = pattern.search(text)
            if match is None:
                continue
            if lines is None:
                lines = text.splitlines()
            line_no = text.count("\n", 0, match.start()) + 1
            excerpt = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else match.group(0)
            bucket = hits.setdefault(feature, [])
            if len(bucket) < 4:  # a handful of examples is enough evidence
                bucket.append(
                    Signal(feature=feature, file=rel, line=line_no, excerpt=excerpt[:200])
                )

        for m in _ENDPOINT_RE.finditer(text):
            route = m.group(1)
            if any(
                k in route.lower()
                for k in (
                    "chat",
                    "completion",
                    "ask",
                    "query",
                    "prompt",
                    "message",
                    "generate",
                    "agent",
                    "rag",
                )
            ):
                endpoints.add(route)
        for m in _PORT_RE.finditer(text):
            ports.add(m.group(1))

    surface.features = {feature: feature in hits for feature, _ in _PATTERNS}
    surface.signals = [s for bucket in hits.values() for s in bucket]

    surface.is_llm_application = any(
        surface.features.get(k)
        for k in (
            "llm_sdk",
            "llm_framework",
            "chat_completion_call",
            "http_llm_endpoint",
            "mcp_integration",
        )
    )
    surface.application_kind, surface.confidence = _classify_kind(surface.features)

    rationale: dict[str, list[str]] = {}
    for feature, present in surface.features.items():
        if not present:
            continue
        for category, why in _FEATURE_TO_CATEGORIES.get(feature, ()):
            rationale.setdefault(category, []).append(f"{feature}: {why}")

    for control, (category, note) in _MISSING_CONTROL_NOTES.items():
        if surface.is_llm_application and not surface.features.get(control):
            surface.missing_controls.append(f"{control} -- {note}")
            if control != "rate_limiting":  # LLM10 stays opt-in; see below
                rationale.setdefault(category, []).append(f"missing {control}: {note}")

    surface.category_rationale = {k: sorted(set(v)) for k, v in sorted(rationale.items())}
    # LLM10 is never recommended automatically: its probes stress the target, and
    # the scanner itself requires an explicit opt-in flag.
    surface.recommended_categories = sorted(c for c in surface.category_rationale if c != "LLM10")

    surface.candidate_endpoints = sorted(
        f"http://localhost:{port}{route}"
        for route in (sorted(endpoints) or [])
        for port in (sorted(ports) or ["8000"])
    )[:12]

    surface.scan_readiness, surface.next_steps = _readiness(surface)
    return surface


def _readiness(surface: AttackSurface) -> tuple[str, list[str]]:
    """Decide whether a scan can proceed and what the operator must supply."""
    if not surface.is_llm_application:
        return "not_applicable", [
            "No LLM SDK, framework, or model call was found. This scanner tests LLM "
            "behaviour at run time and has nothing to test here.",
            "If the LLM lives in a separate service, inspect that repository instead.",
        ]

    steps: list[str] = []
    if surface.candidate_endpoints:
        steps.append(
            "Start the application locally, then scan the running endpoint with "
            f"--target {surface.candidate_endpoints[0]} --target-type url."
        )
    else:
        steps.append(
            "No HTTP prompt endpoint was detected. Either start the app and supply its "
            "URL explicitly, or scan the underlying model directly with --target-type ollama."
        )

    steps.append(
        'The endpoint must accept POST {"prompt": "..."} and return '
        '{"response": "..."} or {"message": "..."}; add a thin test adapter if it does not.'
    )
    if surface.features.get("system_prompt"):
        steps.append(
            "Pass the real system prompt with --system-prompt @path and a unique "
            "--canary token planted in it, so LLM07 leakage is detected deterministically "
            "instead of being left to the judge."
        )
    if surface.features.get("rag_retrieval") or surface.features.get("document_ingestion"):
        steps.append(
            "Use a disposable copy of the vector store: LLM08 and LLM04 probes write "
            "adversarial content that should not reach a real index."
        )
    if surface.features.get("autonomous_action"):
        steps.append(
            "Run against a sandboxed instance. Model output can reach shell/eval here, so "
            "a successful LLM06 probe could execute something real."
        )
    steps.append("Confirm with the user that they own or are authorized to test the target.")

    return "ready_with_setup", steps


def surface_to_dict(surface: AttackSurface) -> dict[str, Any]:
    """Plain-dict view, for callers that do not want the Pydantic model."""
    return surface.model_dump(mode="json")
