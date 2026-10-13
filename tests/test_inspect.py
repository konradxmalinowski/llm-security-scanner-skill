"""Attack-surface inspection: activation conditions and per-shape classification.

These are the tests that decide whether the skill engages at all, so a false
negative here means a real LLM app goes unscanned and a false positive means a
pointless scan.
"""

from __future__ import annotations

from pathlib import Path

from llm_scanner_skill.inspect import inspect_project


def _write(root: Path, name: str, content: str) -> None:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class TestActivation:
    def test_non_llm_project_is_not_applicable(self, tmp_path: Path) -> None:
        """The skill must decline rather than scan a plain web app."""
        _write(tmp_path, "app.py", "from flask import Flask\napp = Flask(__name__)\n")
        _write(tmp_path, "requirements.txt", "flask\nsqlalchemy\n")
        s = inspect_project(tmp_path)
        assert not s.is_llm_application
        assert s.scan_readiness == "not_applicable"
        assert "No LLM SDK" in s.next_steps[0]

    def test_empty_project(self, tmp_path: Path) -> None:
        s = inspect_project(tmp_path)
        assert not s.is_llm_application
        assert s.scan_readiness == "not_applicable"

    def test_nonexistent_path(self, tmp_path: Path) -> None:
        s = inspect_project(tmp_path / "nope")
        assert s.scan_readiness == "not_ready"
        assert s.notes

    def test_openai_sdk_is_detected(self, tmp_path: Path) -> None:
        _write(tmp_path, "svc.py", "from openai import OpenAI\nclient = OpenAI()\n")
        s = inspect_project(tmp_path)
        assert s.is_llm_application
        assert s.features["llm_sdk"]


class TestShapeClassification:
    def test_chatbot(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "app.py",
            """
from flask import Flask, request, jsonify
from openai import OpenAI
app = Flask(__name__)
SYSTEM_PROMPT = "You are a helpful bot."

@app.post("/chat")
def chat():
    data = request.get_json()
    prompt = data.get("prompt", "")
    return jsonify({"response": call_model(SYSTEM_PROMPT, prompt)})
""",
        )
        s = inspect_project(tmp_path)
        assert s.application_kind == "chatbot_or_llm_api"
        assert s.confidence == "high"
        assert s.features["user_controlled_prompt"]
        assert s.features["system_prompt"]
        assert "LLM01" in s.recommended_categories
        assert "LLM07" in s.recommended_categories

    def test_rag(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "rag.py",
            """
import chromadb
from langchain.vectorstores import Chroma
from langchain_community.document_loaders import PyPDFLoader

def answer(q):
    docs = store.similarity_search(q)
    return llm.invoke(build_prompt(docs, q))
""",
        )
        s = inspect_project(tmp_path)
        assert s.application_kind == "rag_application"
        assert s.features["rag_retrieval"] and s.features["vector_db"]
        assert "LLM08" in s.recommended_categories
        assert "LLM04" in s.recommended_categories

    def test_tool_using_agent(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "agent.py",
            """
import subprocess
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.tools import tool

@tool
def run_cmd(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
""",
        )
        s = inspect_project(tmp_path)
        assert s.application_kind == "tool_using_agent"
        assert s.features["tool_calling"] and s.features["autonomous_action"]
        assert "LLM06" in s.recommended_categories
        assert "LLM05" in s.recommended_categories
        assert any("sandbox" in step.lower() for step in s.next_steps)

    def test_mcp_server(self, tmp_path: Path) -> None:
        _write(tmp_path, "server.py", "from mcp.server import MCPServer\nserver = MCPServer()\n")
        s = inspect_project(tmp_path)
        assert s.application_kind == "mcp_server_or_client"
        assert "LLM06" in s.recommended_categories
        assert "LLM03" in s.recommended_categories

    def test_multi_agent(self, tmp_path: Path) -> None:
        _write(tmp_path, "crew.py", "from crewai import Crew\ncrew = Crew(agents=[])\n")
        s = inspect_project(tmp_path)
        assert s.application_kind == "multi_agent_system"

    def test_sdk_without_endpoint(self, tmp_path: Path) -> None:
        _write(tmp_path, "lib.py", "import ollama\nresp = ollama.chat(model='x', messages=[])\n")
        s = inspect_project(tmp_path)
        assert s.application_kind in {"llm_integration", "llm_api"}
        assert any("ollama" in step for step in s.next_steps)


class TestEvidence:
    def test_signals_carry_file_and_line(self, tmp_path: Path) -> None:
        _write(tmp_path, "a.py", "# line1\n# line2\nfrom openai import OpenAI\n")
        s = inspect_project(tmp_path)
        sig = next(x for x in s.signals if x.feature == "llm_sdk")
        assert sig.file == "a.py"
        assert sig.line == 3
        assert "openai" in sig.excerpt

    def test_rationale_explains_every_recommended_category(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "app.py",
            """
from openai import OpenAI
from flask import request
@app.post("/chat")
def chat():
    return reply(request.get_json().get("prompt"))
""",
        )
        s = inspect_project(tmp_path)
        for category in s.recommended_categories:
            assert s.category_rationale.get(category), f"{category} has no rationale"

    def test_missing_controls_reported(self, tmp_path: Path) -> None:
        _write(tmp_path, "app.py", "from openai import OpenAI\n@app.post('/chat')\ndef c(): ...\n")
        s = inspect_project(tmp_path)
        joined = " ".join(s.missing_controls)
        assert "rate_limiting" in joined
        assert "auth_present" in joined

    def test_present_controls_are_not_flagged(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "app.py",
            """
from openai import OpenAI
from slowapi import Limiter
import bleach
from fastapi import Depends
def get_current_user(): ...

@app.post("/chat")
def chat(user = Depends(get_current_user)):
    return bleach.clean(reply())
""",
        )
        s = inspect_project(tmp_path)
        assert s.features["rate_limiting"]
        assert s.features["output_validation"]
        assert s.features["auth_present"]
        assert s.missing_controls == []


class TestEndpointInference:
    def test_route_and_port_combine(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "app.py",
            """
from openai import OpenAI
@app.post("/chat")
def chat(): ...
if __name__ == "__main__":
    app.run(port=5000)
""",
        )
        s = inspect_project(tmp_path)
        assert "http://localhost:5000/chat" in s.candidate_endpoints

    def test_non_llm_routes_are_ignored(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "app.py",
            """
from openai import OpenAI
@app.post("/healthz")
def health(): ...
@app.post("/billing/invoice")
def invoice(): ...
""",
        )
        s = inspect_project(tmp_path)
        assert not any("healthz" in e or "invoice" in e for e in s.candidate_endpoints)


class TestSafety:
    def test_vendored_dirs_are_skipped(self, tmp_path: Path) -> None:
        """A dependency's own LLM code must not make the project an LLM app."""
        _write(tmp_path, "node_modules/pkg/index.js", "import OpenAI from 'openai'\n")
        _write(tmp_path, ".venv/lib/x.py", "from openai import OpenAI\n")
        _write(tmp_path, "main.py", "print('hello')\n")
        s = inspect_project(tmp_path)
        assert not s.is_llm_application

    def test_project_code_is_never_executed(self, tmp_path: Path) -> None:
        """Static read only. If this imported the file, the marker would appear."""
        marker = tmp_path / "EXECUTED"
        _write(
            tmp_path,
            "evil.py",
            f"from openai import OpenAI\nopen({str(marker)!r}, 'w').write('x')\n",
        )
        inspect_project(tmp_path)
        assert not marker.exists()

    def test_oversized_files_skipped(self, tmp_path: Path) -> None:
        _write(tmp_path, "huge.json", "x" * 600_000)
        _write(tmp_path, "main.py", "print(1)\n")
        s = inspect_project(tmp_path)
        assert s.files_scanned == 1

    def test_binary_and_unknown_suffixes_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "blob.bin").write_bytes(b"\x00\x01from openai import OpenAI")
        s = inspect_project(tmp_path)
        assert not s.is_llm_application

    def test_llm10_never_auto_recommended(self, tmp_path: Path) -> None:
        """DoS probes require consent, so they are never suggested by default."""
        _write(
            tmp_path,
            "app.py",
            """
from openai import OpenAI
from flask import request
@app.post("/chat")
def chat(): return reply(request.get_json().get("prompt"))
""",
        )
        s = inspect_project(tmp_path)
        assert "LLM10" not in s.recommended_categories

    def test_undecodable_bytes_do_not_crash(self, tmp_path: Path) -> None:
        (tmp_path / "weird.py").write_bytes(b"\xff\xfe from openai import OpenAI\n")
        s = inspect_project(tmp_path)
        assert isinstance(s.files_scanned, int)


def test_result_serializes(tmp_path: Path) -> None:
    import json

    (tmp_path / "a.py").write_text("from openai import OpenAI\n", encoding="utf-8")
    data = json.loads(inspect_project(tmp_path).to_json())
    assert data["schema_version"] == "1.0"
    assert "features" in data and "signals" in data
