"""The authorization gate. These are the tests that keep this a defensive tool."""

from __future__ import annotations

import pytest

from llm_scanner_skill.authz import TargetClass, authorize, classify_target


class TestClassification:
    @pytest.mark.parametrize(
        "target",
        [
            "http://localhost:8000/chat",
            "http://127.0.0.1:5000/chat",
            "https://localhost/api",
            "http://[::1]:8080/chat",
        ],
    )
    def test_loopback(self, target: str) -> None:
        cls, _ = classify_target(target, "url")
        assert cls is TargetClass.LOOPBACK

    @pytest.mark.parametrize(
        "target", ["http://10.0.0.5:8000/chat", "http://192.168.1.10/chat", "http://172.16.4.2/x"]
    )
    def test_private(self, target: str) -> None:
        cls, _ = classify_target(target, "url")
        assert cls is TargetClass.PRIVATE

    def test_public_ip_is_external(self) -> None:
        cls, _ = classify_target("http://93.184.216.34/chat", "url")
        assert cls is TargetClass.EXTERNAL

    def test_ollama_model_name(self) -> None:
        cls, _ = classify_target("mistral:7b", "ollama")
        assert cls is TargetClass.OLLAMA_LOCAL

    def test_ollama_type_with_a_url_is_not_local(self) -> None:
        """A URL passed as an ollama target is a mistake, not a local model."""
        cls, warnings = classify_target("http://evil.example.com", "ollama")
        assert cls is TargetClass.UNKNOWN
        assert warnings

    def test_unresolvable_host_is_unknown_not_local(self) -> None:
        """Ambiguity must resolve AGAINST scanning."""
        cls, warnings = classify_target(
            "http://this-host-does-not-exist-32kj4h.invalid/chat", "url"
        )
        assert cls is TargetClass.UNKNOWN
        assert any("could not be resolved" in w for w in warnings)

    def test_empty_target(self) -> None:
        cls, _ = classify_target("", "url")
        assert cls is TargetClass.UNKNOWN

    def test_production_marker_warns(self) -> None:
        _, warnings = classify_target("http://api.prod.corp-internal.invalid/chat", "url")
        assert any("production" in w.lower() for w in warnings)

    def test_nonprod_marker_suppresses_production_warning(self) -> None:
        _, warnings = classify_target("http://api.staging.corp.invalid/chat", "url")
        assert not any("production host" in w for w in warnings)


class TestGate:
    def test_loopback_needs_no_ack(self) -> None:
        d = authorize("http://localhost:8000/chat", "url")
        assert d.allowed and not d.requires_ack

    def test_local_ollama_needs_no_ack(self) -> None:
        assert authorize("mistral:7b", "ollama").allowed

    def test_private_is_refused_without_ack(self) -> None:
        d = authorize("http://10.0.0.5:8000/chat", "url")
        assert not d.allowed
        assert d.requires_ack

    def test_private_allowed_with_ack(self) -> None:
        assert authorize("http://10.0.0.5:8000/chat", "url", authorized=True).allowed

    def test_external_is_refused_without_ack(self) -> None:
        d = authorize("http://93.184.216.34/chat", "url")
        assert not d.allowed and d.requires_ack

    def test_external_with_ack_warns_about_scope(self) -> None:
        d = authorize("http://93.184.216.34/chat", "url", authorized=True)
        assert d.allowed
        assert any("EXTERNAL" in w for w in d.warnings)

    @pytest.mark.parametrize(
        "target",
        [
            "https://api.openai.com/v1/chat/completions",
            "https://api.anthropic.com/v1/messages",
            "https://generativelanguage.googleapis.com/v1/models",
            "https://api.mistral.ai/v1/chat",
            "https://api.groq.com/openai/v1/chat",
            "https://bedrock-runtime.bedrock.amazonaws.com/invoke",
        ],
    )
    def test_third_party_providers_refused(self, target: str) -> None:
        d = authorize(target, "url")
        assert not d.allowed
        assert "third-party model provider" in d.reason

    @pytest.mark.parametrize(
        "target",
        ["https://api.openai.com/v1/chat/completions", "https://api.anthropic.com/v1/messages"],
    )
    def test_provider_refusal_survives_authorization(self, target: str) -> None:
        """A user saying 'I'm authorized' cannot unlock someone else's API."""
        d = authorize(target, "url", authorized=True)
        assert not d.allowed
        assert not d.requires_ack, "a hard refusal must not invite an acknowledgement"

    def test_dos_needs_ack_even_on_localhost(self) -> None:
        d = authorize("http://localhost:8000/chat", "url", include_dos_tests=True)
        assert not d.allowed
        assert "LLM10" in d.reason

    def test_dos_allowed_with_ack_and_warns(self) -> None:
        d = authorize("http://localhost:8000/chat", "url", authorized=True, include_dos_tests=True)
        assert d.allowed
        assert any("degrade or exhaust" in w for w in d.warnings)

    def test_unknown_target_refused_without_ack(self) -> None:
        d = authorize("http://nonexistent-7h3k2j.invalid/chat", "url")
        assert not d.allowed and d.requires_ack

    def test_decision_serializes(self) -> None:
        d = authorize("http://localhost:8000/chat", "url").to_dict()
        assert set(d) == {"allowed", "target_class", "reason", "requires_ack", "warnings"}
        assert isinstance(d["target_class"], str)
