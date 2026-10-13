"""Target classification and the authorization gate.

This is the module that keeps the skill a defensive tool rather than an attack
automation front-end. An AI agent asked to "scan this" must not be able to point
51 adversarial payloads at an arbitrary host just because a URL was in scope of
the conversation.

The rule, in one sentence: anything that is not demonstrably the operator's own
local machine requires an explicit, per-invocation authorization acknowledgement,
and some targets are refused outright.

Classification is deliberately conservative -- an unresolvable or ambiguous host
is treated as EXTERNAL, not as local.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from enum import StrEnum
from urllib.parse import urlparse

__all__ = [
    "AuthorizationDecision",
    "TargetClass",
    "authorize",
    "classify_target",
]


class TargetClass(StrEnum):
    """Where a target lives, which determines how much proof of ownership is needed."""

    LOOPBACK = "loopback"
    PRIVATE = "private"
    EXTERNAL = "external"
    OLLAMA_LOCAL = "ollama_local"
    UNKNOWN = "unknown"


# Hostname fragments that suggest a production system. Matching one never blocks
# on its own -- it escalates the warning an agent must relay to the user, because
# running even non-destructive probes against production is a decision a human
# makes, not an agent.
_PRODUCTION_MARKERS: tuple[str, ...] = (
    "prod",
    "production",
    "live",
    "www",
    "api.",
    "app.",
)

# Hostname fragments that suggest a non-production environment. Used only to
# soften the production warning, never to grant authorization.
# Deliberately does NOT include "internal": "api.prod.internal" is a production host
# that happens to live on a private network, and suppressing the warning there would
# hide the single most likely production target an agent is pointed at.
_NONPROD_MARKERS: tuple[str, ...] = (
    "localhost",
    "dev",
    "test",
    "staging",
    "stage",
    "qa",
    "sandbox",
    "local",
)

# Hosts belonging to well-known third-party model providers. Scanning these is
# refused unconditionally: they are not the user's systems, a scan would violate
# their terms of service, and the payloads would be billed to someone's account.
_REFUSED_HOST_SUFFIXES: tuple[str, ...] = (
    "openai.com",
    "anthropic.com",
    "claude.ai",
    "googleapis.com",
    "generativelanguage.googleapis.com",
    "cohere.ai",
    "cohere.com",
    "mistral.ai",
    "huggingface.co",
    "together.ai",
    "groq.com",
    "perplexity.ai",
    "x.ai",
    "deepseek.com",
    "azure.com",
    "bedrock.amazonaws.com",
)

_LOOPBACK_HOSTNAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})

# An Ollama model name, e.g. "mistral:7b" or "llama3.2:3b". Not a URL at all.
_OLLAMA_MODEL_RE = re.compile(r"^[A-Za-z0-9._/-]+(?::[A-Za-z0-9._-]+)?$")


class AuthorizationDecision:
    """The outcome of the gate: whether a scan may proceed, and what to tell the user."""

    __slots__ = ("allowed", "reason", "requires_ack", "target_class", "warnings")

    def __init__(
        self,
        *,
        allowed: bool,
        target_class: TargetClass,
        reason: str = "",
        requires_ack: bool = False,
        warnings: list[str] | None = None,
    ) -> None:
        self.allowed = allowed
        self.target_class = target_class
        self.reason = reason
        self.requires_ack = requires_ack
        self.warnings: list[str] = warnings or []

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "target_class": str(self.target_class),
            "reason": self.reason,
            "requires_ack": self.requires_ack,
            "warnings": list(self.warnings),
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"AuthorizationDecision(allowed={self.allowed}, "
            f"target_class={self.target_class!s}, requires_ack={self.requires_ack})"
        )


def _resolve_to_ips(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve *hostname* to IP addresses, returning [] when resolution fails.

    An empty list is treated by the caller as UNKNOWN (and therefore as needing
    authorization), never as local.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (OSError, UnicodeError):
        return []
    out: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        sockaddr = info[4]
        try:
            out.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    return out


def classify_target(target: str, target_type: str) -> tuple[TargetClass, list[str]]:
    """Classify *target* and return (class, warnings).

    ``target_type`` follows the scanner's own vocabulary: ``"ollama"`` for a local
    model name, ``"url"`` for an HTTP endpoint.
    """
    warnings: list[str] = []
    target = (target or "").strip()

    if not target:
        return TargetClass.UNKNOWN, ["Empty target."]

    if target_type == "ollama":
        # An Ollama target is a model name served by the operator's own daemon.
        # It is local by construction; a value that is not a plausible model name
        # is suspicious rather than local.
        if _OLLAMA_MODEL_RE.match(target) and "://" not in target:
            return TargetClass.OLLAMA_LOCAL, warnings
        return TargetClass.UNKNOWN, [
            f"{target!r} does not look like an Ollama model name (expected e.g. 'mistral:7b')."
        ]

    parsed = urlparse(target if "://" in target else f"http://{target}")
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return TargetClass.UNKNOWN, [f"Could not parse a hostname out of {target!r}."]

    for suffix in _REFUSED_HOST_SUFFIXES:
        if hostname == suffix or hostname.endswith(f".{suffix}"):
            return TargetClass.EXTERNAL, [
                f"{hostname} belongs to a third-party model provider. "
                "Scanning it is out of scope for this tool."
            ]

    # Environment warnings are computed BEFORE classification branches, so they are
    # attached whatever the class turns out to be. In particular an internal
    # production hostname the agent's machine cannot resolve still gets the
    # production warning -- that is the case where it matters most.
    lowered = hostname.lower()
    looks_nonprod = any(marker in lowered for marker in _NONPROD_MARKERS)
    has_prod_marker = any(marker in lowered for marker in _PRODUCTION_MARKERS)
    if has_prod_marker and not looks_nonprod:
        warnings.append(
            f"{hostname} looks like a production host. Confirm with the user before "
            "scanning, and prefer a staging or local copy."
        )

    if hostname in _LOOPBACK_HOSTNAMES:
        return TargetClass.LOOPBACK, warnings

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ips = _resolve_to_ips(hostname)
        if not ips:
            warnings.append(
                f"{hostname} could not be resolved; treating it as external and "
                "requiring explicit authorization."
            )
            return TargetClass.UNKNOWN, warnings
        # A hostname is only as local as its least-local address.
        if all(a.is_loopback for a in ips):
            cls = TargetClass.LOOPBACK
        elif all(a.is_private or a.is_loopback or a.is_link_local for a in ips):
            cls = TargetClass.PRIVATE
        else:
            cls = TargetClass.EXTERNAL
    else:
        if ip.is_loopback:
            cls = TargetClass.LOOPBACK
        elif ip.is_private or ip.is_link_local:
            cls = TargetClass.PRIVATE
        else:
            cls = TargetClass.EXTERNAL

    if parsed.scheme == "http" and cls is TargetClass.EXTERNAL:
        warnings.append(
            "Target is external and uses plaintext http://; payloads and any API key "
            "would cross the network unencrypted."
        )

    return cls, warnings


def authorize(
    target: str,
    target_type: str,
    *,
    authorized: bool = False,
    include_dos_tests: bool = False,
) -> AuthorizationDecision:
    """Decide whether a scan of *target* may proceed.

    Policy:

    - A third-party model provider is refused outright, with or without an
      acknowledgement. The skill does not scan systems the user cannot own.
    - ``LOOPBACK`` and ``OLLAMA_LOCAL`` proceed without an acknowledgement: the
      target is the operator's own machine.
    - ``PRIVATE``, ``EXTERNAL`` and ``UNKNOWN`` require ``authorized=True``, which
      the caller may only set after the user has confirmed they own or are
      permitted to test the target.
    - ``include_dos_tests`` (OWASP LLM10) requires ``authorized=True`` even on
      loopback, because it deliberately stresses the target. The scanner itself
      already gates LLM10 behind an opt-in flag; this is the second lock.
    """
    cls, warnings = classify_target(target, target_type)

    for suffix in _REFUSED_HOST_SUFFIXES:
        host = (urlparse(target if "://" in target else f"http://{target}").hostname or "").lower()
        if host == suffix or host.endswith(f".{suffix}"):
            return AuthorizationDecision(
                allowed=False,
                target_class=cls,
                reason=(
                    f"Refused: {host} is a third-party model provider endpoint. This skill "
                    "only tests systems the user operates. Point it at your own application "
                    "or a local model instead."
                ),
                warnings=warnings,
            )

    if cls is TargetClass.UNKNOWN and not authorized:
        return AuthorizationDecision(
            allowed=False,
            target_class=cls,
            reason=(
                "Refused: the target could not be classified as local. Confirm with the "
                "user that they own or are authorized to test it, then re-run with "
                "authorized=true."
            ),
            requires_ack=True,
            warnings=warnings,
        )

    needs_ack = cls in {TargetClass.PRIVATE, TargetClass.EXTERNAL, TargetClass.UNKNOWN}

    if needs_ack and not authorized:
        return AuthorizationDecision(
            allowed=False,
            target_class=cls,
            reason=(
                f"Refused: {target} is classified as {cls!s}, not local. Ask the user to "
                "confirm they own or have written permission to test this target, then "
                "re-run with authorized=true."
            ),
            requires_ack=True,
            warnings=warnings,
        )

    if include_dos_tests and not authorized:
        return AuthorizationDecision(
            allowed=False,
            target_class=cls,
            reason=(
                "Refused: OWASP LLM10 (Unbounded Consumption) probes deliberately stress "
                "the target and can degrade it. They require an explicit authorization "
                "acknowledgement even against localhost -- re-run with authorized=true."
            ),
            requires_ack=True,
            warnings=warnings,
        )

    if cls is TargetClass.EXTERNAL:
        warnings.append(
            "Scanning an EXTERNAL target on the user's stated authorization. Keep the scan "
            "to the agreed scope and stop if the user withdraws permission."
        )
    if include_dos_tests:
        warnings.append(
            "LLM10 DoS probes are enabled. These can degrade or exhaust the target; do not "
            "run them against anything serving real traffic."
        )

    return AuthorizationDecision(allowed=True, target_class=cls, warnings=warnings)
