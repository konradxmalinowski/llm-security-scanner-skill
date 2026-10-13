# Contributing

## Setup

```bash
git clone https://github.com/konradxmalinowski/llm-security-scanner-skill
cd llm-security-scanner-skill
uv venv && uv pip install -e ".[dev]"

ollama serve &
ollama pull llama3.2:3b

.venv/bin/llm-scanner-skill doctor
```

## Checks

```bash
ruff check .            # lint
ruff format .           # format
pytest -q               # the full suite

pytest tests/test_contract.py -q    # assumptions about the real scanner
pytest tests/test_platforms.py -q   # skill structure + every platform manifest
```

All four must pass; CI runs them on Python 3.11, 3.12 and 3.13.

## The rule that matters

**The skill layer must never reimplement the scanner.** Payloads, the judge, detectors,
reconciliation and reporters live in `llm-security-scanner`. This repository adds only
what an agent needs that the CLI does not provide.

Tests enforce it: no scanner symbol (`OllamaJudge`, `LLMScanner`, `run_detectors`,
`reconcile`, `YamlPayloadLoader`, `judge_criteria`) may appear in the skill's scripts or
in the MCP layer, and each skill script must stay under 25 lines.

## Changing the skill's knowledge

There is exactly one skill directory, `skills/llm-security-scan/`. A test fails if a
second `SKILL.md` appears anywhere. Platform adapters are manifests, never copies.

Budget, enforced by tests:

| File | Limit | Why |
|---|---|---|
| `SKILL.md` | 500 lines | Loads whole on activation |
| `references/*.md` | 250 lines | Loaded on demand; smaller means less context |
| `scripts/*.py` | 25 lines | They are wrappers |
| `AGENTS.md`, `GEMINI.md` | 80 lines | Always in context |

Every relative link in the skill is checked, so a renamed reference fails the build
rather than silently breaking progressive disclosure.

## Changing the MCP tools

Regenerate the derived function declarations and commit them:

```bash
python tools/gen_tools_json.py
```

CI fails if `platforms/generic/tools.json` drifts from the server's definitions.

## Adding a platform adapter

1. Read the platform's **official** documentation and cite it in `docs/PLATFORMS.md`.
2. Add install manifests/metadata only — never duplicate the skill.
3. Add a `platforms/<name>/README.md` with installation and the platform's exact gaps.
4. Add assertions to `tests/test_platforms.py` validating the manifest against the
   published format.
5. Update the matrix in `docs/PLATFORMS.md`, including what the platform does **not**
   support.

Do not claim support that is not implemented and tested. An honest ❌ with a reason is
worth more than an optimistic ✅.

## Commits and releases

Conventional Commits, because release-please reads them:

```
feat: add Cursor platform adapter
fix: classify split-horizon hostnames as unknown
docs: document the Gemini environment sanitization caveat
test: cover zero-width bypass of the lexical pass
chore: bump scanner floor to 0.9.0
```

Releases are automatic:

1. Commit to `main` with a Conventional Commit prefix.
2. `release-please` maintains an open Release PR that bumps the version in
   `pyproject.toml`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`,
   `gemini-extension.json`, `src/llm_scanner_skill/__init__.py` and `SKILL.md`, and
   updates `CHANGELOG.md`.
3. Merge it. release-please creates the `vX.Y.Z` tag and GitHub Release.
4. `release.yml` verifies the version is consistent across every manifest, checks the
   wheel really bundles the skill, and publishes to PyPI via trusted publishing (OIDC).

Never bump a version by hand — the release workflow fails on a mismatch.

### One-time repository setup

Two things must be configured by hand before releases work. Until they are, the
`release-please` job skips itself with a notice rather than failing, and `release.yml`
fails at the publish step.

1. **`RELEASE_PLEASE_TOKEN`** — a fine-grained PAT scoped to *Contents* and *Pull
   requests* (read/write) on this repository only, added as a repository secret. The
   default `GITHUB_TOKEN` is deliberately not used: a tag it creates would not trigger
   `release.yml`, so no release would ever publish.
2. **PyPI trusted publishing** — register a pending publisher on PyPI for
   `llm-security-scanner-skill` (owner `konradxmalinowski`, repo
   `llm-security-scanner-skill`, workflow `release.yml`, environment `pypi`), and create a
   GitHub environment named `pypi`. No API token is stored anywhere; publishing uses OIDC.

## Keeping up with the scanner

A nightly job runs the contract tests against the latest `llm-security-scanner` release
and opens a `contract-break` issue on failure. If you pick one up:

1. Read what changed in the scanner.
2. Update the adapter — usually `adapter._build_argv`, `config.CONFIG_KEYS`, or
   `envelope._VERDICT_SOURCE_TO_CONFIDENCE`.
3. Add or adjust the contract assertion so the same break cannot recur silently.
4. Raise the dependency floor in `pyproject.toml` if the fix needs the newer scanner.
