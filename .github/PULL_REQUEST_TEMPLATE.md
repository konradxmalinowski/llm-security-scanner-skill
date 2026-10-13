## What and why

## Checklist

- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `pytest -q` passes
- [ ] `pytest tests/test_contract.py -q` passes (assumptions about the real scanner)
- [ ] `pytest tests/test_platforms.py -q` passes (skill structure + manifests)
- [ ] No scanner logic was duplicated into the skill layer
- [ ] Still exactly one `SKILL.md` in the repository
- [ ] Conventional Commit title (`feat:`, `fix:`, `docs:`, `test:`, `chore:`)

### If the MCP tools changed

- [ ] Ran `python tools/gen_tools_json.py` and committed the result

### If a platform adapter changed

- [ ] Official documentation cited in `docs/PLATFORMS.md`
- [ ] `platforms/<name>/README.md` states the platform's gaps honestly
- [ ] Manifest assertions added to `tests/test_platforms.py`

### If the security model changed

- [ ] `docs/SECURITY_MODEL.md` updated
- [ ] A test covers the new control
