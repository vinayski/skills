# Malicious Injection Patterns Report

## Scope
This report documents patterns in this repository that match base64 decoding piped into a shell (`bash`/`sh`), which is a common malicious injection technique. Examples below are taken directly from files in the repo and are shown as documentation or detection patterns (no code execution performed).

## Findings by category

### 1) Base64 decode piped to **bash** (explicit command/pattern)
These entries show the classic `base64 -d ... | bash` execution chain.

- `base64 -d \| bash` in `skills/nukewire/clawdefender/scripts/clawdefender.sh` (pattern list).
- `base64 -d payload.b64 | bash` in `skills/starbuck100/clawdhub-contributor/auditor/tests/test_patterns.py` (test case for `B64_EXEC_001`).

### 2) Base64 decode piped to **sh** (explicit command/pattern)
These entries show the same technique using `sh`.

- `base64 --decode \| sh` in `skills/nukewire/clawdefender/scripts/clawdefender.sh` (pattern list).

### 3) Regex rules detecting base64 decode → shell execution
Detection rules in this repo explicitly flag base64 decode operations piped to interpreters, including `bash`/`sh` and `--decode` variants.

- `regex: r"(base64\s+(-d|--decode)|atob)\s*.*\|\s*(bash|sh|eval|python[23]?|perl|source)"` in `skills/starbuck100/clawdhub-contributor/auditor/patterns.py`.
- `regex: "base64\s+(-d|--decode).*\\|\\s*(bash|sh|python|perl)"` in `skills/patfire94/skill-flag/patterns/backdoors.yaml`.

## Notes
- These occurrences appear in detection rules and test data meant to identify suspicious behavior; they are still representative of the risky injection patterns this report targets.
