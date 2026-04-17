# ttp-staleness

Score your Sigma/KQL/EQL detection rules for ATT&CK technique staleness.

## Status

**Scaffolding.** The CLI, settings, models, and stub modules are in place. Rule parsing, ATT&CK indexing, scoring, and reporting are not yet implemented — sub-modules currently return empty data so the end-to-end pipeline can be exercised. See `docs/superpowers/plans/` for the implementation plan.

## Requirements

- Python **3.11** or newer (tested on 3.12)

## Install

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
ttp-staleness --help
ttp-staleness --version
ttp-staleness scan path/to/rules
```

### `scan` options

| Option | Default | Description |
|---|---|---|
| `RULE_DIR` (positional) | — | Directory of Sigma rules to scan. Must exist. |
| `--format {terminal,json,html}` | `terminal` | Output format. |
| `-o, --output PATH` | _stdout_ | Write output to a file instead of stdout. |
| `--min-severity {low,medium,high,critical}` | `low` | Only show rules at or above this severity. |
| `--no-cache` | off | Bypass the disk cache and fetch a fresh ATT&CK bundle (`ttl_hours=0`). |
| `--domain {enterprise-attack,ics-attack,mobile-attack}` | `enterprise-attack` | ATT&CK domain to fetch. |

Progress spinners go to **stderr**; the report goes to **stdout** so JSON output can be piped safely:

```bash
ttp-staleness scan path/to/rules --format json | jq '.findings'
ttp-staleness scan path/to/rules --format json -o report.json
```

Exit codes:

- `0` — scan completed with no critical findings
- `1` — at least one rule scored `critical` (useful for CI gating)
- other — argument/parse errors from Click

### Environment variables

All settings can be overridden via `TTP_`-prefixed env vars (or a `.env` file in the working directory):

| Variable | Default | Purpose |
|---|---|---|
| `TTP_CACHE_DIR` | `~/.cache/ttp-staleness` | Where the ATT&CK bundle is cached. |
| `TTP_CACHE_TTL_HOURS` | `24` | Cache lifetime in hours. |
| `TTP_ATTACK_DOMAIN` | `enterprise-attack` | Default `--domain` value. |
| `TTP_NO_CACHE` | `false` | If truthy, always bypass the cache. |

## Development

```bash
pytest -q                     # run the test suite (38 tests)
ruff check src/ tests/        # lint
mypy src/                     # type-check (strict)
```

The package layout:

```
src/ttp_staleness/
├── cli.py              # click entrypoint (main + scan)
├── settings.py         # pydantic-settings config
├── console.py          # rich stdout + stderr consoles
├── models.py           # Severity, Rule, Finding, Report, AttackIndex, AttackTechnique
├── cache.py            # DiskCache (SHA-256 keys, TTL on read)
├── attack_client.py    # build_index()   — STUB
├── rule_parser.py      # parse_rule_dir() — STUB
├── scorer.py           # score_rules()   — STUB
└── reporter.py         # render()        — terminal/json/html (stub rendering)
```

## License

MIT
