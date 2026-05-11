# Detect-Forge Rebrand — Design Spec

**Date:** 2026-05-11
**Status:** Approved (design); plan pending
**Source of truth:** [Detect-Forge — Company OS](https://www.notion.so/34554a38001c812f933fe9238633120c) §2 (Distribution Architecture) and §8 (Naming Conventions)

## Goal

Rebrand the Python package `ttp-staleness` to `detect-forge` and restructure the CLI from a single command into a subcommand suite. The May 23 2026 public launch ships under the `detect-forge` name with `stale` as the first real subcommand and stubs in place for the rest of the suite.

## Why now

The Company OS (§3) records the rename decision on Apr 24 2026 ("Architecture A — single PyPI package with subcommands"). The roadmap still uses the old name in the May 23 launch row, but every other section of the OS uses `detect-forge`. The package has never been published to PyPI, so there is no installed-user base to migrate; the rebrand can be a hard cut. The May 23 launch is 12 days out, so this PR ships the rename plus the subcommand skeleton before any future capability work.

## Scope

In scope:
- Rename Python package `src/ttp_staleness/` → `src/detect_forge/`.
- Move all existing stale logic (`attack_client`, `rule_parser`, `scorer`, `reporter`, `models`, `templates/`) into a new `detect_forge.stale` submodule.
- New `detect_forge.cli` Click root group registering five subcommands: `stale` (real), `backtest`, `coverage`, `cti` (group with `ingest` verb), `audit` (stubs).
- Stub subcommands print a not-implemented message to stderr and exit `1`.
- Console script renamed from `ttp-staleness` to `detect-forge` (single entrypoint, no alias).
- Env var prefix changed from `TTP_` to `DETECT_FORGE_`.
- `Settings.no_cache` wired through to `cli.scan`, resolving the existing TODO.
- Exit code on critical findings changed from `1` to `2` per OS §8 convention.
- Cache directory default changed to XDG-compliant `$XDG_CACHE_HOME/detect-forge/` (falling back to `~/.cache/detect-forge/`).
- `README.md` rewritten to reflect new name, subcommand surface, env vars, and exit codes.
- All tests migrated to new import paths; three new test modules added.

Out of scope (deferred):
- `.detect-forge.toml` config file loading (OS §8) — wait until `backtest` lands so the config schema can be shaped with two real subcommands.
- Real implementations of `backtest`, `coverage`, `cti ingest`, `audit`.
- Migration of `data/rules/*.toml` fixtures to `.yml` (TODO carried forward).
- Populating `AttackIndex.attack_version` (existing TODO).
- PyPI alias package, console-script alias, or `TTP_*` env-var back-compat (hard cut, no users).
- Release tooling changes (hatch-vcs, OIDC publishing) — covered elsewhere in the OS roadmap.

## Design decisions

### Package layout

```
src/detect_forge/
├── __init__.py
├── cli.py                  # Click root group "detect-forge"; registers subcommands
├── settings.py             # DETECT_FORGE_* via pydantic-settings
├── console.py              # Rich consoles (unchanged)
├── cache.py                # XDG-aware cache; DEFAULT_CACHE_DIR replaced by helper
├── common.py               # @common_output_options decorator
├── exit_codes.py           # CLEAN=0, RESERVED=1, GATED=2
├── stale/
│   ├── __init__.py         # public API: from detect_forge.stale import scan
│   ├── cli.py              # @click.command("stale"); current scan() logic
│   ├── attack_client.py
│   ├── rule_parser.py
│   ├── scorer.py
│   ├── reporter.py
│   ├── models.py
│   └── templates/
│       └── report.html.j2
├── backtest/
│   ├── __init__.py
│   └── cli.py              # stub registered as @click.command("backtest")
├── coverage/
│   ├── __init__.py
│   └── cli.py              # stub registered as @click.command("coverage")
├── cti/
│   ├── __init__.py
│   └── cli.py              # @click.group("cti"); registers ingest stub
└── audit/
    ├── __init__.py
    └── cli.py              # stub registered as @click.command("audit")
```

Each subcommand module exports a `register(group)` function that the root `cli.py` calls during group construction. This keeps the registration list explicit in `cli.py` and lets each submodule own its Click wiring.

### CLI surface

```
$ detect-forge --help
Usage: detect-forge [OPTIONS] COMMAND [ARGS]...

  Detection engineering toolkit. One install, one config, one CI step.

Commands:
  stale     Score detection rules for ATT&CK technique staleness.
  backtest  Adversarial replay (not yet implemented).
  coverage  Coverage gap mapping (not yet implemented).
  cti       CTI-to-detection generation (not yet implemented).
  audit     Reserved — runs every check once 2+ subcommands ship.
```

`detect-forge stale` carries the existing `scan` flag surface verbatim:

```
Usage: detect-forge stale [OPTIONS] RULE_DIR

Options:
  --format [terminal|json|html]
  -o, --output PATH
  --min-severity [low|medium|high|critical]
  --no-cache
  --domain [enterprise-attack|ics-attack|mobile-attack]
```

Shared options (`--format`, `--output`, `--min-severity`) are wired via a `@common_output_options` decorator in `common.py`. Subcommand-specific options (`--no-cache`, `--domain`) stay on `stale` directly. Future subcommands compose the shared decorator as they need it.

### Exit codes

`detect_forge/exit_codes.py` defines three named constants used throughout the CLI:

| Constant | Value | Meaning |
|---|---|---|
| `CLEAN` | 0 | Scan completed, no gating findings |
| `RESERVED` | 1 | Tool error, stub, or unimplemented command |
| `GATED` | 2 | CI-gating condition met (e.g. `stale` found a `critical`) |

This is a **breaking change** from the current behavior — `cli.py:110` exits `1` on critical and will exit `2` instead. Documented in release notes for the May 23 launch.

### Settings

```python
from .cache import _default_cache_dir

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DETECT_FORGE_",
        env_file=".env",
        extra="ignore",
    )
    cache_dir: Path = Field(default_factory=_default_cache_dir)
    cache_ttl_hours: int = 24
    attack_domain: str = "enterprise-attack"
    no_cache: bool = False
```

The cache-dir factory lives in `cache.py` (next section) and is imported here so the default and the path helper stay in sync.

`no_cache` is now wired into `stale.cli.scan` as `ttl = 0 if (no_cache or settings.no_cache) else settings.cache_ttl_hours`. The TODO at `src/ttp_staleness/settings.py:13` is resolved by this change and removed.

No `TTP_*` env vars are read. Hard cut.

### Cache directory

`cache.py` replaces the module-level `DEFAULT_CACHE_DIR = Path.home() / ".cache" / "ttp-staleness"` with a factory:

```python
def _default_cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "detect-forge"
```

This is referenced by `Settings.cache_dir`'s `default_factory` and by `cache.cache_path()`'s default argument. No migration of `~/.cache/ttp-staleness/` is performed — on macOS the path falls back to `~/.cache/detect-forge/` either way, and Linux users with `XDG_CACHE_HOME` set get a respectful default.

### Stub behavior

Each stub registers a Click command that prints to `stderr` and exits `1`. Template (for `backtest`):

```
detect-forge: 'backtest' is not yet implemented.
Ship target: Jun 28, 2026.
Track at https://github.com/Detect-Forge/detect-forge/issues
```

Ship targets per OS §2:
- `backtest` — Jun 28 2026
- `coverage` — Q3 2026
- `cti ingest` — Q3–Q4 2026
- `audit` — TBD (after 2+ subcommands ship)

`detect-forge cti` (no verb) shows Click's standard group help; only `ingest` is registered. Additional verbs are added when their designs land.

### Tests

Migrate every `from ttp_staleness ...` import:
- `from ttp_staleness import cli, settings, cache, console` → `from detect_forge import cli, settings, cache, console`
- `from ttp_staleness.{attack_client,rule_parser,scorer,reporter,models}` → `from detect_forge.stale.{...}`

Add three new test modules:

| File | Coverage |
|---|---|
| `tests/stubs/test_stub_subcommands.py` | Each stub exits `1`, prints expected message fragments to stderr |
| `tests/test_exit_codes.py` | Constants match the spec; `stale` exits `2` (not `1`) on critical |
| `tests/test_cache_xdg.py` | `_default_cache_dir()` honors `XDG_CACHE_HOME` and falls back to `~/.cache/detect-forge/` |

Update `tests/conftest.py` autouse fixture to strip `DETECT_FORGE_*` env vars instead of `TTP_*`.

### `pyproject.toml`

```toml
[project]
name = "detect-forge"
# ... unchanged ...

[project.scripts]
detect-forge = "detect_forge.cli:main"

[tool.hatch.build.targets.wheel]
packages = ["src/detect_forge"]
include = ["src/detect_forge/stale/templates/*"]
```

Project URLs already point at `Detect-Forge/detect-forge` (updated in an earlier commit).

### README

Full rewrite:
- Title `# Detect-Forge`
- Subcommand surface section showing the five commands
- `Install`: `pip install -e ".[dev]"`
- `Usage`: examples for `detect-forge stale ./rules`, `detect-forge --help`, `detect-forge stale --format json | jq`
- Env var table changed to `DETECT_FORGE_*`
- Exit code table updated to 0/1/2 with new semantics
- Status section updated to reflect rebrand and current shipping subcommand

### Resolved TODOs

- `src/ttp_staleness/settings.py:13` — `TTP_NO_CACHE` is now read via `DETECT_FORGE_NO_CACHE` and wired through; remove the TODO comment.

### Carried-forward TODOs

- `src/ttp_staleness/rule_parser.py:99` (becomes `src/detect_forge/stale/rule_parser.py`) — `.toml` vs `.yml` glob mismatch. The TODO comment is preserved in the rebranded file; fix is out of scope.
- `src/detect_forge/stale/models.py` — `AttackIndex.attack_version` population is still TODO.

## Open items not decided here

These are deliberately deferred and should not be assumed during implementation:

- `.detect-forge.toml` discovery rules (XDG vs upward walk vs repo-root-only) — deferred until `backtest` lands.
- Telemetry default — Notion OS does not specify on/off default; not introduced in this PR.
- CLI flag surface for any future subcommand beyond `stale` — each gets its own design.

## Acceptance criteria

- `pip install -e ".[dev]"` installs the package as `detect-forge`.
- `detect-forge --help` lists all five subcommands.
- `detect-forge stale ./rules` produces identical output to the old `ttp-staleness scan ./rules` for the same inputs (modulo exit code 1→2 on critical).
- `detect-forge backtest`, `coverage`, `cti ingest`, `audit` print the stub message to stderr and exit `1`.
- `DETECT_FORGE_CACHE_DIR=/tmp/x detect-forge stale ./rules` writes the ATT&CK cache to `/tmp/x`.
- `XDG_CACHE_HOME=/tmp/xdg detect-forge stale ./rules` (with `DETECT_FORGE_CACHE_DIR` unset) writes the cache to `/tmp/xdg/detect-forge/`.
- `ruff check src/ tests/`, `mypy src/`, and `pytest -q` all pass.
- No file in `src/` or `tests/` references `ttp_staleness` or `TTP_` after migration.
- README contains no `ttp-staleness` references.
