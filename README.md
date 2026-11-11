# tiny-audit — Immutable, Tamper-Evident Audit Log

> **Zero dependencies. HMAC-SHA256 signed. Append-only. Verifiable.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](tiny_audit.py)

Every entry is signed with HMAC-SHA256. Entries can never be deleted or
modified without detection — only appended. The chain is verifiable at any point. Great for
compliance, agentic workflows, financial systems, and anywhere you need
**"this happened and nobody tampered with it"**.

```bash
pip install tiny-audit
```

## Why?

| Approach | Problem |
|----------|--------|
| `logging` module | Entries can be deleted/modified |
| SQL audit table | DB admin can DELETE |
| CloudWatch / Datadog | Costly, vendor lock-in |
| **tiny-audit** | **Zero deps, verifiable, self-contained** |

## Quick Start

```python
from tiny_audit import AuditLog, Level

log = AuditLog("/data/audit.log", secret="super-secret-key")

# Log any action
log.log(Level.INFO, "user.login",    {"user_id": 42, "ip": "1.2.3.4"})
log.log(Level.WRITE, "order.placed", {"order_id": "ORD-99", "amount": 150.00})
log.log(Level.READ,  "config.fetch", {"keys": ["api_key", "db_url"]})
log.log(Level.ADMIN, "user.promote", {"user_id": 99, "role": "admin"})

# Verify integrity — raises AuditError if tampered
log.verify()

# Query entries
for entry in log.query(actor="agent-1", limit=100):
    print(entry.action, entry.data)

# Export for compliance
log.export_jsonl("/data/audit-export.jsonl")
```

## Decorator — Auto-Log Function Calls

```python
audit = AuditLog("/data/audit.log", secret="key")

@audit.audit("user.fetch", level=Level.READ, actor_arg=0)
def get_user(user_id: int) -> dict:
    return db.get(user_id)

@audit.audit("order.create", level=Level.WRITE, actor_arg=1)
async def create_order(user_id: int, items: list) -> dict:
    ...
```

## How Integrity Works

Each entry stores a **chain hash** (`prev_hash`) and a **sequence number**
(`seq`). Both, plus a monotonic position, are inside the HMAC-SHA256 message.
When you call `verify()`, we walk the whole file and confirm:

1. `prev_hash` chains correctly
2. `seq` runs `0, 1, 2, ...` with no gap and no reorder
3. the HMAC signature on each entry is valid
4. (with `high_water_path=`) the log is not shorter than it has ever been

```
seq  prev_hash    hash
0    GENESIS      a3f2...
1    a3f2...      b7c1...
2    b7c1...      d9e4...
```

### The deletion case, honestly

0.1.0 caught *edits* and missed *deletions of the tail*. A shorter chain is
still a valid chain — every surviving line still chains and still verifies —
so `truncate -s` or a half-finished log rotation left a log that reported
itself intact. That is the cheapest tamper there is, and it is the one an
audit log exists to catch.

`seq` closes the middle-deletion and reorder cases on its own. The tail needs
a witness *outside* the chain, because a log cannot prove its own length:

```python
log = AuditLog("/data/audit.log", secret=SECRET,
               high_water_path="/var/lib/myapp/audit.highwater.json")

log.log(Level.INFO, "user.login", {"user_id": 42})
log.verify()          # True

# The high-water mark is raised on every write and never lowered — including
# by reopening the log. Keep it somewhere the log's own writer cannot rewrite.
log.anchor()          # {"entries": N, "last_seq": N-1}
```

Delete the last two lines and `verify()` raises
`AuditError: Log truncated: N-2 entries on disk, but N were recorded`.
Without a `high_water_path`, truncation is still undetectable — that is a
property of hash chains, not a bug, and it is pinned by a test.

## API Reference

### `AuditLog(path, secret, buffer_size=1, max_entry_size=65536, high_water_path=None)`

| Argument | Default | Description |
|----------|---------|-------------|
| `path` | — | Path to JSONL audit log file |
| `secret` | `"change-me"` | HMAC secret key |
| `buffer_size` | `1` | Flush to disk every N entries |
| `max_entry_size` | `65536` | Max entry payload bytes |
| `high_water_path` | `None` | Sidecar recording the highest `seq` ever written; enables truncation detection |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `log(level, action, data, actor, idempotency_key)` | `AuditEntry` | Append signed entry |
| `flush()` | — | Force flush buffer to disk |
| `verify()` | `bool` | Verify chain, sequence and signatures (raises on tampered) |
| `anchor()` | `dict` | Current high-water mark (`entries`, `last_seq`) |
| `query(action, actor, level, since, until, limit)` | `Iterator[AuditEntry]` | Query entries |
| `count()` | `int` | Total entry count |
| `export_jsonl(path)` | `int` | Export to JSONL |
| `export_dict()` | `list[dict]` | Export all as dicts |
| `audit(action, level, actor_arg)` | `Decorator` | Auto-log function calls |

### Levels

```python
from tiny_audit import Level
Level.DEBUG   # 10
Level.INFO    # 20
Level.WARNING # 30
Level.ERROR   # 40
Level.CRITICAL# 50
Level.READ    # 1  — data was read
Level.WRITE   # 2  — data was created/modified
Level.DELETE  # 3  — data was deleted
Level.ADMIN   # 4  — admin action
```

## Files

- `tiny_audit.py` — The library (~350 LOC)
- `tests/test_tiny_audit.py` — Tests
- `LICENSE` — MIT
- `pyproject.toml` — Packaging metadata

> This is a Python library. It previously shipped a `package.json`, which is
> an npm manifest: nothing read it, so it only served to declare the name
> `tiny-audit` on a registry this project does not publish to. It has been
> removed in favour of `pyproject.toml`.

## Ecosystem

Part of the **[tiny-\* ecosystem](https://github.com/hussain-alsaibai)** —
zero-dependency, single-file Python libraries for AI agents and modern
backend tooling. See also: `tiny-prompt`, `tiny-diff`, `tiny-retry`,
`tiny-task`, `tiny-eventbus`.

---

*Built by [OpenClaw](https://github.com/hussain-alsaibai) 🦞*
