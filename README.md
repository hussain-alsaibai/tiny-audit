# tiny-audit — Immutable, Tamper-Evident Audit Log

> **Zero dependencies. HMAC-SHA256 signed. Append-only. Verifiable.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](tiny_audit.py)

Every entry is signed with HMAC-SHA256. Entries can never be deleted or
modified — only appended. The chain is verifiable at any point. Great for
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

Each entry stores a **chain hash** (`prev_hash`) — the hash of the previous
entry. The first entry uses `"GENESIS"`. Every entry is also signed with
HMAC-SHA256. When you call `verify()`, we walk the entire file and confirm:

1. `prev_hash` chains correctly
2. HMAC signature is valid

If any line is modified or deleted, `verify()` raises `AuditError`.

```
Entry 1: prev_hash=GENESIS, hash=a3f2...
Entry 2: prev_hash=a3f2..., hash=b7c1...
Entry 3: prev_hash=b7c1..., hash=d9e4...
```

## API Reference

### `AuditLog(path, secret, buffer_size=1, max_entry_size=65536)`

| Argument | Default | Description |
|----------|---------|-------------|
| `path` | — | Path to JSONL audit log file |
| `secret` | `"change-me"` | HMAC secret key |
| `buffer_size` | `1` | Flush to disk every N entries |
| `max_entry_size` | `65536` | Max entry payload bytes |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `log(level, action, data, actor, idempotency_key)` | `AuditEntry` | Append signed entry |
| `flush()` | — | Force flush buffer to disk |
| `verify()` | `bool` | Verify chain + signatures (raises on tampered) |
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
- `package.json` — Metadata

## Ecosystem

Part of the **[tiny-\* ecosystem](https://github.com/hussain-alsaibai)** —
zero-dependency, single-file Python libraries for AI agents and modern
backend tooling. See also: `tiny-prompt`, `tiny-diff`, `tiny-retry`,
`tiny-task`, `tiny-eventbus`.

---

*Built by [OpenClaw](https://github.com/hussain-alsaibai) 🦞*
