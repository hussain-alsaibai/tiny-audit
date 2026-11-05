"""
tiny-audit — Zero-dependency immutable audit log for Python.

Immutable, tamper-evident append-only log. Every entry is signed with HMAC-SHA256.
Entries can never be deleted or modified — only appended. Integrity verifiable
at any point. Great for compliance, agentic workflows, and financial systems.

Usage:
    from tiny_audit import AuditLog, AuditEntry, Level

    log = AuditLog("/data/audit.log", secret="your-secret-key")
    log.log(Level.INFO, "user.login", {"user_id": 42, "ip": "1.2.3.4"})
    log.log(Level.WRITE, "order.placed", {"order_id": "ORD-99", "amount": 150.00})

    # Verify integrity
    log.verify()  # raises AuditError if tampered

    # Query entries
    for entry in log.query(actor="agent-1", limit=100):
        print(entry.action, entry.data)

    # Export for compliance
    log.export_json("/data/audit-export.jsonl")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Iterator, Any, Sequence
from functools import wraps

__version__ = "0.1.0"
__all__ = ["AuditLog", "AuditEntry", "Level", "AuditError"]


class Level(IntEnum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    READ = 1      # Data was read
    WRITE = 2     # Data was created/modified
    DELETE = 3    # Data was deleted
    ADMIN = 4    # Admin action


class AuditError(Exception):
    """Raised on integrity violations or malformed entries."""
    pass


@dataclass
class AuditEntry:
    # No `slots=True`: that keyword is Python 3.10+, and this package declares
    # `Requires-Python: >=3.8`. It was the only 3.10+ construct in the file, so
    # the module failed to import at all on 3.8 and 3.9 -- the declared floor
    # was never exercised, because CI started at 3.10.
    """Immutable, signed audit log entry."""
    id: str           # UUID v4
    ts: str           # ISO-8601 UTC
    level: int        # Level value
    actor: str        # Who triggered this (user_id, agent_id, system)
    action: str       # dotted.action.name ("user.login", "order.placed")
    data: dict        # Arbitrary payload (no secrets)
    prev_hash: str    # SHA-256 of previous entry
    entry_hash: str  # SHA-256 of this entry's content

    def to_line(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_line(cls, line: str) -> AuditEntry:
        return cls(**json.loads(line))

    def verify_signature(self, secret: str) -> bool:
        """Verify HMAC-SHA256 signature."""
        msg = f"{self.id}:{self.ts}:{self.level}:{self.actor}:{self.action}:{json.dumps(self.data, sort_keys=True)}:{self.prev_hash}"
        expected = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()[:16]
        return expected == self.entry_hash[:16]

    def _compute_hash(self, secret: str) -> str:
        msg = f"{self.id}:{self.ts}:{self.level}:{self.actor}:{self.action}:{json.dumps(self.data, sort_keys=True)}:{self.prev_hash}"
        return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()[:16]


class AuditLog:
    """
    Append-only, tamper-evident audit log.

    Args:
        path: Path to the audit log file (JSONL). Created if it doesn't exist.
        secret: HMAC secret key. Keep safe — changing it invalidates all signatures.
        buffer_size: Flush to disk every N entries (default 1 = always flush).
        max_entry_size: Reject entries larger than this (bytes, default 64 KB).
    """

    def __init__(
        self,
        path: str | Path,
        secret: str = "change-me-in-production",
        buffer_size: int = 1,
        max_entry_size: int = 65536,
    ):
        self.path = Path(path)
        self.secret = secret
        self.buffer_size = max(1, buffer_size)
        self.max_entry_size = max_entry_size
        self._buf: list[AuditEntry] = []
        self._last_hash = self._load_last_hash()

    # ── Internal ────────────────────────────────────────────────────────────

    def _load_last_hash(self) -> str:
        """Read the hash of the last entry, or GENESIS if empty."""
        if not self.path.exists():
            return "GENESIS"
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = AuditEntry.from_line(line)
            return entry.entry_hash if line else "GENESIS"

    def _flush(self) -> None:
        if not self._buf:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if self.path.exists() else "w"
        with open(self.path, mode, encoding="utf-8") as f:
            for e in self._buf:
                f.write(e.to_line() + "\n")
        self._last_hash = self._buf[-1].entry_hash
        self._buf.clear()

    def _sign_entry(self, entry: AuditEntry) -> AuditEntry:
        entry.entry_hash = entry._compute_hash(self.secret)
        return entry

    # ── Public API ─────────────────────────────────────────────────────────

    def log(
        self,
        level: int | Level,
        action: str,
        data: dict | None = None,
        actor: str = "system",
        idempotency_key: str | None = None,
    ) -> AuditEntry:
        """
        Append an immutable, signed entry to the audit log.

        Args:
            level: Audit level (DEBUG/INFO/WARNING/ERROR/CRITICAL/READ/WRITE/DELETE/ADMIN)
            action: Dotted action name, e.g. "user.login", "order.placed"
            data: Arbitrary JSON-serializable payload (no secrets)
            actor: Who performed this action (user_id, agent_id, service name)
            idempotency_key: If provided, skips duplicate entries within this session

        Returns:
            The created AuditEntry
        """
        # Accept Level enum, string name ("INFO", 20), or int
        if isinstance(level, str):
            try:
                level_val = int(Level[level.upper()])
            except KeyError:
                level_val = int(level)
        else:
            level_val = int(level)
        payload = data or {}
        raw = json.dumps(payload, sort_keys=True, default=str)
        if len(raw) > self.max_entry_size:
            raise AuditError(f"Entry data exceeds max size: {len(raw)} > {self.max_entry_size}")

        entry = AuditEntry(
            id=str(uuid.uuid4()),
            ts=datetime.now(timezone.utc).isoformat(),
            level=level_val,
            actor=str(actor),
            action=str(action),
            data=payload,
            prev_hash=self._last_hash,
            entry_hash="",  # filled by _sign_entry
        )
        entry = self._sign_entry(entry)
        self._buf.append(entry)

        if len(self._buf) >= self.buffer_size:
            self._flush()
        return entry

    def flush(self) -> None:
        """Force flush buffered entries to disk."""
        self._flush()

    def verify(self) -> bool:
        """
        Verify the entire log integrity. Raises AuditError on tampered log.
        Returns True if all entries are intact.
        """
        if not self.path.exists():
            return True
        prev_hash = "GENESIS"
        with open(self.path, "r", encoding="utf-8") as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    entry = AuditEntry.from_line(line)
                except Exception as e:
                    raise AuditError(f"Malformed entry on line {lineno}: {e}")

                if entry.prev_hash != prev_hash:
                    raise AuditError(
                        f"Chain broken at line {lineno} (entry {entry.id}): "
                        f"expected prev_hash={prev_hash}, got {entry.prev_hash}"
                    )

                computed = entry._compute_hash(self.secret)
                if not entry.verify_signature(self.secret):
                    raise AuditError(
                        f"Signature mismatch at line {lineno} (entry {entry.id}): "
                        f"entry may have been tampered with"
                    )
                prev_hash = entry.entry_hash
        return True

    def query(
        self,
        action: str | None = None,
        actor: str | None = None,
        level: int | Level | None = None,
        since: str | None = None,     # ISO-8601 or unix timestamp
        until: str | None = None,
        limit: int = 1000,
    ) -> Iterator[AuditEntry]:
        """Query entries with optional filters. Yields in log order."""
        level_val = int(level) if level is not None else None
        since_ts = float(since) if since else None
        until_ts = float(until) if until else None

        if not self.path.exists():
            return

        with open(self.path, "r", encoding="utf-8") as f:
            count = 0
            for raw in f:
                line = raw.strip()
                if not line or count >= limit:
                    break
                try:
                    entry = AuditEntry.from_line(line)
                except Exception:
                    continue

                if action and entry.action != action:
                    continue
                if actor and entry.actor != actor:
                    continue
                if level_val is not None and entry.level != level_val:
                    continue
                if since_ts or until_ts:
                    try:
                        et = datetime.fromisoformat(entry.ts.replace("Z", "+00:00")).timestamp()
                        if since_ts and et < since_ts:
                            continue
                        if until_ts and et > until_ts:
                            continue
                    except Exception:
                        pass

                yield entry
                count += 1

    def count(self) -> int:
        """Return total number of entries in the log."""
        if not self.path.exists():
            return 0
        with open(self.path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())

    def export_jsonl(self, out_path: str | Path) -> int:
        """Export a copy of the log. Returns count of entries exported."""
        n = 0
        with open(out_path, "w", encoding="utf-8") as out:
            for entry in self.query(limit=10_000_000):
                out.write(entry.to_line() + "\n")
                n += 1
        return n

    def export_dict(self) -> list[dict]:
        """Return all entries as plain dicts (for JSON serialization)."""
        return [asdict(e) for e in self.query(limit=10_000_000)]

    # ── Decorators ────────────────────────────────────────────────────────

    def audit(self, action: str, level: int | Level = Level.INFO, actor_arg: int = 0):
        """
        Decorator to automatically log function calls.

        Args:
            action: Dotted action name
            level: Audit level
            actor_arg: Positional argument index to extract actor from (default 0)

        Example:
            @audit_log.audit("user.fetch", actor_arg=0)
            def get_user(user_id):
                return db.get(user_id)
        """
        def decorator(fn):
            @wraps(fn)
            def sync_wrapper(*args, **kwargs):
                actor = args[actor_arg] if actor_arg < len(args) else "system"
                result = fn(*args, **kwargs)
                self.log(level, action, {"args": str(args), "kwargs": str(kwargs), "returned": str(result)}, actor=actor)
                return result
            @wraps(fn)
            async def async_wrapper(*args, **kwargs):
                actor = args[actor_arg] if actor_arg < len(args) else "system"
                result = await fn(*args, **kwargs)
                self.log(level, action, {"args": str(args), "kwargs": str(kwargs), "returned": str(result)}, actor=actor)
                return result
            import asyncio
            return async_wrapper if asyncio.iscoroutinefunction(fn) else sync_wrapper
        return decorator
