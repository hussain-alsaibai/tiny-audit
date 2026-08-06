"""Tests for tiny-audit."""
import os
import tempfile
import pytest
from tiny_audit import AuditLog, AuditEntry, Level, AuditError

def test_log_and_query():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "audit.log")
        log = AuditLog(path, secret="test-secret")

        log.log(Level.INFO, "user.login", {"user_id": 1})
        log.log(Level.WRITE, "order.placed", {"order_id": "O1"})
        log.log(Level.READ, "item.fetch", {"item_id": 42})
        log.flush()

        entries = list(log.query())
        assert len(entries) == 3
        assert entries[0].action == "user.login"
        assert entries[1].action == "order.placed"
        assert entries[2].level == Level.READ

def test_verify_integrity():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "audit.log")
        log = AuditLog(path, secret="test-secret")
        log.log(Level.INFO, "test.one", {"n": 1})
        log.log(Level.INFO, "test.two", {"n": 2})
        log.flush()

        assert log.verify() is True

def test_verify_tampered_entry_raises():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "audit.log")
        log = AuditLog(path, secret="test-secret")
        log.log(Level.INFO, "test.one", {"n": 1})
        log.flush()

        # Tamper with the file — JSON has no spaces after colon
        with open(path, "r+") as f:
            content = f.read()
            content = content.replace('"n":1', '"n":999')
            f.seek(0)
            f.write(content)

        log2 = AuditLog(path, secret="test-secret")
        with pytest.raises(AuditError):
            log2.verify()

def test_chain_hash_integrity():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "audit.log")
        log = AuditLog(path, secret="test-secret")
        log.log(Level.INFO, "a", {})
        log.log(Level.INFO, "b", {})
        log.log(Level.INFO, "c", {})
        log.flush()

        lines = open(path).readlines()
        assert len(lines) == 3
        # prev_hash of entry 2 should be hash of entry 1
        e1 = AuditEntry.from_line(lines[0])
        e2 = AuditEntry.from_line(lines[1])
        assert e2.prev_hash == e1.entry_hash

def test_query_by_actor():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "audit.log")
        log = AuditLog(path, secret="secret")
        log.log(Level.INFO, "act", {}, actor="alice")
        log.log(Level.INFO, "act", {}, actor="bob")
        log.log(Level.INFO, "act", {}, actor="alice")
        log.flush()

        alice = list(log.query(actor="alice"))
        assert len(alice) == 2
        bob = list(log.query(actor="bob"))
        assert len(bob) == 1

def test_query_by_level():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "audit.log")
        log = AuditLog(path, secret="secret")
        log.log(Level.INFO, "act", {}, actor="a")
        log.log(Level.ERROR, "act", {}, actor="b")
        log.log(Level.INFO, "act", {}, actor="c")
        log.flush()

        errors = list(log.query(level=Level.ERROR))
        assert len(errors) == 1
        assert errors[0].actor == "b"

def test_query_by_action():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "audit.log")
        log = AuditLog(path, secret="secret")
        log.log(Level.INFO, "login", {})
        log.log(Level.INFO, "logout", {})
        log.log(Level.INFO, "login", {})
        log.flush()

        logins = list(log.query(action="login"))
        assert len(logins) == 2

def test_count():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "audit.log")
        log = AuditLog(path, secret="secret")
        for i in range(10):
            log.log(Level.INFO, "act", {"n": i})
        log.flush()
        assert log.count() == 10

def test_export_jsonl():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "audit.log")
        out = os.path.join(tmpdir, "export.jsonl")
        log = AuditLog(path, secret="secret")
        log.log(Level.INFO, "act", {"x": 1})
        log.log(Level.INFO, "act", {"x": 2})
        log.flush()

        n = log.export_jsonl(out)
        assert n == 2
        lines = open(out).readlines()
        assert len(lines) == 2

def test_entry_has_uuid_and_timestamp():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "audit.log")
        log = AuditLog(path, secret="secret")
        entry = log.log(Level.INFO, "act", {})
        assert len(entry.id) == 36  # UUID4
        assert entry.ts  # ISO timestamp
        assert entry.ts.endswith("+00:00")

def test_export_dict():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "audit.log")
        log = AuditLog(path, secret="secret")
        log.log(Level.INFO, "act", {"key": "val"})
        log.flush()
        d = log.export_dict()
        assert len(d) == 1
        assert d[0]["action"] == "act"

def test_log_accepts_string_level():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "audit.log")
        log = AuditLog(path, secret="secret")
        log.log("INFO", "act", {})  # pass string name instead of enum
        log.flush()
        entries = list(log.query())
        assert entries[0].level == 20
