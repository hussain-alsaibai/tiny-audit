"""A tamper-evident log must detect the tamper nobody bothers to hide.

tiny-audit 0.1.0 signed every entry and chained them with prev_hash, so
*editing* an entry raised AuditError. *Deleting the newest entries* did not:
a shorter chain is still a valid chain. Proven before the fix —

    log 3 entries -> verify() True -> truncate to 1 line -> verify() True

That is the cheapest tamper there is (tail -n, head -n, a rotate that dies
part-way) and it is exactly what an audit log exists to catch.

Two mechanisms, both here:

1. `AuditEntry.seq` — a monotonic position that is part of the HMAC message,
   so a deleted middle entry shifts the positions and raises "Sequence gap".
2. `high_water_path` — a sidecar recording the highest sequence ever seen,
   raised on write and never lowered. A truncated log's own tail cannot be
   compared to itself, so the witness has to live outside the chain.

Note the floor honestly: **without** a high_water_path, truncation is still
undetectable, because there is nothing to compare the surviving length to.
`test_truncation_is_undetectable_without_a_witness` pins that, so the limit is
documented behaviour rather than a surprise.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tiny_audit import AuditEntry, AuditError, AuditLog, Level  # noqa: E402


def _write(tmp: str, n: int, hw: str | None = None) -> AuditLog:
    log = AuditLog(os.path.join(tmp, "audit.jsonl"), secret="s3cret", high_water_path=hw)
    for i in range(n):
        log.log(Level.INFO, f"step.{i}", {"i": i})
    log.flush()
    return log


def _lines(tmp: str) -> list[str]:
    return [
        ln
        for ln in open(os.path.join(tmp, "audit.jsonl"), encoding="utf-8").read().splitlines()
        if ln.strip()
    ]


def _rewrite(tmp: str, lines: list[str]) -> None:
    with open(os.path.join(tmp, "audit.jsonl"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


class TestSequenceNumbers(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.log = _write(self.tmp, 5)

    def test_entries_are_numbered_from_zero(self) -> None:
        seqs = [e.seq for e in self.log.query(limit=99)]
        self.assertEqual(seqs, [0, 1, 2, 3, 4])

    def test_seq_is_part_of_the_signature(self) -> None:
        entry = self.log.query(limit=1).__next__()
        self.assertTrue(entry.verify_signature("s3cret"))
        tampered = AuditEntry(**{**entry.__dict__, "seq": entry.seq + 10})
        self.assertFalse(tampered.verify_signature("s3cret"))

    def test_append_continues_after_reopen(self) -> None:
        del self.log
        log = AuditLog(os.path.join(self.tmp, "audit.jsonl"), secret="s3cret")
        log.log(Level.INFO, "after.reopen", {})
        log.flush()
        self.assertEqual(log.query(limit=99).__next__().seq, 0)
        self.assertEqual([e.seq for e in log.query(limit=99)][-1], 5)


class TestTruncation(unittest.TestCase):
    def test_truncation_is_detected_with_a_witness(self) -> None:
        tmp = tempfile.mkdtemp()
        hw = os.path.join(tmp, "audit.hw.json")
        log = _write(tmp, 3, hw=hw)
        self.assertTrue(log.verify())

        _rewrite(tmp, _lines(tmp)[:2])

        with self.assertRaises(AuditError) as caught:
            log.verify()
        self.assertIn("truncated", str(caught.exception).lower())

    def test_truncation_survives_reopen(self) -> None:
        """The witness must not be rewritten by the log it is witnessing."""
        tmp = tempfile.mkdtemp()
        hw = os.path.join(tmp, "audit.hw.json")
        _write(tmp, 3, hw=hw)
        _rewrite(tmp, _lines(tmp)[:1])

        log = AuditLog(os.path.join(tmp, "audit.jsonl"), secret="s3cret", high_water_path=hw)
        self.assertEqual(log.anchor()["last_seq"], 2, "reopen lowered the witness")
        with self.assertRaises(AuditError):
            log.verify()

    def test_truncation_is_undetectable_without_a_witness(self) -> None:
        """Documented limit: a chain cannot prove its own length."""
        tmp = tempfile.mkdtemp()
        log = _write(tmp, 3)
        _rewrite(tmp, _lines(tmp)[:1])
        self.assertTrue(log.verify())


class TestSpliceAndReorder(unittest.TestCase):
    def test_deleting_a_middle_entry_is_detected(self) -> None:
        tmp = tempfile.mkdtemp()
        log = _write(tmp, 4)
        lines = _lines(tmp)
        _rewrite(tmp, [lines[0], lines[2], lines[3]])
        with self.assertRaises(AuditError) as caught:
            log.verify()
        self.assertIn("Sequence gap", str(caught.exception))

    def test_reordering_is_detected(self) -> None:
        tmp = tempfile.mkdtemp()
        log = _write(tmp, 3)
        lines = _lines(tmp)
        _rewrite(tmp, [lines[0], lines[2], lines[1]])
        with self.assertRaises(AuditError):
            log.verify()

    def test_appending_a_foreign_entry_is_detected(self) -> None:
        """An attacker with the secret still cannot graft onto a foreign chain."""
        tmp = tempfile.mkdtemp()
        log = _write(tmp, 2)
        other = tempfile.mkdtemp()
        foreign = _write(other, 3)
        lines = _lines(tmp) + [_lines(other)[0]]
        _rewrite(tmp, lines)
        with self.assertRaises(AuditError):
            log.verify()
        del foreign
