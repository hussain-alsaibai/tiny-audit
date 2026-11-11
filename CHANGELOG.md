# Changelog

All notable changes to tiny-audit are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] — 2026-11-11

### Fixed

- **Deleting entries from the end of the log was undetectable.** `verify()`
  checked the `prev_hash` chain and the HMAC signature. A truncated log still
  satisfies both: every surviving line chains from the one before it and
  carries a valid signature. Proven before the fix, on the 0.1.0 code:

  ```
  3 entries            -> verify() True
  rewrite to 1 entry   -> verify() True   # <- the tamper
  ```

  `tail -n`, `head -n`, or a log rotation that dies halfway all produce a log
  that reports itself intact. For a package whose entire purpose is
  tamper-evidence, that was the load-bearing case.

### Added

- **`AuditEntry.seq`** — a monotonic entry number, part of the HMAC message.
  Deleting or reordering a *middle* entry now raises
  `AuditError: Sequence gap at line N`, because positions no longer line up.
- **`high_water_path=`** on `AuditLog` — an optional sidecar recording the
  highest `seq` ever written. It is raised on every flush and **never
  lowered, including on reopen**, so a truncated log is caught even by a fresh
  `AuditLog` instance. `verify()` raises
  `AuditError: Log truncated: 2 entries on disk, but 3 were recorded`.
  `anchor()` reads the current mark.
- `tests/test_truncation.py` — 9 tests covering truncation with and without a
  witness, middle deletion, reorder, and appending an entry from a foreign
  chain. All 9 fail against 0.1.0.

### Note on the limit

Without `high_water_path`, truncation is still undetectable. A hash chain
cannot prove its own length; the witness has to live outside the chain. That
limit is pinned by `test_truncation_is_undetectable_without_a_witness` so it
is documented behaviour rather than a surprise.
