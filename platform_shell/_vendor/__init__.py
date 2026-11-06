"""Pinned copies of code and contracts from Tim's existing repos.

Each file here is vendored so this repo stays self-contained in CI (the source
repos are private). At runtime the installed upstream package is preferred when
it is importable; these copies are the fallback.

| File | Source repo | Source path | Commit |
|------|-------------|-------------|--------|
| audittrail_chain.py | timjm25/AuditTrailService | audittrail/model.py (_compute_hash, GENESIS_HASH, ACTIONS, ACTOR_TYPES) | 7b052ab465a5798a9b962c59b2ea28a510d83c6e |
| common_1_0_0.json | timjm25/CDMOAgentContracts | schemas/Common/1.0.0.json (verbatim) | 8c7bf2c4cfd7057215bb3901a97b26506d2dbca6 |
"""
