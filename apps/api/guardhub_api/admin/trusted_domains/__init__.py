"""Admin trusted domains (ADR-0003, docs/architecture.md §8.5).

An admin proves ownership of one exact host once; while that proof stays published (re-checked
in the background) the admin can create and scan projects for exactly that origin without the
proof prompt. It never allows scanning a target without a currently valid proof.
"""
