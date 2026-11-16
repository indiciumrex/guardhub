# ADR-0002 — Queue wire protocol: JSON over Redis Streams

- **Status:** Accepted
- **Date:** 2026-11-16
- **Context sections:** GUARDHUB_STANDARDS.md §3, §4 ("Arq (Python→Redis) + Go consumer")

## Context

§4 lists "Arq (Python→Redis) + Go consumer". Arq's on-wire job format is Python-specific
(pickled/msgpack job tuples in sorted sets), so a Go consumer can't read it cleanly, and
emulating it would couple the scanner to Arq internals.

## Decision

- The **Python → Go** boundary uses **Redis Streams with versioned JSON payloads**
  (`gh:jobs`, consumer group `gh-scanners`). **Go → Python** results use the `gh:events` stream.
  The exact contract lives in `docs/architecture.md` §Queue protocol.
- The API ingests `gh:events` with a small async consumer process (`guardhub_api.worker`).
- **Arq stays the choice for Python-only background jobs** (Phase 1: scheduled scans,
  alerts). The MVP needs none, so Arq isn't installed yet. No new runtime or language is added.

## Consequences

- Language-neutral, versioned (`"v": 1`) contract. Consumer groups give at-least-once
  delivery with XACK and reclaiming of stuck messages.
- Payload fields are derived from `packages/shared/finding.schema.json`, so all three languages
  stay in sync.
