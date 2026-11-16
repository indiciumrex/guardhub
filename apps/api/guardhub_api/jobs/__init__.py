"""Python-only background jobs on Arq (docs/architecture.md §8.1): scheduler and alerts.

`client` enqueues (used by api and api-worker); `worker` runs the jobs (service `api-jobs`).
"""
