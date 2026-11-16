"""Entrypoint of the `api-jobs` service: `python -m guardhub_api.jobs` runs the Arq worker."""

from __future__ import annotations

from arq.worker import run_worker

from guardhub_api.common.logging import configure_logging
from guardhub_api.common.observability import init_observability
from guardhub_api.config import get_settings
from guardhub_api.jobs.worker import WorkerSettings


def main() -> None:
    configure_logging(get_settings().log_level)  # also fails fast on missing/weak configuration
    init_observability("api-jobs")  # no-op unless SENTRY_DSN_API (or SENTRY_DSN) is set
    run_worker(WorkerSettings)  # type: ignore[arg-type]  # Arq reads the settings class attributes


if __name__ == "__main__":
    main()
