"""Create a local `.env` from `.env.example` with strong random secrets (never committed).

Usage:  python ops/scripts/gen_secrets.py [--force] [--demo]
  --force  overwrite an existing .env
  --demo   also allow the local e2e demo target (SCANNER_ALLOW_PRIVATE_HOSTS=demo-target)
"""

from __future__ import annotations

import base64
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

GENERATED = {
    "POSTGRES_PASSWORD": lambda: secrets.token_urlsafe(32),
    "GUARDHUB_APP_DB_PASSWORD": lambda: secrets.token_urlsafe(32),
    "REDIS_PASSWORD": lambda: secrets.token_urlsafe(32),
    "JWT_SECRET": lambda: secrets.token_urlsafe(48),
    "DATA_ENCRYPTION_KEY": lambda: base64.b64encode(secrets.token_bytes(32)).decode(),
    "HASH_PEPPER": lambda: secrets.token_urlsafe(48),
}


def main() -> int:
    target = ROOT / ".env"
    if target.exists() and "--force" not in sys.argv:
        print(".env already exists (use --force to overwrite)")
        return 1
    lines = []
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        key = line.split("=", 1)[0].strip()
        if key in GENERATED:
            line = f"{key}={GENERATED[key]()}"
        elif key == "SCANNER_ALLOW_PRIVATE_HOSTS" and "--demo" in sys.argv:
            line = "SCANNER_ALLOW_PRIVATE_HOSTS=demo-target"
        lines.append(line)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {target} with fresh random secrets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
