"""
Run a backend service from the repository root.

  python app.py upstream   # Vulnerable-api mock on port 5001 (start this first)
  python app.py proxy      # Proxy + RBAC panel on port 5002
"""
from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

SERVICES = {
    "upstream": {
        "dir": ROOT / "upstream-service",
        "port": "5001",
        "env": {},
        "label": "upstream-service (Vulnerable-api)",
    },
    "proxy": {
        "dir": ROOT / "proxy-gateway",
        "port": "5002",
        "env": {"UPSTREAM_API_BASE": "http://127.0.0.1:5001"},
        "label": "proxy-gateway",
    },
}


def _usage() -> None:
    print(__doc__.strip())
    print()
    print("Open two terminals from the repo root, activate .venv in each, then:")
    print("  python app.py upstream")
    print("  python app.py proxy")
    print()
    print("Panel: http://localhost:5002/panel")
    print("Or use Docker: docker compose up --build")


def main() -> None:
    if len(sys.argv) != 2:
        _usage()
        sys.exit(1 if len(sys.argv) > 1 else 0)

    name = sys.argv[1].lower().strip()
    if name in ("-h", "--help", "help"):
        _usage()
        sys.exit(0)

    spec = SERVICES.get(name)
    if not spec:
        print(f"Unknown service: {name!r}\n")
        _usage()
        sys.exit(1)

    service_dir = spec["dir"]
    entry = service_dir / "app.py"
    if not entry.is_file():
        print(f"Missing {entry}")
        sys.exit(1)

    os.chdir(service_dir)
    if str(service_dir) not in sys.path:
        sys.path.insert(0, str(service_dir))

    os.environ["PORT"] = spec["port"]
    for key, value in spec["env"].items():
        os.environ[key] = value

    print(f"Starting {spec['label']} on http://127.0.0.1:{spec['port']}")
    runpy.run_path(str(entry), run_name="__main__")


if __name__ == "__main__":
    main()
