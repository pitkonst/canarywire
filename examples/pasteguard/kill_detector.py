"""Fault helper: kill the GLiNER detector process inside the pasteguard container.

PasteGuard runs its proxy and detector as two processes under supervisord in one container; the
detector has no other handle we can `docker compose stop` (it's not a separate service). This
script walks `/proc`, finds the process whose cmdline mentions the detector's port (5002) and is
not supervisord itself, and SIGKILLs it. Supervisord restarts the detector a few seconds later, so
this is meant to be run right before a request, giving a short window where `/health` reports
`degraded` and the proxy fails closed.

Run inside the container:
    docker compose exec -T pasteguard python3 /opt/canarywire/kill_detector.py
"""

import os
import signal
from pathlib import Path

me = os.getpid()
for entry in Path("/proc").iterdir():
    if entry.name.isdigit() and int(entry.name) != me:
        try:
            cmd = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode()
        except OSError:
            continue
        if "5002" in cmd and "supervisord" not in cmd:
            os.kill(int(entry.name), signal.SIGKILL)
            print("killed", entry.name, cmd[:100])
