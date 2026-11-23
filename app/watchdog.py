"""Self-restart when the panel is stuck: Docker restarts a container whose process exits
(restart: unless-stopped), but not one that is merely unhealthy or hung.

Two checks:
  - a thread outside the event loop: if the loop has not ticked for LOOP_STUCK (something blocks it),
    nothing inside the loop could notice, so the thread ends the process;
  - a task in the loop: if the panel's own loops (DNS, Cloudflare, engine; heartbeat.liveness) have
    been stale for LOOPS_STALE, it ends the process too.
Before exiting it stores the reason; the next start records it in the history (and alerts).
Off with MULTICDN_OFFLINE=1 (tests) or MULTICDN_WATCHDOG=0.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from datetime import UTC, datetime, timedelta

from . import heartbeat
from .i18n import tn

log = logging.getLogger("multicdn")

TICK = 15                            # seconds between ticks of the event loop
LOOP_STUCK = 300                     # no tick for this long: the loop is blocked
LOOPS_STALE = timedelta(minutes=20)  # panel loops stale for this long
EXIT_CODE = 70
REASON_KEY = "watchdog_exit"


def enabled() -> bool:
    return os.environ.get("MULTICDN_OFFLINE") != "1" and os.environ.get("MULTICDN_WATCHDOG", "1") != "0"


class Watchdog:
    def __init__(self, state, exit_fn=os._exit, clock=time.monotonic):
        self.state = state
        self.exit_fn = exit_fn
        self.clock = clock
        self.last_tick = clock()
        self.stale_since: datetime | None = None

    def _exit(self, reason: str) -> None:
        log.critical("watchdog: %s; exiting so that Docker restarts the panel", reason)
        try:
            self.state.events.set_value(REASON_KEY, reason)
        except Exception:  # the database may be what is stuck: exit anyway
            pass
        self.exit_fn(EXIT_CODE)

    # ---- in the event loop
    async def tick_forever(self) -> None:
        while True:
            self.last_tick = self.clock()
            self.check_loops()
            await asyncio.sleep(TICK)

    def check_loops(self, now: datetime | None = None) -> None:
        now = now or datetime.now(UTC)
        if now - self.state.started_at < heartbeat.STARTUP_GRACE:
            return
        stale = heartbeat.liveness(self.state, now)
        if not stale:
            self.stale_since = None
            return
        self.stale_since = self.stale_since or now
        if now - self.stale_since >= LOOPS_STALE:
            self._exit(tn("its own tasks were stopped for {minutes} min ({loops})",
                          minutes=int(LOOPS_STALE.total_seconds() // 60), loops=", ".join(stale)))

    # ---- in a thread
    def check_stuck(self) -> bool:
        if self.clock() - self.last_tick > LOOP_STUCK:
            self._exit(tn("it stopped responding for more than {minutes} min",
                          minutes=LOOP_STUCK // 60))
            return True
        return False

    def start_thread(self) -> threading.Thread:
        def run():
            while not self.check_stuck():
                time.sleep(30)
        thread = threading.Thread(target=run, name="multicdn-watchdog", daemon=True)
        thread.start()
        return thread


def report_previous_exit(state) -> None:
    """On start: if the watchdog ended the previous process, say so in the history (it alerts)."""
    reason = state.events.get_value(REASON_KEY)
    if reason:
        state.events.add(actor="auto", kind="alert", summary=tn(
            "The panel restarted itself: {reason}", reason=reason))
        state.events.conn.execute("DELETE FROM settings WHERE key = ?", (REASON_KEY,))
        state.events.conn.commit()
