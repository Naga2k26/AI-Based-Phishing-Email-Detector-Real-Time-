import threading
import time
from typing import Callable, List

from config import Config


class Scheduler:
    """A very small in-process scheduler meant for simple periodic jobs.

    It exposes `scheduler.running` to match the expectations in `app.py`.
    """

    def __init__(self):
        self.jobs = []  # list of job dicts: {id, func, interval, next_run}
        self._lock = threading.Lock()
        self._thread = None
        self._running = False
        self._next_id = 1

        # Expose `scheduler.running` as referenced by app.py
        self.scheduler = self

    @property
    def running(self) -> bool:
        return self._running

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)

    def add_email_scan_job(self, func: Callable, minutes: int = None) -> int:
        interval = minutes or Config.SCAN_INTERVAL_MINUTES
        with self._lock:
            job_id = self._next_id
            self._next_id += 1
            job = {
                'id': job_id,
                'func': func,
                'interval': interval * 60,
                'next_run': time.time() + (interval * 60)
            }
            self.jobs.append(job)
        return job_id

    def get_jobs(self) -> List[dict]:
        with self._lock:
            return [{'id': j['id'], 'next_run': j['next_run'], 'interval': j['interval']} for j in self.jobs]

    def _run_loop(self):
        while self._running:
            now = time.time()
            to_run = []
            with self._lock:
                for job in self.jobs:
                    if now >= job['next_run']:
                        to_run.append(job)
            for job in to_run:
                try:
                    job['func']()
                except Exception:
                    # job should not crash the loop
                    pass
                with self._lock:
                    job['next_run'] = time.time() + job['interval']
            time.sleep(1)
