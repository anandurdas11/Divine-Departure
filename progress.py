"""
progress.py

Tiny dependency-free terminal progress bar. Renders on a single line via carriage
return, degrades to nothing when stdout is not a TTY (e.g. piped to a file / CI log).
"""

import shutil
import sys
import time


class ProgressBar:
    def __init__(self, total, label="", width=32, stream=None, min_interval=0.05):
        self.total = max(int(total), 0)
        self.label = label
        self.width = width
        self.stream = stream or sys.stdout
        self.min_interval = min_interval
        self.count = 0
        self._last_draw = 0.0
        self._start = time.time()
        self.enabled = bool(getattr(self.stream, "isatty", lambda: False)()) and self.total > 0
        if self.enabled:
            self._draw(force=True)

    def update(self, step=1, suffix=""):
        self.count += step
        if not self.enabled:
            return
        now = time.time()
        if now - self._last_draw < self.min_interval and self.count < self.total:
            return
        self._draw(suffix=suffix)

    def _draw(self, force=False, suffix=""):
        if not self.enabled:
            return
        self._last_draw = time.time()
        frac = 1.0 if self.total == 0 else min(self.count / self.total, 1.0)
        filled = int(frac * self.width)
        bar = "#" * filled + "-" * (self.width - filled)
        elapsed = time.time() - self._start
        cols = shutil.get_terminal_size((100, 20)).columns
        txt = f"\r{self.label} [{bar}] {frac*100:5.1f}% ({self.count}/{self.total}) {elapsed:4.1f}s"
        if suffix:
            txt += f"  {suffix}"
        self.stream.write(txt[: max(cols - 1, 10)].ljust(min(len(txt), cols - 1)))
        self.stream.flush()

    def finish(self, msg=""):
        if not self.enabled:
            return
        self.count = self.total
        self._draw(force=True)
        cols = shutil.get_terminal_size((100, 20)).columns
        self.stream.write("\r" + " " * (cols - 1) + "\r")
        if msg:
            self.stream.write(msg + "\n")
        self.stream.flush()

    # allow use as a context manager
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.finish()
        return False
