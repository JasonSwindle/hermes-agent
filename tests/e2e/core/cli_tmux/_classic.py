"""Shared harness for the classic-CLI tmux suites (``display.interface: cli``).

A real ``python -m hermes_cli.main`` runs in a private tmux server (own ``-L`` socket) with a
hermetic fake HOME / HERMES_HOME and a config that routes the model to a loopback
``FakeLLMServer``. The CLI is a thin client of the profile's gateway daemon, which it spawns on
first connect; cleanup stops that daemon and then kills anything left whose environ carries this
run's exact ``HERMES_HOME`` (never a pattern kill).

Driver rule (the CLI reads an Enter processed within 50 ms of the last buffer change as a pasted
newline): type with ``send-keys -l``, wait until the composer shows the text, pause, then send
``Enter`` separately. Each step waits for its needle, then until the screen (digits masked) has
been static for ``quiet`` seconds.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from tests.fakes.fake_llm_provider import MODEL_ID, OFFER_VERSION

REPO_ROOT = Path(__file__).resolve().parents[4]
COLS, ROWS = 160, 50
PROMPT = "\u276f"
STATUS_BAR = f"\u2624 {MODEL_ID}"
_DIGITS = re.compile(r"\d")
_TRACEBACK = "Traceback (most recent call last)"

BASE_CONFIG = f"""model:
  provider: custom
  base_url: {{base_url}}
  default: {MODEL_ID}
  context_length: 128000
agent:
  api_max_retries: 1
telemetry:
  shared_metrics:
    enabled: false
    send: false
    offer_version: {OFFER_VERSION}
display:
  interface: cli
approvals:
  mode: manual
  timeout: 60
skills:
  creation_nudge_interval: 0
updates:
  check: false
models_dev:
  url: http://127.0.0.1:9/api.json
auxiliary:
  title_generation:
    enabled: false
"""


@dataclass
class ClassicHome:
    root: Path
    extra_env: dict[str, str] = field(default_factory=dict)

    @property
    def home(self) -> Path:
        return self.root / "home"

    @property
    def hermes_home(self) -> Path:
        return self.home / ".hermes"

    @property
    def work(self) -> Path:
        return self.root / "work"

    @property
    def stderr_log(self) -> Path:
        return self.root / "stderr.log"

    def write(self, base_url: str, extra_config: str = "") -> ClassicHome:
        self.hermes_home.mkdir(parents=True, exist_ok=True)
        self.work.mkdir(parents=True, exist_ok=True)
        (self.hermes_home / "config.yaml").write_text(BASE_CONFIG.format(base_url=base_url) + extra_config,
                                                      encoding="utf-8")
        (self.hermes_home / ".env").write_text("OPENAI_API_KEY=sk-fake-e2e\n", encoding="utf-8")
        return self

    def env(self) -> dict[str, str]:
        """Allowlisted child env: no inherited HERMES_*, provider keys, display or TMUX variables."""
        keep = ("PATH", "LANG", "USER", "LOGNAME", "SHELL", "TMPDIR")
        env = {k: os.environ[k] for k in keep if k in os.environ}
        env.update({
            "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "TERM": "xterm-256color", "TZ": "UTC",
            "HOME": str(self.home), "HERMES_HOME": str(self.hermes_home), "PYTHONPATH": str(REPO_ROOT),
            # The child's state.db IS this tmp home's db; the live-DB guard would refuse it under pytest.
            "HERMES_STATE_DB_GUARD_BYPASS": "1", "PYTHONFAULTHANDLER": "1", "NO_GCE_CHECK": "True",
        })
        env.update(self.extra_env)
        return env

    def argv(self, *args: str) -> list[str]:
        return [sys.executable, "-m", "hermes_cli.main", *args]

    def run(self, *args: str, timeout: float = 180.0) -> subprocess.CompletedProcess:
        """A non-TTY run (stdout piped): ``chat -q`` one-shots, ``gateway stop``."""
        return subprocess.run(self.argv(*args), cwd=self.work, env=self.env(), capture_output=True, text=True,
                              timeout=timeout, stdin=subprocess.DEVNULL, check=False)

    def pids(self) -> set[int]:
        needle = f"HERMES_HOME={self.hermes_home}".encode()
        found: set[int] = set()
        for entry in os.listdir("/proc"):
            if not entry.isdigit() or int(entry) == os.getpid():
                continue
            try:
                with open(f"/proc/{entry}/environ", "rb") as fh:
                    if needle in fh.read().split(b"\0"):
                        found.add(int(entry))
            except OSError:
                continue
        return found

    def reap(self) -> None:
        """Operator stop for the profile's gateway, then SIGTERM/SIGKILL whatever this home still runs."""
        self.run("gateway", "stop", timeout=60)
        for sig, grace in ((signal.SIGTERM, 8.0), (signal.SIGKILL, 2.0)):
            for pid in self.pids():
                try:
                    os.kill(pid, sig)
                except OSError:
                    pass
            end = time.monotonic() + grace
            while self.pids() and time.monotonic() < end:
                time.sleep(0.2)


class Pane:
    """One private tmux server holding the CLI pane ``p``."""

    def __init__(self, ch: ClassicHome) -> None:
        self.ch = ch
        self.sock = f"hermes-e2e-classic-{uuid.uuid4().hex[:8]}"

    def tmux(self, *args: str) -> str:
        env = {k: v for k, v in os.environ.items() if not k.startswith("TMUX")}
        return subprocess.run(["tmux", "-L", self.sock, *args], capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=30, check=False, env=env).stdout

    def launch(self, *args: str) -> None:
        self.tmux("kill-server")
        env = self.ch.env()
        envs = " ".join(f"{k}={shlex.quote(v)}" for k, v in env.items())
        cmd = (f"exec env -i {envs} {' '.join(shlex.quote(a) for a in self.ch.argv(*args))} "
               f"2>>{shlex.quote(str(self.ch.stderr_log))}")
        subprocess.run(["tmux", "-L", self.sock, "-f", os.devnull, "new-session", "-d", "-s", "p", "-x", str(COLS),
                        "-y", str(ROWS), "-c", str(self.ch.work), "sh", "-c", cmd], check=True, timeout=30,
                       env={k: v for k, v in os.environ.items() if not k.startswith("TMUX")})
        self.tmux("set", "-g", "remain-on-exit", "on")
        self.tmux("set", "-g", "history-limit", "50000")

    def screen(self) -> str:
        return self.tmux("capture-pane", "-p", "-t", "p")

    def scrollback(self) -> str:
        return self.tmux("capture-pane", "-p", "-J", "-t", "p", "-S", "-", "-E", "-")

    def dead(self) -> bool:
        return self.tmux("display-message", "-p", "-t", "p", "#{pane_dead}").strip() == "1"

    def keys(self, *k: str) -> None:
        self.tmux("send-keys", "-t", "p", *k)

    def wait(self, needles: list[str], timeout: float = 60.0, *, full: bool = False) -> str | None:
        """The first needle seen (screen, or the whole scrollback with ``full``), None on timeout/exit."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            text = self.scrollback() if full else self.screen()
            for needle in needles:
                if needle in text:
                    return needle
            if self.dead():
                return None
            time.sleep(0.25)
        return None

    def settle(self, quiet: float = 2.0, timeout: float = 20.0) -> None:
        end = time.monotonic() + timeout
        last, since = None, time.monotonic()
        while time.monotonic() < end:
            text = _DIGITS.sub("#", self.screen())
            if text != last:
                last, since = text, time.monotonic()
            elif time.monotonic() - since >= quiet:
                return
            time.sleep(0.2)

    def submit(self, text: str) -> None:
        self.tmux("send-keys", "-t", "p", "-l", text)
        self.wait([f"{PROMPT} {text}"[-40:]], 10)
        time.sleep(1.2)
        self.keys("Enter")

    def wait_dead(self, timeout: float = 30.0) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end and not self.dead():
            time.sleep(0.3)
        return self.dead()

    def ready(self, timeout: float = 120.0) -> str | None:
        """Wait for the running app's status bar (painted in raw mode), then let startup settle."""
        hit = self.wait([STATUS_BAR], timeout)
        self.settle(quiet=3.0, timeout=30)
        time.sleep(1.5)
        return hit

    def kill(self) -> None:
        self.tmux("kill-server")


def assert_no_traceback(text: str, where: str) -> None:
    assert _TRACEBACK not in text, f"{where}: a traceback reached the terminal:\n{text[-4000:]}"


def text_of(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(str(p.get("text", "")) if isinstance(p, dict) else str(p) for p in content)
    return json.dumps(content)


def last_user(body: dict) -> str:
    for message in reversed(body.get("messages") or []):
        if message.get("role") == "user":
            return text_of(message.get("content"))
    return ""
