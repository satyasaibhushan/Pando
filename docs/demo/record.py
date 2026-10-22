#!/usr/bin/env python3
"""Record the README demo: two containers stand in for two machines.

Every command shown runs for real against target/release/pando. The script
types each command into the recording, runs it in the matching container
through a pseudo-terminal, and writes docs/demo/demo.cast (asciicast v2).
render.sh turns that into poster.png, demo.webm and demo.mp4. The poster is
the screen at the `poster` marker, just before the dashboard opens.

    cargo build --release
    python3 docs/demo/record.py

Needs Docker. IMAGE (default rust:1) must provide bash and git.
"""

import fcntl
import json
import os
import pty
import select
import struct
import subprocess
import termios
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "demo.cast"
BINARY = ROOT / "target" / "release" / "pando"
IMAGE = os.environ.get("IMAGE", "rust:1")
NETWORK = "pando-demo"
COLS, ROWS = 100, 28
HOSTS = ("studio", "laptop")

events = []
started = time.monotonic()


def emit(data):
    events.append([round(time.monotonic() - started, 3), "o", data])


def docker(*args, check=True):
    return subprocess.run(["docker", *args], check=check, capture_output=True, text=True)


def setup():
    teardown()
    docker("network", "create", NETWORK)
    for host in HOSTS:
        docker(
            "run", "-d", "--name", f"pando-{host}", "--hostname", host,
            "--network", NETWORK, "-v", f"{BINARY}:/usr/local/bin/pando:ro",
            IMAGE, "sleep", "infinity",
        )
        docker(
            "exec", f"pando-{host}", "bash", "-c",
            "useradd -m alex && su alex -c 'git config --global user.name Alex"
            " && git config --global user.email alex@example.test"
            " && git config --global init.defaultBranch main'",
        )
    # Two repositories on studio, one of them mid-edit.
    shell("studio", """
        mkdir -p code/storefront/src code/orders-api
        cd code/storefront && git init -q
        printf '# storefront\\n' > README.md
        printf 'export const total = (items) => items.length\\n' > src/cart.ts
        git add . && git commit -qm 'Start storefront'
        printf 'export const total = (items) =>\\n  items.reduce((sum, item) => sum + item.price * item.qty, 0)\\n' > src/cart.ts
        printf 'STRIPE_KEY=sk_test_fictional\\n' > .env
        cd ../orders-api && git init -q && printf '# orders-api\\n' > README.md
        git add . && git commit -qm 'Start orders-api'
    """)


def teardown():
    for host in HOSTS:
        docker("rm", "-f", f"pando-{host}", check=False)
    docker("network", "rm", NETWORK, check=False)


def shell(host, script):
    return docker("exec", "-u", "alex", "-w", "/home/alex", f"pando-{host}", "bash", "-c", script)


def prompt(host, cwd):
    emit(f"\x1b[1;32malex@{host}\x1b[0m:\x1b[1;34m{cwd}\x1b[0m$ ")


def type_line(text):
    for ch in text:
        emit(ch)
        time.sleep(0.035)
    time.sleep(0.25)
    emit("\r\n")


def comment(host, cwd, text):
    prompt(host, cwd)
    emit(f"\x1b[2m# {text}\x1b[0m\r\n")
    time.sleep(0.9)


def run(host, cwd, command, keys=(), shown=None):
    """Type `shown` (default: command), run command, stream its output."""
    prompt(host, cwd)
    type_line(shown or command)
    workdir = "/home/alex" + cwd[1:] if cwd.startswith("~") else cwd
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    proc = subprocess.Popen(
        ["docker", "exec", "-it", "-e", "TERM=xterm-256color", "-u", "alex", "-w", workdir,
         f"pando-{host}", "bash", "-c", command],
        stdin=slave, stdout=slave, stderr=slave, close_fds=True,
    )
    os.close(slave)
    pending = list(keys)
    output = b""
    began = time.monotonic()
    while True:
        if pending and time.monotonic() >= began + pending[0][0]:
            os.write(master, pending.pop(0)[1])
        ready, _, _ = select.select([master], [], [], 0.05)
        if ready:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            output += data
            emit(data.decode("utf-8", "replace"))
        elif proc.poll() is not None and not pending:
            break
    proc.wait()
    os.close(master)
    time.sleep(0.8)
    return output.decode("utf-8", "replace")


def main():
    if not BINARY.exists():
        raise SystemExit("build first: cargo build --release")
    setup()
    try:
        emit("\x1b[2J\x1b[H")
        comment("studio", "~/code/storefront", "studio: the desk machine, mid-edit")
        run("studio", "~/code/storefront", "git status --short")
        run("studio", "~", "pando up --name studio --no-services")
        # The service install starts this in real use; --no-services skips it.
        docker("exec", "-d", "-u", "alex", "-w", "/home/alex", "pando-studio", "pando", "daemon")
        time.sleep(1.5)
        run("studio", "~", "pando share code --no-services")
        invite = run("studio", "~", "pando invite")
        code = invite.split("--code ")[1].split()[0]
        emit("\r\n")
        comment("laptop", "~", "laptop: a second machine on the same network")
        run("laptop", "~", f"pando up --to studio:7337 --code {code} --name laptop --no-services")
        run("laptop", "~", "pando join code --no-services")
        run("laptop", "~/Pando/code/storefront", "git status --short && git diff --stat")
        run("laptop", "~", "pando devices")
        run("laptop", "~", "pando status")
        events.append([round(time.monotonic() - started, 3), "m", "poster"])
        run("laptop", "~", "pando", keys=[(3.5, b"j"), (5.0, b"q")])
        prompt("laptop", "~")
        time.sleep(1.5)
    finally:
        teardown()
    header = {"version": 2, "width": COLS, "height": ROWS, "env": {"TERM": "xterm-256color"}}
    OUT.write_text("\n".join([json.dumps(header), *map(json.dumps, events)]) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
