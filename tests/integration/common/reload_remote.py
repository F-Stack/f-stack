#!/usr/bin/env python3
"""Per-run, bounded client probe execution; no global process cleanup."""

import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

from reload_checks import identity, signal_owned, digest


def atomic(path, data):
    pending = path.with_suffix(".next")
    with pending.open("x") as f:
        json.dump(data, f)
        f.write("\n")
    os.replace(pending, path)


def job_paths(root, name):
    root = Path(root)
    if (not root.is_absolute() or root.is_symlink() or not root.is_dir()
            or not re.fullmatch(r"[A-Za-z0-9_-]+", name)):
        raise ValueError("invalid job path")
    return root / (name + ".json"), root / (name + ".log")


def run(root, name, seconds, script, argv):
    status, logfile = job_paths(root, name)
    seconds = int(seconds)
    if not 1 <= seconds <= 14400 or script not in ("m4_lc.py", "m4_cps.py", "m4_stream.py", "m4_outage.py"):
        raise ValueError("invalid probe")
    if status.exists() or logfile.exists():
        raise ValueError("job already exists")
    targets = [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == "--server"]
    if len(targets) != 1:
        raise ValueError("one server is required")
    started = time.monotonic()
    data = {"version": 1, "job": name, "run_id": Path(root).name,
            "state": "starting", "started": time.time(), "deadline_seconds": seconds,
            "manager": identity(os.getpid()), "process": None,
            "script_sha256": digest(Path(root) / script),
            "arguments": [v.replace(targets[0], "<TARGET_IP>") for v in argv]}
    atomic(status, data)
    proc = None
    owner = None
    result = 125
    reason = "manager_error"
    selector = selectors.DefaultSelector()
    try:
        with logfile.open("x") as out:
            proc = subprocess.Popen([sys.executable, "-B", str(Path(root) / script), *argv],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, close_fds=True)
            try:
                owner = identity(proc.pid)
            except (FileNotFoundError, ProcessLookupError):
                proc.wait(timeout=1)
            data.update(state="running", process=owner)
            atomic(status, data)
            selector.register(proc.stdout, selectors.EVENT_READ)
            pending = b""
            while selector.get_map() or proc.poll() is None:
                if time.monotonic() - started >= seconds:
                    result, reason = 124, "deadline"
                    break
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    pending += chunk
                    if len(pending) > 1048576:
                        raise ValueError("probe output line exceeds limit")
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        out.write(line.decode("utf-8", "replace").replace(targets[0], "<TARGET_IP>") + "\n")
                    out.flush()
                if not selector.get_map():
                    time.sleep(0.05)
            else:
                result, reason = proc.wait(), "exited"
            if pending:
                out.write(pending.decode("utf-8", "replace").replace(targets[0], "<TARGET_IP>"))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        data["error_type"] = type(exc).__name__
    finally:
        cleanup_ok = True
        try:
            if proc is not None and proc.poll() is None:
                if owner is None:
                    owner = identity(proc.pid)
                rc = signal_owned(owner, "TERM", 2)
                if rc == 3:
                    rc = signal_owned(owner, "KILL", 2)
                cleanup_ok = rc == 0
                if cleanup_ok:
                    proc.wait(timeout=2)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            cleanup_ok = False
        selector.close()
        if proc is not None and proc.stdout:
            proc.stdout.close()
        data.update(state="finished" if cleanup_ok else "cleanup_failed", exit_code=result,
                    reason=reason, child_exit_code=proc.returncode if proc is not None else None,
                    ended=time.time(), elapsed=time.monotonic() - started)
        atomic(status, data)
    return 0 if cleanup_ok else 1


def inspect(root, name, command):
    status, logfile = job_paths(root, name)
    with status.open() as f:
        data = json.load(f)
    if data.get("run_id") != Path(root).name or data.get("job") != name or data.get("version") != 1:
        raise ValueError("job evidence identity mismatch")
    if command == "stop":
        if data["state"] == "finished":
            return 0
        until = time.monotonic() + 8
        while time.monotonic() < until:
            owner = data.get("process")
            if owner:
                rc = signal_owned(owner, "TERM", 1)
                if rc == 3:
                    rc = signal_owned(owner, "KILL", 1)
                if rc != 0:
                    return rc
            time.sleep(0.1)
            data = json.loads(status.read_text())
            if data["state"] == "finished":
                return 0
            if data["state"] == "cleanup_failed":
                return 1
        return 1
    if command == "running":
        return 0 if data["state"] == "running" and data.get("process") and identity(data["process"]["pid"]) == data["process"] else 1
    if data["state"] == "cleanup_failed":
        return 1
    if data["state"] != "finished":
        return 75
    if logfile.exists():
        sys.stdout.write(logfile.read_text())
    print("GR_PROBE_EXIT job=%s rc=%d" % (name, data["exit_code"]))
    return 0 if data["exit_code"] == 0 else 1


def cleanup(root):
    path = Path(root)
    job_paths(root, "all")
    if path.parent != Path("/tmp") or not re.fullmatch(r"gr_[0-9_]+_[0-9a-f]{8}", path.name):
        raise ValueError("not a probe-owned directory")
    for status in path.glob("*.json"):
        data = json.loads(status.read_text())
        if data.get("run_id") != path.name or data.get("state") != "finished":
            raise ValueError("unfinished probe")
        for role in ("process", "manager"):
            item = data.get(role)
            if item is None:
                continue
            until = time.monotonic() + 5
            while time.monotonic() < until:
                try:
                    current = identity(item["pid"])
                    if current["start_time"] != item["start_time"]:
                        break
                except (FileNotFoundError, ProcessLookupError):
                    break
                time.sleep(0.05)
            else:
                raise ValueError("probe or manager still exists")
    return subprocess.call(["/data/workspace/rm_tmp_file.sh", str(path)])


if __name__ == "__main__":
    try:
        command, root, name, *args = sys.argv[1:]
        if command == "cleanup" and name == "all" and not args:
            result = cleanup(root)
        elif command == "run":
            result = run(root, name, args[0], args[1], args[2:])
        elif command in ("result", "running", "stop") and not args:
            result = inspect(root, name, command)
        else:
            raise ValueError("invalid probe command")
        sys.exit(result)
    except (OSError, ValueError, KeyError, IndexError, subprocess.TimeoutExpired):
        print("REMOTE_PROBE_FAILED", file=sys.stderr)
        sys.exit(2)
