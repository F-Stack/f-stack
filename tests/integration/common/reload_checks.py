#!/usr/bin/env python3
"""Validation and evidence checks for the graceful-reload harness."""

import fcntl
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time

CASES = {"precheck", "baseline", "rt01", "rt02", "rv9", "gr0", "rt12", "rt13"}
SAFE_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")
KILL_TOOL = "/data/workspace/kill_process.sh"


def address(value):
    if "%" in value:
        raise ValueError("scoped addresses are not supported")
    return ipaddress.ip_address(value)


def validate(values):
    address(values["TARGET_IP"])
    if values.get("KERNEL_NIC_IP"):
        address(values["KERNEL_NIC_IP"])
    if not re.fullmatch(r"(?:[A-Za-z_][A-Za-z0-9_.-]*@)?[A-Za-z0-9][A-Za-z0-9_.-]*", values["CLIENT"]):
        raise ValueError("invalid client host")
    names = values["CASES"].split(",")
    if len(names) != len(set(names)) or any(n not in CASES for n in names):
        raise ValueError("unknown or duplicate case")
    bounds = {"ROUNDS": (1, 10000), "INTERVAL": (1, 3600), "POLL": (1, 60),
              "WORKERS": (1, 30), "DRAIN_TIMEOUT": (1, 900), "STARTUP_WAIT": (1, 120),
              "STREAM_MB": (1, 1024), "RTE_FRESH_MIN": (1, 1440),
              "SHUTDOWN_TIMEOUT": (0, 900)}
    for key, (low, high) in bounds.items():
        value = values[key]
        if not re.fullmatch(r"0|[1-9][0-9]{0,5}", value) or not low <= int(value) <= high:
            raise ValueError("invalid " + key)
    duration = float(values["BASELINE_DURATION"])
    if not math.isfinite(duration) or not 1 <= duration <= 14400:
        raise ValueError("invalid baseline duration")
    if int(values["ROUNDS"]) * int(values["INTERVAL"]) + 90 > 14400:
        raise ValueError("round budget exceeds four hours")
    if values["GRACEFUL"] not in ("0", "1") or values["ZC_BUILD"] not in ("auto", "0", "1"):
        raise ValueError("invalid build or graceful form")
    for key in ("NGINX_BIN", "FSTACK_TPL", "PROBE_DIR", "OUT", "BUILD_MANIFEST"):
        value = values.get(key, "")
        if value and (not SAFE_PATH.fullmatch(value) or ".." in Path(value).parts):
            raise ValueError("invalid " + key + " path")
    if values.get("LCORE_MASK") and not re.fullmatch(r"[0-9a-fA-F]{1,8}", values["LCORE_MASK"]):
        raise ValueError("invalid lcore mask")
    if values.get("LCORE_LIST"):
        cores = values["LCORE_LIST"].split(",")
        if (any(not re.fullmatch(r"0|[1-9][0-9]?", c) or int(c) > 31 for c in cores)
                or len(cores) != len(set(cores))):
            raise ValueError("invalid lcore list")


def summary(kind, text):
    prefix = {"lc": "LC_SUMMARY", "cps": "CPS_SUMMARY", "stream": "STREAM_SUMMARY",
              "outage": "OUTAGE_SUMMARY"}[kind]
    lines = [line for line in text.splitlines() if line.startswith(prefix + " ")]
    if len(lines) != 1:
        raise ValueError("missing or duplicate summary")
    fields = {}
    for token in lines[0].split()[1:]:
        key, sep, value = token.partition("=")
        if not sep or not key or key in fields:
            raise ValueError("invalid summary field")
        fields[key] = value

    def integer(key):
        value = fields.get(key, "")
        if not re.fullmatch(r"0|[1-9][0-9]*", value):
            raise ValueError("missing or invalid count: " + key)
        return int(value)

    expected = integer("workers_expected")
    if (expected == 0 or integer("workers_done") != expected
            or integer("workers_active") != expected or integer("worker_errors") != 0):
        raise ValueError("incomplete or failed probe worker")
    declared = integer("conns") + 1 if kind == "lc" else integer("threads") if kind == "cps" else 12 if kind == "stream" else 1
    if expected != declared:
        raise ValueError("worker count does not match probe shape")
    if kind == "lc":
        conns, reqs, fresh = (integer(k) for k in ("conns", "reqs", "fresh_n"))
        if any(integer(k) for k in ("fail", "reconnects", "fresh_fail")):
            raise ValueError("connection failure")
        if reqs + fresh == 0 or (conns > 0 and reqs < conns) or fresh == 0:
            raise ValueError("insufficient traffic samples")
    elif kind == "cps":
        n = integer("n")
        if n == 0 or integer("ok") != n or integer("fail") != 0:
            raise ValueError("CPS failure or empty samples")
    elif kind == "stream":
        # The probe is duration-bounded now: it keeps streaming past the drain
        # so "still running after the reload" can be observed, and therefore
        # completes at least one full wave of 12 (more when the duration spans
        # several). Integrity is unchanged -- every completed stream must be
        # counted as ok, md5_ok and eof_clean.
        streams = integer("streams")
        if streams < 12 or any(integer(k) != streams
                               for k in ("ok", "md5_ok", "eof_clean")):
            raise ValueError("stream integrity failure")
        stall_keys = [k for k in fields if re.fullmatch(r"stalls\(>[0-9.]+s\)", k)]
        if len(stall_keys) != 1 or integer(stall_keys[0]) != 0:
            raise ValueError("stream stall or missing count")
    else:
        if integer("ok") == 0 or integer("windows") == 0:
            raise ValueError("empty outage evidence")
        value = fields.get("longest_outage", "")
        if not value.endswith("s"):
            raise ValueError("missing outage duration")
        duration = float(value[:-1])
        if not math.isfinite(duration) or not 0.3 <= duration <= 2.5:
            raise ValueError("outage outside baseline band")
    return fields


def aggregate(records, expected=None):
    if not records or len({r["case"] for r in records}) != len(records):
        return 5
    if expected is not None and {r["case"] for r in records} != set(expected):
        return 5
    if any("exit_code" not in r or type(r["exit_code"]) is not int for r in records):
        return 5
    failures = sum(r["verdict"] == "FAIL" or r.get("exit_code", 0) != 0 for r in records)
    if failures:
        return 100 + min(failures, 150)
    if any(r["verdict"] != "PASS" for r in records):
        return 6
    return 0


def digest(path):
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def production_sources(root=None):
    root = Path(root) if root is not None else Path(__file__).resolve().parents[3]
    roots = ("lib", "freebsd", "dpdk", "mk", "app/nginx-1.28.0/src",
             "app/nginx-1.28.0/auto", "app/nginx-1.28.0/configure")
    paths = set()

    def scan_error(error):
        raise error

    generated = ("app/nginx-1.28.0/objs", "dpdk/build")
    for name in (*roots, *generated):
        base = root / name
        if not base.exists():
            if name in ("mk",):
                continue
            raise ValueError("production source root missing")
        if base.is_file():
            paths.add(base)
            continue
        seen = set()
        for directory, dirs, files in os.walk(base, followlinks=True, onerror=scan_error):
            real = Path(directory).resolve()
            if real in seen:
                dirs[:] = []
                continue
            seen.add(real)
            dirs[:] = sorted(d for d in dirs if d not in (".git", "__pycache__", "doc", "docs", "logs"))
            paths.update((Path(directory) / d).absolute() for d in dirs
                         if (Path(directory) / d).is_symlink())
            for filename in sorted(files):
                p = Path(directory) / filename
                if (p.suffix in (".c", ".h", ".S", ".s", ".asm", ".inc", ".mk", ".py", ".sh", ".ninja",
                                 ".in", ".map", ".lds", ".def", ".tbl", ".awk", ".pc")
                        or filename in ("Makefile", "meson.build", "meson_options.txt", "configure")
                        or name.endswith("/auto")):
                    if not p.is_file() and not p.is_symlink():
                        raise ValueError("invalid production source type")
                    paths.add(p.absolute())
    return paths


def source_record(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("source path must be absolute")
    if path.is_symlink():
        target = os.readlink(path)
        target_kind = "file" if path.is_file() else "directory" if path.is_dir() else "missing"
        return {"path": str(path), "kind": "symlink", "target": target,
                "sha256": hashlib.sha256(os.fsencode(target)).hexdigest(),
                "target_kind": target_kind,
                "target_sha256": digest(path) if target_kind == "file" else None}
    if not path.is_file():
        raise ValueError("invalid production source type")
    return {"path": str(path), "kind": "file", "sha256": digest(path)}


def verify_build(path, nginx, expected_head):
    with open(path) as f:
        data = json.load(f)
    if data.get("version") != 1 or data.get("source_head") != expected_head:
        raise ValueError("build source identity mismatch")
    if data.get("fault_injection") is not False or not data.get("build_commands"):
        raise ValueError("production build provenance missing")
    sources = data.get("source_files", [])
    if not sources or len({item["path"] for item in sources}) != len(sources):
        raise ValueError("source content inventory missing")
    if {Path(item["path"]) for item in sources} != production_sources():
        raise ValueError("production source inventory coverage mismatch")
    for item in sources:
        if source_record(item["path"]) != item:
            raise ValueError("source content changed after build")
    link = data["link_record"]
    if (link.get("libfstack_sha256") != data["libfstack"]["sha256"]
            or link.get("nginx_sha256") != data["nginx"]["sha256"]
            or link.get("source_files") != sources
            or not link.get("command") or not link.get("exit_code") == 0):
        raise ValueError("link inputs are not bound to output")
    log = data["build_log"]
    if not Path(log["path"]).is_absolute() or digest(log["path"]) != log["sha256"]:
        raise ValueError("build execution log mismatch")
    if link["command"] not in Path(log["path"]).read_text():
        raise ValueError("link command absent from build evidence")
    for role in ("nginx", "libfstack"):
        item = data[role]
        file = Path(item["path"])
        if not file.is_absolute() or not file.is_file() or digest(file) != item["sha256"]:
            raise ValueError("build artifact mismatch")
    if Path(data["nginx"]["path"]).resolve() != Path(nginx).resolve():
        raise ValueError("tested binary differs from manifest")
    if not isinstance(data.get("zc_recv"), bool) or not isinstance(data.get("zc_send"), bool):
        raise ValueError("build form missing")
    return data


def identity(pid):
    p = Path("/proc") / str(pid)
    fields = (p / "stat").read_text().rsplit(")", 1)[1].split()
    exe = os.readlink(p / "exe")
    if fields[0] == "Z":
        raise ProcessLookupError(pid)
    if exe.endswith(" (deleted)"):
        raise ValueError("live process executable was deleted")
    st = (p / "exe").stat()
    return {"pid": int(pid), "start_time": int(fields[19]), "exe": exe,
            "device": st.st_dev, "inode": st.st_ino}


def signal_owned(item, sig, wait=0):
    try:
        current = identity(item["pid"])
    except (FileNotFoundError, ProcessLookupError):
        if sig in ("TERM", "KILL", "QUIT", "INT"):
            return 0
        raise ValueError("control signal target already exited")
    if current != item:
        raise ValueError("PID reused or executable changed")
    args = [KILL_TOOL, "--signal", sig, "--pid", str(item["pid"]),
            "--start-time", str(item["start_time"]), "--exe", item["exe"],
            "--device", str(item["device"]), "--inode", str(item["inode"]),
            "--wait", str(wait)]
    return subprocess.call(args, stdout=subprocess.DEVNULL)


def bounded(seconds, argv, handoff=None):
    if not math.isfinite(seconds) or not 0 < seconds <= 14400 or not argv:
        raise ValueError("invalid command deadline")
    supervisor = Path(__file__).with_name("reload_supervisor.py")
    if handoff is not None:
        from reload_supervisor import request, wait_phase
        inventory, run_id = handoff
        if (not os.environ.get("GR_SUPERVISOR_FD")
                or Path(inventory) != Path(os.environ["GR_SUPERVISOR_ROOT"]) / "processes.json"):
            raise ValueError("startup requires a live supervisor")
        stack = os.environ["GR_SUPERVISOR_STACK"]
        request("start", stack, dict(argv=argv, sha256=digest(argv[0])), run_id=run_id)
        wait_phase(stack, "running", min(seconds, 10))
        return 0
    proc = subprocess.Popen([sys.executable, "-B", str(supervisor), "command", str(seconds), "--", *argv],
                            stdin=subprocess.DEVNULL, close_fds=True)
    item = identity(proc.pid)
    try:
        return proc.wait(timeout=seconds + 12)
    except subprocess.TimeoutExpired:
        if signal_owned(item, "TERM", 2) == 3:
            signal_owned(item, "KILL", 1)
        proc.wait(timeout=2)
        raise RuntimeError("command supervisor failed to finish")


def collect_processes(run_id, nginx, existing):
    from reload_supervisor import request
    if not os.environ.get("GR_SUPERVISOR_FD"):
        raise RuntimeError("process inventory requires a live supervisor")
    value = request("status", os.environ["GR_SUPERVISOR_STACK"], run_id=run_id)
    if value["failure"]:
        raise RuntimeError("process ownership could not be verified")
    return [item["current"] for item in value["members"] if item["current"]]


def resources(prefix, process_file):
    if not re.fullmatch(r"container-gr_[0-9_]+_[0-9a-f]{8}", prefix):
        raise ValueError("invalid resource namespace")
    for item in json.loads(Path(process_file).read_text()):
        try:
            identity(item["pid"])
        except (FileNotFoundError, ProcessLookupError):
            continue
        raise ValueError("registered process still exists")
    runtime = Path("/var/run/dpdk") / prefix
    pages = list(Path("/dev/hugepages").glob(prefix + "map_*"))
    targets = pages + ([runtime] if runtime.exists() else [])
    if any(p.is_symlink() or p.stat().st_uid != os.getuid() for p in targets):
        raise ValueError("resource ownership mismatch")
    needles = [str(p) for p in targets]
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            mapped = (proc / "maps").read_text()
            if any(path in mapped for path in needles):
                raise ValueError("resource still mapped")
            for fd in (proc / "fd").iterdir():
                try:
                    opened = os.readlink(fd)
                except FileNotFoundError:
                    continue
                if any(opened == path or opened.startswith(path + "/") for path in needles):
                    raise ValueError("resource still open")
        except (FileNotFoundError, ProcessLookupError):
            continue
    return targets


def reclaim_resources(prefix, process_file):
    targets = resources(prefix, process_file)
    snapshots = {p: p.stat() for p in targets}
    handles = []
    try:
        for target in targets:
            entries = list(target.rglob("*")) if target.is_dir() else [target]
            for p in entries:
                if p.is_symlink() or p.stat().st_uid != os.getuid():
                    raise ValueError("resource ownership changed")
                snapshots[p] = p.stat()
                if p.is_file():
                    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    handles.append(fd)
                    current = os.fstat(fd)
                    expected = snapshots[p]
                    if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
                        raise ValueError("resource replaced before lock")
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for p, expected in snapshots.items():
            current = p.lstat()
            if (current.st_dev, current.st_ino, current.st_mode) != (expected.st_dev, expected.st_ino, expected.st_mode):
                raise ValueError("resource replaced before reclaim")
        for p in targets:
            if subprocess.call(["/data/workspace/rm_tmp_file.sh", str(p)]) != 0:
                raise RuntimeError("resource reclaim failed")
        return 0
    finally:
        for fd in handles:
            os.close(fd)


def main(argv):
    command, *args = argv
    if command == "validate":
        values = dict(a.split("=", 1) for a in args)
        validate(values)
    elif command == "url":
        ip = address(args[0])
        print("http://%s/" % ("[" + str(ip) + "]" if ip.version == 6 else str(ip)))
    elif command == "summary":
        print(json.dumps(summary(args[0], sys.stdin.read())))
    elif command == "aggregate":
        with open(args[0]) as f:
            expected = set(args[1].split(",")) | {"precheck"} if len(args) > 1 else None
            return aggregate([json.loads(line) for line in f if line.strip()], expected)
    elif command == "record":
        path, case, verdict, criterion, measured, exit_code = args
        with open(path, "a") as f:
            f.write(json.dumps({"case": case, "verdict": verdict, "criterion": criterion,
                                "measured": measured, "exit_code": int(exit_code)}) + "\n")
    elif command == "verify-build":
        print(json.dumps(verify_build(*args)))
    elif command == "identity":
        print(json.dumps(identity(int(args[0]))))
    elif command == "bounded":
        return bounded(float(args[0]), args[1:])
    elif command == "bounded-start":
        return bounded(float(args[0]), args[3:], (args[1], args[2]))
    elif command == "resources":
        for path in resources(*args):
            print(path)
    elif command == "reclaim":
        from reload_supervisor import request
        request("assert-stopped", os.environ["GR_SUPERVISOR_STACK"])
        return reclaim_resources(*args)
    elif command == "collect":
        path, run_id, nginx = args
        print(json.dumps(collect_processes(run_id, nginx, [])))
    elif command in ("signal", "stop"):
        raise ValueError("target control requires reload_supervisor")
    else:
        raise ValueError("unknown check")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, KeyError, OSError, IndexError, RuntimeError):
        print("RELOAD_CHECK_FAILED", file=sys.stderr)
        sys.exit(2)
