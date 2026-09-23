"""Shared dual-stack HTTP probes with complete-response accounting."""

import argparse
import hashlib
import ipaddress
import math
import socket
import threading
import time


def response(sock, chunk_size=65536, gap=0, expect_md5=None, expect_eof=False, path="/",
             strict=True):
    # strict=False reports the integrity verdict instead of raising, so the
    # caller can count md5_ok and eof_clean separately. Printing one counter
    # under four names makes the criterion an identity, not a check.
    connection = "close" if expect_eof else "keep-alive"
    sock.sendall(("GET %s HTTP/1.1\r\nHost: reload-test\r\nConnection: %s\r\n\r\n" % (path, connection)).encode("ascii"))
    data = b""
    while b"\r\n\r\n" not in data:
        part = sock.recv(4096)
        if not part:
            raise ValueError("EOF in headers")
        data += part
        if len(data) > 65536:
            raise ValueError("headers exceed limit")
    head, body = data.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n", 1)[0].split()
    if len(status) < 2 or status[1] != b"200":
        raise ValueError("non-200 status")
    lengths = [line.split(b":", 1)[1].strip() for line in head.split(b"\r\n")[1:]
               if line.lower().startswith(b"content-length:")]
    if len(lengths) != 1 or not lengths[0].isdigit():
        raise ValueError("one content length required")
    length = int(lengths[0])
    if length <= 0 or length > 1024 * 1024 * 1024:
        raise ValueError("invalid body length")
    digest = hashlib.md5(body)
    received = len(body)
    worst = 0.0
    while received < length:
        before = time.monotonic()
        if gap:
            time.sleep(gap)
        part = sock.recv(min(chunk_size, length - received))
        worst = max(worst, time.monotonic() - before)
        if not part:
            raise ValueError("EOF before complete body")
        received += len(part)
        digest.update(part)
    if received != length:
        raise ValueError("body length mismatch")
    md5_ok = True
    if expect_md5 and digest.hexdigest() != expect_md5:
        md5_ok = False
        if strict:
            raise ValueError("body digest mismatch")
    eof_clean = True
    if expect_eof and sock.recv(1) != b"":
        eof_clean = False
        if strict:
            raise ValueError("trailing body bytes")
    return received, digest.hexdigest(), worst, md5_ok, eof_clean


def main(mode):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--timeout", type=float, default=2)
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--fresh", type=float, default=0.5)
    parser.add_argument("--conns", type=int, default=24)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--streams", type=int, default=12)
    parser.add_argument("--chunk", type=int, default=16384)
    parser.add_argument("--gap", type=float, default=0.1)
    parser.add_argument("--stall", type=float, default=3)
    parser.add_argument("--expect-md5", default="")
    parser.add_argument("--path", default="/dl/big.bin")
    a = parser.parse_args()
    try:
        ipaddress.ip_address(a.server)
    except ValueError:
        parser.error("invalid server address")
    if not 1 <= a.port <= 65535 or not 1 <= a.chunk <= 1048576:
        parser.error("invalid port or chunk size")
    for value in (a.timeout, a.duration, a.interval, a.fresh, a.stall):
        if not math.isfinite(value) or not 0 < value <= 14400:
            parser.error("invalid time value")
    if not math.isfinite(a.gap) or not 0 <= a.gap <= 60:
        parser.error("invalid gap")
    if not all(0 <= n <= 1024 for n in (a.conns, a.threads, a.streams)):
        parser.error("invalid concurrency")
    if mode in ("cps", "stream") and (a.threads == 0 or a.streams == 0):
        parser.error("zero concurrency")
    if mode == "stream" and (len(a.expect_md5) != 32 or any(c not in "0123456789abcdef" for c in a.expect_md5)):
        parser.error("stream digest required")
    if not a.path.startswith("/") or any(ord(c) < 33 or ord(c) > 126 for c in a.path):
        parser.error("invalid HTTP path")
    started = time.monotonic()
    until = started + a.duration
    lock = threading.Lock()
    stats = dict(reqs=0, fail=0, fresh_n=0, fresh_fail=0, streams=0, ok=0, md5_ok=0,
                 eof_clean=0, integrity_fail=0, stalls=0, worst=0.0,
                 reconnects=0, workers_done=0, workers_active=0, worker_errors=0,
                 outage_start=None, windows=0, longest=0.0)
    local = threading.local()

    def connect():
        return socket.create_connection((a.server, a.port), timeout=a.timeout)

    def traffic(kind, keep):
        sock = None
        connected = False
        while time.monotonic() < until:
            begin = time.monotonic()
            error = None
            try:
                if sock is None:
                    sock = connect()
                    if keep and connected:
                        with lock:
                            stats["reconnects"] += 1
                    connected = True
                response(sock, expect_eof=not keep)
            except (OSError, ValueError) as exc:
                error = type(exc).__name__
            finally:
                if sock is not None and (not keep or error):
                    sock.close()
                    sock = None
            with lock:
                key = "reqs" if kind == "lc" else "fresh_n"
                stats[key] += 1
                stats["fail" if kind == "lc" else "fresh_fail"] += bool(error)
                local.requests += 1
                if mode == "outage":
                    if error:
                        if stats["outage_start"] is None:
                            stats["outage_start"] = begin
                            stats["windows"] += 1
                        stats["longest"] = max(stats["longest"], time.monotonic() - stats["outage_start"])
                    else:
                        stats["outage_start"] = None
                if error:
                    print("PROBE_ERROR kind=%s type=%s" % (kind, error), flush=True)
            pace = a.interval if kind == "lc" else (a.fresh if mode == "lc" else 0)
            if pace:
                time.sleep(max(0, pace - (time.monotonic() - begin)))
        if sock:
            sock.close()

    def stream(index):
        # Duration-bounded: one download used to be the whole life of the
        # probe, so it died exactly when the reload finished draining it and
        # "probe still running after the reload" could not be observed. The
        # wave repeats until --duration, keeping the connection set warm past
        # the drain; a failure still ends this worker and fails the probe.
        while time.monotonic() < until:
            begin = time.monotonic()
            local.wave += 1
            ok = False
            try:
                with connect() as sock:
                    size, digest, worst, md5_ok, eof_clean = response(
                        sock, a.chunk, a.gap, a.expect_md5, True, a.path, strict=False)
                with lock:
                    stats["streams"] += 1
                    stats["ok"] += bool(md5_ok and eof_clean)
                    stats["md5_ok"] += bool(md5_ok)
                    stats["eof_clean"] += bool(eof_clean)
                    stats["integrity_fail"] += not (md5_ok and eof_clean)
                    stats["stalls"] += worst > a.stall
                    stats["worst"] = max(stats["worst"], worst)
                    print("STREAM wid=%d wave=%d bytes=%d md5=%s md5_ok=%d eof_clean=%d "
                          "start=%.6f end=%.6f" %
                          (index, local.wave, size, digest, bool(md5_ok), bool(eof_clean),
                           begin - started, time.monotonic() - started), flush=True)
                ok = bool(md5_ok and eof_clean)
            except (OSError, ValueError) as exc:
                print("STREAM_FAIL wid=%d wave=%d type=%s" %
                      (index, local.wave, type(exc).__name__), flush=True)
            local.requests += 1
            if not ok:
                with lock:
                    stats["worker_errors"] += 1
                return

    def guarded(target, *args):
        local.requests = 0
        local.wave = 0
        try:
            target(*args)
        except BaseException as exc:
            with lock:
                stats["worker_errors"] += 1
            print("PROBE_THREAD_ERROR type=%s" % type(exc).__name__, flush=True)
        finally:
            with lock:
                stats["workers_done"] += 1
                stats["workers_active"] += local.requests > 0

    if mode == "stream":
        jobs = [(stream, i) for i in range(a.streams)]
    elif mode == "lc":
        jobs = [(traffic, "lc", True) for _ in range(a.conns)] + [(traffic, "fresh", False)]
    else:
        jobs = [(traffic, "fresh", False) for _ in range(a.threads if mode == "cps" else 1)]
    workers = [threading.Thread(target=guarded, args=job) for job in jobs]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    details = " workers_expected=%d workers_done=%d workers_active=%d worker_errors=%d" % (
        len(workers), stats["workers_done"], stats["workers_active"], stats["worker_errors"])
    if mode == "lc":
        line = "LC_SUMMARY conns=%d reqs=%d fail=%d reconnects=%d fresh_n=%d fresh_fail=%d" % (
            a.conns, stats["reqs"], stats["fail"], stats["reconnects"], stats["fresh_n"], stats["fresh_fail"])
    elif mode == "cps":
        line = "CPS_SUMMARY threads=%d n=%d ok=%d fail=%d" % (
            a.threads, stats["fresh_n"], stats["fresh_n"] - stats["fresh_fail"], stats["fresh_fail"])
    elif mode == "stream":
        # streams= is the number of COMPLETED downloads (one wave is 12);
        # ok / md5_ok / eof_clean are counted independently, so a corrupt or
        # truncated body shows up as a divergence instead of an alias.
        line = ("STREAM_SUMMARY streams=%d ok=%d md5_ok=%d eof_clean=%d integrity_fail=%d "
                "stalls(>%ss)=%d worst_gap=%.3fs") % (
            stats["streams"], stats["ok"], stats["md5_ok"], stats["eof_clean"],
            stats["integrity_fail"], a.stall, stats["stalls"], stats["worst"])
    else:
        line = "OUTAGE_SUMMARY ok=%d windows=%d longest_outage=%.3fs" % (
            stats["fresh_n"] - stats["fresh_fail"], stats["windows"], stats["longest"])
    print(line + details, flush=True)
    if stats["worker_errors"] or stats["workers_active"] != len(workers):
        return 1
    if mode == "outage":
        return 0 if stats["fresh_n"] > stats["fresh_fail"] else 1
    return int(bool(stats["fail"] or stats["fresh_fail"] or stats["reconnects"] or
                    (mode == "stream" and (stats["streams"] < a.streams or stats["stalls"] or
                                           stats["ok"] != stats["streams"] or
                                           stats["md5_ok"] != stats["streams"] or
                                           stats["eof_clean"] != stats["streams"]))))
