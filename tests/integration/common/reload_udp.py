#!/usr/bin/env python3
"""UDP probes for the graceful-reload harness (rt33/rt34/rt35).

usage (client side, run as a bounded reload_remote.py job):
  reload_udp.py serve --server <bind_addr> --port <port>
      UDP echo upstream: replies "up port=<peer_port> <payload>".
  reload_udp.py flows --server <addr> --port <port> --flows N
                --duration S [--interval I] [--timeout T] [--name NAME]
      N flows, one connected socket (one source port) each, stop-and-wait:
      a datagram every I s, a reply expected within T s. Prints one
      UDP_PROGRESS line per second and a final UDP_SUMMARY <json> line.
usage (harness side):
  reload_udp.py check <job_log> --mode old|new|switch
                [--old a,b] [--new c,d] [--max-lost N] [--need-switch]
      'old'/'new': every reply comes from that set (pid= tokens) or, for
      the proxy, every flow keeps one upstream port; 'switch': each flow
      goes old -> new at most once (exactly once with --need-switch).
      Prints CHECK ok=0|1 <details>.
"""
import json
import selectors
import socket
import sys
import time


def arg(argv, name, default=None, conv=str):
    if name in argv:
        i = argv.index(name)
        if i + 1 < len(argv):
            return conv(argv[i + 1])
    if default is None:
        raise SystemExit("missing " + name)
    return default


def family(addr):
    return socket.AF_INET6 if ":" in addr else socket.AF_INET


def serve(argv):
    addr = arg(argv, "--server")
    port = arg(argv, "--port", conv=int)
    s = socket.socket(family(addr), socket.SOCK_DGRAM)
    s.bind((addr, port))
    print("UDP_SERVE listening port=%d" % port, flush=True)
    seen = {}
    last = time.monotonic()
    while True:
        data, peer = s.recvfrom(65535)
        s.sendto(b"up port=%d " % peer[1] + data, peer)
        seen[peer[1]] = seen.get(peer[1], 0) + 1
        now = time.monotonic()
        if now - last >= 1.0:
            last = now
            print("UDP_SERVE ports=%d dgrams=%d" % (len(seen), sum(seen.values())),
                  flush=True)


class Flow:
    def __init__(self, idx, addr, port, name):
        self.idx = idx
        self.sock = socket.socket(family(addr), socket.SOCK_DGRAM)
        self.sock.connect((addr, port))
        self.sock.setblocking(False)
        self.lport = self.sock.getsockname()[1]
        self.name = name
        self.seq = 0
        self.sent = 0
        self.recv = 0
        self.lost = 0
        self.refused = 0
        self.stray = 0
        self.errors = 0
        self.wait_seq = None
        self.deadline = 0.0
        self.next_send = 0.0
        self.tokens = []        # [t, token] on every change of responder
        self.ports = []         # distinct upstream ports, in order

    def send(self, now, interval):
        self.seq += 1
        msg = "%s f=%d s=%d" % (self.name, self.idx, self.seq)
        try:
            self.sock.send(msg.encode())
            self.sent += 1
        except ConnectionRefusedError:
            self.refused += 1
        except OSError:
            self.errors += 1
        self.wait_seq = self.seq
        self.next_send = now + interval

    def note(self, t, token, port):
        if not self.tokens or self.tokens[-1][1] != token:
            self.tokens.append([round(t, 3), token])
        if port is not None and port not in self.ports:
            self.ports.append(port)


def flows(argv):
    addr = arg(argv, "--server")
    port = arg(argv, "--port", conv=int)
    nflows = arg(argv, "--flows", 4, int)
    duration = arg(argv, "--duration", 10.0, float)
    interval = arg(argv, "--interval", 0.2, float)
    timeout = arg(argv, "--timeout", 1.0, float)
    name = arg(argv, "--name", "udp")
    sel = selectors.DefaultSelector()
    fl = []
    for i in range(nflows):
        f = Flow(i, addr, port, name)
        sel.register(f.sock, selectors.EVENT_READ, f)
        fl.append(f)
    t0 = time.monotonic()
    end = t0 + duration
    last = t0
    for f in fl:
        f.next_send = t0 + 0.01 * f.idx
    while True:
        now = time.monotonic()
        for f in fl:
            if f.wait_seq is not None and now >= f.deadline:
                f.lost += 1
                f.wait_seq = None
                # a late reply carries no seq for "return": keep it apart
                f.next_send = max(f.next_send, now + interval)
            if f.wait_seq is None and now >= f.next_send and now < end:
                f.send(now, interval)
                f.deadline = now + timeout
        if now >= end and all(f.wait_seq is None for f in fl):
            break
        for key, _ in sel.select(0.02):
            f = key.data
            try:
                data = f.sock.recv(65535)
            except ConnectionRefusedError:
                f.refused += 1
                continue
            except BlockingIOError:
                continue
            except OSError:
                f.errors += 1
                continue
            text = data.decode(errors="replace")
            words = text.split()
            want = "s=%d" % (f.wait_seq or -1)
            up = None
            token = words[0] if words else "?"
            # an echo carries the seq, so a late reply is told apart; a
            # stream "return" reply carries only the pid
            if token == "up" and len(words) > 1 and words[1].startswith("port="):
                up = int(words[1][5:])
                if want not in words:
                    f.stray += 1
                    continue
            if f.wait_seq is None:
                f.stray += 1
                continue
            f.recv += 1
            f.wait_seq = None
            f.note(now - t0, token, up)
        if now - last >= 1.0:
            last = now
            print("UDP_PROGRESS elapsed=%.1f sent=%d recv=%d lost=%d refused=%d"
                  % (now - t0, sum(f.sent for f in fl), sum(f.recv for f in fl),
                     sum(f.lost for f in fl), sum(f.refused for f in fl)), flush=True)
    out = {"name": name, "flows": [
        {"idx": f.idx, "lport": f.lport, "sent": f.sent, "recv": f.recv,
         "lost": f.lost, "refused": f.refused, "stray": f.stray,
         "errors": f.errors, "tokens": f.tokens,
         "ports": f.ports} for f in fl]}
    out["sent"] = sum(f.sent for f in fl)
    out["recv"] = sum(f.recv for f in fl)
    out["lost"] = sum(f.lost for f in fl)
    out["refused"] = sum(f.refused for f in fl)
    out["stray"] = sum(f.stray for f in fl)
    out["errors"] = sum(f.errors for f in fl)
    print("UDP_SUMMARY " + json.dumps(out, separators=(",", ":")), flush=True)


def check(argv):
    path = argv[0]
    mode = arg(argv, "--mode")
    old = set(x for x in arg(argv, "--old", "").split(",") if x)
    new = set(x for x in arg(argv, "--new", "").split(",") if x)
    max_lost = arg(argv, "--max-lost", 0, int)
    need_switch = "--need-switch" in argv
    with open(path) as f:
        line = [ln for ln in f if ln.startswith("UDP_SUMMARY ")][-1]
    s = json.loads(line[len("UDP_SUMMARY "):])
    ok = s["sent"] > 0 and s["refused"] == 0 and s.get("errors", 0) == 0
    bad = []
    for fl in s["flows"]:
        pids = [t[1][4:] for t in fl["tokens"] if t[1].startswith("pid=")]
        if fl["lost"] > max_lost:
            bad.append("f%d lost=%d" % (fl["idx"], fl["lost"]))
        if fl["recv"] == 0:
            bad.append("f%d no reply" % fl["idx"])
        if pids:
            want = old if mode == "old" else new
            if mode in ("old", "new") and (len(pids) != 1 or pids[0] not in want):
                bad.append("f%d pids=%s" % (fl["idx"], "/".join(pids)))
            if mode == "switch":
                seq = "".join("o" if p in old else "n" if p in new else "?"
                              for p in pids)
                if not old or not new:
                    seq = "?"
                if seq not in (("on",) if need_switch else ("o", "on", "n")):
                    bad.append("f%d pids=%s" % (fl["idx"], seq))
        elif mode == "switch":
            bad.append("f%d no pid" % fl["idx"])
        elif mode in ("old", "new") and len(fl["ports"]) != 1:
            bad.append("f%d ports=%s" % (fl["idx"], fl["ports"]))
    ok = ok and not bad
    ports = sorted(p for fl in s["flows"] for p in fl["ports"])
    par = sorted(set(p & 1 for p in ports))
    print("CHECK ok=%d flows=%d sent=%d recv=%d lost=%d refused=%d stray=%d "
          "parity=%s bad=[%s]"
          % (ok, len(s["flows"]), s["sent"], s["recv"], s["lost"], s["refused"],
             s.get("stray", 0), "".join(str(p) for p in par) or "NA",
             "; ".join(bad[:6])))
    return 0 if ok else 1


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    cmd, argv = sys.argv[1], sys.argv[2:]
    if cmd == "serve":
        serve(argv)
    elif cmd == "flows":
        flows(argv)
    elif cmd == "check":
        sys.exit(check(argv))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
