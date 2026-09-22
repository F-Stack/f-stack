#!/usr/bin/env python3
"""Linux per-run descendant supervision for the reload harness."""

import argparse
import ctypes
import fcntl
import json
import math
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import sys
import time

from reload_checks import digest, identity

# Environment variables a run may forward into the supervised stack.
FAULT_ENV_KEYS = {"FF_FAULT", "FF_FAULT_DELAY_MS"}

KILL_TOOL = "/data/workspace/kill_process.sh"
POLL = 0.05
CLEANUP_SECONDS = 10
MAX_MEMBERS = 4096
MAX_PACKET = 65536


def subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    value = ctypes.c_int()
    if (libc.prctl(36, 1, 0, 0, 0) != 0
            or libc.prctl(37, ctypes.byref(value), 0, 0, 0) != 0 or value.value != 1):
        raise OSError(ctypes.get_errno(), "subreaper unavailable")
    if os.execve not in os.supports_fd or not hasattr(os, "pidfd_open"):
        raise RuntimeError("descriptor execution or pidfd unavailable")
    if signal.getsignal(signal.SIGCHLD) == signal.SIG_IGN:
        raise RuntimeError("SIGCHLD must remain waitable")


def proc_stat(pid):
    fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
    return fields[0], int(fields[1]), int(fields[19])


def exited(fd):
    return bool(select.select([fd], [], [], 0)[0])


def children(pid):
    result = set()
    for task in (Path("/proc") / str(pid) / "task").iterdir():
        try:
            result.update(map(int, (task / "children").read_text().split()))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


def atomic(path, data):
    pending = path.with_name(path.name + ".next")
    with pending.open("x") as out:
        json.dump(data, out, sort_keys=True)
        out.write("\n")
        out.flush()
    os.replace(pending, path)


class ProcessTree:
    def __init__(self, event=None):
        subreaper()
        self.pid = os.getpid()
        self.members = {}
        self.history = {}
        self.exec_pipes = {}
        self.allowed = set()
        self.failure = None
        self.no_children = False
        self.event_sink = event or (lambda value: None)
        self.default_stack = None
        self.orphan_role = "orphan"
        self.helper_targets = {}

    def emit(self, kind, **fields):
        try:
            self.event_sink(dict(event=kind, monotonic=time.monotonic(), **fields))
        except (OSError, ValueError):
            self.fail("event_persistence_failed")

    def fail(self, reason):
        self.failure = self.failure or reason

    def parent_valid(self, parent, ancestor):
        if parent == self.pid:
            return True
        if ancestor is None or self.members.get(parent) is not ancestor:
            return False
        try:
            return (proc_stat(parent)[2] == ancestor["start_time"]
                    and not exited(ancestor["pidfd"]))
        except (FileNotFoundError, ProcessLookupError):
            return False

    def register(self, pid, parent, role, stack, relation):
        ancestor = self.members.get(parent)
        if not self.parent_valid(parent, ancestor):
            return None
        state, actual_parent, start = proc_stat(pid)
        if actual_parent != parent:
            return None
        known = self.members.get(pid)
        if known and known["start_time"] != start:
            self.fail("registered_pid_reused")
            return None
        if known and exited(known["pidfd"]):
            return None
        if known is None and len(self.members) >= MAX_MEMBERS:
            raise RuntimeError("descendant limit exceeded")
        fd = known["pidfd"] if known is not None else os.pidfd_open(pid)
        retained = known is not None
        try:
            current = None if state == "Z" else identity(pid)
            _, again_parent, again_start = proc_stat(pid)
            if (again_parent != parent or again_start != start
                    or (current is not None and current["start_time"] != start)):
                return None
            # The same parent instance must span both child PPID observations.
            if not self.parent_valid(parent, ancestor):
                self.emit("ancestry_unconfirmed", pid=pid, start_time=start, parent=parent)
                return None
            if known is not None:
                if known["parent"] != parent:
                    self.emit("reparented", pid=pid, start_time=start,
                              old_parent=known["parent"], parent=parent)
                    known["parent"] = parent
                    if parent == self.pid:
                        known["relation"] = "adopted_by_subreaper"
                return known
            item = dict(pid=pid, start_time=start, pidfd=fd, parent=parent,
                        role=role, stack=stack, relation=relation,
                        initial=current, current=current, exec_pending=False)
            self.members[pid] = item
            retained = True
            self.history.pop(pid, None)
            self.no_children = False
            self.emit("registered", pid=pid, start_time=start, parent=parent,
                      role=role, stack=stack, relation=relation, image=current)
            return item
        finally:
            if not retained:
                os.close(fd)

    def spawn(self, argv, role, stack=None, env=None, pass_fds=()):
        if not argv:
            raise ValueError("empty command")
        executable = shutil.which(argv[0]) if not os.path.isabs(argv[0]) else argv[0]
        if not executable:
            raise ValueError("executable unavailable")
        executable = str(Path(executable).resolve(strict=True))
        binary = os.open(executable, os.O_RDONLY | os.O_CLOEXEC)
        st = os.fstat(binary)
        image_key = (st.st_dev, st.st_ino)
        if role == "target" and image_key not in self.allowed:
            os.close(binary)
            raise ValueError("unapproved executable")
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        error_read, error_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        pid = None
        try:
            pid = os.fork()
            if pid == 0:
                try:
                    keep = {0, 1, 2, binary, gate_read, error_write, *pass_fds}
                    for name in os.listdir("/proc/self/fd"):
                        fd = int(name)
                        if fd not in keep:
                            try:
                                os.close(fd)
                            except OSError:
                                pass
                    for fd in pass_fds:
                        os.set_inheritable(fd, True)
                    if os.read(gate_read, 1) != b"G":
                        os._exit(126)
                    os.close(gate_read)
                    if role == "helper":
                        null = os.open("/dev/null", os.O_RDWR)
                        os.dup2(null, 0)
                        os.dup2(null, 1)
                        os.dup2(null, 2)
                        if null > 2:
                            os.close(null)
                    os.execve(binary, [executable, *argv[1:]], env if env is not None else dict(os.environ))
                except BaseException:
                    try:
                        os.write(error_write, b"EXEC_FAILED")
                    except OSError:
                        pass
                    os._exit(127)
            os.close(gate_read)
            gate_read = -1
            os.close(error_write)
            error_write = -1
            item = self.register(pid, self.pid, role, stack, "direct_fork")
            if item is None:
                raise RuntimeError("root registration failed")
            item.update(exec_pending=True, intended_image=image_key,
                        exec_deadline=time.monotonic() + 10)
            self.exec_pipes[pid] = error_read
            error_read = -1
            self.emit("launch_intent", pid=pid, role=role, stack=stack,
                      executable=executable, device=st.st_dev, inode=st.st_ino)
            os.write(gate_write, b"G")
            return pid
        finally:
            for fd in (binary, gate_read, gate_write, error_read, error_write):
                if fd >= 0:
                    os.close(fd)

    def discover(self):
        queue = [self.pid]
        visited = set()
        while queue:
            parent = queue.pop()
            if parent in visited:
                continue
            visited.add(parent)
            if len(visited) > MAX_MEMBERS:
                raise RuntimeError("descendant scan limit exceeded")
            ancestor = self.members.get(parent)
            if parent != self.pid:
                if ancestor is None or exited(ancestor["pidfd"]):
                    continue
                try:
                    if proc_stat(parent)[2] != ancestor["start_time"]:
                        raise RuntimeError("ancestor identity mismatch")
                except (FileNotFoundError, ProcessLookupError):
                    continue
            try:
                candidates = children(parent)
            except (FileNotFoundError, ProcessLookupError):
                continue
            for pid in candidates:
                try:
                    role = ancestor["role"] if ancestor else self.orphan_role
                    stack = ancestor["stack"] if ancestor else self.default_stack
                    relation = "verified_descendant" if ancestor else "adopted_by_subreaper"
                    item = self.register(pid, parent, role, stack, relation)
                    if item is None:
                        continue
                    if not exited(item["pidfd"]):
                        current = identity(pid)
                        if current["start_time"] != item["start_time"]:
                            raise RuntimeError("descendant identity mismatch")
                        key = (current["device"], current["inode"])
                        if item["role"] == "orphan" and key in self.allowed and self.default_stack:
                            item["role"] = "target"
                            item["stack"] = self.default_stack
                        if current != item["current"]:
                            self.emit("image_observed", pid=pid, start_time=item["start_time"], image=current)
                            item["current"] = current
                        if item["exec_pending"]:
                            if key == item["intended_image"]:
                                item["exec_pending"] = False
                                self.emit("expected_image_observed", pid=pid)
                            elif time.monotonic() >= item["exec_deadline"]:
                                self.fail("exec_observation_timeout")
                        elif item["role"] == "target" and key not in self.allowed:
                            self.fail("unexpected_target_image")
                        elif item["role"] == "orphan":
                            self.fail("unclassified_adopted_process")
                        queue.append(pid)
                except (FileNotFoundError, ProcessLookupError):
                    continue

    def tick(self):
        self.discover()
        for pid, fd in list(self.exec_pipes.items()):
            try:
                data = os.read(fd, 64)
            except BlockingIOError:
                continue
            if data:
                self.fail("exec_failed")
                self.emit("exec_failed", pid=pid)
            os.close(fd)
            del self.exec_pipes[pid]
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                self.no_children = True
                break
            if pid == 0:
                self.no_children = False
                break
            code = os.waitstatus_to_exitcode(status)
            self.history[pid] = code
            if len(self.history) > 8192:
                self.history.pop(next(iter(self.history)))
            self.emit("reaped", pid=pid, exit_code=code)
            helper = self.helper_targets.pop(pid, None)
            if helper:
                target, sig, deadline = helper
                self.emit("signal_result", helper=pid, pid=target, signal=sig, exit_code=code)
                if code != 0 and target in self.members and not exited(self.members[target]["pidfd"]):
                    self.fail("signal_helper_failed")
        self.check_helper_deadlines()
        for pid, item in list(self.members.items()):
            if exited(item["pidfd"]):
                self.emit("exited", pid=pid, start_time=item["start_time"], role=item["role"], stack=item["stack"])
                os.close(item["pidfd"])
                del self.members[pid]

    def check_helper_deadlines(self):
        if any(time.monotonic() >= deadline for _, _, deadline in self.helper_targets.values()):
            self.fail("signal_helper_timeout")

    def active(self, stack=None):
        return [item for item in self.members.values()
                if (stack is None or (item["stack"] == stack and item["role"] in ("target", "orphan")))
                and not exited(item["pidfd"])]

    def send(self, item, sig, control=False):
        if exited(item["pidfd"]):
            if control:
                raise ValueError("control target exited")
            return
        current = identity(item["pid"])
        if current["start_time"] != item["start_time"]:
            raise ValueError("signal identity mismatch")
        if control and (current["device"], current["inode"]) not in self.allowed:
            raise ValueError("control target image not approved")
        args = ["/bin/bash", KILL_TOOL, "--signal", sig, "--pid", str(item["pid"]),
                "--start-time", str(current["start_time"]), "--exe", current["exe"],
                "--device", str(current["device"]), "--inode", str(current["inode"]), "--wait", "0"]
        helper = self.spawn(args, "helper")
        self.helper_targets[helper] = (item["pid"], sig, time.monotonic() + 2)
        self.emit("signal_requested", pid=item["pid"], start_time=item["start_time"], signal=sig, helper=helper)

    def stop(self, stack=None):
        start = time.monotonic()
        sent = set()
        error = None
        while time.monotonic() - start < CLEANUP_SECONDS:
            try:
                self.tick()
            except (OSError, ValueError, RuntimeError) as exc:
                error = type(exc).__name__
            active = self.active(stack)
            if not active:
                if stack is not None or self.no_children:
                    if error:
                        raise RuntimeError("cleanup observation failed: " + error)
                    return
            sig = "TERM" if time.monotonic() - start < 3 else "KILL"
            for item in active:
                if item["role"] == "helper" and time.monotonic() - start < 3:
                    continue
                key = (item["pid"], item["start_time"], sig)
                if key in sent:
                    continue
                try:
                    self.send(item, sig)
                except (OSError, ValueError, RuntimeError) as exc:
                    error = type(exc).__name__
                sent.add(key)
                if time.monotonic() - start >= CLEANUP_SECONDS:
                    break
            time.sleep(POLL)
        raise RuntimeError("cleanup deadline exceeded")

    def close(self):
        for item in self.members.values():
            os.close(item["pidfd"])
        for fd in self.exec_pipes.values():
            os.close(fd)
        self.exec_pipes.clear()
        self.members.clear()


class Supervisor:
    def __init__(self, root, run_id, seconds):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir() or not run_id or not 0 < seconds <= 14400:
            raise ValueError("invalid supervisor run")
        if self.root.stat().st_uid != os.getuid() or self.root.stat().st_mode & 0o077:
            raise ValueError("private supervisor directory required")
        self.run_id = run_id
        self.deadline = time.monotonic() + seconds
        self.events = (self.root / "ownership-events.jsonl").open("x")
        self.tree = ProcessTree(self.event)
        self.caller_fd = os.pidfd_open(os.getppid())
        self.server, self.client = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.server.setblocking(False)
        self.sequence_path = self.root / "supervisor-sequence"
        with self.sequence_path.open("x") as out:
            out.write("0\n")
        self.controller = None
        self.stack = None
        self.launcher = None
        self.phase = "idle"
        self.last_sequence = 0
        self.stopping = None
        self.sent = set()
        self.closed = False
        self.shutdown_requested = False
        self.allowed_files = {}
        self.started_stacks = set()
        self.saved_state = None
        self.result = 0

    def event(self, value):
        self.events.write(json.dumps(dict(run_id=self.run_id, **value)) + "\n")
        self.events.flush()

    def snapshot(self):
        live = self.tree.active(self.stack) if self.stack else []
        value = dict(version=1, run_id=self.run_id, supervisor=identity(os.getpid()),
                     controller=self.controller, stack=self.stack, phase=self.phase,
                     failure=self.tree.failure, members=[dict(
                         pid=i["pid"], start_time=i["start_time"], role=i["role"],
                         relation=i["relation"], parent=i["parent"], initial=i["initial"],
                         current=i["current"]) for i in live])
        if value != self.saved_state:
            atomic(self.root / "supervisor.json", value)
            atomic(self.root / "processes.json", [i["current"] for i in live if i["current"]])
            self.saved_state = value
        return value

    def approve_image(self, path, expected):
        path = str(Path(path).resolve(strict=True))
        if digest(path) != expected:
            raise ValueError("binary digest mismatch")
        st = os.stat(path)
        self.tree.allowed.add((st.st_dev, st.st_ino))
        self.allowed_files[path] = (st.st_dev, st.st_ino, expected)

    def dispatch(self, message, caller):
        sequence = message.get("sequence")
        if type(sequence) is not int or sequence <= self.last_sequence:
            raise ValueError("stale control sequence")
        self.last_sequence = sequence
        if message.get("run_id") != self.run_id:
            raise ValueError("wrong control run")
        member = self.tree.members.get(caller)
        if not member or member["role"] != "controller" or exited(member["pidfd"]):
            raise ValueError("control caller not owned")
        op = message["operation"]
        args = message.get("arguments", {})
        if op == "hello":
            return self.snapshot()
        if op == "allow-image":
            self.approve_image(args["path"], args["sha256"])
            return {"approved": True}
        if op == "start":
            if (self.tree.failure or self.phase not in ("idle", "stopped")
                    or (self.stack is not None and self.tree.active(self.stack))):
                raise ValueError("previous stack not stopped")
            stack = message.get("stack")
            if not isinstance(stack, str) or not stack or stack in self.started_stacks:
                raise ValueError("reused stack identity")
            argv = args["argv"]
            if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
                raise ValueError("invalid launch arguments")
            self.approve_image(argv[0], args["sha256"])
            self.stack = stack
            self.started_stacks.add(stack)
            self.tree.default_stack = stack
            env = {k: v for k, v in os.environ.items() if not k.startswith("GR_SUPERVISOR_")}
            env["FF_RELOAD_RUN_ID"] = self.run_id
            # The supervisor may predate the run that needs these, so its own
            # environment is not enough: fault variables are forwarded with the
            # request, restricted to a fixed allowlist (never arbitrary env).
            extra = args.get("env")
            if isinstance(extra, dict):
                for key, value in extra.items():
                    if key in FAULT_ENV_KEYS and isinstance(value, str):
                        env[key] = value
            self.launcher = self.tree.spawn(argv, "target", stack, env)
            self.phase = "starting"
            self.start_deadline = time.monotonic() + 10
            self.expect_daemon = bool(args.get("daemon", True))
            return self.snapshot()
        if message.get("stack") != self.stack:
            raise ValueError("wrong stack identity")
        if op == "status":
            return self.snapshot()
        if op == "assert-stopped":
            if self.phase != "stopped" or self.tree.active(self.stack) or self.tree.failure:
                raise ValueError("stack termination unconfirmed")
            return {"stopped": True}
        if op == "stop":
            if self.phase not in ("stopped", "stopping"):
                self.stopping = time.monotonic()
                self.sent.clear()
                self.phase = "stopping"
            return self.snapshot()
        if op == "signal":
            if self.phase != "running" or self.tree.failure:
                raise ValueError("stack not controllable")
            item = self.tree.members.get(args["pid"])
            if (not item or item["role"] != "target" or item["stack"] != self.stack
                    or item["start_time"] != args["start_time"]):
                raise ValueError("signal target not owned")
            sig = args["signal"]
            if sig not in ("HUP", "USR1", "USR2", "WINCH", "QUIT", "TERM", "INT", "KILL", "STOP", "CONT"):
                raise ValueError("invalid signal")
            self.tree.send(item, sig, control=True)
            return {"requested": True}
        raise ValueError("unknown control operation")

    def control(self):
        try:
            wire, ancillary, flags, _ = self.server.recvmsg(MAX_PACKET, socket.CMSG_SPACE(12))
        except BlockingIOError:
            return
        if not wire:
            self.closed = True
            return
        token = None
        sequence = None
        try:
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                raise ValueError("control packet truncated")
            credentials = [struct.unpack("3i", value[:12]) for level, kind, value in ancillary
                           if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS]
            if len(credentials) != 1 or credentials[0][1] != os.getuid():
                raise ValueError("missing control credentials")
            message = json.loads(wire)
            token, sequence = message.get("token"), message.get("sequence")
            self.tree.tick()
            answer = self.dispatch(message, credentials[0][0])
            reply = dict(ok=True, value=answer)
        except (KeyError, ValueError, OSError, RuntimeError, TypeError) as exc:
            reply = dict(ok=False, error=type(exc).__name__)
        packet = json.dumps(dict(token=token, sequence=sequence, run_id=self.run_id, **reply)).encode()
        if len(packet) > MAX_PACKET:
            raise RuntimeError("control response limit exceeded")
        try:
            self.server.send(packet)
        except (BrokenPipeError, BlockingIOError):
            self.closed = True

    def progress(self):
        self.tree.tick()
        active = self.tree.active(self.stack) if self.stack else []
        if self.phase == "starting":
            code = self.tree.history.get(self.launcher)
            observed = any(i["current"] and not i["exec_pending"]
                           and (i["current"]["device"], i["current"]["inode"]) in self.tree.allowed for i in active)
            if code not in (None, 0):
                self.tree.fail("launcher_failed")
            elif observed and (not self.expect_daemon or code == 0):
                self.phase = "running"
            elif time.monotonic() >= self.start_deadline:
                self.tree.fail("startup_registration_timeout")
        if self.phase == "stopping":
            elapsed = time.monotonic() - self.stopping
            if not active:
                self.tree.tick()
                active = self.tree.active(self.stack)
            if not active:
                self.phase = "stopped"
                self.tree.default_stack = None
            elif elapsed >= CLEANUP_SECONDS:
                self.tree.fail("stack_cleanup_timeout")
            else:
                sig = "TERM" if elapsed < 3 else "KILL"
                for item in active:
                    key = (item["pid"], item["start_time"], sig)
                    if key not in self.sent:
                        try:
                            self.tree.send(item, sig)
                        except (OSError, ValueError, RuntimeError):
                            self.tree.fail("stack_signal_failed")
                        self.sent.add(key)
        self.snapshot()

    def run(self, argv):
        env = dict(os.environ, GR_SUPERVISOR_FD=str(self.client.fileno()),
                   GR_SUPERVISOR_ID=json.dumps(identity(os.getpid())),
                   GR_SUPERVISOR_RUN=self.run_id, GR_SUPERVISOR_ROOT=str(self.root),
                   GR_SUPERVISOR_SEQUENCE=str(self.sequence_path))
        self.controller = self.tree.spawn(argv, "controller", env=env, pass_fds=(self.client.fileno(),))
        self.client.close()
        old_handlers = {s: signal.signal(s, self.interrupted) for s in (signal.SIGTERM, signal.SIGINT)}
        try:
            while True:
                self.progress()
                self.control()
                code = self.tree.history.get(self.controller)
                if code is not None:
                    self.result = code if code != 0 or self.phase in ("idle", "stopped") else 125
                    break
                if (self.tree.failure or self.closed or self.shutdown_requested
                        or exited(self.caller_fd) or time.monotonic() >= self.deadline):
                    self.result = 125
                    break
                select.select([self.server], [], [], POLL)
        except (OSError, ValueError, RuntimeError, KeyError):
            self.tree.fail("supervisor_error")
            self.result = 125
        finally:
            try:
                self.tree.stop()
                if self.tree.failure:
                    self.result = 125
                self.phase = "finished" if self.result == 0 else "failed"
                self.snapshot()
                self.event(dict(event="run_finished", result=self.result, echild=self.tree.no_children))
            except (OSError, ValueError, RuntimeError):
                self.result = 125
                self.phase = "cleanup_failed"
                try:
                    self.snapshot()
                except (OSError, ValueError, RuntimeError):
                    pass
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)
            self.server.close()
            self.tree.close()
            os.close(self.caller_fd)
            self.events.close()
        return self.result if self.result >= 0 else 128 - self.result

    def interrupted(self, signum, frame):
        self.shutdown_requested = True


def request(operation, stack=None, arguments=None, run_id=None, timeout=2):
    started = time.monotonic()
    expected = json.loads(os.environ["GR_SUPERVISOR_ID"])
    if identity(expected["pid"]) != expected:
        raise RuntimeError("supervisor identity changed")
    fd = int(os.environ["GR_SUPERVISOR_FD"])
    channel = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_SEQPACKET)
    lock_fd = None
    try:
        peer, uid, _ = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if peer != expected["pid"] or uid != os.getuid():
            raise RuntimeError("supervisor channel mismatch")
        lock_fd = os.open(os.environ["GR_SUPERVISOR_SEQUENCE"], os.O_RDWR | os.O_NOFOLLOW)
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() - started >= timeout:
                    raise TimeoutError("control lock deadline")
                time.sleep(0.01)
        raw = os.read(lock_fd, 64)
        sequence = int(raw) + 1
        os.lseek(lock_fd, 0, os.SEEK_SET)
        os.write(lock_fd, (str(sequence) + "\n").encode())
        os.ftruncate(lock_fd, os.lseek(lock_fd, 0, os.SEEK_CUR))
        token = os.urandom(12).hex()
        run_id = run_id if run_id is not None else os.environ["GR_SUPERVISOR_RUN"]
        message = dict(operation=operation, stack=stack, arguments=arguments or {},
                       run_id=run_id, sequence=sequence, token=token)
        wire = json.dumps(message).encode()
        if len(wire) >= MAX_PACKET:
            raise ValueError("control request too large")
        channel.settimeout(max(0.001, timeout - (time.monotonic() - started)))
        channel.sendall(wire)
        response = json.loads(channel.recv(MAX_PACKET))
        if (response.get("token"), response.get("sequence"), response.get("run_id")) != (token, sequence, run_id):
            raise RuntimeError("stale control response")
        if not response.get("ok"):
            raise RuntimeError("control request rejected")
        return response["value"]
    finally:
        channel.close()
        if lock_fd is not None:
            os.close(lock_fd)


def wait_phase(stack, desired, seconds):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        value = request("status", stack, timeout=min(2, max(0.001, until - time.monotonic())))
        if value["failure"]:
            raise RuntimeError("supervised run failed")
        if value["phase"] == desired:
            return value
        time.sleep(POLL)
    raise TimeoutError("supervisor phase deadline")


def command(seconds, argv):
    if not math.isfinite(seconds) or not 0 < seconds <= 14400:
        raise ValueError("invalid command deadline")
    tree = ProcessTree()
    tree.orphan_role = "command"
    stop_requested = []
    handlers = {s: signal.signal(s, lambda *_: stop_requested.append(True)) for s in (signal.SIGINT, signal.SIGTERM)}
    result = 125
    try:
        root = tree.spawn(argv, "command")
        until = time.monotonic() + seconds
        while True:
            tree.tick()
            if tree.failure or stop_requested:
                break
            if root in tree.history:
                result = tree.history[root]
                if result == 0 and tree.active():
                    result = 125
                break
            if time.monotonic() >= until:
                result = 124
                break
            time.sleep(POLL)
    finally:
        try:
            tree.stop()
        finally:
            tree.close()
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    return result if result >= 0 else 128 - result


def main(argv):
    op, *args = argv
    if op == "run":
        root, run_id, seconds, *cmd = args
        if cmd and cmd[0] == "--":
            cmd.pop(0)
        lock_fd = None
        try:
            lock_path = os.environ.get("GR_SUPERVISOR_LOCK")
            if lock_path:
                lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                if os.fstat(lock_fd).st_uid != os.getuid():
                    raise ValueError("lock ownership mismatch")
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return Supervisor(root, run_id, float(seconds)).run(cmd)
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
    if op == "command":
        seconds, *cmd = args
        if cmd and cmd[0] == "--":
            cmd.pop(0)
        return command(float(seconds), cmd)
    if op == "hello":
        value = request("hello", run_id=args[0])
    elif op == "start":
        stack, sha, *cmd = args
        env = {k: v for k, v in os.environ.items() if k in FAULT_ENV_KEYS}
        value = request("start", stack, dict(argv=cmd, sha256=sha, env=env))
        value = wait_phase(stack, "running", 10)
    elif op == "stop":
        value = request("stop", args[0])
        value = wait_phase(args[0], "stopped", CLEANUP_SECONDS + 2)
    elif op == "signal":
        stack, pid, sig = args
        value = request("status", stack)
        targets = [i for i in value["members"] if i["pid"] == int(pid)]
        if len(targets) != 1:
            raise ValueError("unregistered control PID")
        value = request("signal", stack, dict(pid=int(pid), start_time=targets[0]["start_time"], signal=sig))
    elif op in ("status", "assert-stopped"):
        value = request(op, args[0])
    else:
        raise ValueError("unknown supervisor operation")
    print(json.dumps(value))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError, RuntimeError, IndexError):
        print("RELOAD_SUPERVISOR_FAILED", file=sys.stderr)
        raise SystemExit(125)
