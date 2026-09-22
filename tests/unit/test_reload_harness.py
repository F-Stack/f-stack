#!/usr/bin/env python3
"""Offline tests: no nginx, DPDK, SSH or network-interface changes."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import shutil
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "tests/integration/common"
sys.path.insert(0, str(COMMON))
import reload_checks as checks
import reload_remote as remote

HARNESS = ROOT / "tests/integration/test_graceful_reload.sh"
KILL = Path("/data/workspace/kill_process.sh")
TRASH = Path("/data/workspace/rm_tmp_file.sh")


def default_values():
    return dict(TARGET_IP="192.0.2.1", CLIENT="f-stack-client", CASES="precheck,rt01,rv9",
                ROUNDS="100", INTERVAL="15", POLL="5", WORKERS="2", DRAIN_TIMEOUT="120",
                STARTUP_WAIT="28", STREAM_MB="8", RTE_FRESH_MIN="10", SHUTDOWN_TIMEOUT="0",
                BASELINE_DURATION="330", GRACEFUL="1", ZC_BUILD="auto", NGINX_BIN="/safe/nginx",
                FSTACK_TPL="/safe/config.ini", PROBE_DIR="/safe/probes", OUT="", BUILD_MANIFEST="")


class ValidationTests(unittest.TestCase):
    def test_ipv4_ipv6(self):
        for address in ("192.0.2.1", "2001:db8::1"):
            values = default_values()
            values["TARGET_IP"] = address
            checks.validate(values)

    def test_injection_and_bad_hosts(self):
        for value in ("192.0.2.1;false", "$(false)", "192.0.2.1\nfalse", "-oProxyCommand=false"):
            values = default_values()
            values["TARGET_IP"] = value
            with self.assertRaises(ValueError):
                checks.validate(values)
        for value in ("-host", "host;false", "host name", "user@-host"):
            values = default_values()
            values["CLIENT"] = value
            with self.assertRaises(ValueError):
                checks.validate(values)

    def test_invalid_counts_cases_and_paths(self):
        for key, value in (("ROUNDS", "0"), ("WORKERS", "31"), ("ROUNDS", "08"),
                           ("SHUTDOWN_TIMEOUT", "$(false)"), ("BASELINE_DURATION", "nan"),
                           ("BASELINE_DURATION", ".."), ("CASES", "rt01,rt01"),
                           ("CASES", "unknown"), ("CASES", "rt01,"),
                           ("OUT", "/safe/path;false"), ("OUT", "/safe/../other")):
            with self.subTest(key=key, value=value):
                values = default_values()
                values[key] = value
                with self.assertRaises(ValueError):
                    checks.validate(values)

    def test_lc_exact_fields(self):
        text = ("LC_SUMMARY conns=0 reqs=0 fail=0 reconnects=0 fresh_n=20 fresh_fail=0"
                " workers_expected=1 workers_done=1 workers_active=1 worker_errors=0")
        checks.summary("lc", text)
        for bad in (text.replace("fail=0 reconnects", "fail=1 reconnects"),
                    text.replace("fresh_fail=0", "fresh_fail=1"),
                    text.replace("fresh_n=20", "fresh_n=0"),
                    text + " fail=0", text + "\n" + text, "NO_DATA"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                checks.summary("lc", bad)

    def test_stream_and_cps(self):
        good = ("STREAM_SUMMARY streams=12 ok=12 md5_ok=12 eof_clean=12 stalls(>3.0s)=0 worst_gap=0.1s"
                " workers_expected=12 workers_done=12 workers_active=12 worker_errors=0")
        checks.summary("stream", good)
        with self.assertRaisesRegex(ValueError, "stream integrity failure"):
            checks.summary("stream", good.replace("md5_ok=12", "md5_ok=11"))
        # The probe is duration-bounded and completes >= one full wave, so a
        # larger count is valid -- an incomplete wave is not.
        checks.summary("stream", good.replace("streams=12 ok=12 md5_ok=12 eof_clean=12",
                                              "streams=36 ok=36 md5_ok=36 eof_clean=36"))
        for bad in (good.replace("streams=12 ok=12 md5_ok=12 eof_clean=12",
                                 "streams=11 ok=11 md5_ok=11 eof_clean=11"),
                    good.replace("streams=12 ok=12 md5_ok=12 eof_clean=12",
                                 "streams=36 ok=35 md5_ok=36 eof_clean=36"),
                    good.replace("stalls(>3.0s)=0", "stalls(>3.0s)=1")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                checks.summary("stream", bad)
        cps = ("CPS_SUMMARY threads=1 n=20 ok=20 fail=0 wall=1s qps=20"
               " workers_expected=1 workers_done=1 workers_active=1 worker_errors=0")
        checks.summary("cps", cps)
        with self.assertRaisesRegex(ValueError, "CPS failure or empty samples"):
            checks.summary("cps", cps.replace("n=20 ok=20", "n=0 ok=0"))

    def test_partial_workers_cannot_hide_behind_total_samples(self):
        good = ("LC_SUMMARY conns=2 reqs=100 fail=0 reconnects=0 fresh_n=100 fresh_fail=0"
                " workers_expected=3 workers_done=3 workers_active=3 worker_errors=0")
        checks.summary("lc", good)
        for bad in (good.replace("workers_done=3", "workers_done=2"),
                    good.replace("workers_active=3", "workers_active=2"),
                    good.replace("worker_errors=0", "worker_errors=1"),
                    good.replace(" workers_expected=3", ""),
                    good.replace("conns=2", "conns=1")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                checks.summary("lc", bad)

    def test_aggregate_requires_selected_cases_and_exit_codes(self):
        records = [dict(case="precheck", verdict="PASS", exit_code=0)]
        self.assertEqual(checks.aggregate(records, {"precheck"}), 0)
        self.assertNotEqual(checks.aggregate(records, {"precheck", "rt01"}), 0)
        self.assertNotEqual(checks.aggregate(records * 2), 0)
        self.assertNotEqual(checks.aggregate([dict(case="rt01", verdict="PASS")]), 0)

    def test_nonpass_and_exit_mismatch(self):
        self.assertEqual(checks.aggregate([]), 5)
        self.assertEqual(checks.aggregate([dict(case="rt01", verdict="PASS", exit_code=0)]), 0)
        for verdict in ("SKIP", "LIMITED", "BLOCKED", "NOT_RUN"):
            self.assertNotEqual(checks.aggregate([dict(case="rt01", verdict=verdict, exit_code=0)]), 0)
        self.assertNotEqual(checks.aggregate([dict(case="rt01", verdict="PASS", exit_code=1)]), 0)
        self.assertNotEqual(checks.aggregate([dict(case="rt01", verdict="FAIL", exit_code=0)]), 0)


class OwnedProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix="reload-unit-", dir="/data/workspace"))
        cls.old_audit = os.environ.get("KILL_IDENTITY_AUDIT")
        os.environ["KILL_IDENTITY_AUDIT"] = str(cls.work / "signals.jsonl")

    @classmethod
    def tearDownClass(cls):
        if cls.old_audit is None:
            os.environ.pop("KILL_IDENTITY_AUDIT", None)
        else:
            os.environ["KILL_IDENTITY_AUDIT"] = cls.old_audit
        rc = subprocess.call([str(TRASH), str(cls.work)], stdout=subprocess.DEVNULL)
        if rc:
            raise RuntimeError("test artifact cleanup failed")

    def child(self, code="import time; time.sleep(60)"):
        proc = subprocess.Popen([sys.executable, "-B", "-c", code],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        item = checks.identity(proc.pid)

        def cleanup():
            if proc.poll() is None:
                checks.signal_owned(item, "TERM", 1)
            if proc.poll() is None:
                checks.signal_owned(item, "KILL", 1)
            proc.wait(timeout=2)
        self.addCleanup(cleanup)
        return proc, item

    def test_identity_mismatch_refused(self):
        proc, item = self.child()
        for mismatch in ("start_time", "device", "inode"):
            wrong = dict(item)
            wrong[mismatch] += 1
            args = [str(KILL), "--signal", "TERM", "--pid", str(proc.pid),
                    "--start-time", str(wrong["start_time"]), "--exe", wrong["exe"],
                    "--device", str(wrong["device"]), "--inode", str(wrong["inode"])]
            with self.subTest(mismatch=mismatch):
                self.assertEqual(subprocess.call(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL), 4)
                self.assertIsNone(proc.poll())

    def test_explicit_signal_does_not_escalate(self):
        proc, item = self.child()
        self.assertEqual(checks.signal_owned(item, "STOP"), 0)
        self.assertIsNone(proc.poll())
        self.assertEqual(checks.signal_owned(item, "CONT"), 0)
        self.assertEqual(checks.signal_owned(item, "TERM", 1), 0)
        proc.wait(timeout=2)

    def test_bounded_exit_and_timeout(self):
        self.assertEqual(checks.bounded(3, [sys.executable, "-B", "-c", "raise SystemExit(7)"]), 7)
        self.assertEqual(checks.bounded(0.2, [sys.executable, "-B", "-c", "import time; time.sleep(60)"]), 124)

    def test_bounded_child_exit_and_startup_handoff(self):
        owner_path = self.work / "bounded-child.json"
        child = ("import sys,os,json,time; from pathlib import Path; "
                 "sys.path.insert(0,%r); import reload_checks; "
                 "Path(%r).write_text(json.dumps(reload_checks.identity(os.getpid()))); time.sleep(10)"
                 % (str(COMMON), str(owner_path)))
        parent = ("import subprocess,sys,time; "
                  "subprocess.Popen([sys.executable,'-B','-c',%r]); time.sleep(0.3)" % child)
        self.assertEqual(checks.bounded(3, [sys.executable, "-B", "-c", parent]), 125)
        item = json.loads(owner_path.read_text())
        with self.assertRaises((FileNotFoundError, ProcessLookupError)):
            checks.identity(item["pid"])
        with self.assertRaisesRegex(ValueError, "live supervisor"):
            checks.bounded(3, [sys.executable], (self.work / "unowned.json", "unowned"))

    def test_production_inventory_includes_new_and_generated_sources(self):
        root = self.work / "source-tree"
        for name in ("lib", "freebsd", "dpdk", "app/nginx-1.28.0/src",
                     "app/nginx-1.28.0/auto", "app/nginx-1.28.0/objs", "dpdk/build"):
            (root / name).mkdir(parents=True, exist_ok=True)
        files = ("lib/new.c", "freebsd/new.h", "dpdk/build/rte_config.h",
                 "app/nginx-1.28.0/configure", "app/nginx-1.28.0/auto/options",
                 "app/nginx-1.28.0/objs/ngx_modules.c")
        for name in files:
            (root / name).write_text("fixture")
        (root / "config.ini").write_text("local only")
        dangling = root / "dpdk/build/legacy.h"
        dangling.symlink_to("missing.h")
        alias = root / "dpdk/source-alias"
        alias.symlink_to("../lib", target_is_directory=True)
        found = checks.production_sources(root)
        self.assertTrue({root / name for name in files} <= found)
        self.assertTrue({dangling, alias} <= found)
        self.assertNotIn(root / "config.ini", found)
        record = checks.source_record(dangling)
        self.assertEqual(record["kind"], "symlink")
        self.assertEqual(record["target"], "missing.h")
        self.assertEqual(record["target_kind"], "missing")
        target = dangling.parent / "missing.h"
        target.write_text("generated target")
        self.assertNotEqual(checks.source_record(dangling), record)
        self.assertEqual(checks.source_record(dangling)["target_sha256"], checks.digest(target))
        self.assertEqual(checks.source_record(alias)["target_kind"], "directory")

    def test_wrong_case_cannot_be_renamed_to_pass(self):
        outdir = self.work / "wrong-case"
        outdir.mkdir()
        script = ('source "$1"; OUT="$2"; LOG=/dev/null; '
                  'case_rt01() { record rt02 PASS criterion measured; }; run_case rt01')
        result = checks.bounded(3, ["bash", "-c", script, "test", str(HARNESS), str(outdir)])
        self.assertNotEqual(result, 0)
        record = json.loads((outdir / "results.jsonl").read_text())
        self.assertEqual(record["case"], "rt01")
        self.assertEqual(record["verdict"], "FAIL")
        self.assertNotEqual(record["exit_code"], 0)

    def test_foreign_deleted_executable_is_not_inspected(self):
        procdir = mock.MagicMock()
        procdir.name = "45678"
        procdir.__truediv__.return_value.read_bytes.return_value = b"OTHER=1\0"
        with mock.patch.object(Path, "iterdir", return_value=iter([procdir])), \
                mock.patch.object(checks, "identity", side_effect=ValueError("deleted executable")) as read_identity:
            with self.assertRaisesRegex(RuntimeError, "live supervisor"):
                checks.collect_processes("owned-run", sys.executable, [])
            read_identity.assert_not_called()

    def test_reclaim_requires_unlocked_backing(self):
        page = self.work / "backing"
        page.write_text("fixture")
        with page.open() as locked, mock.patch.object(checks, "resources", return_value=[page]), \
                mock.patch.object(checks.subprocess, "call", return_value=0) as remove:
            checks.fcntl.flock(locked, checks.fcntl.LOCK_SH | checks.fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                checks.reclaim_resources("fixture", "fixture")
            remove.assert_not_called()
            checks.fcntl.flock(locked, checks.fcntl.LOCK_UN)
            self.assertEqual(checks.reclaim_resources("fixture", "fixture"), 0)
            remove.assert_called_once_with([str(TRASH), str(page)])

    def test_wrapper_validation_before_signals(self):
        for args in (("--signal", "BAD"), ("--pid", "1"), ("--signal", "HUP", "--wait", "nan")):
            rc = subprocess.call([str(KILL), *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertNotEqual(rc, 0)

    def test_source_has_no_execution(self):
        result = subprocess.Popen(["bash", "-c", 'source "$1"; printf SOURCE_OK', "test", str(HARNESS)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = result.communicate(timeout=3)
        self.assertEqual(result.returncode, 0, err)
        self.assertEqual(out, b"SOURCE_OK")

    def test_cli_rejects_before_output_creation(self):
        for args in (("--rounds",), ("-t", "192.0.2.1", "-c", "unknown"),
                     ("-t", "192.0.2.1;false"), ("-t", "2001:db8::1", "--workers", "0")):
            proc = subprocess.Popen(["bash", str(HARNESS), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate(timeout=3)
            self.assertEqual(proc.returncode, 2, (out, err))

    def test_build_identity_binding(self):
        nginx = self.work / "nginx"
        lib = self.work / "libfstack.a"
        nginx.write_text("offline fixture")
        lib.write_text("archive fixture")
        manifest = self.work / "build.json"
        data = dict(version=1, source_head="head", fault_injection=False,
                    build_commands=["fixture-only"], zc_recv=False, zc_send=False,
                    nginx=dict(path=str(nginx), sha256=checks.digest(nginx)),
                    libfstack=dict(path=str(lib), sha256=checks.digest(lib)))
        source = self.work / "source.fixture"
        source.write_text("source fixture")
        inventory_mock = mock.patch.object(checks, "production_sources", return_value={source})
        enumerate_sources = inventory_mock.start()
        self.addCleanup(inventory_mock.stop)
        log = self.work / "build.log"
        log.write_text("fixture-link\n")
        data["source_files"] = [checks.source_record(source)]
        data["link_record"] = dict(command="fixture-link", exit_code=0,
                                   source_files=data["source_files"],
                                   libfstack_sha256=data["libfstack"]["sha256"],
                                   nginx_sha256=data["nginx"]["sha256"])
        data["build_log"] = dict(path=str(log), sha256=checks.digest(log))
        manifest.write_text(json.dumps(data))
        checks.verify_build(manifest, nginx, "head")
        enumerate_sources.return_value = {source, self.work / "omitted.c"}
        with self.assertRaisesRegex(ValueError, "inventory coverage mismatch"):
            checks.verify_build(manifest, nginx, "head")
        enumerate_sources.return_value = {source}
        for candidate, head in ((lib, "head"), (nginx, "stale")):
            with self.assertRaises(ValueError):
                checks.verify_build(manifest, candidate, head)
        for key in ("source_files", "link_record", "build_log"):
            incomplete = dict(data)
            del incomplete[key]
            manifest.write_text(json.dumps(incomplete))
            with self.subTest(missing=key), self.assertRaises((ValueError, KeyError)):
                checks.verify_build(manifest, nginx, "head")
        manifest.write_text(json.dumps(data))
        source.write_text("changed source at same HEAD")
        with self.assertRaisesRegex(ValueError, "source content changed"):
            checks.verify_build(manifest, nginx, "head")
        source.write_text("source fixture")
        link = self.work / "legacy-source.h"
        link.symlink_to("missing-source.h")
        enumerate_sources.return_value = {source, link}
        data["source_files"].append(checks.source_record(link))
        manifest.write_text(json.dumps(data))
        checks.verify_build(manifest, nginx, "head")
        replacement = self.work / "replacement-source.h"
        replacement.symlink_to("other-missing-source.h")
        os.replace(replacement, link)
        with self.assertRaisesRegex(ValueError, "source content changed"):
            checks.verify_build(manifest, nginx, "head")
        data["source_files"][-1] = checks.source_record(link)
        manifest.write_text(json.dumps(data))
        lib.write_text("changed")
        with self.assertRaisesRegex(ValueError, "build artifact mismatch"):
            checks.verify_build(manifest, nginx, "head")

    def test_foreign_process_not_collected(self):
        proc, item = self.child()
        with self.assertRaisesRegex(RuntimeError, "live supervisor"):
            checks.collect_processes("unowned-test-marker", item["exe"], [])
        self.assertIsNone(proc.poll())

    def test_driver_result_and_cleanup_failure(self):
        script = ('source "$1"; OUT="$2"; LOG=/dev/null; '
                  'case_rt01() { record rt01 PASS criterion measured; return 7; }; '
                  'run_case rt01; rc=$?; [ "$rc" = 7 ] || exit 9; '
                  'python3 -B "$CHECKS" aggregate "$OUT/results.jsonl"; '
                  '[ "$?" != 0 ] || exit 10; '
                  'stop_probes() { return 1; }; stop_stack() { return 0; }; '
                  'cleanup_epilogue; [ "$?" != 0 ] && [ "$CLEANUP_FAILED" = 1 ] || exit 11; '
                  'case_rt02() { record rt02 PASS criterion measured; }; '
                  'run_case rt02; [ "$?" != 0 ] && [ "${C_VERDICT[1]}" = FAIL ]')
        result = subprocess.Popen(["bash", "-c", script, "test", str(HARNESS), str(self.work)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = result.communicate(timeout=5)
        self.assertEqual(result.returncode, 0, (out, err))

    def test_remote_local_fixture_execution(self):
        root = self.work / "remote-exec"
        root.mkdir()
        probe = root / "m4_cps.py"
        probe.write_text('print("CPS_SUMMARY n=1 ok=1 fail=0", flush=True)\n')
        self.assertEqual(remote.run(str(root), "success", 3, probe.name, ["--server", "192.0.2.1"]), 0)
        data = json.loads((root / "success.json").read_text())
        self.assertEqual(data["state"], "finished")
        self.assertEqual(data["exit_code"], 0)
        probe.write_text('import time\ntime.sleep(60)\n')
        self.assertEqual(remote.run(str(root), "timeout", 1, probe.name, ["--server", "192.0.2.1"]), 0)
        self.assertEqual(json.loads((root / "timeout.json").read_text())["exit_code"], 124)
        with self.assertRaises(ValueError):
            remote.run(str(root), "success", 1, probe.name, ["--server", "192.0.2.1"])

    def test_http_response_integrity(self):
        sys.path.insert(0, str(COMMON / "reload_probes"))
        from http_probe import response
        sock = mock.Mock()
        sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", b""]
        self.assertEqual(response(sock, expect_eof=True)[0], 3)
        for wire in (b"HTTP/1.1 500 Error\r\nContent-Length: 3\r\n\r\nabc",
                     b"HTTP/1.1 200 OK\r\n\r\nabc",
                     b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc",
                     b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nabc"):
            sock = mock.Mock()
            sock.recv.side_effect = [wire, b""]
            with self.assertRaises(ValueError):
                response(sock)

    def test_resource_namespace_rejects_public_paths(self):
        with self.assertRaises(ValueError):
            checks.resources("rte", self.work / "absent")
        proc, item = self.child()
        inventory = self.work / "active.json"
        inventory.write_text(json.dumps([item]))
        with self.assertRaises(ValueError):
            checks.resources("container-gr_20260918_000000_1_abcdef12", inventory)
        self.assertIsNone(proc.poll())

    def test_remote_stale_and_nonzero_results(self):
        root = self.work / "remote"
        root.mkdir(exist_ok=True)
        status = root / "probe.json"
        status.write_text(json.dumps(dict(version=1, run_id="other", job="probe", state="finished", exit_code=0)))
        with self.assertRaises(ValueError):
            remote.inspect(str(root), "probe", "result")
        status.write_text(json.dumps(dict(version=1, run_id=root.name, job="probe", state="finished", exit_code=1)))
        self.assertNotEqual(remote.inspect(str(root), "probe", "result"), 0)


class ParentAuthorizationTests(unittest.TestCase):
    """Deterministic proc/pidfd races; no real processes or signals."""

    def setUp(self):
        import reload_supervisor as supervisor
        self.supervisor = supervisor
        self.events = []
        with mock.patch.object(supervisor, "subreaper"):
            self.tree = supervisor.ProcessTree(self.events.append)
        self.tree.pid = 100
        self.parent_pid = 200
        self.child_pid = 300
        self.parent_fd = 10
        self.child_fd = 11
        self.parent_start = 20
        self.child_start = 30
        self.parent_exited = False
        self.parent_missing = False
        self.child_parent = self.parent_pid
        self.after_child_identity = lambda: None
        self.parent_observation = lambda: None
        image = dict(pid=self.parent_pid, start_time=self.parent_start,
                     exe="/offline/fixture", device=1, inode=2)
        self.parent = dict(pid=self.parent_pid, start_time=self.parent_start,
                           pidfd=self.parent_fd, parent=self.tree.pid, role="target",
                           stack="test-stack", relation="direct_fork", initial=image,
                           current=image, exec_pending=False)
        self.tree.members[self.parent_pid] = self.parent
        self.tree.history[self.child_pid] = 7
        self.tree.allowed.add((1, 2))
        self.tree.default_stack = "test-stack"
        self.patch("proc_stat", side_effect=self.stat_view)
        self.patch("identity", side_effect=self.identity_view)
        self.patch("children", side_effect=lambda pid: {self.parent_pid} if pid == self.tree.pid
                   else {self.child_pid} if pid == self.parent_pid else set())
        self.patch("exited", side_effect=lambda fd: fd == self.parent_fd and self.parent_exited)
        self.open_fd = self.patch("os.pidfd_open", return_value=self.child_fd)
        self.close_fd = self.patch("os.close")

    def patch(self, name, **kwargs):
        patcher = mock.patch("reload_supervisor." + name, **kwargs)
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def stat_view(self, pid):
        if pid == self.parent_pid:
            self.parent_observation()
            if self.parent_missing:
                raise ProcessLookupError(pid)
            return "S", self.tree.pid, self.parent_start
        if pid == self.child_pid:
            return "S", self.child_parent, self.child_start
        raise AssertionError("unexpected simulated PID")

    def identity_view(self, pid):
        if pid == self.child_pid:
            self.after_child_identity()
        return dict(pid=pid, start_time=self.parent_start if pid == self.parent_pid else self.child_start,
                    exe="/offline/fixture", device=1, inode=2)

    def register_child(self):
        return self.tree.register(self.child_pid, self.parent_pid, "target", "test-stack", "verified_descendant")

    def assert_not_published(self):
        self.assertNotIn(self.child_pid, self.tree.members)
        self.assertEqual(self.tree.history[self.child_pid], 7)
        self.assertFalse(any(e["event"] == "registered" and e["pid"] == self.child_pid for e in self.events))
        self.assertNotIn(self.child_pid, [i["pid"] for i in self.tree.active("test-stack")])

    def test_stable_parent_is_checked_before_publication(self):
        validations = []

        def check_unpublished():
            self.assert_not_published()
            validations.append(True)

        self.after_child_identity = lambda: setattr(self, "parent_observation", check_unpublished)
        item = self.register_child()
        self.assertTrue(validations, "parent was not revalidated after the child identity read")
        self.assertIs(self.tree.members[self.child_pid], item)
        self.assertNotIn(self.child_pid, self.tree.history)
        self.close_fd.assert_not_called()

    def test_parent_exits_before_publication_without_stop_authority(self):
        self.after_child_identity = lambda: setattr(self, "parent_exited", True)
        self.assertIsNone(self.register_child())
        self.assert_not_published()
        self.close_fd.assert_called_once_with(self.child_fd)
        with mock.patch.object(self.tree, "tick"), mock.patch.object(self.tree, "send") as send:
            self.tree.stop("test-stack")
            send.assert_not_called()

    def test_reused_parent_in_discovery_never_authorizes_candidate(self):
        def reuse_parent():
            self.parent_exited = True
            self.parent_start += 1

        self.after_child_identity = reuse_parent
        self.tree.discover()
        self.open_fd.assert_called_once_with(self.child_pid)
        self.close_fd.assert_called_once_with(self.child_fd)
        self.assert_not_published()
        with mock.patch.object(self.tree, "tick"), mock.patch.object(self.tree, "send") as send:
            self.tree.stop("test-stack")
            send.assert_not_called()

    def test_missing_parent_during_revalidation_releases_candidate(self):
        self.after_child_identity = lambda: setattr(self, "parent_missing", True)
        self.assertIsNone(self.register_child())
        self.assert_not_published()
        self.close_fd.assert_called_once_with(self.child_fd)

    def test_invalid_parent_does_not_reparent_existing_authority(self):
        image = self.identity_view(self.child_pid)
        known = dict(pid=self.child_pid, start_time=self.child_start, pidfd=self.child_fd,
                     parent=self.tree.pid, role="target", stack="test-stack",
                     relation="adopted_by_subreaper", initial=image, current=image, exec_pending=False)
        self.tree.members[self.child_pid] = known
        previous = dict(known)
        self.after_child_identity = lambda: setattr(self, "parent_exited", True)
        self.assertIsNone(self.register_child())
        self.assertEqual(known, previous)
        self.assertFalse(any(e["event"] == "reparented" for e in self.events))
        self.open_fd.assert_not_called()
        self.close_fd.assert_not_called()

    def test_exited_known_child_is_not_a_pid_reuse_failure(self):
        image = self.identity_view(self.child_pid)
        known = dict(pid=self.child_pid, start_time=self.child_start, pidfd=self.child_fd,
                     parent=self.parent_pid, role="target", stack="test-stack",
                     relation="verified_descendant", initial=image, current=image, exec_pending=False)
        self.tree.members[self.child_pid] = known
        self.patch("exited", side_effect=lambda fd: fd == self.child_fd)
        self.patch("proc_stat", side_effect=lambda pid: ("Z", self.parent_pid, self.child_start)
                   if pid == self.child_pid else self.stat_view(pid))
        self.assertIsNone(self.register_child())
        self.assertIsNone(self.tree.failure)
        self.assertIs(self.tree.members[self.child_pid], known)
        self.assertNotIn(self.child_pid, [i["pid"] for i in self.tree.active("test-stack")])
        self.assertFalse(any(e["event"] == "registered" for e in self.events))
        self.open_fd.assert_not_called()
        self.close_fd.assert_not_called()

    def test_rejected_candidate_can_be_proven_by_direct_adoption(self):
        self.after_child_identity = lambda: setattr(self, "parent_exited", True)
        self.assertIsNone(self.register_child())
        self.assert_not_published()
        self.child_parent = self.tree.pid
        self.after_child_identity = lambda: None
        item = self.tree.register(self.child_pid, self.tree.pid, "target", "test-stack", "adopted_by_subreaper")
        self.assertIs(item, self.tree.members[self.child_pid])
        self.assertEqual(item["relation"], "adopted_by_subreaper")
        self.assertEqual(self.open_fd.call_count, 2)
        self.close_fd.assert_called_once_with(self.child_fd)

    def test_changed_child_parent_is_not_published(self):
        self.after_child_identity = lambda: setattr(self, "child_parent", 999)
        self.assertIsNone(self.register_child())
        self.assert_not_published()
        self.close_fd.assert_called_once_with(self.child_fd)

    def test_parent_exit_after_proof_keeps_valid_child_authority(self):
        def after_publication(event):
            self.events.append(event)
            if event["event"] == "registered":
                self.parent_exited = True
                self.child_parent = self.tree.pid

        self.tree.event_sink = after_publication
        item = self.register_child()
        self.assertIs(item, self.tree.members[self.child_pid])
        adopted = self.tree.register(self.child_pid, self.tree.pid, "target", "test-stack", "adopted_by_subreaper")
        self.assertIs(adopted, item)
        self.assertEqual(item["parent"], self.tree.pid)
        self.assertEqual(item["relation"], "adopted_by_subreaper")
        self.close_fd.assert_not_called()


def wait_fixture(root, pattern, seconds=8):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        for path in root.glob(pattern):
            try:
                return json.loads(path.read_text())
            except json.JSONDecodeError:
                pass
        time.sleep(0.02)
    raise TimeoutError("fixture barrier: " + pattern)


def ownership_controller(mode, root):
    import reload_supervisor as supervisor
    root = Path(root)
    stack = "fixture-stack"
    hello = supervisor.request("hello")
    supervisor.atomic(root / "controller-ready.json", checks.identity(os.getpid()))
    if mode == "guard-loss":
        until = time.monotonic() + 8
        while time.monotonic() < until and not (root / "guard-ended").exists():
            time.sleep(0.02)
        try:
            supervisor.request("hello")
        except (OSError, ValueError, KeyError, RuntimeError):
            supervisor.atomic(root / "guard-loss-result.json", dict(blocked=True, resource_reclaim=False))
            return 0
        raise RuntimeError("dead supervisor accepted")
    if mode == "authority":
        for operation, wrong_stack, kwargs in (("hello", None, dict(run_id="wrong-run")),
                                               ("assert-stopped", "wrong-stack", {})):
            try:
                supervisor.request(operation, wrong_stack, **kwargs)
            except RuntimeError:
                continue
            raise RuntimeError("stale authority accepted")
        counter = Path(os.environ["GR_SUPERVISOR_SEQUENCE"])
        counter.write_text(str(int(counter.read_text()) - 1) + "\n")
        try:
            supervisor.request("hello")
        except RuntimeError:
            return 0
        raise RuntimeError("replayed sequence accepted")
    fixture = ROOT / "tests/unit/reload_process_fixture"
    image = fixture
    if mode == "exec-failure":
        image = root / "not-executable"
        image.write_text("offline invalid executable fixture")
    scenario = "late" if mode == "late" else "exec" if mode.startswith("exec-") else "tree"
    argv = [str(image), scenario, str(root)]
    if scenario == "exec":
        other = str(Path(shutil.which("sleep")).resolve())
        if mode == "exec-allowed":
            supervisor.request("allow-image", arguments=dict(path=other, sha256=checks.digest(other)))
        argv.append(other)
    supervisor.request("start", stack, dict(argv=argv, sha256=checks.digest(image)))
    first = wait_fixture(root, "launcher-initial-*.json")
    if first["proc_marker"] != 1 or first["getenv_marker"] != 1:
        raise RuntimeError("initial environment marker absent")
    (root / "allow-daemon").touch()
    master = wait_fixture(root, "master-erased-*.json")
    if master["proc_marker"] != 0 or master["getenv_marker"] != 1:
        raise RuntimeError("initial environment was not rewritten")
    supervisor.wait_phase(stack, "running", 8)
    (root / "allow-workers").touch()
    if scenario == "exec":
        until = time.monotonic() + 8
        while time.monotonic() < until:
            value = supervisor.request("status", stack)
            if value["failure"]:
                raise RuntimeError("unapproved exec rejected")
            if any(i["current"] and i["current"]["exe"] == other for i in value["members"]):
                break
            time.sleep(0.02)
        else:
            raise TimeoutError("exec observation")
    else:
        worker = wait_fixture(root, "worker-alive-*.json")
        primary = wait_fixture(root, "primary-alive-*.json")
        wait_fixture(root, "master-ready-*.json")
        if primary["closed_inherited_fds"] != 1:
            raise RuntimeError("inherited descriptors not closed")
        reports = [master, worker, primary]
        if any(r["proc_marker"] or not r["getenv_marker"] for r in reports):
            raise RuntimeError("post-title environment mismatch")
        expected = {r["pid"] for r in reports}
        until = time.monotonic() + 5
        while time.monotonic() < until:
            value = supervisor.request("status", stack)
            if expected <= {i["pid"] for i in value["members"]}:
                break
            time.sleep(0.02)
        else:
            raise RuntimeError("descendant inventory incomplete")
        primary_item = next(i for i in value["members"] if i["pid"] == primary["pid"])
        if primary_item["parent"] != hello["supervisor"]["pid"]:
            raise RuntimeError("primary not adopted by supervisor")
        supervisor.atomic(root / "expected-members.json", [checks.identity(pid) for pid in sorted(expected)])
        if mode == "controller-exit":
            return 7
        if mode == "disconnect":
            os.close(int(os.environ["GR_SUPERVISOR_FD"]))
            return 6
        if mode == "persistence":
            (root / "supervisor.json.next").write_text("blocked atomic publication")
        if mode == "identity":
            item = value["members"][0]
            bad = dict(pid=item["pid"], start_time=item["start_time"] + 1, signal="TERM")
            try:
                supervisor.request("signal", stack, bad)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("wrong start time accepted")
            outsider = json.loads((root / "bystander.json").read_text())
            try:
                supervisor.request("signal", stack, dict(pid=outsider["pid"], start_time=outsider["start_time"], signal="TERM"))
            except RuntimeError:
                pass
            else:
                raise RuntimeError("outside process accepted")
    supervisor.request("stop", stack)
    value = supervisor.wait_phase(stack, "stopped", 12)
    if value["members"] or not supervisor.request("assert-stopped", stack)["stopped"]:
        raise RuntimeError("termination not confirmed")
    supervisor.atomic(root / "controller-result.json", dict(stopped=True, members=0))
    return 0


class OwnershipSupervisorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix="reload-owned-", dir="/data/workspace"))
        cls.started = time.monotonic()
        cls.old_audit = os.environ.get("KILL_IDENTITY_AUDIT")
        os.environ["KILL_IDENTITY_AUDIT"] = str(cls.work / "signals.jsonl")

    @classmethod
    def tearDownClass(cls):
        if cls.old_audit is None:
            os.environ.pop("KILL_IDENTITY_AUDIT", None)
        else:
            os.environ["KILL_IDENTITY_AUDIT"] = cls.old_audit
        if subprocess.call([str(TRASH), str(cls.work)], stdout=subprocess.DEVNULL) != 0:
            raise RuntimeError("ownership test cleanup failed")

    def run_scenario(self, mode, successful=True):
        self.assertLess(time.monotonic() - self.started, 180)
        root = self.work / mode
        root.mkdir(mode=0o700)
        outsider = subprocess.Popen([sys.executable, "-B", "-c", "import time; time.sleep(45)"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        outsider_id = checks.identity(outsider.pid)
        (root / "bystander.json").write_text(json.dumps(outsider_id))
        env = dict(os.environ, OWN_TEST_MARKER="offline-owned-fixture")
        env.pop("GR_SUPERVISOR_LOCK", None)
        cmd = [sys.executable, "-B", str(COMMON / "reload_supervisor.py"),
               "run", str(root), mode, "25", "--", sys.executable, "-B", str(Path(__file__).resolve()),
               "--ownership-controller", mode, str(root)]
        controller_id = None
        process = None
        try:
            with (root / "output.log").open("w") as log:
                process = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env)
                process_id = checks.identity(process.pid)
                if mode == "guard-loss":
                    controller_id = wait_fixture(root, "controller-ready.json")
                    import reload_supervisor as supervisor
                    self.assertEqual(supervisor.proc_stat(controller_id["pid"])[1], process.pid)
                    self.assertEqual(checks.signal_owned(process_id, "KILL", 1), 0)
                    process.wait(timeout=2)
                    (root / "guard-ended").touch()
                    result = wait_fixture(root, "guard-loss-result.json")
                    self.assertEqual(result, dict(blocked=True, resource_reclaim=False))
                else:
                    try:
                        code = process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        if checks.signal_owned(process_id, "TERM", 2) == 3:
                            checks.signal_owned(process_id, "KILL", 1)
                        process.wait(timeout=2)
                        self.fail("supervisor exceeded offline deadline")
                    output = (root / "output.log").read_text()
                    if successful:
                        self.assertEqual(code, 0, output)
                        state = json.loads((root / "supervisor.json").read_text())
                        self.assertEqual(state["phase"], "finished")
                        self.assertEqual(state["members"], [])
                        events = [json.loads(line) for line in (root / "ownership-events.jsonl").read_text().splitlines()]
                        self.assertTrue(events[-1]["echild"])
                    else:
                        self.assertNotEqual(code, 0, output)
                        if mode in ("exec-unknown", "exec-failure"):
                            state = json.loads((root / "supervisor.json").read_text())
                            self.assertEqual(state["failure"], "unexpected_target_image" if mode == "exec-unknown" else "exec_failed")
                        if mode == "controller-exit":
                            self.assertEqual(code, 7, output)
            self.assertIsNone(outsider.poll())
            expected = root / "expected-members.json"
            if expected.exists():
                for item in json.loads(expected.read_text()):
                    try:
                        current = checks.identity(item["pid"])
                    except (FileNotFoundError, ProcessLookupError):
                        continue
                    self.assertNotEqual(current["start_time"], item["start_time"], "owned descendant survived")
            if mode == "late":
                spawned = wait_fixture(root, "master-late-spawn-*.json")
                events = [json.loads(line) for line in (root / "ownership-events.jsonl").read_text().splitlines()]
                pid = spawned["spawned_child"]
                self.assertTrue(any(e["event"] == "registered" and e["pid"] == pid for e in events))
                self.assertTrue(any(e["event"] == "exited" and e["pid"] == pid for e in events))
        finally:
            if process is not None and process.poll() is None:
                if checks.signal_owned(process_id, "TERM", 2) == 3:
                    checks.signal_owned(process_id, "KILL", 1)
                process.wait(timeout=2)
            if controller_id is not None:
                checks.signal_owned(controller_id, "TERM", 1)
            if outsider.poll() is None:
                if checks.signal_owned(outsider_id, "TERM", 1) == 3:
                    checks.signal_owned(outsider_id, "KILL", 1)
            outsider.wait(timeout=2)
            evidence = os.environ.get("RELOAD_OWN_EVIDENCE_DIR")
            if evidence:
                target = Path(evidence) / mode
                shutil.copytree(root, target)

    def test_owned_01_03_erased_environment_and_double_fork(self):
        self.run_scenario("tree")

    def test_owned_04_late_orphan_during_stop(self):
        self.run_scenario("late")

    def test_owned_05_permitted_exec(self):
        self.run_scenario("exec-allowed")

    def test_owned_05_unpermitted_exec(self):
        self.run_scenario("exec-unknown", False)

    def test_owned_05_wrong_identity_and_bystander(self):
        self.run_scenario("identity")

    def test_owned_05_stale_control_authority(self):
        self.run_scenario("authority")

    def test_owned_06_controller_exit(self):
        self.run_scenario("controller-exit", False)

    def test_owned_06_controller_disconnect(self):
        self.run_scenario("disconnect", False)

    def test_owned_07_supervisor_loss_blocks_reclaim(self):
        self.run_scenario("guard-loss", False)

    def test_owned_08_exec_failure(self):
        self.run_scenario("exec-failure", False)

    def test_owned_08_persistence_failure(self):
        self.run_scenario("persistence", False)

    def test_owned_08_helper_deadline(self):
        import reload_supervisor as supervisor
        tree = object.__new__(supervisor.ProcessTree)
        tree.failure = None
        tree.helper_targets = {123: (456, "TERM", 20.0)}
        with mock.patch.object(supervisor.time, "monotonic", return_value=19.0):
            tree.check_helper_deadlines()
        self.assertIsNone(tree.failure)
        with mock.patch.object(supervisor.time, "monotonic", return_value=20.0):
            tree.check_helper_deadlines()
        self.assertEqual(tree.failure, "signal_helper_timeout")


class SummaryFetchCodeTests(unittest.TestCase):
    """wait_client_summary must separate "no data" from "reported and failed".

    A probe that printed its summary but exited non-zero is a real verdict
    failure (harness return 2, recorded FAIL); only a timeout or an absent
    summary is NO_DATA (return 1, recorded SKIP).
    """

    RUNTIME = COMMON / "reload_runtime.sh"

    def run_fetch(self, stub_out, stub_rc, pattern="STREAM_SUMMARY"):
        with tempfile.TemporaryDirectory() as out:
            script = (
                "set -u\n"
                "CLIENT=stub REMOTE_DIR=/tmp/stub OUT=%s CURRENT_PROBE=p\n"
                ". %s\n"
                # the stub must win: the sourced file defines the real one
                "run_client() { printf '%%s\\n' \"$STUB_OUT\"; return \"$STUB_RC\"; }\n"
                "wait_client_summary /dev/null '%s' 1\n"
                "exit $?\n" % (out, self.RUNTIME, pattern))
            env = dict(os.environ, STUB_OUT=stub_out, STUB_RC=str(stub_rc))
            return subprocess.run(["bash", "-c", script], env=env,
                                  capture_output=True, text=True)

    def summary(self, streams=12):
        return ("STREAM_SUMMARY streams=%d ok=%d md5_ok=%d eof_clean=%d "
                "stalls(>3.0s)=0 worst_gap=0.1s workers_expected=12 "
                "workers_done=12 workers_active=12 worker_errors=0"
                % (streams, streams, streams, streams))

    def test_reported_and_passed(self):
        self.assertEqual(self.run_fetch(self.summary(), 0).returncode, 0)

    def test_reported_but_failed_is_not_no_data(self):
        # The probe says so itself: it printed a summary and exited non-zero.
        self.assertEqual(self.run_fetch(self.summary(), 1).returncode, 2)
        self.assertEqual(self.run_fetch(self.summary(), 3).returncode, 2)

    def test_absent_summary_is_no_data(self):
        self.assertEqual(self.run_fetch("GR_PROBE_EXIT job=p rc=0", 0).returncode, 1)

    def test_timeout_is_no_data(self):
        self.assertEqual(self.run_fetch("still running", 75).returncode, 1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--ownership-controller":
        try:
            raise SystemExit(ownership_controller(sys.argv[2], sys.argv[3]))
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            print("OWN_CONTROLLER_FAILED " + type(exc).__name__, file=sys.stderr)
            raise SystemExit(19)
    unittest.main()
