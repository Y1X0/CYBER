"""uid+nft execution backend — kernel-level egress confinement.

The security tests are REAL (not mocked): they install nft rules and prove the kernel DROPS an
unauthorized destination for the run's uid while allowing the authorized one. They are gated on the
capability actually being present (root + nftables), so CI without CAP_NET_ADMIN skips them; the
non-privileged tests (backend selection, uid uniqueness, offline delegation) always run.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
import uuid

import pytest
from guardian_core.tool import EffectiveScope, ToolJob
from guardian_scanner.tools.backends import get_backend
from guardian_scanner.tools.backends.inproc import InprocSandboxBackend
from guardian_scanner.tools.backends.uid_nft import (
    UidNftBackend,
    _alloc_uid,
    _free_uid,
    _table,
    isolate,
    reap_orphans,
)

# A world-accessible interpreter (the unprivileged run-uid must be able to exec it).
_PY = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable


def _nft(*a):
    return subprocess.run(["nft", *a], capture_output=True, text=True, check=False)


def _can_isolate() -> bool:
    if os.geteuid() != 0:
        return False
    if _nft("add", "table", "inet", "guardian_probe").returncode != 0:
        return False
    _nft("delete", "table", "inet", "guardian_probe")
    return True


_kernel = pytest.mark.skipif(not _can_isolate(), reason="requires root + nftables (CAP_NET_ADMIN)")


def _job(job_id, targets, ports, *, allow_live=True):
    return ToolJob(
        tenant_id="t", job_id=job_id, tool_key="nmap",
        scope=EffectiveScope(targets=tuple(targets), ports=tuple(ports), protocols=("tcp",),
                             network_allowed=True, read_only=True),
        settings={"allow_live": allow_live})


# ── non-privileged: seam + selection + allocation + offline delegation ──
def test_backend_selection():
    assert type(get_backend("uid_nft")).__name__ == "UidNftBackend"
    assert type(get_backend("inproc")).__name__ == "InprocSandboxBackend"
    assert type(get_backend(None)).__name__ == "InprocSandboxBackend"


def test_uid_allocation_is_unique_and_freed():
    a, b = _alloc_uid(), _alloc_uid()
    try:
        assert a != b                                    # concurrent runs never share a uid
    finally:
        _free_uid(a)
        _free_uid(b)
    c = _alloc_uid()                                      # freed uid becomes reusable
    _free_uid(c)


def test_offline_run_delegates_to_inproc(monkeypatch):
    # allow_live not set ⇒ no external process ⇒ no nft needed (works without CAP_NET_ADMIN).
    called = {}
    orig = InprocSandboxBackend.run
    monkeypatch.setattr(InprocSandboxBackend, "run",
                        lambda self, job, fn: called.setdefault("inproc", True) or orig(self, job, fn))
    UidNftBackend().run(_job("j", ["10.0.0.5"], (80,), allow_live=False), lambda: [])
    assert called.get("inproc") is True


def test_isolation_refuses_non_ip_target():
    from guardian_scanner.tools.backends.uid_nft import IsolationError, _install_rules
    with pytest.raises(IsolationError):
        _install_rules(_table("x"), 61500, _job("x", ["example.com"], (80,)))


# ── REAL kernel-level enforcement ──
def _listen(ip, port, stop):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(8)
    s.settimeout(0.5)
    while not stop.is_set():
        try:
            c, _ = s.accept()
            c.close()
        except (OSError, TimeoutError):
            continue
    s.close()


def _tester_binary():
    # Written under /tmp (world-traversable) so the unprivileged run-uid can reach it — pytest's
    # tmp_path parents are 0700. Caller removes it.
    path = f"/tmp/g_ct_{uuid.uuid4().hex}.py"  # noqa: S108
    with open(path, "w") as fh:
        fh.write(
            "import socket,sys\n"
            "def probe(ip,port):\n"
            "    s=socket.socket(); s.settimeout(2)\n"
            "    try: s.connect((ip,int(port))); print(f'{ip}:{port}=OK')\n"
            "    except Exception as e: print(f'{ip}:{port}={type(e).__name__}')\n"
            "    finally:\n"
            "        try: s.close()\n"
            "        except OSError: pass\n"
            "for a in sys.argv[1:]:\n"
            "    ip,port=a.split('#'); probe(ip,port)\n"
        )
    os.chmod(path, 0o755)
    return path


@_kernel
def test_kernel_allows_authorized_drops_everything_else():
    from guardian_scanner.tools.nmap_runner import run_nmap
    allow_port, deny_port = 19801, 19802
    stop = threading.Event()
    threads = [threading.Thread(target=_listen, args=("127.0.0.1", p, stop), daemon=True)
               for p in (allow_port, deny_port)]
    threads += [threading.Thread(target=_listen, args=("127.0.0.2", allow_port, stop), daemon=True)]
    for t in threads:
        t.start()
    time.sleep(0.4)
    tester = _tester_binary()

    # Scope authorizes ONLY 127.0.0.1:allow_port.
    job = _job("kern1", ["127.0.0.1"], (allow_port,))
    try:
        with isolate(job):
            res = run_nmap([_PY, tester,
                            f"127.0.0.1#{allow_port}",   # authorized IP+port  → OK
                            f"127.0.0.1#{deny_port}",    # authorized IP, bad port → DROP
                            f"127.0.0.2#{allow_port}",   # unauthorized IP     → DROP
                            "127.0.0.1#53"],            # DNS not in scope     → DROP
                           wall_seconds=20)
        out = res.xml.decode()
    finally:
        stop.set()
        os.remove(tester)
    assert f"127.0.0.1:{allow_port}=OK" in out                       # allowed
    assert f"127.0.0.1:{deny_port}=TimeoutError" in out              # port dropped by kernel
    assert f"127.0.0.2:{allow_port}=TimeoutError" in out             # unauthorized IP dropped
    assert "127.0.0.1:53=TimeoutError" in out                        # DNS dropped by default


@_kernel
def test_dns_allowed_only_when_explicitly_in_scope():
    from guardian_scanner.tools.nmap_runner import run_nmap
    stop = threading.Event()
    threading.Thread(target=_listen, args=("127.0.0.1", 53, stop), daemon=True).start()
    time.sleep(0.3)
    tester = _tester_binary()
    job = _job("kerndns", ["127.0.0.1"], (53,))          # 53 explicitly authorized
    try:
        with isolate(job):
            res = run_nmap([_PY, tester, "127.0.0.1#53"], wall_seconds=20)
    finally:
        stop.set()
        os.remove(tester)
    assert "127.0.0.1:53=OK" in res.xml.decode()


@_kernel
def test_teardown_removes_nft_table():
    job = _job("teardown1", ["127.0.0.1"], (12345,))
    table = _table(job.job_id)
    with isolate(job):
        assert _nft("list", "table", "inet", table).returncode == 0   # exists during run
    assert _nft("list", "table", "inet", table).returncode != 0       # gone after


@_kernel
def test_reaper_cleans_orphaned_tables():
    orphan = _table("orphaned_crash_job")
    _nft("add", "table", "inet", orphan)
    assert _nft("list", "table", "inet", orphan).returncode == 0
    reap_orphans()
    assert _nft("list", "table", "inet", orphan).returncode != 0      # reaped


@_kernel
def test_cross_run_uids_do_not_share_allowlist():
    from guardian_scanner.tools.nmap_runner import run_nmap
    port_a, port_b = 19811, 19812
    stop = threading.Event()
    for p in (port_a, port_b):
        threading.Thread(target=_listen, args=("127.0.0.1", p, stop), daemon=True).start()
    time.sleep(0.4)
    tester = _tester_binary()
    # Run A authorizes port_a only; from A's uid, port_b (B's target) must be dropped.
    job_a = _job("runA", ["127.0.0.1"], (port_a,))
    try:
        with isolate(job_a):
            res = run_nmap([_PY, tester,
                            f"127.0.0.1#{port_a}", f"127.0.0.1#{port_b}"], wall_seconds=20)
        out = res.xml.decode()
    finally:
        stop.set()
        os.remove(tester)
    assert f"127.0.0.1:{port_a}=OK" in out
    assert f"127.0.0.1:{port_b}=TimeoutError" in out                 # B's scope never leaks into A
