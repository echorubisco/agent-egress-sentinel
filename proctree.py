#!/usr/bin/env python3
"""
Process-ancestry attribution.

The hole this closes: until 2026-07-27 an "agent" was recognised only by matching
a token against a process's OWN name/argv. So when Claude Code shelled out to
`git push`, or an agent ran `npm`, `curl`, or a language runtime, that child's
egress carried no token and was attributed to nobody -- "per-agent" was really
"per-process-whose-own-argv-contains-a-token". For any agent that does its network
work in subprocesses that is most of its traffic.

Now an unmatched process walks up its ancestors: if an ancestor is an agent, the
flow is attributed to that agent and the alert says so ("claude via git").

ppid comes from libproc via ctypes -- no fork, and it works where spawning `ps` is
blocked. argv still needs `ps` (there is no public libproc call for it), so the
identity string per pid is: nettop's process name + libproc's name + argv when
available. Ancestry works even when argv does not.

PORTABILITY. Only the three primitives below are platform-specific: `proc_info`
(ppid + name), `proc_start`, and `argv`. `ancestors()` and `attribute()` -- the
depth bound, the cycle guard, the confusable exclusion, the "attribute to the
ancestor but report the child" rule -- are deliberately written once against
those primitives, because a second copy of the walk is a second chance to get
the termination conditions wrong, and that is true across an OS boundary too.
The Windows backend uses Toolhelp32 + GetProcessTimes via ctypes, mirroring the
libproc approach: no fork, works where spawning a helper is blocked. `argv`
there needs psutil; without it the walk degrades to process names only, which
is the same degradation POSIX already has when `ps` is unavailable. See
PLATFORMS.md for what this does and does not buy on Windows.
"""

import ctypes
import ctypes.util
import subprocess
import sys
import time

_IS_WIN = sys.platform.startswith("win")

_PROC_PIDTBSDINFO = 3
_MAXCOMLEN = 16


class _BSDInfo(ctypes.Structure):
    _fields_ = [("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32),
                ("pbi_xstatus", ctypes.c_uint32), ("pbi_pid", ctypes.c_uint32),
                ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
                ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32),
                ("pbi_rgid", ctypes.c_uint32), ("pbi_svuid", ctypes.c_uint32),
                ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
                ("pbi_comm", ctypes.c_char * _MAXCOMLEN),
                ("pbi_name", ctypes.c_char * (2 * _MAXCOMLEN)),
                ("pbi_nfiles", ctypes.c_uint32), ("pbi_pgid", ctypes.c_uint32),
                ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
                ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32),
                ("pbi_start_tvsec", ctypes.c_uint64),
                ("pbi_start_tvusec", ctypes.c_uint64)]


def _libproc():
    try:
        return ctypes.CDLL(ctypes.util.find_library("proc")
                           or "/usr/lib/libSystem.dylib", use_errno=True)
    except OSError:
        return None


_LIB = _libproc()


def proc_info(pid):
    """(ppid, name) for pid, or None. No subprocess."""
    if _IS_WIN:
        return _win_proc_info(pid)
    rec = _bsdinfo(pid)
    if rec is None:
        return None
    b = rec
    name = (b.pbi_name or b.pbi_comm or b"").decode("utf-8", "replace")
    return int(b.pbi_ppid), name


def proc_start(pid):
    """Process start time (seconds since epoch) for pid, or None.

    Used by the dead-man check: a heartbeat claims (pid, start_time), so a
    replacement process cannot inherit a dead sentinel's identity just by
    reusing its pid -- the start time would differ.
    """
    if _IS_WIN:
        return _win_proc_start(pid)
    rec = _bsdinfo(pid)
    return None if rec is None else int(rec.pbi_start_tvsec)


def _bsdinfo(pid):
    if _LIB is None:
        return None
    try:
        b = _BSDInfo()
        n = _LIB.proc_pidinfo(int(pid), _PROC_PIDTBSDINFO, 0,
                              ctypes.byref(b), ctypes.sizeof(b))
    except (ValueError, OSError):
        return None
    return b if n > 0 else None


# ------------------------------------------------------------- Windows ---
# Toolhelp32 for ppid+name, GetProcessTimes for start time. Same contract as the
# libproc path above: no fork, returns None rather than raising.
if _IS_WIN:                                        # pragma: no cover - platform
    _MAX_PATH = 260
    _TH32CS_SNAPPROCESS = 0x00000002
    _QUERY_LIMITED_INFORMATION = 0x1000
    # FILETIME is 100-ns ticks since 1601-01-01; this is the offset to 1970.
    _EPOCH_DELTA = 116444736000000000

    class _ProcessEntry32W(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_uint32),
                    ("cntUsage", ctypes.c_uint32),
                    ("th32ProcessID", ctypes.c_uint32),
                    ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", ctypes.c_uint32),
                    ("cntThreads", ctypes.c_uint32),
                    ("th32ParentProcessID", ctypes.c_uint32),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", ctypes.c_uint32),
                    ("szExeFile", ctypes.c_wchar * _MAX_PATH)]

    class _FileTime(ctypes.Structure):
        _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

        def epoch(self):
            v = (self.high << 32) | self.low
            return None if v < _EPOCH_DELTA else (v - _EPOCH_DELTA) // 10_000_000

    _K32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Handles must be declared: a default c_int restype truncates a 64-bit
    # handle to garbage, which fails in a way that looks like "no such process".
    _K32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    _K32.OpenProcess.restype = ctypes.c_void_p
    _K32.CloseHandle.argtypes = [ctypes.c_void_p]
    _K32.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(_FileTime)] * 4

    _SNAP_TTL = 1.0                                # seconds
    _snap_cache = {"at": 0.0, "map": {}}

    def _win_snapshot():
        """{pid: (ppid, name)} for every process, cached for _SNAP_TTL.

        Toolhelp32 has no "one process" mode -- it enumerates the whole table --
        so a six-level ancestry walk would otherwise enumerate it six times per
        flow. The TTL matches the app's 1 s tick, and staleness is harmless here:
        a pid that died mid-walk is exactly the None the callers already handle.
        """
        now = time.time()
        if now - _snap_cache["at"] < _SNAP_TTL and _snap_cache["map"]:
            return _snap_cache["map"]
        out = {}
        snap = _K32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
        if snap in (None, 0) or snap == ctypes.c_void_p(-1).value:
            return _snap_cache["map"]              # keep the last good map
        try:
            e = _ProcessEntry32W()
            e.dwSize = ctypes.sizeof(_ProcessEntry32W)
            ok = _K32.Process32FirstW(ctypes.c_void_p(snap), ctypes.byref(e))
            while ok:
                out[int(e.th32ProcessID)] = (int(e.th32ParentProcessID), e.szExeFile)
                ok = _K32.Process32NextW(ctypes.c_void_p(snap), ctypes.byref(e))
        finally:
            _K32.CloseHandle(ctypes.c_void_p(snap))
        if out:
            _snap_cache.update(at=now, map=out)
            _start_memo.clear()                    # start times age out with the map
        return _snap_cache["map"]

    _start_memo = {}

    def _win_proc_info(pid):
        """(ppid, name), with a dead-parent guard POSIX does not need.

        Windows does NOT reparent an orphan. When a parent exits, the child keeps
        its numeric ppid, and once the OS recycles that number the field points at
        an unrelated process -- where POSIX would have moved the child to init and
        the walk would have stopped at pid 1. Believing that field attributes an
        agent's egress to whatever inherited the number, and wrong attribution is
        the one failure mode this tool exists to refuse. So a claimed parent is
        rejected unless it is OLDER than the child: a recycled pid is necessarily
        younger, and a real parent necessarily is not.

        NOT MEASURED. This is a guard against a documented platform behaviour, not
        a fix for an observed misattribution -- while building this the walk did
        read `claude.exe -> sihost.exe`, which looked like the bug, but sihost
        predates claude by ten minutes and is a plausible real launcher. So the
        rule is right and the anecdote was not evidence for it. How often the
        field is actually stale on a live desktop is unknown here.

        Returned as ppid 0, which the shared walk already reads as "no parent".
        The walk itself stays single-sourced: this quirk belongs to the platform
        layer, not to the attribution rules.
        """
        try:
            rec = _win_snapshot().get(int(pid))
            if rec is None:
                return None
            ppid, name = rec
            if ppid <= 0:
                return rec
            child, parent = _start_cached(pid), _start_cached(ppid)
            if child is not None and parent is not None and parent > child:
                return 0, name                     # recycled pid, not our parent
            return rec
        except Exception:
            return None

    def _start_cached(pid):
        pid = int(pid)
        if pid not in _start_memo:
            _start_memo[pid] = _win_proc_start(pid)
        return _start_memo[pid]

    def _win_proc_start(pid):
        h = None
        try:
            h = _K32.OpenProcess(_QUERY_LIMITED_INFORMATION, False, int(pid))
            if not h:
                return None
            created, exited, kern, user = (_FileTime() for _ in range(4))
            if not _K32.GetProcessTimes(ctypes.c_void_p(h), ctypes.byref(created),
                                        ctypes.byref(exited), ctypes.byref(kern),
                                        ctypes.byref(user)):
                return None
            return created.epoch()
        except Exception:
            return None
        finally:
            if h:
                _K32.CloseHandle(ctypes.c_void_p(h))


def argv(pid):
    """Full command line for pid, lowercased; '' when unavailable.

    POSIX forks `ps`; Windows has no equivalent one-shot and asks psutil, which
    reads the PEB. Both may legitimately return '' -- `ps` can be blocked, and
    reading another user's command line on Windows is a privileged act -- so
    callers must stay correct without it. attribute() already is: it matches on
    "name + argv", and ancestry itself never needs argv.
    """
    if _IS_WIN:
        try:
            import psutil
            return " ".join(psutil.Process(int(pid)).cmdline()).strip().lower()
        except Exception:
            return ""
    try:
        return subprocess.run(["ps", "-o", "command=", "-p", str(pid)],
                              capture_output=True, text=True,
                              timeout=3).stdout.strip().lower()
    except Exception:
        return ""


def argv_many(pids):
    """{pid: argv} for several pids at once, lowercased. Missing pids are absent.

    Exists for the PreToolUse hook, which runs before EVERY tool call and walks
    six ancestors. Six `ps` forks per tool call is not a price a monitoring side
    channel gets to charge, and `ps -p a,b,c` costs one. Windows has no batch
    form, but psutil reads the PEB in-process, so the loop forks nothing there
    either. Same failure contract as argv(): silence, never an exception.
    """
    pids = [int(p) for p in pids]
    if not pids:
        return {}
    if _IS_WIN:
        return {p: a for p in pids if (a := argv(p))}
    try:
        out = subprocess.run(
            ["ps", "-o", "pid=,command=", "-p", ",".join(str(p) for p in pids)],
            capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return {}
    found = {}
    for line in out.splitlines():
        head, _, cmd = line.strip().partition(" ")
        try:
            found[int(head)] = cmd.strip().lower()
        except ValueError:
            continue
    return found


def ancestors(pid, max_depth=6, info=proc_info):
    """[pid, ppid, grandparent, ...] up to max_depth, stopping at launchd.

    `attribute()` above answers "which agent owns this traffic" and deliberately
    returns only a token. Reconciliation needs the raw chain instead: an agent
    declares an activity under ITS OWN pid, and the bytes come out of a
    descendant (kiro-cli -> bash -> curl). So the question is "is any ancestor of
    the flow's pid a pid that declared something", and that needs the ids.

    Same depth bound and cycle guard as attribute() -- intentionally sharing the
    rules rather than re-deriving the walk, because a second copy of the walk is
    a second chance to get the termination conditions wrong. Returns at least
    [pid] so a caller can always iterate the result.
    """
    chain = [pid]
    seen = {pid}
    cur, depth = pid, 0
    while depth < max_depth:
        rec = info(cur)
        if rec is None:
            break
        ppid, _pname = rec
        if ppid <= 1 or ppid in seen:          # reached launchd, or a cycle
            break
        seen.add(ppid)
        chain.append(ppid)
        cur, depth = ppid, depth + 1
    return chain


def attribute(name, pid, match, max_depth=6, info=proc_info, get_argv=argv):
    """Return (agent_token, via) or (None, None).

    `match(identity_string)` -> token or None (the caller supplies tokenisation +
    the confusable exclusion, so this module stays free of policy).
    `via` is None when the process itself matched, else the name of the descendant
    the traffic actually came from, for the alert text ("claude via git").

    Walks at most max_depth ancestors and stops at pid<=1. `info`/`get_argv` are
    injectable so the walk is unit-testable without a live process table.
    """
    own = match(f"{name} {get_argv(pid)}")
    if own:
        return own, None
    seen = set()
    cur, depth = pid, 0
    while depth < max_depth:
        rec = info(cur)
        if rec is None:
            return None, None
        ppid, _pname = rec
        if ppid <= 1 or ppid in seen:          # reached launchd, or a cycle
            return None, None
        seen.add(ppid)
        prec = info(ppid)
        if prec is None:
            return None, None
        hit = match(f"{prec[1]} {get_argv(ppid)}")
        if hit:
            return hit, name                   # attribute to ancestor, report child
        cur, depth = ppid, depth + 1
    return None, None
