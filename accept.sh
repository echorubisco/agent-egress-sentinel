#!/usr/bin/env bash
# accept.sh -- one-click acceptance for Agent Egress Sentinel.
# Run on the machine you chose (personal Mac recommended; see README/EDR note).
#
#   ./accept.sh preflight              # step 0: tools, iface, rumps, sni.jsonl state
#   ./accept.sh sniffer                # terminal A: start sudo sniffer (foreground)
#   ./accept.sh check-p0a              # verify sni.jsonl owner == you (P0-A gate)
#   ./accept.sh harvest                # step 1: dump observed domains for triage
#   ./accept.sh zero-red [minutes]     # step 2: headless watch, PASS = 0 red (default 60)
#   ./accept.sh curl-test [file]       # step 3: end-to-end red-path test (auto pass/fail)
#   ./accept.sh calibrate [minutes]    # measure the benign breadth ceiling -> MIN_DESTS
#
# zero-red / curl-test are HEADLESS: they reuse sentinel.py's pure functions
# (parse_flows/aggregate_flows) so no GUI is needed for the gates. Run the rumps
# app separately if you also want to eyeball the menu-bar colors.

set -u
cd "$(dirname "$0")"

DATA_DIR="$HOME/.agent-egress-sentinel"
SNI_FILE="$DATA_DIR/sni.jsonl"
EVENTS="$DATA_DIR/accept_events.log"
PY=python3

ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }
info() { printf '  ....  %s\n' "$1"; }

iface() { route -n get default 2>/dev/null | awk '/interface:/{print $2}'; }

# ---------------------------------------------------------------- watcher ---
# Headless red/amber watcher built on sentinel's pure functions. Prints one
# line per event and appends to $EVENTS. Args: <seconds> [label]
watch_py() {
"$PY" - "$1" "${2:-watch}" <<'PYEOF'
import sys, time, datetime, pathlib
from sentinel import (NettopStream, aggregate_flows, FLAG_BYTES, ALLOW,
                      BASELINE_TTL, _TOKEN_SPLIT)
from sni_sniffer import SNICache
from ledger import DestLedger, CovertChannelDetector, DestinationFanout
import proctree

seconds, label = int(sys.argv[1]), sys.argv[2]
sni = SNICache()
events = pathlib.Path.home() / ".agent-egress-sentinel" / "accept_events.log"
events.parent.mkdir(exist_ok=True)
# Production semantics (2026-07-27): streaming nettop, warm-up seeding, baseline
# persisted with a TTL, ancestry attribution. An earlier version of this watcher
# used `baseline = dict(flows)` with no warm-up -- the pre-fix rule -- so it
# measured the wrong thing.
stream = NettopStream(); stream.start()
baseline, seen_ts, agent_cache = {}, {}, {}
warmup = True
red = amber = ticks = 0

def match(blob):
    t = set(_TOKEN_SPLIT.split(blob.lower()))
    return None if t & ALLOW.confusables() else next(iter(t & ALLOW.agent_tokens()), None)

def agent_for(name, pid):
    key = (name, pid)
    if key not in agent_cache:
        agent_cache[key] = proctree.attribute(name, pid, match)
    return agent_cache[key]

def emit(line):
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    print(f"{ts}  {line}", flush=True)
    with events.open("a") as f:
        f.write(f"{ts}  [{label}] {line}\n")

emit(f"watch start ({seconds}s, floor={FLAG_BYTES//1024//1024}MB burst, tokens={sorted(ALLOW.agent_tokens())})")
end = time.time() + seconds
ledger = DestLedger(); chan = CovertChannelDetector(); fan = DestinationFanout()
while time.time() < end:
    try:
        now = time.time()
        flows = stream.snapshot(now)
        def observe(pid, kind, dest, delta, ip):
            ledger.add(pid, kind, dest, delta, now)
            chan.observe(pid, dest, delta, now)
            fan.observe(pid, ip, delta, now)
        per = aggregate_flows(flows, baseline, sni.domain_for_ip, ALLOW.matches,
                              observe=observe, warmup=warmup)
        warmup = False
        for k, v in flows.items():
            baseline[k] = v; seen_ts[k] = now
        for k in [k for k, ts in seen_ts.items() if now - ts > BASELINE_TTL]:
            del seen_ts[k]; baseline.pop(k, None)
        ledger.gc(now); chan.gc(now); fan.gc(now)
        ticks += 1
        for (name, pid), agg in per.items():
            breaches = ledger.breaches(pid, now)
            if not breaches:
                continue
            a, via = agent_for(name, pid)
            if not a:
                continue
            lbl = f"{a} via {via}" if via else a
            doms = {d: lv for (kind, d), lv in breaches.items() if kind == "dom"}
            if doms:
                red += 1
                dests = ", ".join(sorted(doms, key=doms.get, reverse=True)[:3])
                emit(f"RED   {lbl} ({name}.{pid}) "
                     f"{int(sum(doms.values()))//1024//1024} MB -> likely non-AI: {dests}")
            else:
                amber += 1
                emit(f"AMBER {lbl} ({name}.{pid}) unresolved dest "
                     f"(sniffer running?)")
    except Exception as e:
        emit(f"ERROR tick: {e}")
    time.sleep(1)

emit(f"watch end: ticks={ticks} red={red} amber={amber} stream_restarts={stream.restarts}")
sys.exit(1 if red else 0)   # exit 0 == zero red
PYEOF
}

# ------------------------------------------------------------ subcommands ---
cmd_preflight() {
  echo "== STEP 0: preflight =="
  for t in nettop tcpdump curl "$PY"; do
    command -v "$t" >/dev/null && ok "$t present" || bad "$t MISSING"
  done
  IF=$(iface); [ -n "$IF" ] && ok "default interface: $IF" || bad "no default interface found"
  "$PY" -c "import rumps" 2>/dev/null && ok "rumps installed (GUI available)" \
    || info "rumps NOT installed -- gates run headless anyway; 'pip install rumps' for the menu-bar app"
  "$PY" -c "from sentinel import parse_flows, aggregate_flows, ALLOW; assert 'kiro' in ALLOW.agent_tokens()" \
    && ok "sentinel imports headless; kiro in token set" || bad "sentinel import / token check failed"
  "$PY" tests/test_parse.py >/dev/null 2>&1 && ok "test_parse.py green" || bad "test_parse.py FAILED"
  "$PY" tests/test_classify.py >/dev/null 2>&1 && ok "test_classify.py green" || bad "test_classify.py FAILED"
  if [ -f "$SNI_FILE" ]; then
    info "sni.jsonl exists: $(ls -l "$SNI_FILE" | awk '{print $3, $5"B", $6, $7}') -- stale? clear before harvest"
  else
    info "sni.jsonl absent (fresh start)"
  fi
  grep -q SEED-UNVERIFIED ai_endpoints.yaml \
    && info "allowlist still SEED-UNVERIFIED -- harvest must replace it before zero-red" \
    || ok "allowlist version is not SEED-UNVERIFIED"
}

cmd_sniffer() {
  echo "== sniffer (terminal A, blocks; Ctrl-C to stop) =="
  IF=${SENTINEL_IFACE:-$(iface)}
  [ -n "$IF" ] || { bad "no interface; set SENTINEL_IFACE"; exit 1; }
  read -r -p "  Clear old $SNI_FILE for a clean capture? [y/N] " a
  [ "${a:-n}" = "y" ] && rm -f "$SNI_FILE" && info "cleared"
  info "starting: SENTINEL_IFACE=$IF sudo -E $PY sni_sniffer.py  (sudo will prompt)"
  info "after ~10s, run './accept.sh check-p0a' in another terminal"
  SENTINEL_IFACE="$IF" exec sudo -E "$PY" sni_sniffer.py
}

cmd_check_p0a() {
  echo "== P0-A gate: sni.jsonl readable by you =="
  [ -f "$SNI_FILE" ] || { bad "sni.jsonl does not exist -- is the sniffer running?"; exit 1; }
  OWNER=$(ls -l "$SNI_FILE" | awk '{print $3}')
  ME=${SUDO_USER:-$USER}
  [ "$OWNER" = "$ME" ] && ok "owner=$OWNER (== $ME): chown-back worked" \
    || { bad "owner=$OWNER != $ME -- P0-A regression, sentinel cannot read domains"; exit 1; }
  [ -r "$SNI_FILE" ] && ok "file readable" || { bad "file not readable"; exit 1; }
  N=$(wc -l < "$SNI_FILE" | tr -d ' ')
  [ "$N" -gt 0 ] && ok "$N SNI records captured" || info "0 records yet -- generate some TLS traffic"
}

cmd_calibrate() {
  MINS=${1:-30}
  echo "== calibrate MIN_DESTS (empirical benign ceiling) =="
  info "do REAL work for $MINS min while this runs -- run your agents, install packages,"
  info "browse, let Cursor index. The point is to find the busiest BENIGN breadth."
  info "current MIN_DESTS=$("$PY" -c 'from ledger import DestinationFanout as F; print(F.MIN_DESTS)')"
"$PY" - "$MINS" <<'PYEOF'
import sys, time, collections
from sentinel import NettopStream, aggregate_flows, BASELINE_TTL, ALLOW, _TOKEN_SPLIT
from sni_sniffer import SNICache
from ledger import DestinationFanout
import proctree

mins = float(sys.argv[1]); end = time.time() + mins*60
sni = SNICache(); stream = NettopStream(); stream.start()
fan = DestinationFanout()
baseline, seen_ts, cache = {}, {}, {}
peak = collections.Counter()          # (name,pid) -> highest fan-out count seen
warm = True

def match(b):
    t = set(_TOKEN_SPLIT.split(b.lower()))
    return None if t & ALLOW.confusables() else next(iter(t & ALLOW.agent_tokens()), None)

while time.time() < end:
    now = time.time()
    flows = stream.snapshot(now)
    aggregate_flows(flows, baseline, sni.domain_for_ip, ALLOW.matches, warmup=warm,
                    observe=lambda pid, kind, dest, delta, ip: fan.observe(pid, ip, delta, now))
    warm = False
    for k, v in flows.items():
        baseline[k] = v; seen_ts[k] = now
    for k in [k for k, ts in seen_ts.items() if now - ts > BASELINE_TTL]:
        del seen_ts[k]; baseline.pop(k, None)
    fan.gc(now)
    for (name, pid) in {(k[0], k[1]) for k in flows}:
        hit = fan.fanout(pid, now)
        n = hit[0] if hit else len(
            [d for (p, d), (tot, ts) in fan._seen.items()
             if p == pid and now - ts <= fan.WINDOW_SEC and tot <= fan.SMALL_BYTES])
        if n > peak[(name, pid)]:
            peak[(name, pid)] = n
            if (name, pid) not in cache:
                cache[(name, pid)] = proctree.attribute(name, pid, match)
    time.sleep(2)

print(f"\n== benign breadth ceiling over {mins:.0f} min ==")
rows = sorted(peak.items(), key=lambda kv: -kv[1])[:15]
for (name, pid), n in rows:
    a, via = cache.get((name, pid), (None, None))
    tag = (f"{a} via {via}" if via else a) if a else "-"
    print(f"  peak {n:3d} low-byte dests / {fan.WINDOW_SEC}s   {name}.{pid}   agent={tag}")
agents = [n for (k, n) in peak.items() if cache.get(k, (None,))[0]]
allp = [n for n in peak.values()]
print(f"\n  max across ALL processes:   {max(allp) if allp else 0}")
print(f"  max across AGENT processes: {max(agents) if agents else 0}")
print(f"  current MIN_DESTS = {DestinationFanout.MIN_DESTS}")
print("\n  Rule of thumb: set MIN_DESTS above the AGENT max with headroom (e.g. 2x).")
print("  Do NOT convert an observed count to a real one with a single factor.")
print("  Recall is min(1, L/T) in the per-connection lifetime L at the shipped")
print("  T=1s, so an observed N corresponds to N real destinations at L>=1s but")
print("  ~17N at L~50ms. Measured: 5.8% / 36.8% / 54.4% / 100% at 50ms / 300ms /")
print("  500ms / >=1s. (An earlier version of this line said 'recall is ~48%, so")
print("  N observed == 2N real'. That 48% was one workload's connection lifetime,")
print("  not a property of the sampler, and it is withdrawn -- see ROADMAP 07-30.)")
PYEOF
}

cmd_harvest() {
  echo "== STEP 1: harvest (allowlist from measurement, not memory) =="
  cmd_check_p0a || exit 1
  info "run each supported agent on REAL work ~10 min first (Cursor: index a big repo)"
  "$PY" harvest.py | tee "$DATA_DIR/harvest_$(date +%Y%m%d_%H%M).txt"
  echo
  info "triage the domains into ai_endpoints.yaml, bump version off SEED-UNVERIFIED,"
  info "then run: ./accept.sh zero-red"
}

cmd_zero_red() {
  MIN=${1:-60}
  echo "== STEP 2: zero-red watch (${MIN} min per agent; keep sniffer running) =="
  grep -q SEED-UNVERIFIED ai_endpoints.yaml \
    && info "WARNING: allowlist still SEED-UNVERIFIED -- expect false reds until harvest is folded in"
  info "use your agents on real work now; watching..."
  if watch_py $((MIN * 60)) "zero-red"; then
    ok "GATE 2 PASS: zero red alerts in ${MIN} min (ambers are OK if sniffer was off)"
  else
    bad "GATE 2 FAIL: red alert(s) fired -- see $EVENTS; false positive => fix allowlist, real => working as intended"
    exit 1
  fi
}

cmd_curl_test() {
  echo "== STEP 3: end-to-end red path (needs sniffer running for domain resolution) =="
  cmd_check_p0a || exit 1
  F=${1:-/tmp/egress-test-50mb.bin}
  [ -f "$F" ] || { info "creating 50MB test file $F"; mkfile -n 50m "$F" 2>/dev/null || dd if=/dev/urandom of="$F" bs=1m count=50 2>/dev/null; }
  # ln -s, NOT cp. A *copied* system binary fails macOS code-signature validation
  # and is SIGKILLed on exec ("Killed: 9"), so this gate reported "nothing fired"
  # for a reason that had nothing to do with the sentinel. The symlink executes
  # the real signed binary while argv[0] still carries the agent token. Matches
  # the README procedure; they were out of sync until 2026-08-06.
  ln -sf "$(command -v curl)" /tmp/claude-egress-test
  trap 'rm -f /tmp/claude-egress-test' EXIT         # survives the exit-1 paths below
  info "watcher up (60s), then uploading at 3MB/s so the transfer spans multiple ticks"
  : > "$EVENTS.curl"; watch_py 60 "curl-test" > "$EVENTS.curl" 2>&1 &
  WPID=$!
  sleep 4
  /tmp/claude-egress-test --silent --show-error --limit-rate 3M -T "$F" https://transfer.sh/egress-test.bin \
    || info "upload errored (transfer.sh flaky?) -- try another target, e.g. -T to your own server"
  wait "$WPID"; RC=$?
  echo "---- watcher output ----"; cat "$EVENTS.curl"; echo "------------------------"
  if grep -q "RED   claude" "$EVENTS.curl"; then
    grep -q "likely non-AI: [a-z0-9.-]*transfer" "$EVENTS.curl" \
      && ok "GATE 3 PASS: red fired, destination is a DOMAIN (join works end-to-end)" \
      || { ok "GATE 3 PASS: red fired"; info "but destination not the expected domain -- check the RED line above"; }
  elif grep -q "AMBER claude" "$EVENTS.curl"; then
    bad "GATE 3 FAIL: stuck at amber (unresolved) -- SNI join dead: check sniffer iface + check-p0a"
    exit 1
  else
    bad "GATE 3 FAIL: nothing fired -- transfer too fast/failed? check upload actually ran, retry with a bigger file"
    exit 1
  fi
  rm -f /tmp/claude-egress-test
}

case "${1:-help}" in
  preflight)  cmd_preflight ;;
  sniffer)    cmd_sniffer ;;
  check-p0a)  cmd_check_p0a ;;
  harvest)    cmd_harvest ;;
  zero-red)   cmd_zero_red "${2:-60}" ;;
  curl-test)  cmd_curl_test "${2:-}" ;;
  calibrate)  cmd_calibrate "${2:-30}" ;;
  *) sed -n '2,16p' "$0" ;;
esac
