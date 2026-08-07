#!/usr/bin/env python3
"""
Read the XML that etw_probe.py produced and answer the four questions in its
header. Prints a verdict, not a dump.

Normally you do not run this yourself -- `python tools/etw_probe.py` invokes it
with the right arguments. It is a separate file so a trace can be re-examined
without re-capturing, and so this parsing is testable without elevation.

The verdict that matters is Q1+Q3 together: **can one event tell us "this pid
sent N bytes to this remote address", and does a 50 ms connection produce one?**
If yes, a Windows build is event-driven and the `min(1, L/T)` recall bound that
defines the macOS build does not apply to it -- which is the claim PLATFORMS.md
§3 makes on documentation alone and this is here to settle.

If no, say so loudly. A Windows port that inherits the same sampling blind spot
is a much less interesting project, and finding that out costs two minutes here
versus a week of writing a consumer.

    python tools/etw_probe_summarize.py <probe.xml> [--probe-pid N]

Parsed with iterparse: a 30-second kernel-network trace is routinely hundreds of
MB of XML and will not fit in memory as a tree.
"""

import argparse
import collections
import re
import sys
import xml.etree.ElementTree as ET

# tracerpt namespaces every element; matching on the local name avoids hardcoding
# a schema URL that differs across Windows builds.
_LOCAL = re.compile(r"\{.*\}")

# Field names the Kernel-Network manifest is documented to use. Spellings differ
# across builds, so each concept gets a set of candidates and we report which one
# actually appeared -- guessing one name and finding nothing is exactly the
# "silently measured zero" failure this repo keeps hitting.
FIELDS = {
    "pid":    ("PID", "ProcessId", "ProcessID"),
    "size":   ("size", "Size", "NumBytes", "dataLength"),
    "daddr":  ("daddr", "DestAddr", "DestinationAddress", "saddr_v6", "daddr_v6"),
    "dport":  ("dport", "DestPort", "DestinationPort"),
    "saddr":  ("saddr", "SourceAddress"),
    "sport":  ("sport", "SourcePort"),
    # Present on ~98% of events, and MEASURED CONSTANT AT 0 on Windows 11
    # (2026-08-06). The name promises a per-connection identifier and the field
    # does not deliver one. Kept only so its cardinality can be reported and the
    # degeneracy called out -- see the guard in main(). Never use it as a key
    # without checking how many distinct values it actually takes.
    "connid": ("connid", "ConnId", "ConnectionId"),
}


def local(tag):
    return _LOCAL.sub("", tag or "")


def events(path):
    """Yield (task_or_opcode, {field: value}) per event, streaming.

    `elem.clear()` alone is not enough: the cleared Event elements stay attached
    to the root, so the tree still grows to the size of the file. Clearing the
    root's accumulated children each time is what makes this bounded, which
    matters because a 30 s kernel-network trace decodes to hundreds of MB.
    """
    context = ET.iterparse(path, events=("start", "end"))
    root = None
    for ev, elem in context:
        if root is None:
            root = elem                        # first start event is the root
            continue
        if ev != "end" or local(elem.tag) != "Event":
            continue
        name, data = None, {}
        for child in elem:
            lt = local(child.tag)
            if lt == "System":
                for s in child:
                    ls = local(s.tag)
                    if ls in ("Task", "Opcode", "EventID"):
                        name = f"{name or ''}{'/' if name else ''}{ls}={s.text or s.get('Name', '')}"
                    if ls == "Execution":
                        data.setdefault("_sys_pid", s.get("ProcessID"))
            elif lt in ("EventData", "UserData"):
                for d in child.iter():
                    n = d.get("Name")
                    if n and d.text is not None:
                        data[n] = d.text
                    elif local(d.tag) not in ("EventData", "UserData") and d.text:
                        data[local(d.tag)] = d.text
        yield name or "?", data
        elem.clear()
        root.clear()                           # drop the finished siblings too


def pick(data, names):
    for n in names:
        if n in data:
            return n, data[n]
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("xml")
    ap.add_argument("--probe-pid", type=int, default=None,
                    help="the probe's own pid; its connections were "
                         "deliberately short-lived (Q3)")
    ap.add_argument("--generated", type=int, default=None,
                    help="how many short-lived connections the probe actually "
                         "completed -- the ground truth Q3 is measured against")
    args = ap.parse_args()

    total = 0
    by_task = collections.Counter()
    seen_fields = collections.Counter()
    resolved = collections.Counter()          # which candidate name was found
    complete = 0                              # events carrying pid+size+daddr
    probe_flows, probe_bytes = set(), 0
    probe_conns = set()                       # distinct connid -- degenerate, see below
    probe_keys = set()                        # distinct 4-tuple -- the Q3 measure
    sample = None

    for name, data in events(args.xml):
        total += 1
        by_task[name] += 1
        for k in data:
            if not k.startswith("_"):
                seen_fields[k] += 1
        got = {}
        for concept, names in FIELDS.items():
            found, val = pick(data, names)
            if found:
                resolved[f"{concept}={found}"] += 1
                got[concept] = val
        if "pid" in got and "size" in got and "daddr" in got:
            complete += 1
            if sample is None:
                sample = dict(got, _event=name)
            if args.probe_pid is not None:
                try:
                    if int(got["pid"]) == args.probe_pid:
                        probe_flows.add((got.get("daddr"), got.get("dport")))
                        probe_bytes += int(got["size"])
                        if got.get("connid") is not None:
                            probe_conns.add(got["connid"])
                        # The standard 4-tuple. The local ephemeral port is what
                        # actually distinguishes one short connection from the
                        # next; `connid` claims to and does not.
                        probe_keys.add((got.get("saddr"), got.get("sport"),
                                        got.get("daddr"), got.get("dport")))
                except (TypeError, ValueError):
                    pass

    if not total:
        print("NO EVENTS PARSED. Either the trace was empty or tracerpt wrote a "
              "shape this does not understand. Check the XML by hand before "
              "concluding anything -- 'zero events' and 'parser does not match' "
              "are the same output, which is the failure mode this repo is about.")
        return 2

    print(f"events parsed              : {total:,}")
    print(f"events with pid+size+daddr : {complete:,}  "
          f"({100.0 * complete / total:.1f}%)")
    print()
    print("top event types")
    for k, v in by_task.most_common(8):
        print(f"  {v:>9,}  {k}")
    print()
    print("field names actually present (top 15)")
    for k, v in seen_fields.most_common(15):
        print(f"  {v:>9,}  {k}")
    if resolved:
        print()
        print("concept -> field name resolved to")
        for k, v in sorted(resolved.items()):
            print(f"  {v:>9,}  {k}")
    if sample:
        print()
        print(f"sample complete event ({sample.pop('_event')})")
        for k, v in sample.items():
            print(f"    {k:<6} = {v}")

    print()
    print("=" * 66)
    q1 = complete > 0
    print(f"Q1  one event carries pid + bytes + remote address : "
          f"{'YES' if q1 else 'NO'}")
    if not q1:
        print("      -> the fields live on different events and must be joined;")
        print("         that is a different (harder) design than nettop's rows.")

    # Q3, and why it is counted THIS way.
    #
    # The first version of this check asked "did the probe's destinations show
    # up?" and answered YES on 3 distinct remotes -- from 210 connections, i.e.
    # ~70 hits per destination. A SAMPLER would also have found all three. The
    # check passed for a reason unrelated to what it claimed to test, which is
    # this project's own Wrong #3 (a run that measured its harness) committed
    # inside the tool built to avoid it.
    #
    # The second version keyed on `connid` -- exact ground truth, fails loudly.
    # It reported 1 seen / 220 made = 0% and printed "NOT SUPPORTED, this looks
    # sampled, PLATFORMS.md is wrong". It was wrong, and worse than the first
    # error, because a confident false negative would have killed a correct
    # design decision. `connid` IS PRESENT ON 98% OF EVENTS AND CONSTANT AT 0 --
    # the set had one element because the field is not populated, not because
    # connections were missed. A field named like an identifier is not one.
    #
    # Third version: the standard 4-tuple (saddr, sport, daddr, dport). The local
    # ephemeral port is what actually differs between consecutive short
    # connections. Expect MORE tuples than requests -- DNS lookups and redirects
    # are connections too -- so this is a floor test, not an equality test.
    #
    # The general rule, which is the only durable thing to come out of three
    # wrong versions: BEFORE KEYING ON A FIELD, COUNT ITS DISTINCT VALUES. A
    # degenerate key turns "we observed nothing" and "we cannot tell them apart"
    # into the same output, which is this repo's recurring failure shape wearing
    # yet another hat. The cardinality line below exists so the next person does
    # not have to rediscover it from a sample event.
    if args.probe_pid is None:
        print("Q3  (skipped -- pass --probe-pid to test short-lived recall)")
    elif not probe_keys:
        print("Q3  short-lived connection recall                  : UNANSWERABLE")
        print("      -> no events at all from the probe pid. Check the connection")
        print("         count the probe printed before concluding anything about")
        print("         the provider -- zero traffic reads identically here.")
    elif args.generated is None:
        print(f"Q3  distinct connections seen from probe pid       : "
              f"{len(probe_keys)}  (no ground truth -- pass --generated N)")
    else:
        seen, made = len(probe_keys), args.generated
        ratio = (seen / made) if made else 0.0
        print(f"Q3  short-lived connection recall                  : "
              f"{seen} seen / {made} made = {ratio:.0%}")
        print(f"      keyed on (saddr,sport,daddr,dport); "
              f"{len(probe_flows)} distinct remotes, {probe_bytes:,} bytes")
        # Cardinality of every candidate key, so a degenerate one is visible
        # rather than silently producing a confident verdict. connid=1 here is
        # what the second version of this check tripped over.
        print(f"      key cardinality: 4-tuple={len(probe_keys)} "
              f"connid={len(probe_conns)} remotes={len(probe_flows)}")
        if len(probe_conns) <= 1 < seen:
            print("      NOTE: connid is constant -> not a connection id on this")
            print("            provider. Do not key a consumer on it.")
        if ratio >= 0.95:
            print("      -> EVENT-DRIVEN. min(1, L/T) does not bound this source:")
            print("         short connections are not being missed. PLATFORMS.md")
            print("         section 3 holds, and a Windows build would be")
            print("         better-instrumented than the macOS one.")
        elif ratio >= 0.5:
            print("      -> PARTIAL. Better than the macOS sampler at this")
            print("         lifetime, but something is dropping connections.")
            print("         Find out what before writing the consumer.")
        else:
            print("      -> NOT SUPPORTED. This looks sampled, not event-driven.")
            print("         PLATFORMS.md section 3 is wrong; fix the document")
            print("         before writing any code that depends on it.")
    print("=" * 66)
    return 0


if __name__ == "__main__":
    sys.exit(main())
