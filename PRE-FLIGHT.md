# PRE-FLIGHT

_Last swept 2026-08-06. One page, because the checklist used to live in four
(LAUNCH-PREREGISTRATION §7, SHOW-HN-DRAFT 未决, ai_endpoints.yaml header,
README "before you ship"), which is how the `cp`/`ln -s` mismatch below survived
for a week in a repo that has a section about not shipping broken checks._

The framing changed on 2026-08-06: this is a personal research project, not a
startup validation run. [LAUNCH-PREREGISTRATION.md](LAUNCH-PREREGISTRATION.md)
is superseded and its §3 verdict machinery is void. **What survives is only the
list below, and only for one reason: a false accusation is the only failure mode
here that damages a user.** Everything else can be fixed after publishing.

---

## 1. One substitution before the repo goes public

```bash
grep -rl 'YOUR-GITHUB-USER' . | xargs sed -i '' 's|YOUR-GITHUB-USER|<your-gh-handle>|g'
```

That is the whole set. `update_ping.py` derives its URL from it, and the README's
contact link is a GitHub-relative `../../issues/new`, so nothing else needs an
absolute URL. (Drop the `''` after `-i` on GNU sed.)

---

## 2. Gates — none have been run

They need a Mac (`nettop`, `tcpdump`) with the agents actually installed. They
have never been executed. That is the honest status and it should stay written
down until it changes.

| # | Gate | Command | Status | What it protects |
|---|---|---|---|---|
| 1 | Harvest the allowlist from measurement | `./accept.sh harvest` | ❌ not run | `ai_endpoints.yaml` still says `SEED-UNVERIFIED` — the seed list is **from memory**. Known trap: Cursor's codebase indexing is the largest legit AI flow on a dev Mac and is more than `api2.cursor.sh`. Miss it and every Cursor user's first index fires a hero false positive |
| 2 | One hour per agent → zero red | `./accept.sh zero-red 60` | ❌ not run | The only failure mode that hurts a user: accusing their agent of exfiltration when it did its job |
| 3 | End-to-end red path | `./accept.sh curl-test` | ❌ not run | That the product's one output — a red alert naming a process and a domain — works at all |
| — | Breadth calibration | `./accept.sh calibrate 30` | ❌ not run | `MIN_DESTS=20` is a guess. It is amber-only, so this is informational, not blocking |

**Gate 3 could not have passed before 2026-08-06.** `accept.sh` built its test
binary with `cp $(command -v curl)`, and a copied system binary fails macOS
code-signature validation and is SIGKILLed on exec — the README said so and the
script did the other thing. It would have reported "nothing fired" for a reason
with no connection to the sentinel. Now `ln -sf`. Anyone who ran the gate before
today got a meaningless result.

Order: 1 → 2 → 3. Gate 2 against an unharvested allowlist just measures the
allowlist.

---

## 3. The one number worth more than the gates

**The reconciler has never seen real traffic.** It is the only check in this repo
that is not a threshold — it asks "did anything declare this?" instead of "is
this unusual?" — and its false-positive rate is completely unmeasured, because
until 2026-08-06 nothing wrote the declaration contract.

There is now a producer: [`hooks/claude_code_declare.py`](hooks/claude_code_declare.py).
Install it (instructions in its docstring and in the README), run an ordinary
working session, and read the ambers. The enumerable false-positive sources are
already listed — OS telemetry, package managers, editor sync, CDN redirect
chains, connection reuse — so the output is a subtractable list, not a mystery.

This is cheaper than the gates and answers a bigger question. It is also the
only way to find out whether the "checklist model" idea works at all, as opposed
to being an argument that sounds right.

Caveats, so the first number is read correctly:

- The hook declares **no `bytes`** (outbound size is unknown before the call), so
  the volume sub-check is skipped and only presence matching is exercised.
- Only `WebFetch` and `Bash` are covered, and only when a host is parseable from
  the command. Everything else declares nothing **on purpose** — a declaration
  with no target is a wildcard that silences the pid.
- Novelty baselines reset per run, so the first two minutes after a restart are
  quiet by design.

---

## 4. Known-unverified, carried forward

- `ai_endpoints.yaml` version is `SEED-UNVERIFIED`. Gate 1 is what clears it.
- PQ ClientHello reassembly (`SENTINEL_REASSEMBLE=1`) is implemented but **off by
  default** because it requires capturing all outbound 443 and hex-dumping it
  (measured 3.1–3.4× amplification). So the shipped default silently misses a
  split ClientHello. Undecided whether to flip it.
- Breadth (`fanout`) is on by default and uncalibrated. Amber only.
- SIGSTOP-and-resume inside the 15 s dead-man window, and the sibling-process
  confused deputy, are documented and not closable at this privilege level.
- **The Windows port is half-built and its half is live-verified.** As of
  2026-08-06 the suite is **19 of 19 files, 268 assertions, green on Windows**
  (was 3 of 13 — ten of those were a single `import pwd` in `paths.py`, the last
  was `tcpdump -r`). Byte counts work: `wincapture.py` reads ETW and was verified
  against a real 20 s elevated capture. Offline pcap replay runs anywhere.
  **Still missing: live hostname capture** — no SNI source on Windows, so a
  Windows run would resolve no domains and could only ever produce amber
  "unresolved", never a red alert. That is the safe direction, but it means the
  app is not usable there yet. See [PLATFORMS.md](PLATFORMS.md).
- The ETW work retired one macOS-specific claim and should be read alongside the
  recall table in the README: `min(1, L/T)` is a property of `nettop` sampling,
  **not of metadata-layer observation**. Measured on Windows, 361 short-lived
  connections observed against 301 made.

---

## 5. Cleared on 2026-08-06

- `LICENSE` added. README and the writeup both claimed Apache-2.0 against no
  license file.
- `accept.sh` gate 3 `cp` → `ln -sf` (see §2), with cleanup that survives the
  failure paths.
- The withdrawn **48%** recall constant removed from the two places code still
  taught it as fact: `accept.sh calibrate`'s "N observed ≈ 2N real" advice and
  `sentinel.py`'s `TICK_SEC` comment. Docs withdrew it on 07-30; the code had
  been repeating it for a week. Replaced with `min(1, L/T)` and the measured
  points. The cadence table is kept and relabelled cadence-to-cadence only.
- `update_ping.py` repointed from an unbuilt Cloudflare Worker to a static
  `version.json` in this repo. The unique-IP install count it existed for was an
  instrument of the superseded demand experiment; the endpoint that would have
  collected it is gone rather than unbuilt.
- Placeholders `<your-form-link>`, `<your-worker>` and `<repo-url>` are gone.
  What used to be four independent tokens is now one, `YOUR-GITHUB-USER`, in two
  functional places (`update_ping.py`, the writeup's repo line) — see §1.
- Line counts in README/writeup corrected (~4,100 Python + ~3,300 tests, was
  "~2,600 plus ~2,200").
