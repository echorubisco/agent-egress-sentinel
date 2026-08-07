# Show HN 正文草稿 · v1(2026-07-27)

叙事框按 FUNDING-MEMO §11.2 的结论:**不是**"防下一个 Grok"(窗口在关),而是
"agent 网络行为可观测"(窗口开着且被持续喂料)。开篇用 Ptacek 立威胁模型——把
"你在卖恐惧吗"这条头号质疑在第一段就关掉,且用的不是我们自己的话。

**2026-08-06 状态更新**:预注册已作废(见 LAUNCH-PREREGISTRATION.md 顶部判定),
本项目转为个人研究项目。所以「门没过不投」的理由从「预注册纪律」换成了
**错误指控是这里唯一会伤到用户的失效模式**——验收门仍然要跑,但它保护的是装了
这东西的人,不是一个实验的有效性。发布与否、什么时候发,不再由 §3 决定。

投稿前剩余项见 [PRE-FLIGHT.md](PRE-FLIGHT.md):一处 `YOUR-GITHUB-USER` 替换 +
三道验收门。`<form-link>` 已删除(README 改为 GitHub issue 链接)。

---

## 标题(候选,按推荐排序)

发现帖框,不是产品框。这不是文案偏好——三个独立模型都判定按安全产品发是当前证据支撑不了的,而工程发现是支撑得住的(依据见 ROADMAP「council」节)。

1. `Show HN: What I got wrong five times writing an egress monitor for AI coding agents`
2. `Show HN: Agent Egress Sentinel – measured recall, and the bugs that faked it`
3. `Egress monitoring for AI coding agents: recall turned out to be a function of connection lifetime`

推荐 1:主张是"我测了、我错了五次、这是数字",而不是"这个工具保护你"。它同时满足 Show HN 的要求(有可运行的仓库可以试)。候选 3 是非 Show HN 的普通提交,备用。

**不要用**旧的产品框标题(`see what your AI coding agents send out of your Mac`)——那是一个当前无法兑现的能力承诺:对快速 fan-out 的 recall 低至 5.8%(连接寿命 ~50ms 时)、阈值未校准、三道验收门未跑、且哨兵本身可被它监视的进程杀死。

---

## 正文

I spent a couple of weeks building a small macOS tool that watches what AI coding
agents send out of the machine, and most of what I learned is about how easy it is
to build a monitor that quietly measures nothing. Five times I had something that ran, produced plausible alerts, and was wrong. This is that list, with numbers, and
the code.

**Wrong #1: I attributed bytes and destinations at different granularities.** Byte
counts came per-process, hostnames came per-process, and I joined them. Every one of
these agents ships a telemetry SDK, so Claude Code uploading 6 MB of context to
`api.anthropic.com` while holding an idle `sentry.io` connection produced "claude
sent 6 MB to sentry.io." A false accusation on the main path, not an edge case.
Fixed by taking per-connection rows from `nettop` so bytes and destination come from
one measurement, and by splitting AI-endpoint bytes from the rest *within* a process.

**Wrong #2: my accounting threw away 94% of the bytes it was supposed to count.**
The rule was `delta = current − previous`, and a flow's first sighting was used only
to establish the baseline. A short connection is only ever seen once, so it
contributed zero. Measured on one machine over a 70-second window: of the outbound
bytes belonging to newly-opened flows, **94.2% were discarded, and 34 of 40 new
flows contributed literally nothing**. After the fix: 0.0%, all 54. A new connection
is now counted in full, with a warm-up tick so launching the app doesn't dump your
browser's existing sockets as fresh egress.

**Wrong #3: the detector for the shape I care about recorded nothing at all.**
Exfiltration is volume-shaped — one destination, many bytes — and my leaky-bucket
ledger handles that. Scanning is cardinality-shaped — forty destinations, two KB
each — so no bucket ever fills. I added a destination counter, then measured it:
25 distinct HTTPS destinations, every request succeeding, **0 destinations
recorded**. Same root cause as #2 — and then a second error that was mine rather
than the code's. I drove that run with a shell loop over `curl`: 25 separate
processes holding one destination each. The breadth counter is strictly per
process. That run could not have fired no matter how good the sampler was; it
measured my harness.

Re-run properly — one long-lived process, 57 distinct real destinations — the
counter works and fires. But the number I had already published as "48% recall at
1 s" turned out not to be a property of the sampler at all. Recall is set by how
long each connection stays open relative to the sampling interval, `min(1, L/T)`.
Holding the cadence at the shipped 1 s and controlling the lifetime directly:

| connection lifetime | predicted `L/T` | measured recall | fires at ≥20? |
|---|---|---|---|
| ~50 ms (open, send, close) | 5% | **5.8%** | no (0 of 3) |
| 300 ms | 30% | **36.8%** | yes |
| 500 ms | 50% | **54.4%** | yes |
| 1 s | 100% | **100.0%** | yes |
| 2 s | 100% | **100.0%** | yes |
| held open | 100% | **100.0%** | yes |

Same code, same machine, same 57 destinations; three different answers depending
only on how long the sockets stayed open. So 48% was the recall of *one workload*
(`curl`, TLS included, ~0.5 s per connection) and I'm withdrawing it as a general
figure. The consequence runs the wrong way for a defender: **the faster the
fan-out, the less of it I see** — and a scanner is fast. Raising the polling rate
does not fix a 50 ms window (at 0.5 s you still miss ~90% of it); that needs flow
open/close *events* — eBPF or a NetworkExtension — which I have not built. I do
ship the streaming `nettop` reader at 1 s, but the reason is cost, not recall: it
buys a 1 s cadence at a sixth of the CPU (1.8% vs 10.7% of a core).

**Wrong #4: my hostname parser was reading the server's certificate.** I was
grepping tcpdump's ASCII dump for anything hostname-shaped, on any TLS handshake
record. Replaying public Wireshark captures, one connection to example.com produced
33 records — including the certificate's SAN list and the CA's own URLs
(`crl4.digicert.com`, `cacerts.digicert.com`) — and because the IP→domain cache is
most-recent-wins, a later flow to that IP would have been labelled with the CA's
domain. I now parse the `server_name` extension bytes. Junk rate on those captures
went from 2 of 4 extracted records to 0 of 2 (small numbers; don't over-read them).

**Wrong #5: the noise filter I added deleted the only signal that module existed
for.** Late on I built the cross-check this post argues for: a second module that
reads a declaration log an agent writes (`{ts, pid, tool, target}`) and flags egress
with nothing declared behind it. To keep it quiet I gave it a floor — ignore
anything under 64 KB. A cross-vendor code review pointed out what that means. A
cloud credentials file is about 4 KB. An SSH private key is 2-3 KB. A token is a few
hundred bytes. The floor was blind by construction to the only payload class the
module was built to catch, and a passing test asserted that behaviour as correct, so
the bug was pinned in place by its own test suite. The floor is now conditional on
whether the destination has been seen before — no floor at all for a first-time
destination. The rule I took from it: **a noise control that discards, and a
detector that does not work, are indistinguishable from the outside.** That module
had ten such controls and every one of them was a `continue`.

One more I caught just before it shipped, which is the same mistake in different
clothes. The obvious volume rule is "reading a web page should not upload 5 MB", so
I added inbound byte counts to test the ratio. On this machine every agent flow is
upload-heavy by a wide margin — 19x, 26x, 199x, 201x out-to-in on real sessions --
because pushing context up and getting text back *is* the workload. Upload skew is
the baseline, not the anomaly, so an absolute ratio threshold would have fired
constantly. A relative one (deviation from that pair's own history) fails
differently: a bulk POST the user actually asked for is byte-for-byte
indistinguishable from exfiltration. Authorization is not a function of traffic
volume. Inbound bytes are printed in the alert text and used in no rule at all.
Incidentally the largest uploader on this machine is not an AI agent, it is the EDR
agent, at 128 MB.

And **the one I can't fix cheaply: anything it watches can kill it.** The app runs
as your user with no `launchd` job and no system extension — the same property that
makes it uninstall cleanly is why one `kill` ends it. A green icon is not evidence of
quiet; it's also what dead looks like. Silence is a signal now: the `sudo` sniffer
half cannot be killed by a user-level agent, so it watches the app's heartbeat and
shouts when it goes stale. Exactly how far that goes, and the test that pins the
forgeable case, are in the limits list below.

**One meta-note on those five.** My first two attempts to explain the third
failure were themselves wrong, and the second was embarrassing: I tested an
*egress* detector with *download* workloads (`npm install`, 25 GETs) and briefly
believed I'd found a sampling defect in `nettop`. A 300 KB download emits 518
bytes outbound. The tool was fine; my experiment wasn't. Every number above is
from a run I can point at, and the ones with tiny samples say so.

The threat model, briefly, since it's why I started: cereblab took apart Grok Build
CLI and found it uploading whole repositories — 5.1 GB to a cloud storage bucket
while the actual model call was 192 KB. Thomas Ptacek's read on the more recent
OpenAI-agent-breaches-Hugging-Face incident is the sharper framing:

> "I genuinely believe that if you took an open weights model from 2025 and built a
> pentest harness for it, it could do this kind of sandbox escape and scan/hack in
> most networks. This is only surprising because you assume OpenAI has sounder
> sandboxes."

That's deflationary, not alarmist — the capability is commodity; the wrong
assumption was that the containment was solid. Two honest notes on it: I don't know
why that incident went unnoticed (public reporting establishes a delay, not absent
telemetry, and one analysis argues the signal was drowned by concurrent benchmark
runs), and **my tool would not have caught it** — it identifies agents by matching a
token list against process command lines, and an internal eval harness matches
nothing. The incident is why I think the problem class matters. It is not a demo of
my program.

So, the thing itself: **Agent Egress Sentinel**, a menu-bar app that tells you where
your AI coding agents are sending bytes.

**Metadata only. No TLS decryption. No root certificate.** It reads per-process,
per-connection byte counts from `nettop`, and destination hostnames from the
cleartext SNI in the TLS ClientHello via `tcpdump`. It never sees a payload. The
whole trust ask is one `sudo` for BPF access — compare that with installing a root
CA so a proxy can read everything you do. It also logs its own update-check
connection, because a tool that watches egress should be in its own log.

Three states in the menu bar: 🟢 quiet · 🟡 something moved but I can't name the
destination · 🔴 an agent process pushed real volume to a destination that isn't a
known AI endpoint.

**And what it still can't do**, because I'd rather you hear it from me:

- It doesn't block anything. Ptacek's argument points at containment, and this is
  observation. Blocking on macOS means a NetworkExtension, which means becoming the
  hardest thing on your machine to uninstall, and that's a deliberate later step
  behind an explicit switch, not a silent upgrade.
- **Anything it watches can kill it — now at least noisily.** The menu-bar process
  runs as your user with no `launchd` job and no system extension, so one `kill` ends
  it. The `sudo` sniffer half can't be killed by a user-level agent, so it watches the
  app's heartbeat and shouts when it goes stale, and the app reports coverage gaps on
  restart. That covers a crash or a naive kill. It does **not** cover an adversary that
  keeps writing the heartbeat after killing the app — the file is user-owned, so
  anything running as you can forge it, and closing that needs a privileged helper I
  haven't built. There's a test asserting the forgeable case, so this doesn't get
  mistaken for tamper-proof.
- **"Per-agent" used to mean per-process** — an agent shelling out to `git`, `npm`,
  or `curl` produced traffic attributed to nobody. That's fixed: an unmatched
  process walks up its ancestors and the alert reads `claude via git`. Parent pids
  come from `libproc`, so it costs no forks. It will still miss an agent that runs
  as a bare `node` on a machine where reading argv is blocked.
- **A flow whose entire life falls between two samples never surfaces**, so recall
  is `min(1, L/T)` in the connection lifetime `L` — measured at the shipped 1 s
  cadence: 5.8% at ~50 ms, 36.8% at 300 ms, 54.4% at 500 ms, 100% at ≥1 s. That is
  a sampling limit, not an accounting one, and raising the rate does not close it:
  beating a 50 ms connection means flow events (eBPF), not a faster poll.
- **The shape with the widest blast radius in that Anthropic disclosure would have
  passed this tool on both axes.** Publishing one package to one registry, then
  exfiltrating one set of credentials, is a handful of destinations moving kilobytes —
  far under the 5 MB ledger burst and far under 20 distinct destinations. It still
  reached 15 machines, one of which was a security vendor's scanner that then had its
  own credentials taken and further infrastructure accessed. Volume and breadth are
  the two things this measures, and supply-chain publication is small on both.
- Bytes from connections already open when the app starts aren't counted. It reports
  egress from now on, not history.
- Scanning: the counter now records destinations, but bare SYN probes move ~0 bytes
  and never form a countable flow, and the threshold hasn't been calibrated against
  a real zero-false-positive run. Treat breadth as experimental.
- HTTP/3 over UDP 443 has no cleartext SNI, so QUIC-only traffic shows as amber:
  the volume is visible, the destination isn't nameable.
- Wildcard allowlist entries like `*.openai.azure.com` are multi-tenant. Anyone can
  stand up a tenant there, and at the metadata layer your Azure OpenAI and an
  attacker's look the same. This is a structural hole, not a TODO.
- Whether it would have caught the Grok upload that motivated this: the destination
  is correctly outside the allowlist, and after the accounting fix a single-sample
  70 MB chunk would clear the burst threshold — but 5.1 GB in 73 chunks is an
  average, not a distribution, and I haven't run it end to end. Likely, unverified,
  so I'm not claiming it.

**So why build the weak layer at all?** Because the strong layers all take the
model's word for something, and nothing checks them. That falls out of where the
boundary has to sit, not out of anyone's carelessness.

The separations we trust are enforced by a parse step: a prepared statement kills SQL
injection *as a class* because there is a grammar in which "instruction" is a
production. A prompt has no such step — instructions and data arrive as one token
stream and the model *infers* which is which, so every boundary we can hand it (roles,
special tokens, "treat everything below as data") is more tokens weighted more
heavily, not a mechanism that refuses. Nor can you cut the exposure out: being
steerable by text you did not write is the same property as being useful. Simon
Willison named this in 2022 and has called it structural ever since. The less
flattering analogy is the NX bit, which never ended code execution — it forced
attackers into ROP. Architecture raised the cost; it did not close the class.

What is new is that the whack-a-mole is now documented inside vendors' own disclosure
processes. Håkon Måløy's self-propagating Copilot for Word injection took 144 days to
coordinate with Microsoft, which mitigated the exact proof-of-concept prompt —
rewording it made the worm work again: *"Two mitigation attempts, including a model
upgrade, did not close the class."* His sharper line is the one to keep: *"Relying on
the model to detect XPIAs resembles asking an interpreter to execute an untrusted
program to determine whether that program is safe to execute."* Ten days later
Anthropic published the empirical version out of its own transcripts — 141,006
cyber-evaluation runs reviewed, three in which a Claude model reached the open
internet through a misconfigured range and compromised real production systems (no
escape: the path was open, not exploited). Building a malicious PyPI package for a
capture-the-flag, Mythos 5 judged that on the real internet this would be a real
attack — **"NOT okay, and surely not the intended solution"** — then reasoned its way
back out and never revisited it. It reached the *correct* judgement and the judgement
did not hold. **A self-report can be right and still not be a control.**

Måløy's conclusion is the sentence I would hang this on: *"The long-term challenge
likely lies in designing systems in which goals and intentions also exist
independently of the information being processed."* Databricks' Omnigent is the
clearest published attempt — bind a session to a declared purpose, gate every action
against it *"even when the agent's identity could perform it"* — and it catches
off-task drift that identity checks structurally cannot. But the anchor is a
**declaration**: fixed out-of-band it is a contract, emitted at runtime it is another
model output. An agent compromised *inside* its declared purpose passes every check.
Semantic richness and trustworthiness pull opposite ways — the closer a control sits
to the reasoning, the more it shares a failure domain with what it judges.

Which is the argument for a boring layer underneath. Byte counts and destination
hostnames come from the OS and the wire, not from the agent, so they cannot be
*narrated* — the cheapest available cross-check on a declared intent: **egress with no
corresponding declared purpose is a better exfiltration signal than either layer
alone.** There is a v0 of that check here (the module from Wrong #5), and it gets the
same bluntness as the rest: off unless an agent writes the declaration log, and
its false-positive rate is entirely unmeasured. There is now a Claude Code
`PreToolUse` hook that writes one, so the number is finally obtainable — but I
have not run it long enough to have it, and I would rather say that than publish
a rate I extrapolated from an afternoon.

It cuts against me too. "Assume attacker-controlled content will cause compromise at
some rate" argues for **containment** at least as much as for observation, and every
source above orders it that way — Anthropic's own remediation list validates
internet-access paths *before* the run and monitors second, though it does name
**network logs** alongside transcripts when it gets there. An unforgeable measurement
is also not an unforgeable measurer: anything running as you can kill this app. So the
claim is not "trust this instead" but "**if you're going to gate agents on declared
intent, something outside the agent should be counting the bytes**" — and this is a
4,100-line version of that something. Watching is still the cheapest layer here, not
the strongest one.


**The part I actually want help with.** `ai_endpoints.yaml` is the list of
endpoints a legitimate AI coding agent is expected to talk to. It's an
*allowlist*, which means a stale entry causes a false positive on a new legit
endpoint rather than a missed threat — maintaining it looks like maintaining the
public suffix list, not an antivirus signature database. Right now it's part
official-documentation (Kiro and GitHub Copilot both publish firewall allowlists)
and part harvested from my own captures. Every entry should have a source link.
If you use an agent that isn't covered, a PR with a source is worth more to this
than a star.

Repo (Apache-2.0, ~4,100 lines of Python plus ~3,300 of tests):
`https://github.com/YOUR-GITHUB-USER/agent-egress-sentinel`

It's rough on purpose — the thing I need is whether the alerts are *right*, and I
can only find that out on machines that aren't mine.

---

## 首评自评论(和正文同时发,防守位)

发帖后立刻自评一条,把最容易被当"gotcha"的三点先认掉:

> Author here — three things I expect to get asked:
>
> **"This is just Little Snitch with extra steps."** Mostly fair. Little Snitch
> goes through a NetworkExtension and gets OS-level process→domain attribution,
> which is strictly better ground truth than my `tcpdump` + `nettop` join. What it
> doesn't have is the semantic layer: *which* domains a given agent is supposed to
> talk to. That list is the actual artifact here; the app is a way to make the list
> testable.
>
> **"Detection without blocking is theater."** It's less than blocking, yes. I'm not
> going to claim it's the control the OpenAI incident was missing — I don't know what
> telemetry they had, and my tool wouldn't have matched their harness anyway. The
> narrower claim is in the post: the layers that *do* block are gating on declared
> intent or session policy, which are model-adjacent and therefore self-reported.
> Byte counts off the wire aren't. One `sudo` for BPF buys you the cross-check, and
> it costs less than a system extension in week one.
>
> **"Your SNI join is a heuristic."** Yes — shared front IPs (Cloudflare, GCP) mean
> the destination in a red alert says "likely." Post-quantum ClientHello
> fragmentation also breaks naive single-segment SNI parsing. Per-stream reassembly
> is implemented but opt-in, because it needs a wider capture — so the shipped
> default still misses a split ClientHello. That is a default I should probably
> flip before more people run this.

---

## 未决(投稿前)

- **first-sighting 抑制已修**(2026-07-27,见 ROADMAP)。新建 flow 丢失率 94.2%→0.0%,fanout 计账 0/10→11/12。正文第三条已按"找到并修好 + 剩余边界"重写。
- **阈值未校准**:`MIN_DESTS=20` 不对应单一真实目的地数。触发条件是 `真实目的地数 × min(1, L/T) ≥ 20`,所以随连接寿命变化:≥1s→~20、500ms→~37、300ms→~54、50ms→~345。此前写的「约 40+(可见性 ~48%)」依赖已作废的常数假设,已撤回。**口径再修一次(8-01)**:上述数字不等于「对扫描无用」——Anthropic 7-30 披露里一次 run 扫了约 9,000 个目标,按最差 recall 也是阈值的 ~26 倍;真正的盲区是**小规模(22–50 台)**。限定:该报告未说明那些探测是否带载荷,裸 SYN 在任何量级都不可见;且 n=1。**拒绝按一台空闲机器调参**——校准是"每 agent 1h 零红"验收门的事。若那道门跑出的良性上限远低于 20,再下调。
- **fanout 仍默认启用**且会发 amber。文档已说明它未校准;若要更保守则改为默认关闭(未做)。
- **PQ ClientHello 分片重组已实现,但 opt-in**(`SENTINEL_REASSEMBLE`,默认关闭,理由是宽捕获成本)。原写的"补丁未实现"**已过期并更正**;首评措辞改为 "implemented but opt-in, shipped default still misses it"。**待定:默认是否翻成开启**——不翻的话,正文那句"destination hostnames from the cleartext SNI"在 PQ 握手上就有一个静默缺口。
- ~~缺 LICENSE 文件~~ **已补(08-06)**。此前 README 与本文都写着 Apache-2.0 而仓库里没有该文件。
- 三道验收门仍未跑。**理由已换**(见顶部状态更新):不是预注册纪律,是错误指控会伤到装了它的人。
  另:`accept.sh` 的 gate 3 一直在用 `cp $(command -v curl)` 造测试二进制,而 README 自己写明
  **拷贝的系统二进制会被 macOS 签名校验 SIGKILL**——也就是说这道门在 08-06 之前**跑了也是无效结果**
  ("nothing fired" 的原因与哨兵无关)。已改为 `ln -sf`。**在此之前跑过这道门的结论一律作废。**
- ~~预注册 §3 触达前置~~ **整个 §3 已作废**(08-06 判定)。发布不再产生任何判决。
- 占位符:`<form-link>` 已删除(README 改用 GitHub relative issue 链接,不需要绝对 URL);
  `<repo-url>` 与 `update_ping.py` 的 endpoint 合并为**同一个** `YOUR-GITHUB-USER` token,
  一条 sed 替换,见 [PRE-FLIGHT.md](PRE-FLIGHT.md) §1。
- **对账层第一次有了生产者**(08-06):`hooks/claude_code_declare.py`,一个 Claude Code
  `PreToolUse` hook。它把「误报率完全未知」从**不可测**变成**没测**——这是本仓库现在
  最大的单项未知,而它比再跑一轮验收门便宜。正文与首评已相应改口,**没有**填任何数字。
