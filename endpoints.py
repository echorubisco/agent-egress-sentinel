#!/usr/bin/env python3
"""
Loads the AI-endpoint allowlist from ai_endpoints.yaml.

Two match kinds:
  - exact hostnames (api.anthropic.com)
  - constrained patterns: a single '*' matching EXACTLY ONE dns label, for
    endpoints that cannot be enumerated (Azure OpenAI customer subdomains,
    Bedrock/Vertex region-rotating hosts). '*' never spans dots, so the
    allowlist stays tight and the signal isn't diluted.

Zero-friction: works without PyYAML (fallback line parser), falls back to a
built-in set if the file is unreadable. Hot-reloads on file mtime change so a
user's "add one domain" edit takes effect without restart.
"""

import pathlib
import re
import time

_HERE = pathlib.Path(__file__).resolve().parent
_YAML = _HERE / "ai_endpoints.yaml"

_FALLBACK_EXACT = {
    "api.anthropic.com", "api.openai.com", "api.chatgpt.com", "api.x.ai",
    "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
    "api.githubcopilot.com", "copilot-proxy.githubusercontent.com",
    "api.cursor.sh", "api2.cursor.sh",
}

_EXACT_RE = re.compile(r"^\s*-\s*([a-z0-9][a-z0-9.\-]+\.[a-z]{2,})\s*(?:#.*)?$")
_PATTERN_RE = re.compile(r"^\s*-\s*([a-z0-9.\-]*\*[a-z0-9.\-]*\.[a-z]{2,})\s*(?:#.*)?$")

# Agent detection content also lives in the manifest (governed + hot-reloaded).
# This is the fallback when the file / pyyaml is unavailable. kiro/windsurf are
# here because a sentinel that misses its own author's agent is worthless.
_FALLBACK_AGENT_TOKENS = {"claude", "cursor", "codex", "aider", "grok", "gemini",
                          "copilot", "cline", "kiro", "windsurf"}
_FALLBACK_CONFUSABLES = {"ngrok"}   # 'ngrok http ...' contains the 'grok' token


def _parse_agents(text: str):
    """agents.tokens / agents.confusables from the manifest. pyyaml if present,
    else a tolerant line scan (inline [a, b] or block '- a')."""
    try:
        import yaml
        ag = (yaml.safe_load(text) or {}).get("agents") or {}
        toks = {str(t).strip().lower() for t in (ag.get("tokens") or []) if str(t).strip()}
        conf = {str(t).strip().lower() for t in (ag.get("confusables") or []) if str(t).strip()}
        if toks:
            return toks, (conf or set(_FALLBACK_CONFUSABLES))
    except Exception:
        pass
    toks, conf, section, in_agents = set(), set(), None, False
    for raw in text.splitlines():
        if re.match(r"^agents:\s*$", raw):
            in_agents = True; continue
        if in_agents and re.match(r"^\S", raw):
            break
        if not in_agents:
            continue
        m = re.match(r"^\s+(tokens|confusables):\s*(\[[^\]]*\])?\s*$", raw)
        if m:
            section = m.group(1)
            if m.group(2):
                items = [x.strip().strip("\"'").lower()
                         for x in m.group(2)[1:-1].split(",")]
                (toks if section == "tokens" else conf).update(i for i in items if i)
                section = None
            continue
        li = re.match(r"^\s+-\s*([A-Za-z0-9_\-]+)", raw)
        if li and section:
            (toks if section == "tokens" else conf).add(li.group(1).lower())
    return (toks or set(_FALLBACK_AGENT_TOKENS)), (conf or set(_FALLBACK_CONFUSABLES))


def _pattern_to_regex(pat: str):
    # '*' -> exactly one dns label (no dots)
    parts = [re.escape(p) for p in pat.split("*")]
    return re.compile("^" + "[^.]+".join(parts) + "$")


def _parse_with_pyyaml(text: str):
    import yaml
    data = yaml.safe_load(text) or {}
    exact, patterns = set(), []
    for _prov, hosts in (data.get("providers") or {}).items():
        for h in hosts or []:
            h = str(h).strip().lower()
            (patterns.append(h) if "*" in h else exact.add(h))
    for p in (data.get("patterns") or []):
        patterns.append(str(p).strip().lower())
    return exact, patterns


def _parse_lines(text: str):
    exact, patterns = set(), []
    for line in text.splitlines():
        pm = _PATTERN_RE.match(line)
        if pm:
            patterns.append(pm.group(1).lower()); continue
        em = _EXACT_RE.match(line)
        if em:
            exact.add(em.group(1).lower())
    return exact, patterns


class Allowlist:
    def __init__(self):
        self._mtime = 0
        self._exact = set()
        self._patterns = []
        self._agent_tokens = set(_FALLBACK_AGENT_TOKENS)
        self._confusables = set(_FALLBACK_CONFUSABLES)
        self.reload(force=True)

    def reload(self, force=False):
        try:
            mtime = _YAML.stat().st_mtime
        except OSError:
            if not self._exact:
                self._exact = set(_FALLBACK_EXACT)
            return
        if not force and mtime == self._mtime:
            return
        self._mtime = mtime
        try:
            text = _YAML.read_text()
            try:
                exact, patterns = _parse_with_pyyaml(text)
            except Exception:
                exact, patterns = _parse_lines(text)
            agent_tokens, confusables = _parse_agents(text)
        except Exception:
            exact, patterns = set(_FALLBACK_EXACT), []
            agent_tokens = set(_FALLBACK_AGENT_TOKENS)
            confusables = set(_FALLBACK_CONFUSABLES)
        self._exact = exact or set(_FALLBACK_EXACT)
        self._patterns = [(_pattern_to_regex(p), p) for p in patterns]
        self._agent_tokens = agent_tokens
        self._confusables = confusables

    def matches(self, domain: str) -> bool:
        # cheap hot-reload check (stat once per call is fine at our tick rate)
        self.reload()
        d = (domain or "").lower()
        if d in self._exact:
            return True
        return any(rx.match(d) for rx, _ in self._patterns)

    def summary(self):
        return len(self._exact), len(self._patterns)

    def agent_tokens(self):
        self.reload()
        return self._agent_tokens

    def confusables(self):
        self.reload()
        return self._confusables


# backward-compatible convenience
def load_allowlist():
    a = Allowlist()
    return a._exact | {p for _, p in a._patterns}


if __name__ == "__main__":
    a = Allowlist()
    ne, npat = a.summary()
    print(f"{ne} exact + {npat} pattern endpoints")
    for d in sorted(a._exact):
        print("  exact  ", d)
    for _, p in a._patterns:
        print("  pattern", p)
    # quick self-test of pattern matching
    for probe in ("myco.openai.azure.com", "bedrock-runtime.us-east-1.amazonaws.com",
                  "evil.com", "a.b.openai.azure.com"):
        print(f"  match? {probe:45} -> {a.matches(probe)}")
