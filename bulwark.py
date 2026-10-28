#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bulwark 1.0.0 - read-only Linux incident response and threat detection.

Single-file build: the entire tool in one readable source file.

    sudo python3 bulwark-standalone.py quick     fast triage
    sudo python3 bulwark-standalone.py audit     full assessment
    sudo python3 bulwark-standalone.py snap      record the accepted state
    sudo python3 bulwark-standalone.py check     what changed since then
    python3 bulwark-standalone.py --help         everything else

This file is GENERATED from the bulwark/ package by tools/build_single_py.py.
Do not edit it directly: edit the package and rebuild, or your changes are
lost on the next build and the tests no longer cover what you are running.

Read-only by design. It does not modify the system, and it never executes a
file it discovers during an assessment.

Contents, in order:

   1. bulwark/__init__.py                        version and tool constants
   2. bulwark/models.py                          findings, evidence, module results
   3. bulwark/redact.py                          secret redaction
   4. bulwark/indicators.py                      deterministic indicator patterns
   5. bulwark/host.py                            safe file and command access layer
   6. bulwark/config.py                          configuration and platform detection
   7. bulwark/settings.py                        config file and environment resolution
   8. bulwark/store.py                           evidence directories
   9. bulwark/detection/base.py                  detection module interface
  10. bulwark/detection/accounts.py              detection: accounts and privilege
  11. bulwark/detection/ssh.py                   detection: SSH and remote access
  12. bulwark/detection/persistence.py           detection: persistence mechanisms
  13. bulwark/detection/processes.py             detection: processes
  14. bulwark/detection/network.py               detection: network exposure
  15. bulwark/detection/filesystem.py            detection: filesystem integrity
  16. bulwark/detection/logs.py                  detection: logs and authentication
  17. bulwark/detection/packages.py              detection: package integrity
  18. bulwark/detection/security_controls.py     detection: defensive controls
  19. bulwark/detection/__init__.py              detection module registry
  20. bulwark/engine.py                          audit orchestration and exit codes
  21. bulwark/baseline/create.py                 baseline capture
  22. bulwark/baseline/compare.py                baseline comparison
  23. bulwark/baseline/__init__.py               baseline package exports
  24. bulwark/reporting/json_report.py           reporting: structured JSON
  25. bulwark/reporting/markdown_report.py       reporting: Markdown
  26. bulwark/reporting/terminal.py              reporting: terminal summary
  27. bulwark/reporting/__init__.py              reporting package exports
  28. bulwark/investigate.py                     deeper evidence collection
  29. bulwark/cli.py                             command-line interface
"""


from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as _dt
import enum
import errno
import grp
import hashlib
import ipaddress
import json
import os
import platform
import pwd
import re
import shlex
import shutil
import socket
import stat as statmod
import struct
import subprocess
import sys
import time

from collections import defaultdict
from dataclasses import dataclass
from dataclasses import dataclass, field
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional
from typing import Any, Dict, List, Optional
from typing import Any, Dict, List, Optional, Tuple
from typing import Any, Dict, Optional
from typing import Dict, Iterable, List, Optional, Tuple
from typing import Dict, List
from typing import Dict, List, Optional, Tuple
from typing import Dict, List, Tuple
from typing import Dict, Optional
from typing import List, Optional
from typing import List, Optional, TextIO
from typing import List, Tuple
from typing import Tuple



# ============================================================================
# bulwark/__init__.py
# version and tool constants
# ============================================================================

# Bulwark - Linux incident response and threat detection toolkit for CCDC blue teams.
#
# Read-only by design. The first release discovers, investigates, prioritizes and
# verifies; it never remediates. See README.md for scope and limitations.

__version__ = "1.0.0"
__schema_version__ = "1.0"

TOOL_NAME = "bulwark"



# ============================================================================
# bulwark/models.py
# findings, evidence, module results
# ============================================================================

# Core data model: findings, evidence, module results.
#
# Every detection module emits Findings through this model rather than printing.
# Finding IDs are deterministic (derived from module + rule + target) so that the
# same issue keeps the same ID across runs, which is what makes
# `bulwark look ID` and baseline diffing possible.




def utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def iso(ts: Optional[_dt.datetime]) -> Optional[str]:
    """UTC ISO-8601 with explicit Z suffix. All machine-readable times use this."""
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    return ts.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_from_epoch(epoch: Optional[float]) -> Optional[str]:
    if epoch is None:
        return None
    try:
        return iso(_dt.datetime.fromtimestamp(float(epoch), _dt.timezone.utc))
    except (OverflowError, OSError, ValueError):
        return None


class Severity(enum.Enum):
    CRITICAL = ("critical", 4)
    HIGH = ("high", 3)
    MEDIUM = ("medium", 2)
    LOW = ("low", 1)
    INFO = ("info", 0)

    def __init__(self, label: str, rank: int):
        self.label = label
        self.rank = rank

    def __str__(self) -> str:
        return self.label

    @classmethod
    def from_label(cls, label: str) -> "Severity":
        for member in cls:
            if member.label == str(label).lower():
                return member
        raise ValueError(f"unknown severity: {label!r}")


class Confidence(enum.Enum):
    """How strongly the evidence supports the finding.

    Deliberately independent of Severity: an unauthorized root account found
    only via a timestamp heuristic is CRITICAL severity with LOW confidence.
    """

    HIGH = ("high", 3)
    MEDIUM = ("medium", 2)
    LOW = ("low", 1)

    def __init__(self, label: str, rank: int):
        self.label = label
        self.rank = rank

    def __str__(self) -> str:
        return self.label

    @classmethod
    def from_label(cls, label: str) -> "Confidence":
        for member in cls:
            if member.label == str(label).lower():
                return member
        raise ValueError(f"unknown confidence: {label!r}")


class Category(enum.Enum):
    ACCOUNT = "account"
    PRIVESC = "privilege-escalation"
    AUTHENTICATION = "authentication"
    REMOTE_ACCESS = "remote-access"
    PERSISTENCE = "persistence"
    PROCESS = "process"
    NETWORK = "network"
    INTEGRITY = "integrity"
    PACKAGE = "package"
    POSTURE = "security-posture"
    LOGGING = "logging"

    def __str__(self) -> str:
        return self.value


class BaselineState(enum.Enum):
    """Relationship of a finding to a saved baseline."""

    NO_BASELINE = "no-baseline"   # nothing to compare against
    NEW = "new"                   # not present in baseline
    KNOWN = "known"               # present in baseline, unchanged
    CHANGED = "changed"           # present in baseline but altered

    def __str__(self) -> str:
        return self.value


class ModuleStatus(enum.Enum):
    OK = "ok"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"

    def __str__(self) -> str:
        return self.value


@dataclass
class Evidence:
    """One piece of supporting material behind a finding.

    `content` is always passed through the redactor before storage. Evidence is
    untrusted system-derived text; it is stored and displayed, never executed
    and never interpreted as instructions.
    """

    source: str                    # "file", "command", "proc", "log", "derived"
    locator: str                   # path, argv string, /proc entry, log file
    content: str = ""
    collected_at: str = field(default_factory=lambda: iso(utc_now()))
    truncated: bool = False
    error: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VisibilityGap:
    """Something the tool could not see. Absence of evidence is not evidence of absence."""

    area: str
    reason: str
    impact: str = ""
    needs_root: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    rule_id: str                   # stable per-rule identifier, e.g. "ACCT-UID0-EXTRA"
    module: str
    title: str
    severity: Severity
    confidence: Confidence
    category: Category
    target: str                    # affected path / account / pid / unit / port
    why: str                       # why this matters
    impact: str = ""
    recommendation: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    timestamps: Dict[str, Optional[str]] = field(default_factory=dict)
    baseline_state: BaselineState = BaselineState.NO_BASELINE
    remediation_risk: str = ""
    tags: List[str] = field(default_factory=list)
    correlation_key: Optional[str] = None   # groups related findings into one incident
    partial_evidence: bool = False          # true when based on incomplete data
    references: List[str] = field(default_factory=list)
    _id: Optional[str] = None

    @property
    def id(self) -> str:
        if self._id is None:
            digest = hashlib.sha256(
                f"{self.module}|{self.rule_id}|{self.target}".encode("utf-8", "replace")
            ).hexdigest()[:8]
            prefix = {
                Category.ACCOUNT: "ACCT",
                Category.PRIVESC: "PRIV",
                Category.AUTHENTICATION: "AUTH",
                Category.REMOTE_ACCESS: "RMT",
                Category.PERSISTENCE: "PERS",
                Category.PROCESS: "PROC",
                Category.NETWORK: "NET",
                Category.INTEGRITY: "INTG",
                Category.PACKAGE: "PKG",
                Category.POSTURE: "POST",
                Category.LOGGING: "LOG",
            }[self.category]
            self._id = f"BW-{prefix}-{digest}"
        return self._id

    @property
    def dedup_key(self) -> str:
        return f"{self.module}|{self.rule_id}|{self.target}"

    def sort_key(self):
        # Highest severity first, then highest confidence, then stable by id.
        return (-self.severity.rank, -self.confidence.rank, self.id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "module": self.module,
            "title": self.title,
            "severity": self.severity.label,
            "confidence": self.confidence.label,
            "category": self.category.value,
            "target": self.target,
            "why": self.why,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "baseline_state": self.baseline_state.value,
            "remediation_risk": self.remediation_risk,
            "tags": sorted(set(self.tags)),
            "correlation_key": self.correlation_key,
            "partial_evidence": self.partial_evidence,
            "timestamps": self.timestamps,
            "references": self.references,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class ModuleResult:
    name: str
    version: str
    title: str = ""
    status: ModuleStatus = ModuleStatus.OK
    reason: str = ""                       # why skipped / failed / unsupported
    findings: List[Finding] = field(default_factory=list)
    facts: Dict[str, Any] = field(default_factory=dict)   # structured data for baseline
    gaps: List[VisibilityGap] = field(default_factory=list)
    checks_run: int = 0
    duration_ms: int = 0

    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def gap(self, area: str, reason: str, impact: str = "", needs_root: bool = False) -> None:
        self.gaps.append(VisibilityGap(area=area, reason=reason, impact=impact, needs_root=needs_root))
        if self.status is ModuleStatus.OK:
            self.status = ModuleStatus.PARTIAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "title": self.title,
            "status": self.status.value,
            "reason": self.reason,
            "checks_run": self.checks_run,
            "duration_ms": self.duration_ms,
            "finding_ids": [f.id for f in self.findings],
            "gaps": [g.to_dict() for g in self.gaps],
        }


@dataclass
class Incident:
    """Several findings that point at the same underlying activity."""

    key: str
    title: str
    finding_ids: List[str]
    severity: Severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "severity": self.severity.label,
            "finding_ids": self.finding_ids,
        }


def dedupe(findings: List[Finding]) -> List[Finding]:
    """Collapse identical findings, keeping the highest-severity instance and
    merging evidence. Prevents inflated alert counts when several modules spot
    the same artifact."""
    best: Dict[str, Finding] = {}
    for f in findings:
        key = f.dedup_key
        existing = best.get(key)
        if existing is None:
            best[key] = f
            continue
        if f.sort_key() < existing.sort_key():
            keep, drop = f, existing
        else:
            keep, drop = existing, f
        seen = {(e.source, e.locator, e.content) for e in keep.evidence}
        for e in drop.evidence:
            if (e.source, e.locator, e.content) not in seen:
                keep.evidence.append(e)
        keep.tags = sorted(set(keep.tags) | set(drop.tags))
        best[key] = keep
    return sorted(best.values(), key=lambda f: f.sort_key())


def correlate(findings: List[Finding]) -> List[Incident]:
    """Group findings sharing a correlation key into incidents."""
    groups: Dict[str, List[Finding]] = {}
    for f in findings:
        if f.correlation_key:
            groups.setdefault(f.correlation_key, []).append(f)
    incidents = []
    for key, group in sorted(groups.items()):
        if len(group) < 2:
            continue
        group.sort(key=lambda f: f.sort_key())
        incidents.append(
            Incident(
                key=key,
                title=f"{len(group)} related findings: {group[0].title}",
                finding_ids=[f.id for f in group],
                severity=group[0].severity,
            )
        )
    incidents.sort(key=lambda i: -i.severity.rank)
    return incidents


def severity_counts(findings: List[Finding]) -> Dict[str, int]:
    counts = {s.label: 0 for s in Severity}
    for f in findings:
        counts[f.severity.label] += 1
    return counts



# ============================================================================
# bulwark/redact.py
# secret redaction
# ============================================================================

# Secret redaction.
#
# Everything that reaches a report goes through `redact()`. The goal is that a
# report can be shared with a teammate or a white team without leaking password
# hashes, private keys, API tokens or command-line credentials.
#
# Redaction is deliberately aggressive. It may obscure a detail that would have
# been useful; that tradeoff is intentional. The raw artifact stays on disk at the
# path named in the evidence locator for an operator to inspect directly.



PLACEHOLDER = "[REDACTED]"

# Order matters: more specific patterns first.
_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
    # PEM private key blocks (any flavour)
    (re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL), "[REDACTED PRIVATE KEY BLOCK]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "[REDACTED PRIVATE KEY HEADER]"),

    # crypt(3) hashes as found in /etc/shadow: keep the algorithm id, drop the rest
    (re.compile(r"\$(y|gy|7|6|5|2[aby]|1)\$[./A-Za-z0-9$,=]{8,}"), r"$\1$[REDACTED-HASH]"),

    # JWTs
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"),
     "[REDACTED JWT]"),

    # Cloud / service credentials
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED AWS KEY ID]"),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{16,})"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED SLACK TOKEN]"),

    # key=value / key: value secrets. The leading character class matters:
    # without it, DB_PASSWORD= does not match, because the underscore before
    # PASSWORD is a word character and so there is no \b boundary there.
    (re.compile(
        r"(?i)\b([A-Za-z0-9_.\-]*(?:pass(?:word|wd)?|passphrase|secret|token|"
        r"api[_-]?key|apikey|access[_-]?key|secret[_-]?key|auth[_-]?token|"
        r"private[_-]?key|credentials?))\s*[=:]\s*(\"[^\"]*\"|'[^']*'|\S+)"),
     r"\1=" + PLACEHOLDER),

    # mysql -pSECRET / curl -u user:pass
    (re.compile(r"(?<=\s)-p(?=\S)\S+"), "-p" + PLACEHOLDER),
    (re.compile(r"(?i)(\s-u\s+\S+?):\S+"), r"\1:" + PLACEHOLDER),

    # URLs with inline credentials
    (re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+):[^\s/@]+@"), r"\1:" + PLACEHOLDER + "@"),
)

# Public SSH keys are not secret, but printing whole keys makes reports
# unreadable and invites copy-paste mistakes. Keep type + a short prefix.
_SSH_PUBKEY = re.compile(r"\b(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-[a-z0-9@.-]+)\s+([A-Za-z0-9+/=]{40,})")

# Long opaque base64 blobs. Keep a prefix so an analyst can still recognise a
# known payload, but do not carry kilobytes of encoded data into the report.
_LONG_B64 = re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}")


def _shorten_pubkey(m: re.Match) -> str:
    keytype, blob = m.group(1), m.group(2)
    return f"{keytype} {blob[:16]}...[{len(blob)} chars truncated]"


def _shorten_b64(m: re.Match) -> str:
    blob = m.group(0)
    return f"{blob[:32]}...[{len(blob)} chars truncated]"


def redact(text: str) -> str:
    """Remove or shorten secrets in system-derived text."""
    if not text:
        return text
    out = text
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    out = _SSH_PUBKEY.sub(_shorten_pubkey, out)
    out = _LONG_B64.sub(_shorten_b64, out)
    return out


def redact_argv(argv) -> str:
    """Redact a process command line (list or NUL-joined string)."""
    if isinstance(argv, (list, tuple)):
        text = " ".join(str(a) for a in argv)
    else:
        text = str(argv or "")
    return redact(text)


def truncate(text: str, limit: int) -> Tuple[str, bool]:
    """Clip text to `limit` characters, reporting whether it was cut."""
    if text is None:
        return "", False
    if len(text) <= limit:
        return text, False
    return text[:limit] + f"\n...[truncated, {len(text)} chars total]", True



# ============================================================================
# bulwark/indicators.py
# deterministic indicator patterns
# ============================================================================

# Deterministic indicator patterns shared across detection modules.
#
# These are explainable regular expressions, not machine learning and not an
# external reputation service. Each match carries a human-readable name so a
# finding can state exactly why a command line looked wrong.
#
# Matching text here never results in that text being executed.




@dataclass(frozen=True)
class Indicator:
    key: str
    name: str
    weight: int          # 3 = strong, 2 = moderate, 1 = weak/contextual
    pattern: re.Pattern

    def describe(self) -> str:
        return self.name


def _i(key: str, name: str, weight: int, regex: str) -> Indicator:
    return Indicator(key, name, weight, re.compile(regex, re.IGNORECASE))


COMMAND_INDICATORS: List[Indicator] = [
    # --- Reverse / bind shells -------------------------------------------
    _i("revshell_devtcp", "shell redirected to /dev/tcp or /dev/udp socket", 3,
       r"/dev/(tcp|udp)/[0-9a-z.\-]+/\d+"),
    _i("revshell_nc_exec", "netcat invoked with command execution flag", 3,
       r"\b(nc|ncat|netcat|nc\.traditional)\b[^|;&\n]{0,60}\s-[a-z]*e\b"),
    _i("revshell_nc_fifo", "named pipe piped into netcat (classic reverse shell)", 3,
       r"mkfifo[^|;\n]{0,60}(\||;|&&)[^|\n]{0,80}\b(nc|ncat|netcat)\b"),
    _i("revshell_socat", "socat with EXEC/SYSTEM payload", 3,
       r"\bsocat\b[^\n]{0,80}(exec|system)\s*:"),
    _i("revshell_interactive", "interactive shell spawned with redirected descriptors", 3,
       r"\b(ba|z|k)?sh\s+-[a-z]*i\b[^\n]{0,40}(>&|<&|0<&|>&\d)"),
    _i("revshell_py_socket", "inline Python socket + shell spawn", 3,
       r"python[23]?\b[^\n]{0,200}\bsocket\b[^\n]{0,200}\b(pty\.spawn|subprocess|os\.dup2|execve)"),
    _i("revshell_perl_socket", "inline Perl socket + shell spawn", 3,
       r"perl\b[^\n]{0,200}(socket|IO::Socket)[^\n]{0,200}(exec|system|/bin/(ba)?sh)"),
    _i("revshell_ruby_socket", "inline Ruby socket + shell spawn", 3,
       r"ruby\b[^\n]{0,160}TCPSocket[^\n]{0,160}(exec|system|/bin/(ba)?sh)"),
    _i("revshell_php", "inline PHP socket backdoor", 3,
       r"php\b[^\n]{0,160}(fsockopen|socket_create)"),
    _i("bindshell_nc_listen", "netcat listening in server mode", 3,
       r"\b(nc|ncat|netcat)\b[^\n]{0,60}\s-[a-z]*l[a-z]*\b[^\n]{0,40}(-[a-z]*e\b|-c\b)"),

    # --- Download and execute --------------------------------------------
    _i("download_pipe_shell", "remote content piped directly into a shell", 3,
       r"\b(curl|wget|fetch)\b[^|\n]{0,200}\|\s*(sudo\s+)?(ba|z|k|d)?sh\b"),
    _i("download_pipe_interp", "remote content piped into an interpreter", 3,
       r"\b(curl|wget)\b[^|\n]{0,200}\|\s*(sudo\s+)?(python[23]?|perl|ruby|php|node)\b"),
    _i("download_to_tmp_exec", "download into a temp directory followed by execution", 2,
       r"\b(curl|wget)\b[^\n]{0,160}(/tmp/|/dev/shm/|/var/tmp/)[^\n]{0,80}(chmod|;|&&)"),
    _i("download_insecure", "download with certificate verification disabled", 2,
       r"\b(curl\b[^\n]{0,80}(-k\b|--insecure)|wget\b[^\n]{0,80}--no-check-certificate)"),

    # --- Encoded / obfuscated payloads ------------------------------------
    _i("encoded_base64_exec", "base64-decoded content passed to a shell or interpreter", 3,
       r"base64\s+(-{1,2}d\w*|--decode)[^\n]{0,80}\|\s*(ba|z)?sh\b|"
       r"\|\s*base64\s+(-{1,2}d\w*|--decode)[^\n]{0,80}\|\s*(ba|z)?sh\b"),
    _i("encoded_b64_interp", "interpreter decoding an inline base64 blob", 3,
       r"(python[23]?|perl|ruby|php)\b[^\n]{0,200}(b64decode|decode_base64|base64_decode|"
       r"from_base64|atob)"),
    # Plain `eval` is far too common to flag on its own: Debian's stock
    # /etc/skel/.bashrc contains eval "$(dircolors ...)". Only eval applied to
    # decoded, downloaded or obfuscated content is a signal.
    _i("encoded_eval", "eval applied to decoded or downloaded content", 3,
       r"\beval\b[^\n]{0,120}(base64|b64decode|atob|\$\(\s*(curl|wget)|xxd\s+-r|"
       r"openssl\s+enc|gzip\s+-d|zlib|tr\s+['\"][A-Za-z]|rev\b)"),
    _i("encoded_hex_escape", "long hex-escaped string literal", 2,
       r"(\\x[0-9a-f]{2}){12,}"),
    _i("encoded_rev", "command text reversed with rev/tac to evade inspection", 2,
       r"\|\s*rev\b[^\n]{0,40}\|\s*(ba|z)?sh\b"),

    # --- Persistence-flavoured commands -----------------------------------
    _i("persist_crontab_pipe", "crontab installed from piped stdin", 2,
       r"\|\s*crontab\s+-\b|\bcrontab\s+-\s*$"),
    _i("persist_authkeys_append", "key appended to authorized_keys", 3,
       r">>\s*[^\s;|]*\.ssh/authorized_keys|authorized_keys[^\n]{0,40}(echo|cat|printf)"),
    _i("persist_useradd_uid0", "account created with UID 0", 3,
       r"\buseradd\b[^\n]{0,80}(-u\s*0\b|--uid\s*0\b)|\busermod\b[^\n]{0,80}-u\s*0\b"),
    _i("persist_passwd_nonint", "password set non-interactively", 2,
       r"\b(chpasswd|passwd\s+--stdin)\b|echo\s+[^\n|]{0,60}\|\s*passwd\b"),
    _i("persist_systemd_runtime", "systemd unit written at runtime", 2,
       r">\s*/(etc|run|usr/lib|lib)/systemd/system/\S+\.(service|timer)"),
    # HISTCONTROL=ignoreboth is in Debian's stock .bashrc and is deliberately
    # excluded. Only outright disabling of history is an indicator.
    _i("persist_history_off", "shell history disabled or discarded", 2,
       r"(unset\s+HISTFILE\b|HISTFILE\s*=\s*/dev/null|HISTFILESIZE\s*=\s*0\b|"
       r"HISTSIZE\s*=\s*0\b|set\s+\+o\s+history|ln\s+-s[fn]*\s+/dev/null[^\n]{0,40}history)"),
    _i("persist_ldpreload", "LD_PRELOAD injection", 3,
       r"\bLD_PRELOAD\s*=\s*\S+"),

    # --- Anti-forensics / defence evasion ----------------------------------
    _i("evade_log_wipe", "log files emptied or deleted", 3,
       r"(>\s*/var/log/\S+|\brm\b[^\n]{0,60}/var/log/|\btruncate\b[^\n]{0,40}/var/log/|"
       r"\bshred\b[^\n]{0,60}/var/log/)"),
    _i("evade_history_clear", "shell history cleared", 2,
       r"\bhistory\s+-c\b|\brm\b[^\n]{0,40}\.bash_history|>\s*[^\s;|]*\.bash_history"),
    _i("evade_timestomp", "file timestamps altered", 2,
       r"\btouch\b[^\n]{0,60}(-[a-z]*[dtr]\b|--date|--reference)"),
    _i("evade_immutable", "immutable attribute set on a file", 2,
       r"\bchattr\b[^\n]{0,40}\+i\b"),
    _i("evade_firewall_flush", "firewall rules flushed or default-accept", 2,
       r"\biptables\b[^\n]{0,40}(-F\b|-P\s+\w+\s+ACCEPT)|\bufw\s+disable\b|"
       r"\bsystemctl\s+(stop|disable)\s+(firewalld|ufw)\b"),
    _i("evade_disable_security", "security control stopped or disabled", 2,
       r"\b(setenforce\s+0|systemctl\s+(stop|disable)\s+(auditd|apparmor|selinux|rsyslog)|"
       r"\baa-disable\b)"),

    # --- Credential access --------------------------------------------------
    _i("cred_shadow_read", "direct read of the shadow password file", 2,
       r"\b(cat|cp|scp|tar|dd|less|more|head|tail)\b[^\n]{0,60}/etc/shadow\b"),
    _i("cred_dump_tools", "credential dumping utility", 3,
       r"\b(mimipenguin|lazagne|swap_digger|unshadow|john|hashcat)\b"),
    _i("cred_sshkey_harvest", "SSH private key harvesting", 2,
       r"\b(find|cp|tar|grep)\b[^\n]{0,80}(id_rsa|id_ed25519|id_ecdsa|\.ssh/)"),

    # --- Tunnels and proxies ------------------------------------------------
    _i("tunnel_ssh", "SSH port-forwarding tunnel", 2,
       r"\bssh\b[^\n]{0,80}\s-[a-zA-Z]*[RLD]\s*\d{1,5}:"),
    _i("tunnel_tool", "known tunnelling or C2-capable utility", 2,
       r"\b(chisel|ngrok|frpc|frps|gost|iodine|dnscat2?|ligolo|revsocks|pwncat|"
       r"cloudflared|localtunnel)\b"),

    # --- Offensive tooling --------------------------------------------------
    _i("offensive_payload", "payload-generation or post-exploitation framework artifact", 3,
       r"\b(msfvenom|meterpreter|metasploit|empire|covenant|sliver|havoc|"
       r"beacon\.(exe|dll|bin)|cobaltstrike)\b"),
    _i("offensive_scanner", "network attack tooling invoked locally", 2,
       r"\b(hydra|medusa|patator|responder|crackmapexec|netexec|impacket-\w+)\b"),
    _i("miner", "cryptocurrency miner artifact", 3,
       r"\b(xmrig|minerd|cpuminer|cgminer|ethminer|nicehash|stratum\+tcp|"
       r"--donate-level|randomx)\b"),
]

# Directories that should essentially never hold a persistent, privileged
# executable on a server. Execution from here is a strong location signal.
SUSPICIOUS_EXEC_DIRS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
    "/var/spool/",
    "/var/www/",
    "/srv/",  # weak on purpose: web content dirs are contextual, see weight below
)

STRONG_EXEC_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")

# Shells that give an interactive foothold when set on an account.
INTERACTIVE_SHELLS = {
    "/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh", "/bin/csh",
    "/bin/tcsh", "/bin/fish", "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash",
    "/usr/bin/zsh", "/usr/bin/ksh", "/usr/bin/fish", "/usr/bin/tcsh",
    "/usr/local/bin/bash", "/usr/bin/screen", "/usr/bin/tmux",
}

NOLOGIN_SHELLS = {
    "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false",
    "/nonexistent", "/dev/null", "", "/bin/sync", "/usr/bin/sync",
}

# Binaries that trivially yield a root shell when allowed via sudo NOPASSWD.
# Drawn from the well-known GTFOBins set; each has a documented shell escape.
SUDO_SHELL_ESCAPE_BINARIES = {
    "vi", "vim", "nvim", "nano", "pico", "ed", "emacs", "less", "more", "man",
    "awk", "gawk", "mawk", "sed", "find", "perl", "python", "python2", "python3",
    "ruby", "php", "lua", "node", "nodejs", "tclsh", "expect", "gdb", "ltrace",
    "strace", "nmap", "tar", "zip", "unzip", "rsync", "cpan", "pip", "pip3",
    "git", "ftp", "sftp", "scp", "ssh", "screen", "tmux", "byobu", "env", "nice",
    "timeout", "xargs", "make", "cmake", "docker", "podman", "lxc", "systemctl",
    "journalctl", "apt", "apt-get", "dpkg", "rpm", "yum", "dnf", "crontab",
    "busybox", "bash", "sh", "dash", "zsh", "ksh", "csh", "tclsh", "mount",
    "umount", "dd", "cp", "mv", "chmod", "chown", "chroot", "install", "tee",
    "vigr", "vipw", "visudo", "ed", "pkexec", "openssl", "tcpdump", "wireshark",
    "ansible-playbook", "puppet", "chef-client",
}


def scan(text: Optional[str]) -> List[Indicator]:
    """Return every indicator matching `text`. Text is never executed."""
    if not text:
        return []
    return [ind for ind in COMMAND_INDICATORS if ind.pattern.search(text)]


def score(indicators: List[Indicator]) -> int:
    return sum(i.weight for i in indicators)


def summarize(indicators: List[Indicator], limit: int = 4) -> str:
    if not indicators:
        return ""
    names = [i.describe() for i in indicators[:limit]]
    extra = len(indicators) - len(names)
    text = "; ".join(names)
    if extra > 0:
        text += f"; and {extra} further indicator(s)"
    return text


def in_suspicious_dir(path: Optional[str]) -> Optional[str]:
    """Return the matching suspicious directory prefix, or None."""
    if not path:
        return None
    for d in SUSPICIOUS_EXEC_DIRS:
        if path.startswith(d):
            return d
    return None


def in_strong_suspicious_dir(path: Optional[str]) -> bool:
    return bool(path) and any(path.startswith(d) for d in STRONG_EXEC_DIRS)


# Ranges this tool treats as "on our own network". Deliberately narrower than
# ipaddress.is_private, which also covers the documentation ranges
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), the benchmarking range
# (198.18.0.0/15) and carrier-grade NAT (100.64.0.0/10). Those are not your
# LAN, and an endpoint in one of them is worth seeing rather than filtering
# away. Listing them explicitly also keeps behaviour identical across Python
# versions, whose special-purpose registry tables have changed over time.
_LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(cidr) for cidr in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC1918
        "127.0.0.0/8", "169.254.0.0/16",                   # loopback, link-local
        "0.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32",  # this-network, multicast
        "::1/128", "fe80::/10", "fc00::/7", "ff00::/8", "::/128",
    )
)


def is_private_address(addr: str) -> bool:
    """True when the address is on the local network rather than beyond it.

    An unparseable address returns False, so it is treated as external and
    surfaced rather than quietly dropped.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    for network in _LOCAL_NETWORKS:
        if ip.version == network.version and ip in network:
            return True
    return False



# ============================================================================
# bulwark/host.py
# safe file and command access layer
# ============================================================================

# Host access layer: safe file reads, bounded directory walks, safe subprocess.
#
# Everything a detection module touches on the system goes through `Host`. Two
# reasons:
#
# 1. Safety. One place enforces read-only access, timeouts, argv-only subprocess
#    invocation (never shell=True), symlink policy, size caps and traversal
#    limits.
# 2. Testability. `Host(root=...)` reparents every filesystem read under a
#    directory, so the real detection code can run against a synthetic
#    "compromised host" built in a temp directory. Command output can be stubbed
#    with a recorded runner. No test needs a real backdoor on a real machine.



DEFAULT_TIMEOUT = 15
MAX_READ_BYTES = 512 * 1024          # 512 KiB per file by default
MAX_WALK_ENTRIES = 20000             # hard stop on any single directory walk
MAX_WALK_DEPTH = 6


@dataclass
class CommandResult:
    argv: List[str]
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    error: Optional[str] = None       # "not-found", "timeout", "blocked", ...
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.error is None and self.returncode == 0

    @property
    def ran(self) -> bool:
        return self.error is None

    def argv_str(self) -> str:
        return " ".join(self.argv)


@dataclass
class FileInfo:
    path: str                      # logical path (as the system sees it)
    exists: bool = False
    error: Optional[str] = None
    is_symlink: bool = False
    symlink_target: Optional[str] = None
    is_dir: bool = False
    is_file: bool = False
    mode: Optional[int] = None
    mode_octal: Optional[str] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    owner: Optional[str] = None
    group: Optional[str] = None
    size: Optional[int] = None
    mtime: Optional[float] = None
    ctime: Optional[float] = None
    atime: Optional[float] = None
    nlink: Optional[int] = None
    setuid: bool = False
    setgid: bool = False
    world_writable: bool = False
    sha256: Optional[str] = None

    def to_dict(self) -> Dict:
        d = dict(self.__dict__)
        return {k: v for k, v in d.items() if v is not None and v is not False}


class Host:
    """Read-only view of a Linux host (or a synthetic copy of one)."""

    def __init__(
        self,
        root: str = "/",
        timeout: int = DEFAULT_TIMEOUT,
        runner=None,
        allow_commands: bool = True,
        env: Optional[Dict[str, str]] = None,
    ):
        self.root = os.path.abspath(root) if root != "/" else "/"
        self.is_synthetic = self.root != "/"
        self.timeout = timeout
        # When running against a synthetic root, external commands would query
        # the real machine and produce nonsense, so they are blocked unless a
        # runner is injected.
        self._runner = runner
        self.allow_commands = allow_commands and (runner is not None or not self.is_synthetic)
        self._which_cache: Dict[str, Optional[str]] = {}
        self._cmd_cache: Dict[Tuple[str, ...], CommandResult] = {}
        self._pw_cache: Optional[Dict[int, str]] = None
        self._gr_cache: Optional[Dict[int, str]] = None
        self.env = env or {}
        self.command_log: List[str] = []

    # ---------------------------------------------------------------- paths

    def real(self, path: str) -> str:
        """Map a logical system path to a real on-disk path under the root.

        Traversal is neutralised rather than rejected: `..` above `/` collapses
        to `/`, which is what the kernel does with the same path. The explicit
        check afterwards is defence in depth, so that any future change to the
        normalisation cannot silently start escaping the root.
        """
        if not path.startswith("/"):
            path = "/" + path
        if self.root == "/":
            return os.path.normpath(path)
        normalized = os.path.normpath(path).lstrip("/")
        candidate = os.path.normpath(os.path.join(self.root, normalized))
        if candidate != self.root and not candidate.startswith(self.root + os.sep):
            raise ValueError(f"path escapes configured root: {path}")
        return candidate

    def logical(self, real_path: str) -> str:
        """Inverse of real(): map an on-disk path back to the logical path."""
        if self.root == "/":
            return real_path
        if real_path == self.root:
            return "/"
        if real_path.startswith(self.root + os.sep):
            return real_path[len(self.root):]
        return real_path

    # ----------------------------------------------------------------- stat

    def stat(self, path: str, hash_file: bool = False,
             hash_limit: int = 16 * 1024 * 1024) -> FileInfo:
        """lstat-first metadata. Never follows a symlink silently: if the path
        is a link, the link itself is described and the target recorded."""
        info = FileInfo(path=path)
        try:
            real = self.real(path)
        except ValueError as exc:
            info.error = str(exc)
            return info
        try:
            st = os.lstat(real)
        except FileNotFoundError:
            return info
        except PermissionError:
            info.error = "permission denied"
            return info
        except OSError as exc:
            info.error = f"{errno.errorcode.get(exc.errno, exc.errno)}: {exc.strerror}"
            return info

        info.exists = True
        info.mode = st.st_mode
        info.mode_octal = oct(statmod.S_IMODE(st.st_mode))[2:].rjust(4, "0")
        info.uid, info.gid = st.st_uid, st.st_gid
        info.owner = self.user_name(st.st_uid)
        info.group = self.group_name(st.st_gid)
        info.size = st.st_size
        info.mtime, info.ctime, info.atime = st.st_mtime, st.st_ctime, st.st_atime
        info.nlink = st.st_nlink
        info.setuid = bool(st.st_mode & statmod.S_ISUID)
        info.setgid = bool(st.st_mode & statmod.S_ISGID)
        info.world_writable = bool(st.st_mode & statmod.S_IWOTH)

        if statmod.S_ISLNK(st.st_mode):
            info.is_symlink = True
            try:
                info.symlink_target = os.readlink(real)
            except OSError as exc:
                # /proc/<pid>/exe for a kernel thread behaves exactly like this:
                # the link exists but has no target. Leaving the target None and
                # recording the reason stops callers inventing a path.
                info.symlink_target = None
                info.error = f"link unreadable: {exc.strerror or exc}"
            try:
                tst = os.stat(real)
                info.is_dir = statmod.S_ISDIR(tst.st_mode)
                info.is_file = statmod.S_ISREG(tst.st_mode)
            except OSError:
                pass
        else:
            info.is_dir = statmod.S_ISDIR(st.st_mode)
            info.is_file = statmod.S_ISREG(st.st_mode)

        if hash_file and info.is_file and (info.size or 0) <= hash_limit:
            info.sha256 = self.sha256(path)
        return info

    def sha256(self, path: str, limit: int = 64 * 1024 * 1024) -> Optional[str]:
        try:
            real = self.real(path)
        except ValueError:
            return None
        digest = hashlib.sha256()
        read = 0
        try:
            with open(real, "rb") as fh:
                while True:
                    chunk = fh.read(1024 * 256)
                    if not chunk:
                        break
                    read += len(chunk)
                    if read > limit:
                        return None
                    digest.update(chunk)
        except (OSError, ValueError):
            return None
        return digest.hexdigest()

    def exists(self, path: str) -> bool:
        try:
            return os.path.lexists(self.real(path))
        except ValueError:
            return False

    def is_dir(self, path: str) -> bool:
        try:
            return os.path.isdir(self.real(path))
        except ValueError:
            return False

    # ----------------------------------------------------------------- read

    def read_text(self, path: str, max_bytes: int = MAX_READ_BYTES) -> Tuple[Optional[str], Optional[bool], Optional[str]]:
        """Read a text file.

        Returns (text, truncated, error). `text` is None when unreadable.
        Decoding is lenient because logs and configs on a compromised host are
        not guaranteed to be valid UTF-8.
        """
        try:
            real = self.real(path)
        except ValueError as exc:
            return None, None, str(exc)
        try:
            with open(real, "rb") as fh:
                data = fh.read(max_bytes + 1)
        except FileNotFoundError:
            return None, None, "not found"
        except PermissionError:
            return None, None, "permission denied"
        except IsADirectoryError:
            return None, None, "is a directory"
        except OSError as exc:
            return None, None, f"{exc.strerror or exc}"
        truncated = len(data) > max_bytes
        if truncated:
            data = data[:max_bytes]
        return data.decode("utf-8", errors="replace"), truncated, None

    def read_lines(self, path: str, max_bytes: int = MAX_READ_BYTES) -> Tuple[List[str], Optional[str]]:
        text, _truncated, err = self.read_text(path, max_bytes)
        if text is None:
            return [], err
        return text.splitlines(), None

    def tail_lines(self, path: str, lines: int = 2000,
                   max_bytes: int = 8 * 1024 * 1024) -> Tuple[List[str], Optional[str]]:
        """Read the last N lines of a possibly large log file without loading
        the whole thing into memory."""
        try:
            real = self.real(path)
        except ValueError as exc:
            return [], str(exc)
        try:
            size = os.path.getsize(real)
            with open(real, "rb") as fh:
                if size > max_bytes:
                    fh.seek(size - max_bytes)
                    fh.readline()  # discard partial line
                data = fh.read()
        except FileNotFoundError:
            return [], "not found"
        except PermissionError:
            return [], "permission denied"
        except OSError as exc:
            return [], f"{exc.strerror or exc}"
        decoded = data.decode("utf-8", errors="replace").splitlines()
        return decoded[-lines:], None

    def listdir(self, path: str) -> Tuple[List[str], Optional[str]]:
        try:
            real = self.real(path)
        except ValueError as exc:
            return [], str(exc)
        try:
            return sorted(os.listdir(real)), None
        except FileNotFoundError:
            return [], "not found"
        except PermissionError:
            return [], "permission denied"
        except NotADirectoryError:
            return [], "not a directory"
        except OSError as exc:
            return [], f"{exc.strerror or exc}"

    def walk(self, path: str, max_depth: int = MAX_WALK_DEPTH,
             max_entries: int = MAX_WALK_ENTRIES,
             same_filesystem: bool = True,
             skip_dirs: Iterable[str] = ()) -> Tuple[List[str], List[str], bool]:
        """Bounded, symlink-safe directory walk.

        Returns (file_paths, errors, hit_limit). Symlinked directories are never
        descended into, so a link planted at /tmp/x -> / cannot drag the scan
        across the whole filesystem. Optionally refuses to cross device
        boundaries, which keeps network mounts and container layers out.
        """
        files: List[str] = []
        errors: List[str] = []
        hit_limit = False
        try:
            root_real = self.real(path)
        except ValueError as exc:
            return [], [str(exc)], False
        if not os.path.isdir(root_real):
            return [], [], False
        try:
            base_dev = os.stat(root_real).st_dev
        except OSError:
            base_dev = None

        skip = {s.rstrip("/") for s in skip_dirs}
        stack: List[Tuple[str, int]] = [(root_real, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > max_depth:
                continue
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        if len(files) >= max_entries:
                            hit_limit = True
                            return files, errors, hit_limit
                        logical = self.logical(entry.path)
                        if logical.rstrip("/") in skip:
                            continue
                        try:
                            if entry.is_symlink():
                                # Record the link, never traverse it.
                                files.append(logical)
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                if same_filesystem and base_dev is not None:
                                    try:
                                        if entry.stat(follow_symlinks=False).st_dev != base_dev:
                                            continue
                                    except OSError:
                                        continue
                                stack.append((entry.path, depth + 1))
                            else:
                                files.append(logical)
                        except OSError as exc:
                            errors.append(f"{logical}: {exc.strerror or exc}")
            except PermissionError:
                errors.append(f"{self.logical(current)}: permission denied")
            except OSError as exc:
                errors.append(f"{self.logical(current)}: {exc.strerror or exc}")
        return files, errors, hit_limit

    def glob_dir(self, directory: str, suffix: Optional[str] = None) -> List[str]:
        """Immediate children of a directory, optionally filtered by suffix."""
        names, err = self.listdir(directory)
        if err:
            return []
        out = []
        for name in names:
            if suffix and not name.endswith(suffix):
                continue
            out.append(os.path.join(directory, name))
        return out

    # -------------------------------------------------------------- identity

    def user_name(self, uid: Optional[int]) -> Optional[str]:
        if uid is None:
            return None
        if self.is_synthetic:
            table = self.passwd_uid_map()
            return table.get(uid, str(uid))
        try:
            return pwd.getpwuid(uid).pw_name
        except (KeyError, OSError):
            return str(uid)

    def group_name(self, gid: Optional[int]) -> Optional[str]:
        if gid is None:
            return None
        if self.is_synthetic:
            table = self.group_gid_map()
            return table.get(gid, str(gid))
        try:
            return grp.getgrgid(gid).gr_name
        except (KeyError, OSError):
            return str(gid)

    def passwd_uid_map(self) -> Dict[int, str]:
        if self._pw_cache is None:
            self._pw_cache = {}
            lines, _ = self.read_lines("/etc/passwd")
            for line in lines:
                parts = line.split(":")
                if len(parts) >= 3 and parts[2].isdigit():
                    self._pw_cache.setdefault(int(parts[2]), parts[0])
        return self._pw_cache

    def group_gid_map(self) -> Dict[int, str]:
        if self._gr_cache is None:
            self._gr_cache = {}
            lines, _ = self.read_lines("/etc/group")
            for line in lines:
                parts = line.split(":")
                if len(parts) >= 3 and parts[2].isdigit():
                    self._gr_cache.setdefault(int(parts[2]), parts[0])
        return self._gr_cache

    # -------------------------------------------------------------- commands

    def which(self, name: str) -> Optional[str]:
        if name in self._which_cache:
            return self._which_cache[name]
        found: Optional[str] = None
        if self.is_synthetic:
            for d in ("/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"):
                candidate = os.path.join(d, name)
                if self.exists(candidate):
                    found = candidate
                    break
        else:
            found = shutil.which(name, path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        self._which_cache[name] = found
        return found

    def has(self, name: str) -> bool:
        return self.which(name) is not None

    def run(self, argv: List[str], timeout: Optional[int] = None,
            cache: bool = True, input_text: Optional[str] = None) -> CommandResult:
        """Run an external command safely.

        Always an argument vector, never a shell string: no value derived from
        system state is ever interpolated into a shell. Always bounded by a
        timeout. Output is captured, never streamed to a terminal.
        """
        argv = [str(a) for a in argv]
        key = tuple(argv)
        if cache and key in self._cmd_cache:
            return self._cmd_cache[key]

        result = CommandResult(argv=argv)
        if not self.allow_commands:
            result.error = "blocked"
            result.stderr = "external commands disabled for synthetic host root"
            return result
        if self._runner is not None:
            result = self._runner(argv)
            if cache:
                self._cmd_cache[key] = result
            self.command_log.append(" ".join(argv))
            return result

        if not any(ch in argv[0] for ch in "/"):
            resolved = self.which(argv[0])
            if resolved is None:
                result.error = "not-found"
                result.stderr = f"{argv[0]}: command not found"
                if cache:
                    self._cmd_cache[key] = result
                return result
            argv = [resolved] + argv[1:]
            result.argv = argv

        import time
        started = time.monotonic()
        env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
        }
        env.update(self.env)
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, shell=False, bounded
                argv,
                capture_output=True,
                timeout=timeout or self.timeout,
                env=env,
                input=input_text.encode() if input_text else None,
                check=False,
                shell=False,
            )
            result.returncode = proc.returncode
            result.stdout = proc.stdout.decode("utf-8", errors="replace")
            result.stderr = proc.stderr.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            result.error = "timeout"
            result.stderr = f"timed out after {timeout or self.timeout}s"
        except FileNotFoundError:
            result.error = "not-found"
            result.stderr = f"{argv[0]}: command not found"
        except PermissionError:
            result.error = "permission-denied"
            result.stderr = f"{argv[0]}: permission denied"
        except OSError as exc:
            result.error = "os-error"
            result.stderr = str(exc)
        result.duration_ms = int((time.monotonic() - started) * 1000)
        self.command_log.append(" ".join(argv))
        if cache:
            self._cmd_cache[key] = result
        return result

    # --------------------------------------------------------------- helpers

    def home_dirs(self) -> List[Tuple[str, str, int]]:
        """[(username, home, uid)] from /etc/passwd, for accounts with a home
        directory that actually exists."""
        out = []
        lines, _ = self.read_lines("/etc/passwd")
        for line in lines:
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, _pw, uid, _gid, _gecos, home, _shell = parts[:7]
            if not uid.isdigit() or not home:
                continue
            if self.is_dir(home):
                out.append((name, home.rstrip("/") or "/", int(uid)))
        return out



# ============================================================================
# bulwark/config.py
# configuration and platform detection
# ============================================================================

# Runtime configuration and the audit context passed to detection modules.




# Accounts that ship with mainstream distributions. Presence is expected; it is
# their *configuration* (shell, UID, group membership) that gets scrutinised.
KNOWN_SYSTEM_ACCOUNTS = {
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats",
    "nobody", "systemd-network", "systemd-resolve", "systemd-timesync",
    "systemd-coredump", "systemd-journal-remote", "messagebus", "syslog",
    "_apt", "tss", "uuidd", "tcpdump", "landscape", "pollinate", "fwupd-refresh",
    "usbmux", "sshd", "dnsmasq", "avahi", "colord", "geoclue", "rtkit",
    "saned", "lightdm", "gdm", "sddm", "pulse", "speech-dispatcher", "nm-openvpn",
    "whoopsie", "kernoops", "nvidia-persistenced", "chrony", "ntp", "polkitd",
    "rpc", "rpcuser", "nfsnobody", "dbus", "apache", "nginx", "mysql", "postgres",
    "redis", "mongodb", "memcached", "ftp", "operator", "adm", "halt", "shutdown",
    "postfix", "dovecot", "dovenull", "named", "unbound", "clamav", "amavis",
    "vmail", "vagrant", "ubuntu", "debian", "centos", "fedora", "ec2-user",
    "cloud-init", "snapd", "snap_daemon", "lxd", "docker", "containerd",
    "nslcd", "sssd", "setroubleshoot", "epmd", "nobody4", "sshguard", "fail2ban",
    "node_exporter", "prometheus", "grafana", "zabbix", "nagios", "munin",
}

ADMIN_GROUPS = ("sudo", "wheel", "admin", "adm", "root", "sudoers", "lxd", "docker")

# Groups that confer a path to root even though they are not "admin" groups.
ROOT_EQUIVALENT_GROUPS = {
    "docker": "members can mount the host filesystem into a privileged container",
    "lxd": "members can start a privileged container that mounts the host root",
    "disk": "members can read and write raw block devices, bypassing file permissions",
    "shadow": "members can read password hashes directly",
    "sudo": "members may execute commands as root",
    "wheel": "members may execute commands as root",
    "admin": "members may execute commands as root",
}

CRITICAL_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
    "/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/hosts", "/etc/hostname",
    "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/crontab", "/etc/rc.local",
    "/etc/profile", "/etc/bash.bashrc", "/etc/environment", "/etc/fstab",
    "/etc/login.defs", "/etc/securetty", "/etc/shells", "/etc/inittab",
    "/etc/pam.conf", "/etc/machine-id", "/root/.bashrc", "/root/.profile",
    "/root/.ssh/authorized_keys", "/etc/sysctl.conf",
]

CRITICAL_DIRS = [
    "/etc/sudoers.d", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
    "/etc/cron.weekly", "/etc/cron.monthly", "/etc/profile.d", "/etc/pam.d",
    "/etc/ld.so.conf.d", "/etc/systemd/system", "/etc/init.d",
    "/etc/update-motd.d", "/etc/sysctl.d", "/etc/security",
]

# Directories scanned for setuid binaries and dropped payloads. Bounded on
# purpose: a full-filesystem scan is both slow and dangerous during a round.
SCAN_DIRS = [
    "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin",
    "/usr/local/sbin", "/opt", "/tmp", "/var/tmp", "/dev/shm", "/home",
    "/root", "/srv", "/usr/libexec",
]

PACKAGE_MANAGED_BIN_DIRS = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]

# Ports whose presence is routine on a CCDC-style service box. Used to lower
# noise, never to suppress a finding on its own.
COMMON_SERVICE_PORTS = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    111: "rpcbind", 123: "ntp", 143: "imap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 587: "submission", 631: "ipp", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "mssql", 3000: "http-alt",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8000: "http-alt", 8080: "http-alt", 8443: "https-alt",
    9000: "http-alt", 9090: "http-alt", 11211: "memcached", 27017: "mongodb",
}

# Ports strongly associated with offensive tooling defaults. Not proof on their
# own; they raise confidence when combined with another indicator.
SUSPECT_PORTS = {
    1337: "common backdoor/listener default",
    31337: "classic backdoor port",
    4444: "Metasploit default handler port",
    4445: "Metasploit handler variant",
    5555: "common implant default",
    6666: "common backdoor port",
    7777: "common backdoor port",
    8888: "common implant/handler port",
    9001: "common handler port",
    9999: "common backdoor port",
    1234: "common listener default",
    12345: "NetBus-style backdoor port",
    54321: "common backdoor port",
}


@dataclass
class Config:
    output_dir: str = "./bulwark-evidence"
    baseline_path: Optional[str] = None
    log_lookback_hours: int = 72
    max_log_lines: int = 20000
    quick: bool = False
    modules: Optional[List[str]] = None       # explicit allow-list
    skip_modules: List[str] = field(default_factory=list)
    verbosity: int = 0
    no_color: bool = False
    command_timeout: int = 15
    hash_critical_files: bool = True
    max_findings_per_rule: int = 50           # guard against alert flooding
    root: str = "/"                           # synthetic rootfs for testing
    include_informational: bool = True
    assume_yes: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HostFacts:
    """Identity and capability snapshot of the system under assessment."""

    hostname: str = ""
    fqdn: str = ""
    os_name: str = ""
    os_version: str = ""
    os_id: str = ""
    os_id_like: str = ""
    kernel: str = ""
    architecture: str = ""
    init_system: str = "unknown"
    package_manager: str = "unknown"
    uptime_seconds: Optional[float] = None
    boot_time_utc: Optional[str] = None
    current_time_utc: str = ""
    local_timezone: str = ""
    euid: int = -1
    user: str = ""
    is_root: bool = False
    python_version: str = ""
    container: Optional[str] = None
    available_commands: Dict[str, bool] = field(default_factory=dict)
    machine_id: Optional[str] = None
    synthetic_root: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


PROBE_COMMANDS = [
    "systemctl", "service", "ps", "ss", "netstat", "ip", "ifconfig", "lsof",
    "journalctl", "auditctl", "ausearch", "iptables", "nft", "ufw",
    "firewall-cmd", "dpkg", "rpm", "apt", "dnf", "yum", "crontab", "at",
    "lsmod", "getenforce", "sestatus", "aa-status", "docker", "podman",
    "lastlog", "last", "lsattr", "sshd", "stat", "find", "pacman", "apk", "zypper",
]


def detect_host_facts(host: Host) -> HostFacts:
    facts = HostFacts()
    now = _dt.datetime.now(_dt.timezone.utc)
    facts.current_time_utc = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        facts.local_timezone = str(_dt.datetime.now().astimezone().tzinfo)
    except Exception:  # pragma: no cover - platform dependent
        facts.local_timezone = os.environ.get("TZ", "unknown")

    facts.python_version = sys.version.split()[0]
    if host.is_synthetic:
        facts.synthetic_root = host.root

    # Hostname: prefer the file so a synthetic root reports its own identity.
    text, _, _ = host.read_text("/etc/hostname")
    if text and text.strip():
        facts.hostname = text.strip().splitlines()[0]
    elif not host.is_synthetic:
        facts.hostname = socket.gethostname()
    else:
        facts.hostname = "unknown"
    if not host.is_synthetic:
        try:
            facts.fqdn = socket.getfqdn()
        except OSError:
            facts.fqdn = facts.hostname

    # Distribution
    osr = _parse_os_release(host)
    facts.os_name = osr.get("NAME", "")
    facts.os_version = osr.get("VERSION", osr.get("VERSION_ID", ""))
    facts.os_id = osr.get("ID", "")
    facts.os_id_like = osr.get("ID_LIKE", "")
    if not facts.os_name:
        for legacy in ("/etc/redhat-release", "/etc/debian_version", "/etc/alpine-release"):
            t, _, _ = host.read_text(legacy)
            if t:
                facts.os_name = t.strip().splitlines()[0]
                break

    # Kernel / architecture
    kernel, _, _ = host.read_text("/proc/sys/kernel/osrelease")
    facts.kernel = kernel.strip() if kernel else (platform.release() if not host.is_synthetic else "")
    facts.architecture = platform.machine() if not host.is_synthetic else osr.get("ARCH", "")

    # Privileges
    facts.euid = os.geteuid()
    facts.is_root = facts.euid == 0
    try:
        import pwd as _pwd
        facts.user = _pwd.getpwuid(facts.euid).pw_name
    except (KeyError, ImportError, OSError):
        facts.user = str(facts.euid)

    # Uptime / boot time
    uptime_text, _, _ = host.read_text("/proc/uptime")
    if uptime_text:
        try:
            facts.uptime_seconds = float(uptime_text.split()[0])
            boot = now - _dt.timedelta(seconds=facts.uptime_seconds)
            facts.boot_time_utc = boot.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, IndexError):
            pass

    facts.init_system = _detect_init(host)
    facts.package_manager = _detect_pkg_manager(host)
    facts.container = _detect_container(host)

    mid, _, _ = host.read_text("/etc/machine-id")
    facts.machine_id = mid.strip() if mid else None

    facts.available_commands = {c: host.has(c) for c in PROBE_COMMANDS}
    return facts


def _parse_os_release(host: Host) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        lines, err = host.read_lines(path)
        if err:
            continue
        for line in lines:
            if "=" not in line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip().strip('"').strip("'")
        if out:
            break
    return out


def _detect_init(host: Host) -> str:
    comm, _, _ = host.read_text("/proc/1/comm")
    if comm:
        name = comm.strip()
        if name:
            if "systemd" in name:
                return "systemd"
            if name in ("init", "sysvinit"):
                return "sysvinit" if not host.is_dir("/run/systemd/system") else "systemd"
            return name
    if host.is_dir("/run/systemd/system"):
        return "systemd"
    if host.exists("/sbin/openrc") or host.is_dir("/etc/runlevels"):
        return "openrc"
    if host.is_dir("/etc/init.d"):
        return "sysvinit"
    return "unknown"


def _detect_pkg_manager(host: Host) -> str:
    if host.exists("/var/lib/dpkg/status") or host.has("dpkg"):
        return "dpkg"
    if host.is_dir("/var/lib/rpm") or host.has("rpm"):
        return "rpm"
    if host.has("pacman"):
        return "pacman"
    if host.has("apk"):
        return "apk"
    return "unknown"


def _detect_container(host: Host) -> Optional[str]:
    if host.exists("/.dockerenv"):
        return "docker"
    text, _, _ = host.read_text("/proc/1/cgroup", max_bytes=16384)
    if text:
        lowered = text.lower()
        for marker in ("docker", "containerd", "lxc", "kubepods", "podman"):
            if marker in lowered:
                return marker
    if host.exists("/run/.containerenv"):
        return "podman"
    return None


class AuditContext:
    """Everything a detection module needs. Modules never reach outside this."""

    def __init__(self, host: Host, config: Config, facts: HostFacts,
                 baseline: Optional[Dict[str, Any]] = None, logger=None):
        self.host = host
        self.config = config
        self.facts = facts
        self.baseline = baseline
        self.logger = logger
        self.started_at = _dt.datetime.now(_dt.timezone.utc)
        self.tool_version = __version__
        self._shared: Dict[str, Any] = {}

    # Modules occasionally need a fact another module already computed
    # (listening sockets, say). Share through here rather than re-collecting.
    def share(self, key: str, value: Any) -> Any:
        self._shared[key] = value
        return value

    def shared(self, key: str, default: Any = None) -> Any:
        return self._shared.get(key, default)

    def log(self, level: str, message: str) -> None:
        if self.logger:
            self.logger(level, message)

    def baseline_section(self, name: str) -> Optional[Dict[str, Any]]:
        if not self.baseline:
            return None
        return (self.baseline.get("sections") or {}).get(name)



# ============================================================================
# bulwark/settings.py
# config file and environment resolution   [renamed to avoid collisions: load_settings]
# ============================================================================

# Persistent settings, so repeated options do not have to be typed every run.
#
# Resolution order, lowest priority first:
#
#     built-in default  <  /etc/bulwark.conf  <  user config  <  environment  <  CLI flag
#
# The config file is a trivial `key = value` format with no includes, no
# interpolation and no execution. It is parsed as data: unknown keys are ignored
# with a warning rather than acted on, and values are coerced only into the type
# the key expects.
#
# A config file that is writable by non-root users is ignored, not obeyed. It can
# redirect where evidence is written, which makes it worth the same suspicion the
# tool applies to any other writable configuration on the host.



SYSTEM_CONFIG = "/etc/bulwark.conf"
USER_CONFIG = "~/.config/bulwark/config"

# key -> (type, environment variable)
KNOWN_KEYS: Dict[str, Tuple[str, str]] = {
    "output_dir": ("path", "BULWARK_OUTPUT_DIR"),
    "baseline": ("path", "BULWARK_BASELINE"),
    "lookback_hours": ("int", "BULWARK_LOOKBACK_HOURS"),
    "max_log_lines": ("int", "BULWARK_MAX_LOG_LINES"),
    "timeout": ("int", "BULWARK_TIMEOUT"),
    "top": ("int", "BULWARK_TOP"),
    "no_color": ("bool", "BULWARK_NO_COLOR"),
    "pager": ("bool", "BULWARK_USE_PAGER"),
}

DEFAULTS: Dict[str, Any] = {
    "output_dir": "./bulwark-evidence",
    "baseline": "./bulwark-baseline.json",
    "lookback_hours": 72,
    "max_log_lines": 20000,
    "timeout": 15,
    "top": 10,
    "no_color": False,
    "pager": True,
}

TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}


class Settings:
    """Resolved settings plus a record of where each value came from."""

    def __init__(self) -> None:
        self.values: Dict[str, Any] = dict(DEFAULTS)
        self.sources: Dict[str, str] = {k: "default" for k in DEFAULTS}
        self.warnings: List[str] = []
        self.files_read: List[str] = []

    def get(self, key: str, override: Any = None) -> Any:
        """CLI overrides win over everything else."""
        if override is not None:
            return override
        return self.values.get(key, DEFAULTS.get(key))

    def source_of(self, key: str, override: Any = None) -> str:
        return "command line" if override is not None else self.sources.get(key, "default")

    def apply(self, key: str, raw: Any, source: str) -> None:
        if key not in KNOWN_KEYS:
            self.warnings.append(f"{source}: unknown setting '{key}' ignored")
            return
        kind = KNOWN_KEYS[key][0]
        value = _coerce(kind, raw)
        if value is None:
            self.warnings.append(
                f"{source}: setting '{key}' has an invalid {kind} value {raw!r}, ignored")
            return
        self.values[key] = value
        self.sources[key] = source

    def describe(self) -> List[str]:
        return [f"{k} = {self.values[k]}   ({self.sources[k]})" for k in sorted(self.values)]


def _coerce(kind: str, raw: Any) -> Optional[Any]:
    text = str(raw).strip()
    if kind == "int":
        try:
            value = int(text)
        except ValueError:
            return None
        return value if value > 0 else None
    if kind == "bool":
        lowered = text.lower()
        if lowered in TRUE_VALUES:
            return True
        if lowered in FALSE_VALUES:
            return False
        return None
    if kind == "path":
        return os.path.expanduser(text) if text else None
    return text


def _config_paths() -> List[str]:
    explicit = os.environ.get("BULWARK_CONFIG")
    if explicit:
        return [os.path.expanduser(explicit)]
    return [SYSTEM_CONFIG, os.path.expanduser(USER_CONFIG)]


def _is_safely_owned(path: str) -> Tuple[bool, str]:
    """A config file writable by non-root users is not trusted."""
    try:
        info = os.stat(path)
    except OSError as exc:
        return False, f"cannot stat: {exc.strerror or exc}"
    mode = statmod.S_IMODE(info.st_mode)
    if mode & 0o002:
        return False, f"world-writable (mode {oct(mode)[2:]})"
    # Owned by another non-root user is only a problem when we are not that user.
    if info.st_uid not in (0, os.getuid()):
        return False, f"owned by uid {info.st_uid}"
    return True, ""


def load_settings(argv_config: Optional[str] = None) -> Settings:
    """Build settings from config files and the environment."""
    settings = Settings()

    paths = [os.path.expanduser(argv_config)] if argv_config else _config_paths()
    for path in paths:
        if not os.path.isfile(path):
            continue
        safe, reason = _is_safely_owned(path)
        if not safe:
            settings.warnings.append(
                f"ignoring {path}: {reason}. A writable config can redirect where "
                f"evidence is written, so it is not trusted.")
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                content = fh.read()
        except OSError as exc:
            settings.warnings.append(f"cannot read {path}: {exc.strerror or exc}")
            continue
        settings.files_read.append(path)
        for number, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            if "=" not in stripped:
                settings.warnings.append(f"{path}:{number}: ignored, no '=' found")
                continue
            key, _, value = stripped.partition("=")
            settings.apply(key.strip().lower(), value.strip().strip('"').strip("'"),
                           f"{path}:{number}")

    for key, (_kind, env_var) in KNOWN_KEYS.items():
        raw = os.environ.get(env_var)
        if raw is not None and raw != "":
            settings.apply(key, raw, f"${env_var}")

    return settings


def emit_warnings(settings: Settings, stream=None) -> None:
    stream = stream or sys.stderr
    for warning in settings.warnings:
        stream.write(f"warning: {warning}\n")


SAMPLE_CONFIG = """\
# Bulwark configuration.
#
# Values here are used when the matching command-line option is not given, so
# you can set them once instead of typing them on every run. Every setting can
# also be given as an environment variable (BULWARK_OUTPUT_DIR and friends),
# which wins over this file; a command-line flag wins over both.
#
# Keep this file root-owned and not writable by anyone else. Bulwark ignores a
# config file that other users can write, because it controls where evidence
# goes.

# Where assessment evidence directories are written.
output_dir = /root/ir

# Default baseline file for `bulwark snap` and `bulwark check`.
baseline = /root/ir/baseline.json

# How far back to read logs and look for recent changes, in hours.
lookback_hours = 72

# How many findings the terminal summary shows.
top = 10

# Set to true if your terminal mangles ANSI colour.
# no_color = false

# Page long output through less so you can scroll back. Only applies when
# output is going to a terminal; piping or redirecting is never paged.
# Set $PAGER to choose a different one, or $PAGER=cat to disable.
# pager = true
"""



# ============================================================================
# bulwark/store.py
# evidence directories
# ============================================================================

# Evidence storage: timestamped incident directories.
#
# Each assessment writes into its own directory. An existing directory is never
# silently overwritten; a suffix is added instead, so a re-run during an incident
# cannot destroy the evidence from the previous one.




SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _safe(name: str, fallback: str = "host") -> str:
    """Reduce an untrusted hostname to a safe single path component.

    The hostname comes from /etc/hostname on a host that may be compromised,
    so it is treated as attacker-controlled text. Separators are collapsed and
    parent-directory sequences removed; a leading dot or dash is stripped so
    the result cannot be a hidden file or look like a command flag.
    """
    cleaned = SAFE_NAME.sub("-", (name or "").strip())
    cleaned = re.sub(r"\.{2,}", "-", cleaned)
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    cleaned = cleaned.strip("-.")[:48].strip("-.")
    return cleaned or fallback


def resolve_output_dir(path: str) -> str:
    """Expand and absolutise an output path, rejecting anything that is not a
    usable directory target."""
    expanded = os.path.abspath(os.path.expanduser(path))
    if os.path.exists(expanded) and not os.path.isdir(expanded):
        raise ValueError(f"output path exists and is not a directory: {expanded}")
    return expanded


def create_incident_dir(output_dir: str, hostname: str,
                        prefix: str = "incident") -> str:
    """Create a fresh, private directory for one assessment."""
    base = resolve_output_dir(output_dir)
    os.makedirs(base, mode=0o700, exist_ok=True)
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"{prefix}-{stamp}-{_safe(hostname)}"
    candidate = os.path.join(base, name)
    suffix = 1
    while os.path.exists(candidate):
        suffix += 1
        candidate = os.path.join(base, f"{name}-{suffix}")
    os.makedirs(candidate, mode=0o700)
    return candidate


def write_text(path: str, text: str, mode: int = 0o600) -> str:
    path = os.path.abspath(path)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, mode)
    return path


def write_manifest(incident_dir: str, entries: Dict[str, object]) -> str:
    manifest = {
        "created_at_utc": iso(utc_now()),
        "directory": incident_dir,
        **entries,
    }
    path = os.path.join(incident_dir, "manifest.json")
    write_text(path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return path


def latest_incident_dir(output_dir: str) -> Optional[str]:
    """Most recent incident directory under `output_dir`, or None."""
    try:
        base = resolve_output_dir(output_dir)
    except ValueError:
        return None
    if not os.path.isdir(base):
        return None
    candidates = []
    for name in os.listdir(base):
        full = os.path.join(base, name)
        if not os.path.isdir(full) or not name.startswith("incident-"):
            continue
        report = os.path.join(full, "report.json")
        if os.path.exists(report):
            candidates.append((os.path.getmtime(report), full))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def list_incident_dirs(output_dir: str, limit: int = 20) -> List[Tuple[str, str]]:
    """[(path, created_at)] newest first."""
    try:
        base = resolve_output_dir(output_dir)
    except ValueError:
        return []
    if not os.path.isdir(base):
        return []
    rows = []
    for name in sorted(os.listdir(base), reverse=True):
        full = os.path.join(base, name)
        if not os.path.isdir(full) or not name.startswith("incident-"):
            continue
        report = os.path.join(full, "report.json")
        created = ""
        if os.path.exists(report):
            try:
                with open(report, "r", encoding="utf-8") as fh:
                    document = json.load(fh)
                created = (document.get("assessment") or {}).get("started_at_utc", "")
            except (OSError, json.JSONDecodeError):
                created = "<unreadable>"
        rows.append((full, created))
        if len(rows) >= limit:
            break
    return rows


def load_report(incident_dir: str) -> Dict:
    path = os.path.join(incident_dir, "report.json")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)



# ============================================================================
# bulwark/detection/base.py
# detection module interface
# ============================================================================

# Detection module interface and shared helpers.




EVIDENCE_CHAR_LIMIT = 4000


class DetectionModule:
    """Base class. Subclasses implement `check(ctx, result)`.

    Contract: a module never raises out of `run`, never modifies the system,
    never executes a file it discovered, and always records why it could not
    see something rather than silently returning nothing.
    """

    name: str = "unnamed"
    version: str = "1.0"
    title: str = ""
    description: str = ""
    quick: bool = False            # included in `audit --quick`
    requires_root: bool = False    # degrades (not fails) without root
    requires_commands: tuple = ()  # module is unsupported if none are present

    def check(self, ctx: AuditContext, result: ModuleResult) -> None:  # pragma: no cover
        raise NotImplementedError

    def run(self, ctx: AuditContext) -> ModuleResult:
        result = ModuleResult(name=self.name, version=self.version, title=self.title)
        started = time.monotonic()
        try:
            if self.requires_commands and not any(ctx.host.has(c) for c in self.requires_commands):
                result.status = ModuleStatus.UNSUPPORTED
                result.reason = (
                    "none of the required utilities are present: "
                    + ", ".join(self.requires_commands)
                )
                return result
            if self.requires_root and not ctx.facts.is_root:
                result.gap(
                    area=self.name,
                    reason="running without root; several checks in this module cannot read their sources",
                    impact="findings from this module are based on partial evidence",
                    needs_root=True,
                )
            self.check(ctx, result)
        except Exception as exc:  # noqa: BLE001 - a failing module must not stop the audit
            result.status = ModuleStatus.FAILED
            result.reason = f"{type(exc).__name__}: {exc}"
            ctx.log("error", f"module {self.name} failed: {type(exc).__name__}: {exc}")
        finally:
            result.duration_ms = int((time.monotonic() - started) * 1000)
        return result


# --------------------------------------------------------------------------
# Helpers shared by modules
# --------------------------------------------------------------------------

def file_evidence(ctx: AuditContext, path: str, note: str = "",
                  max_chars: int = EVIDENCE_CHAR_LIMIT,
                  content: Optional[str] = None) -> Evidence:
    """Capture (redacted, truncated) file content plus metadata as evidence."""
    info = ctx.host.stat(path)
    meta: Dict[str, Any] = {}
    if info.exists:
        meta = {
            "mode": info.mode_octal,
            "owner": info.owner,
            "group": info.group,
            "size": info.size,
            "mtime_utc": iso_from_epoch(info.mtime),
            "ctime_utc": iso_from_epoch(info.ctime),
        }
        if info.is_symlink:
            meta["symlink_target"] = info.symlink_target
    if note:
        meta["note"] = note

    if content is None:
        text, _trunc, err = ctx.host.read_text(path)
    else:
        text, err = content, None
    if text is None:
        return Evidence(source="file", locator=path, content="", error=err, meta=meta)
    body, was_truncated = truncate(redact(text), max_chars)
    return Evidence(source="file", locator=path, content=body,
                    truncated=was_truncated, meta=meta)


def lines_evidence(path: str, lines: List[str], note: str = "",
                   max_chars: int = EVIDENCE_CHAR_LIMIT,
                   source: str = "file") -> Evidence:
    body, was_truncated = truncate(redact("\n".join(lines)), max_chars)
    meta = {"note": note} if note else {}
    meta["line_count"] = len(lines)
    return Evidence(source=source, locator=path, content=body,
                    truncated=was_truncated, meta=meta)


def stat_evidence(path: str, info: FileInfo, note: str = "") -> Evidence:
    meta = info.to_dict()
    meta.pop("path", None)
    for key in ("mtime", "ctime", "atime"):
        value = getattr(info, key, None)
        if value is not None:
            meta[f"{key}_utc"] = iso_from_epoch(value)
            meta.pop(key, None)
    if note:
        meta["note"] = note
    summary = (
        f"mode={info.mode_octal} owner={info.owner}:{info.group} "
        f"size={info.size} mtime={iso_from_epoch(info.mtime)}"
    )
    return Evidence(source="file", locator=path, content=summary, meta=meta)


def make_finding(module: str, rule_id: str, title: str, severity: Severity,
                 confidence: Confidence, category: Category, target: str,
                 why: str, impact: str = "", recommendation: str = "",
                 evidence: Optional[List[Evidence]] = None,
                 timestamps: Optional[Dict[str, Optional[str]]] = None,
                 remediation_risk: str = "",
                 tags: Optional[List[str]] = None,
                 correlation_key: Optional[str] = None,
                 partial_evidence: bool = False,
                 baseline_state: BaselineState = BaselineState.NO_BASELINE,
                 references: Optional[List[str]] = None) -> Finding:
    return Finding(
        rule_id=rule_id, module=module, title=title, severity=severity,
        confidence=confidence, category=category, target=target, why=why,
        impact=impact, recommendation=recommendation,
        evidence=evidence or [], timestamps=timestamps or {},
        remediation_risk=remediation_risk, tags=tags or [],
        correlation_key=correlation_key, partial_evidence=partial_evidence,
        baseline_state=baseline_state, references=references or [],
    )


def baseline_state_for(ctx: AuditContext, section: str, key: str,
                       current_value: Any = None) -> BaselineState:
    """Classify an observed item against the baseline.

    NO_BASELINE when no baseline is loaded, NEW when the key is absent, KNOWN
    when present and equal, CHANGED when present but different.
    """
    data = ctx.baseline_section(section)
    if data is None:
        return BaselineState.NO_BASELINE
    items = data.get("items", data)
    if not isinstance(items, dict):
        return BaselineState.NO_BASELINE
    if key not in items:
        return BaselineState.NEW
    if current_value is None:
        return BaselineState.KNOWN
    return BaselineState.KNOWN if items[key] == current_value else BaselineState.CHANGED


def adjust_for_baseline(severity: Severity, confidence: Confidence,
                        state: BaselineState) -> tuple:
    """A finding present in a validated baseline is less likely to be new
    red-team activity, so confidence drops. Severity never drops below HIGH
    on the strength of a baseline alone: a baseline taken from an already
    compromised host would otherwise hide the compromise."""
    if state is BaselineState.KNOWN:
        if severity.rank >= Severity.CRITICAL.rank:
            return severity, confidence           # never suppressed
        if confidence is Confidence.HIGH:
            return severity, Confidence.MEDIUM
        if confidence is Confidence.MEDIUM:
            return severity, Confidence.LOW
    if state is BaselineState.NEW and confidence is Confidence.LOW:
        return severity, Confidence.MEDIUM
    return severity, confidence



# ============================================================================
# bulwark/detection/accounts.py
# detection: accounts and privilege
# ============================================================================

# Accounts, groups and privilege escalation paths.
#
# Password hashes are parsed for *status* only (empty, locked, algorithm). No
# hash, salt or credential ever reaches a finding or a report.




EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)


class Account:
    __slots__ = ("name", "uid", "gid", "gecos", "home", "shell", "line_no")

    def __init__(self, name, uid, gid, gecos, home, shell, line_no):
        self.name, self.uid, self.gid = name, uid, gid
        self.gecos, self.home, self.shell = gecos, home, shell
        self.line_no = line_no

    def to_dict(self):
        return {
            "uid": self.uid, "gid": self.gid, "home": self.home,
            "shell": self.shell, "gecos": self.gecos,
        }


class AccountsModule(DetectionModule):
    name = "accounts"
    version = "1.1"
    title = "Users, groups and privilege escalation"
    description = (
        "Parses passwd/group/shadow metadata and sudoers rules to find "
        "root-equivalent accounts, unexpected administrative access and "
        "dangerous privilege delegation."
    )
    quick = True

    def check(self, ctx: AuditContext, result: ModuleResult) -> None:
        accounts, parse_errors = self._parse_passwd(ctx, result)
        if accounts is None:
            result.reason = "could not read /etc/passwd"
            return

        groups = self._parse_groups(ctx, result)
        shadow = self._parse_shadow(ctx, result)

        result.facts["accounts"] = {a.name: a.to_dict() for a in accounts}
        result.facts["groups"] = {g: sorted(m) for g, m in groups.items()}
        result.facts["uid0_accounts"] = sorted(a.name for a in accounts if a.uid == 0)
        result.facts["admin_members"] = self._admin_members(accounts, groups)
        result.facts["interactive_accounts"] = sorted(
            a.name for a in accounts if a.shell in INTERACTIVE_SHELLS
        )

        for err in parse_errors:
            result.gap("account-parsing", err, "some accounts may not be evaluated")

        self._check_uid0(ctx, result, accounts)
        self._check_duplicates(ctx, result, accounts)
        self._check_admin_groups(ctx, result, accounts, groups)
        self._check_root_equivalent_groups(ctx, result, groups)
        self._check_shells(ctx, result, accounts)
        self._check_shadow_status(ctx, result, accounts, shadow)
        self._check_recent_changes(ctx, result, accounts, shadow)
        self._check_critical_file_perms(ctx, result)
        self._check_sudoers(ctx, result, accounts, groups)
        self._check_home_dirs(ctx, result, accounts)

    # ------------------------------------------------------------- parsing

    def _parse_passwd(self, ctx, result) -> Tuple[Optional[List[Account]], List[str]]:
        lines, err = ctx.host.read_lines("/etc/passwd")
        if err:
            # Not a module failure: FAILED is reserved for the module itself
            # breaking. An unreadable account database is an environmental
            # limit, and it is reported as a visibility gap so that the absence
            # of account findings is not mistaken for an absence of problems.
            result.status = ModuleStatus.SKIPPED
            result.gap("/etc/passwd", f"unreadable: {err}",
                       "no account analysis is possible",
                       needs_root=not ctx.facts.is_root)
            return None, []
        accounts, errors = [], []
        for i, line in enumerate(lines, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                errors.append(f"/etc/passwd line {i}: malformed entry with {len(parts)} fields")
                continue
            name, _pw, uid, gid, gecos, home, shell = parts[:7]
            try:
                uid_i, gid_i = int(uid), int(gid)
            except ValueError:
                errors.append(f"/etc/passwd line {i}: non-numeric uid/gid for {name!r}")
                continue
            accounts.append(Account(name, uid_i, gid_i, gecos, home, shell.strip(), i))
        result.checks_run += 1
        return accounts, errors

    def _parse_groups(self, ctx, result) -> Dict[str, List[str]]:
        groups: Dict[str, List[str]] = {}
        lines, err = ctx.host.read_lines("/etc/group")
        if err:
            result.gap("/etc/group", f"unreadable: {err}",
                       "group membership cannot be evaluated")
            return groups
        for line in lines:
            parts = line.split(":")
            if len(parts) < 4:
                continue
            name, _pw, _gid, members = parts[:4]
            groups[name] = [m for m in members.split(",") if m]
        result.checks_run += 1
        return groups

    def _parse_shadow(self, ctx, result) -> Dict[str, Dict]:
        """Extract *status only* from /etc/shadow. Hashes are never retained."""
        shadow: Dict[str, Dict] = {}
        lines, err = ctx.host.read_lines("/etc/shadow")
        if err:
            result.gap(
                "/etc/shadow",
                f"unreadable: {err}",
                "cannot tell locked accounts from accounts with an active password",
                needs_root=True,
            )
            return shadow
        for line in lines:
            parts = line.split(":")
            if len(parts) < 2:
                continue
            name, pw = parts[0], parts[1]
            entry = {
                "empty_password": pw == "",
                "locked": pw.startswith("!") or pw.startswith("*"),
                "algorithm": None,
                "last_change_days": None,
                "expire_days": None,
            }
            stripped = pw.lstrip("!")
            if stripped.startswith("$"):
                segs = stripped.split("$")
                if len(segs) > 1:
                    entry["algorithm"] = {
                        "1": "md5crypt (weak)", "2a": "bcrypt", "2b": "bcrypt",
                        "2y": "bcrypt", "5": "sha256crypt", "6": "sha512crypt",
                        "7": "scrypt", "y": "yescrypt", "gy": "gost-yescrypt",
                    }.get(segs[1], f"id={segs[1]}")
            if len(parts) > 2 and parts[2].isdigit():
                entry["last_change_days"] = int(parts[2])
            if len(parts) > 7 and parts[7].isdigit():
                entry["expire_days"] = int(parts[7])
            shadow[name] = entry
        result.checks_run += 1
        return shadow

    def _admin_members(self, accounts, groups) -> Dict[str, List[str]]:
        primary_gid_names = {}
        for g, members in groups.items():
            primary_gid_names[g] = set(members)
        out = {}
        for g in ADMIN_GROUPS:
            if g in groups:
                out[g] = sorted(set(groups[g]))
        return out

    # -------------------------------------------------------------- checks

    def _check_uid0(self, ctx, result, accounts):
        result.checks_run += 1
        uid0 = [a for a in accounts if a.uid == 0]
        extra = [a for a in uid0 if a.name != "root"]
        for acct in extra:
            state = baseline_state_for(ctx, "accounts", acct.name, None)
            sev, conf = adjust_for_baseline(Severity.CRITICAL, Confidence.HIGH, state)
            result.add(make_finding(
                module=self.name, rule_id="ACCT-UID0-EXTRA",
                title=f"Non-root account '{acct.name}' has UID 0",
                severity=sev, confidence=conf, category=Category.PRIVESC,
                target=f"user:{acct.name}",
                why=(
                    f"'{acct.name}' is configured with UID 0 in /etc/passwd, which makes it "
                    "fully root-equivalent. The kernel authorises by UID, not by account "
                    "name, so this account has every privilege root has. Distributions ship "
                    "exactly one UID 0 account, named root."
                ),
                impact=(
                    "Anyone who can authenticate as this account owns the host: they can "
                    "read every file, modify any binary, install persistence and disable "
                    "logging."
                ),
                recommendation=(
                    f"Confirm with your team that '{acct.name}' was not created by you. If it "
                    "was not, treat the host as compromised: preserve evidence, then (in a "
                    "later containment step) lock the account with `usermod -L` and remove "
                    "its UID 0 assignment. Check for other access the same actor may hold "
                    "before removing this one."
                ),
                evidence=[
                    lines_evidence("/etc/passwd",
                                   [f"{acct.name}:x:{acct.uid}:{acct.gid}:{acct.gecos}:{acct.home}:{acct.shell}"],
                                   note=f"line {acct.line_no}"),
                    stat_evidence("/etc/passwd", ctx.host.stat("/etc/passwd"),
                                  note="modification time of the account database"),
                ],
                timestamps={"passwd_mtime_utc": iso_from_epoch(ctx.host.stat("/etc/passwd").mtime)},
                remediation_risk=(
                    "If this account is actually used by a competition service, locking it "
                    "will break that service. Verify before acting."
                ),
                tags=["uid0", "privilege-escalation", "high-value"],
                correlation_key=f"account:{acct.name}",
                baseline_state=state,
            ))
        result.facts["uid0_extra"] = [a.name for a in extra]

    def _check_duplicates(self, ctx, result, accounts):
        result.checks_run += 1
        by_uid: Dict[int, List[str]] = {}
        by_name: Dict[str, int] = {}
        for a in accounts:
            by_uid.setdefault(a.uid, []).append(a.name)
            by_name[a.name] = by_name.get(a.name, 0) + 1

        for uid, names in sorted(by_uid.items()):
            if len(names) < 2:
                continue
            sev = Severity.HIGH if uid == 0 else Severity.MEDIUM
            result.add(make_finding(
                module=self.name, rule_id="ACCT-DUP-UID",
                title=f"UID {uid} is shared by {len(names)} accounts: {', '.join(names)}",
                severity=sev, confidence=Confidence.HIGH, category=Category.PRIVESC,
                target=f"uid:{uid}",
                why=(
                    "Several account names map to the same UID. Every one of them has "
                    "identical file ownership and privileges, which is a well-known way to "
                    "hide a second root login behind an innocuous-looking name. A small "
                    "number of distributions ship one intentional alias (for example "
                    "'operator'), so check provenance before concluding."
                ),
                impact="A second credential grants the privileges of the first account.",
                recommendation=(
                    "Determine which of these names your team created. Compare against your "
                    "baseline or a known-good image of the same distribution."
                ),
                evidence=[lines_evidence(
                    "/etc/passwd",
                    [f"{a.name}:x:{a.uid}:{a.gid}:{a.gecos}:{a.home}:{a.shell}"
                     for a in accounts if a.uid == uid])],
                tags=["duplicate-uid"],
                correlation_key=f"uid:{uid}",
                baseline_state=baseline_state_for(ctx, "accounts", names[0]),
            ))

        for name, count in sorted(by_name.items()):
            if count > 1:
                result.add(make_finding(
                    module=self.name, rule_id="ACCT-DUP-NAME",
                    title=f"Account name '{name}' appears {count} times in /etc/passwd",
                    severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                    category=Category.ACCOUNT, target=f"user:{name}",
                    why=(
                        "Duplicate entries for one name mean the resolution order decides "
                        "which UID, home directory and shell apply. This is a plausible way "
                        "to shadow a legitimate account, and it is never the result of "
                        "normal administration."
                    ),
                    impact="The effective configuration of this account is ambiguous.",
                    recommendation="Inspect /etc/passwd directly and establish which entry you created.",
                    evidence=[file_evidence(ctx, "/etc/passwd", note="full account database")],
                    tags=["duplicate-account"],
                ))

    def _check_admin_groups(self, ctx, result, accounts, groups):
        result.checks_run += 1
        baseline_admins = ctx.baseline_section("admin_members")
        for group in ("sudo", "wheel", "admin", "root"):
            members = set(groups.get(group, []))
            # primary-group membership counts too
            gid = self._gid_of(ctx, group)
            if gid is not None:
                members |= {a.name for a in accounts if a.gid == gid}
            if not members:
                continue
            result.facts.setdefault("admin_members", {})[group] = sorted(members)

            known = None
            if baseline_admins:
                items = baseline_admins.get("items", baseline_admins)
                if isinstance(items, dict) and group in items:
                    known = set(items[group])

            for member in sorted(members):
                if member == "root":
                    continue
                if known is not None:
                    state = baseline_state_for(ctx, "accounts", member)
                    if member in known:
                        continue   # present in baseline: expected administrator
                    sev, conf = Severity.HIGH, Confidence.HIGH
                    why_suffix = (
                        f" This membership is not present in the saved baseline, so it was "
                        f"added after the baseline was taken."
                    )
                else:
                    state = baseline_state_for(ctx, "accounts", member)
                    sev, conf = Severity.MEDIUM, Confidence.MEDIUM
                    why_suffix = (
                        " No baseline is available, so this is reported for review rather "
                        "than as confirmed unauthorised access."
                    )
                if member not in {a.name for a in accounts}:
                    sev, conf = Severity.MEDIUM, Confidence.MEDIUM
                    why_suffix += " The member does not exist in /etc/passwd."

                result.add(make_finding(
                    module=self.name, rule_id="ACCT-ADMIN-GROUP",
                    title=f"Account '{member}' is a member of administrative group '{group}'",
                    severity=sev, confidence=conf, category=Category.PRIVESC,
                    target=f"user:{member}|group:{group}",
                    why=(
                        f"Membership of '{group}' normally allows this account to run "
                        f"commands as root via sudo, which is a complete privilege "
                        f"escalation path from a user session to root." + why_suffix
                    ),
                    impact="This account can become root and therefore control the host.",
                    recommendation=(
                        f"Confirm with your team that '{member}' is meant to be an "
                        f"administrator. Cross-check against sudoers rules and the account's "
                        f"login history before changing anything."
                    ),
                    evidence=[lines_evidence(
                        "/etc/group",
                        [f"{group}:x:{gid if gid is not None else '?'}:{','.join(sorted(members))}"])],
                    remediation_risk=(
                        "Removing an administrator who is actually your teammate locks them "
                        "out mid-round. Confirm first."
                    ),
                    tags=["admin-group", "privilege-escalation"],
                    correlation_key=f"account:{member}",
                    baseline_state=state,
                ))

    def _check_root_equivalent_groups(self, ctx, result, groups):
        result.checks_run += 1
        for group, reason in ROOT_EQUIVALENT_GROUPS.items():
            if group in ("sudo", "wheel", "admin"):
                continue    # already covered above
            members = [m for m in groups.get(group, []) if m != "root"]
            if not members:
                continue
            result.add(make_finding(
                module=self.name, rule_id="ACCT-ROOT-EQUIV-GROUP",
                title=f"Group '{group}' grants a root-equivalent path to: {', '.join(members)}",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                category=Category.PRIVESC, target=f"group:{group}",
                why=(
                    f"Membership of '{group}' is not a sudo rule, so it is easy to overlook, "
                    f"but it is still a route to full control: {reason}."
                ),
                impact="These accounts can escalate to root without appearing in sudoers.",
                recommendation=(
                    f"Verify each member is intentional. If the host runs containers as part "
                    f"of the scored services, membership may be legitimate - confirm before "
                    f"removing."
                ),
                evidence=[lines_evidence("/etc/group", [f"{group}:x:*:{','.join(members)}"])],
                remediation_risk="Removing docker/lxd membership can break container services.",
                tags=["privilege-escalation", "indirect-root"],
            ))

    def _check_shells(self, ctx, result, accounts):
        result.checks_run += 1
        suspicious = []
        for a in accounts:
            if a.shell not in INTERACTIVE_SHELLS:
                continue
            if a.uid == 0 and a.name == "root":
                continue
            # A service account that is not expected to log in but has a shell.
            looks_system = a.uid < 1000 and a.uid != 0
            unknown_name = a.name not in KNOWN_SYSTEM_ACCOUNTS
            if looks_system and unknown_name:
                suspicious.append(a)
                state = baseline_state_for(ctx, "accounts", a.name,
                                           {"uid": a.uid, "shell": a.shell, "home": a.home,
                                            "gid": a.gid, "gecos": a.gecos})
                sev, conf = adjust_for_baseline(Severity.HIGH, Confidence.MEDIUM, state)
                result.add(make_finding(
                    module=self.name, rule_id="ACCT-SYSTEM-SHELL",
                    title=f"System-range account '{a.name}' (UID {a.uid}) has an interactive shell",
                    severity=sev, confidence=conf, category=Category.ACCOUNT,
                    target=f"user:{a.name}",
                    why=(
                        f"'{a.name}' sits in the system UID range (below 1000) where accounts "
                        f"normally exist to own files and run daemons, not to log in. It is "
                        f"configured with {a.shell}, and the name does not match any account "
                        f"this tool recognises from a stock distribution. Naming a backdoor "
                        f"account something service-shaped is a common way to blend into a "
                        f"passwd file."
                    ),
                    impact="Provides an interactive foothold that looks like infrastructure.",
                    recommendation=(
                        f"Check whether a package owns this account (`dpkg -S` / `rpm -qf` on "
                        f"its home directory), review its authorized_keys and last login, and "
                        f"compare with a clean image of the same distribution."
                    ),
                    evidence=[lines_evidence(
                        "/etc/passwd",
                        [f"{a.name}:x:{a.uid}:{a.gid}:{a.gecos}:{a.home}:{a.shell}"],
                        note=f"line {a.line_no}")],
                    remediation_risk=(
                        "Some third-party software legitimately creates a system account with "
                        "a shell. Confirm before disabling."
                    ),
                    tags=["account", "suspicious-shell"],
                    correlation_key=f"account:{a.name}",
                    baseline_state=state,
                ))
        result.facts["system_accounts_with_shell"] = [a.name for a in suspicious]

    def _check_shadow_status(self, ctx, result, accounts, shadow):
        result.checks_run += 1
        if not shadow:
            return
        passwd_names = {a.name for a in accounts}
        for name, entry in sorted(shadow.items()):
            if entry["empty_password"]:
                result.add(make_finding(
                    module=self.name, rule_id="ACCT-EMPTY-PASSWORD",
                    title=f"Account '{name}' has an empty password field",
                    severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                    category=Category.AUTHENTICATION, target=f"user:{name}",
                    why=(
                        "The password field in /etc/shadow is empty, which means "
                        "authentication succeeds with no password at all wherever PAM "
                        "permits it (console, su, and SSH if PermitEmptyPasswords is on). "
                        "This is never a default configuration."
                    ),
                    impact="Anyone who can reach a login prompt can take this account.",
                    recommendation=(
                        "Set a password immediately or lock the account. If this is a "
                        "privileged account, assume it has already been used and look for "
                        "follow-on persistence."
                    ),
                    evidence=[Evidence(
                        source="file", locator="/etc/shadow",
                        content=f"{name}: password field is empty (hash never recorded by this tool)",
                        meta={"redaction": "hash material intentionally not collected"})],
                    tags=["empty-password", "authentication"],
                    correlation_key=f"account:{name}",
                ))
            if name not in passwd_names:
                result.add(make_finding(
                    module=self.name, rule_id="ACCT-SHADOW-ORPHAN",
                    title=f"/etc/shadow entry '{name}' has no matching /etc/passwd account",
                    severity=Severity.LOW, confidence=Confidence.MEDIUM,
                    category=Category.ACCOUNT, target=f"user:{name}",
                    why=(
                        "The credential database and the account database disagree. This is "
                        "usually leftover state from a removed account, but it can also mean "
                        "one of the two files was edited by hand."
                    ),
                    impact="Indicates manual editing of authentication files.",
                    recommendation="Run `pwck -r` to list inconsistencies and reconcile them.",
                    evidence=[Evidence(source="derived", locator="/etc/shadow",
                                       content=f"orphan shadow entry: {name}")],
                    tags=["consistency"],
                ))
        for a in accounts:
            if a.name not in shadow:
                result.add(make_finding(
                    module=self.name, rule_id="ACCT-PASSWD-NO-SHADOW",
                    title=f"Account '{a.name}' has no /etc/shadow entry",
                    severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                    category=Category.AUTHENTICATION, target=f"user:{a.name}",
                    why=(
                        "An account present in /etc/passwd with no shadow entry has no "
                        "password policy and, depending on PAM configuration, may be "
                        "treated as having no password."
                    ),
                    impact="Possible password-free authentication path.",
                    recommendation="Run `pwck -r`; lock the account if it should not log in.",
                    evidence=[Evidence(source="derived", locator="/etc/passwd",
                                       content=f"{a.name} present in passwd, absent from shadow")],
                    tags=["consistency", "authentication"],
                    correlation_key=f"account:{a.name}",
                ))

    def _check_recent_changes(self, ctx, result, accounts, shadow):
        """Timestamps are supporting evidence, never proof: an attacker with
        root can set them to anything."""
        result.checks_run += 1
        lookback_days = max(1, ctx.config.log_lookback_hours // 24)
        today_days = int((_dt.datetime.now(_dt.timezone.utc) - EPOCH).days)
        recent = []
        for name, entry in sorted(shadow.items()):
            last = entry.get("last_change_days")
            if last is None or last == 0:
                continue
            age = today_days - last
            if 0 <= age <= lookback_days:
                recent.append((name, age))
        if recent:
            result.add(make_finding(
                module=self.name, rule_id="ACCT-RECENT-PASSWORD-CHANGE",
                title=f"{len(recent)} account password(s) changed in the last {lookback_days} day(s)",
                severity=Severity.LOW, confidence=Confidence.LOW,
                category=Category.AUTHENTICATION, target="shadow:last-change",
                why=(
                    "Recent password changes are expected at the start of a competition "
                    "because blue teams rotate credentials. They are listed here so you can "
                    "confirm each change was yours. An attacker who changes a password locks "
                    "you out of an account you still believe you control."
                ),
                impact="A change you did not make means someone else controls that credential.",
                recommendation=(
                    "Confirm each listed change against your team's credential rotation log. "
                    "Rotate anything you cannot account for."
                ),
                evidence=[Evidence(
                    source="file", locator="/etc/shadow",
                    content="\n".join(f"{n}: changed ~{d} day(s) ago" for n, d in recent),
                    meta={"note": "derived from the last-change field; hashes not read"})],
                tags=["credential-rotation", "timestamp-evidence"],
                partial_evidence=True,
            ))

        passwd_stat = ctx.host.stat("/etc/passwd")
        shadow_stat = ctx.host.stat("/etc/shadow")
        cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=ctx.config.log_lookback_hours)
        for label, info in (("/etc/passwd", passwd_stat), ("/etc/shadow", shadow_stat)):
            if not info.exists or info.mtime is None:
                continue
            mtime = _dt.datetime.fromtimestamp(info.mtime, _dt.timezone.utc)
            if mtime >= cutoff:
                result.add(make_finding(
                    module=self.name, rule_id="ACCT-DB-RECENTLY-MODIFIED",
                    title=f"{label} was modified within the last {ctx.config.log_lookback_hours} hours",
                    severity=Severity.LOW, confidence=Confidence.LOW,
                    category=Category.ACCOUNT, target=label,
                    why=(
                        f"{label} changed recently. On a system you have just received this "
                        f"is expected if you have already rotated passwords; if you have not "
                        f"touched it, something else edited the account database. Note that "
                        f"file timestamps can be forged by anyone with root, so treat this as "
                        f"a lead rather than a fact."
                    ),
                    impact="May indicate account creation or modification by another party.",
                    recommendation=(
                        "Correlate with auth logs and package manager logs for the same "
                        "window, and compare account lists against your baseline."
                    ),
                    evidence=[stat_evidence(label, info)],
                    timestamps={"mtime_utc": iso_from_epoch(info.mtime),
                                "ctime_utc": iso_from_epoch(info.ctime)},
                    tags=["timestamp-evidence"],
                    partial_evidence=True,
                ))

    def _check_critical_file_perms(self, ctx, result):
        result.checks_run += 1
        expectations = {
            "/etc/passwd": (0o644, "world-readable by design, but must not be writable by non-root"),
            "/etc/group": (0o644, "world-readable by design, but must not be writable by non-root"),
            "/etc/shadow": (0o640, "must not be readable by ordinary users"),
            "/etc/gshadow": (0o640, "must not be readable by ordinary users"),
            "/etc/sudoers": (0o440, "must be read-only and root-owned"),
        }
        for path, (expected, note) in expectations.items():
            info = ctx.host.stat(path)
            if not info.exists:
                continue
            mode = info.mode & 0o7777 if info.mode else 0
            problems = []
            if info.uid not in (0, None):
                problems.append(f"owned by UID {info.uid} ({info.owner}) instead of root")
            if mode & 0o002:
                problems.append("world-writable")
            if mode & 0o020 and path in ("/etc/shadow", "/etc/sudoers", "/etc/gshadow"):
                problems.append("group-writable")
            if path in ("/etc/shadow", "/etc/gshadow") and mode & 0o004:
                problems.append("world-readable")
            if not problems:
                continue
            severity = Severity.CRITICAL if ("world-writable" in problems or
                                             path == "/etc/sudoers") else Severity.HIGH
            result.add(make_finding(
                module=self.name, rule_id="ACCT-FILE-PERMS",
                title=f"{path} has unsafe permissions: {', '.join(problems)}",
                severity=severity, confidence=Confidence.HIGH,
                category=Category.PRIVESC, target=path,
                why=(
                    f"{path} is expected to be mode {oct(expected)[2:]} and root-owned - {note}. "
                    f"It is currently mode {info.mode_octal} owned by {info.owner}:{info.group}. "
                    f"A writable account database or sudoers file is a direct, trivially "
                    f"exploitable path to root for any local user."
                ),
                impact="Any local user may be able to grant themselves root.",
                recommendation=(
                    f"Restore the expected ownership and mode "
                    f"(`chown root:root {path}` and `chmod {oct(expected)[2:]} {path}`) once "
                    f"you have recorded the current state as evidence. For /etc/sudoers, "
                    f"validate with `visudo -c` afterwards."
                ),
                evidence=[stat_evidence(path, info)],
                timestamps={"mtime_utc": iso_from_epoch(info.mtime)},
                tags=["file-permissions", "privilege-escalation"],
            ))

    # -------------------------------------------------------------- sudoers

    def _check_sudoers(self, ctx, result, accounts, groups):
        result.checks_run += 1
        files = ["/etc/sudoers"]
        drop_in, err = ctx.host.listdir("/etc/sudoers.d")
        if err and err != "not found":
            result.gap("/etc/sudoers.d", err, "sudo rules in drop-in files were not evaluated",
                       needs_root=True)
        for name in drop_in:
            if name.endswith("~") or name.endswith(".bak") or name.startswith("."):
                continue
            files.append(os.path.join("/etc/sudoers.d", name))

        admin_members = set()
        for g in ("sudo", "wheel", "admin"):
            admin_members |= set(groups.get(g, []))

        collected_rules = []
        for path in files:
            info = ctx.host.stat(path)
            if not info.exists:
                continue
            if path != "/etc/sudoers":
                self._check_sudoers_file_perms(ctx, result, path, info)
            lines, read_err = ctx.host.read_lines(path)
            if read_err:
                result.gap(path, f"unreadable: {read_err}",
                           "sudo rules in this file were not evaluated", needs_root=True)
                continue
            for i, raw in enumerate(lines, 1):
                line = raw.strip()
                if not line or line.startswith("#") and not line.startswith("#include"):
                    continue
                collected_rules.append({"file": path, "line": i, "rule": line})
                self._evaluate_sudo_rule(ctx, result, path, i, line, admin_members, accounts)
        result.facts["sudoers_rules"] = collected_rules

    def _check_sudoers_file_perms(self, ctx, result, path, info):
        mode = (info.mode or 0) & 0o7777
        problems = []
        if info.uid not in (0, None):
            problems.append(f"owned by {info.owner}")
        if mode & 0o022:
            problems.append(f"writable beyond root (mode {info.mode_octal})")
        if not problems:
            return
        result.add(make_finding(
            module=self.name, rule_id="ACCT-SUDOERSD-PERMS",
            title=f"Sudo drop-in file {path} is unsafely owned or writable",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            category=Category.PRIVESC, target=path,
            why=(
                f"{path} is included in the sudo policy and is {', '.join(problems)}. "
                f"A non-root user who can write here can grant themselves unrestricted root. "
                f"sudo itself refuses world-writable files, but the exposure window and the "
                f"intent behind such a change still matter."
            ),
            impact="Direct local privilege escalation to root.",
            recommendation=f"`chown root:root {path}` and `chmod 0440 {path}`; then `visudo -c`.",
            evidence=[stat_evidence(path, info), file_evidence(ctx, path)],
            tags=["sudoers", "privilege-escalation"],
        ))

    def _evaluate_sudo_rule(self, ctx, result, path, line_no, line, admin_members, accounts):
        lowered = line.lower()

        if lowered.startswith("defaults"):
            if "!authenticate" in lowered.replace(" ", ""):
                result.add(make_finding(
                    module=self.name, rule_id="ACCT-SUDO-NOAUTH",
                    title=f"sudo is configured not to authenticate ({path}:{line_no})",
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    category=Category.PRIVESC, target=f"{path}:{line_no}",
                    why=(
                        "`Defaults !authenticate` removes the password prompt from sudo for "
                        "the scope it applies to. Any user with a sudo rule becomes root with "
                        "no credential challenge, so stealing a shell is enough."
                    ),
                    impact="Password compromise is no longer required to reach root.",
                    recommendation="Remove the directive unless your team added it deliberately.",
                    evidence=[lines_evidence(path, [redact(line)], note=f"line {line_no}")],
                    tags=["sudoers", "nopasswd"],
                ))
            if "targetpw" in lowered or "rootpw" in lowered:
                return
            return

        if lowered.startswith(("#include", "@include")):
            return
        if "=" not in line:
            return
        if lowered.startswith(("user_alias", "cmnd_alias", "host_alias", "runas_alias")):
            return

        principal = line.split()[0]
        is_group = principal.startswith("%")
        subject = principal.lstrip("%+")
        nopasswd = "NOPASSWD" in line.upper()
        grants_all = self._grants_all_commands(line)

        # Is this an expected administrator?
        expected = (
            subject in ("root", "ALL")
            or (is_group and subject in ("sudo", "wheel", "admin"))
            or (not is_group and subject in admin_members)
        )

        if nopasswd and grants_all:
            severity = Severity.CRITICAL
            confidence = Confidence.HIGH
            detail = (
                "This rule grants every command as root with no password. It is the single "
                "most direct persistence mechanism available through sudo: the attacker "
                "needs only a shell as this principal."
            )
        elif nopasswd:
            escapes = self._shell_escape_commands(line)
            if escapes:
                severity, confidence = Severity.HIGH, Confidence.HIGH
                detail = (
                    f"The rule is restricted to specific commands, but {', '.join(sorted(escapes))} "
                    f"can spawn a shell or write arbitrary files while running as root, so the "
                    f"restriction provides no real containment."
                )
            else:
                severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
                detail = (
                    "The rule allows a specific command without a password. This is a common "
                    "legitimate pattern for service management, but it removes the credential "
                    "check, so the allowed command must be safe to run as root."
                )
        elif grants_all and not expected:
            severity, confidence = Severity.HIGH, Confidence.MEDIUM
            detail = (
                "This principal can run any command as root. That may be intended, but it is "
                "not an account or group this tool recognises as an established administrator."
            )
        else:
            return

        state = baseline_state_for(ctx, "sudoers", f"{path}:{line.strip()}")
        severity, confidence = adjust_for_baseline(severity, confidence, state)

        result.add(make_finding(
            module=self.name, rule_id="ACCT-SUDO-RULE",
            title=f"Permissive sudo rule for '{principal}' in {os.path.basename(path)}",
            severity=severity, confidence=confidence, category=Category.PRIVESC,
            target=f"{path}:{line_no}",
            why=(
                f"Rule at {path} line {line_no}: `{redact(line)}`. {detail}"
            ),
            impact="Grants root to whoever controls this account or group.",
            recommendation=(
                "Confirm the rule is yours. If it is not, record it as evidence before "
                "changing anything, then validate the file with `visudo -c` after any edit - "
                "a syntax error in sudoers can lock your whole team out of sudo."
            ),
            evidence=[lines_evidence(path, [redact(line)], note=f"line {line_no}")],
            remediation_risk=(
                "A broken sudoers file denies sudo to everyone, including your team. Always "
                "`visudo -c` before and after, and keep a root shell open while editing."
            ),
            tags=["sudoers", "privilege-escalation"] + (["nopasswd"] if nopasswd else []),
            correlation_key=f"account:{subject}" if not is_group else None,
            baseline_state=state,
        ))

    @staticmethod
    def _grants_all_commands(line: str) -> bool:
        _, _, rhs = line.partition("=")
        rhs = rhs.strip()
        # strip runas spec "(ALL:ALL)"
        if rhs.startswith("("):
            _, _, rhs = rhs.partition(")")
        rhs = rhs.replace("NOPASSWD:", "").replace("PASSWD:", "")
        rhs = rhs.replace("SETENV:", "").replace("NOEXEC:", "").strip()
        commands = [c.strip() for c in rhs.split(",") if c.strip()]
        return any(c == "ALL" for c in commands)

    @staticmethod
    def _shell_escape_commands(line: str) -> set:
        _, _, rhs = line.partition("=")
        if rhs.strip().startswith("("):
            _, _, rhs = rhs.partition(")")
        found = set()
        for token in rhs.replace(",", " ").split():
            base = token.strip().rsplit("/", 1)[-1].lower()
            if base in SUDO_SHELL_ESCAPE_BINARIES:
                found.add(base)
        return found

    # ------------------------------------------------------------ home dirs

    # Service accounts are routinely given a shared system directory as their
    # "home". Those are not personal directories, and reporting /bin as a
    # world-writable home directory is noise that buries the real finding.
    NON_HOME_PATHS = {
        "/", "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin", "/usr/games",
        "/usr/local", "/usr/share", "/dev", "/proc", "/sys", "/run", "/etc",
        "/var", "/var/run", "/var/lib", "/var/spool", "/var/cache", "/var/log",
        "/nonexistent", "/dev/null", "/var/empty", "/none",
    }

    def _check_home_dirs(self, ctx, result, accounts):
        result.checks_run += 1
        for a in accounts:
            home = (a.home or "").rstrip("/") or "/"
            if not a.home or home in self.NON_HOME_PATHS:
                continue
            info = ctx.host.stat(a.home)
            if not info.exists:
                continue
            mode = (info.mode or 0) & 0o7777
            if mode & 0o002:
                result.add(make_finding(
                    module=self.name, rule_id="ACCT-HOME-WORLD-WRITABLE",
                    title=f"Home directory {a.home} is world-writable",
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    category=Category.PRIVESC, target=a.home,
                    why=(
                        f"Any local user can create or replace files in {a.home}, including "
                        f"{a.home}/.ssh/authorized_keys and shell startup files. That turns a "
                        f"low-privilege foothold into access as '{a.name}'."
                    ),
                    impact=f"Local users can hijack the '{a.name}' account.",
                    recommendation=f"`chmod 750 {a.home}` and `chown {a.name} {a.home}` after recording evidence.",
                    evidence=[stat_evidence(a.home, info)],
                    tags=["file-permissions", "home-directory"],
                    correlation_key=f"account:{a.name}",
                ))
            # Only meaningful for real login accounts: many service accounts
            # have a root-owned directory recorded as their home by design.
            personal_home = home.startswith(("/home/", "/root")) or a.uid >= 1000
            if (personal_home and info.uid is not None
                    and info.uid != a.uid and a.uid != 0):
                result.add(make_finding(
                    module=self.name, rule_id="ACCT-HOME-WRONG-OWNER",
                    title=f"Home directory {a.home} is not owned by '{a.name}'",
                    severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                    category=Category.ACCOUNT, target=a.home,
                    why=(
                        f"{a.home} is owned by UID {info.uid} ({info.owner}) while the account "
                        f"'{a.name}' has UID {a.uid}. Whoever owns the directory controls the "
                        f"account's SSH keys and shell startup files."
                    ),
                    impact="The listed owner can take over this account.",
                    recommendation="Establish why ownership differs; restore if unintended.",
                    evidence=[stat_evidence(a.home, info)],
                    tags=["home-directory", "ownership"],
                    correlation_key=f"account:{a.name}",
                ))

    @staticmethod
    def _gid_of(ctx, group_name: str) -> Optional[int]:
        lines, _ = ctx.host.read_lines("/etc/group")
        for line in lines:
            parts = line.split(":")
            if len(parts) >= 3 and parts[0] == group_name and parts[2].isdigit():
                return int(parts[2])
        return None



# ============================================================================
# bulwark/detection/ssh.py
# detection: SSH and remote access
# ============================================================================

# SSH daemon configuration and authorized key review.
#
# Key material is fingerprinted, never reproduced. Private keys are detected by
# location and permission only; their contents are never read into evidence.




KEY_TYPES = (
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-rsa-cert-v01@openssh.com", "ssh-ed25519-cert-v01@openssh.com",
)

PRIVATE_KEY_NAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity")

# sshd_config settings worth reporting, with the direction that is risky.
RISKY_SETTINGS = {
    "permitrootlogin": ("yes", "prohibit-password", "without-password", "forced-commands-only"),
    "passwordauthentication": ("yes",),
    "permitemptypasswords": ("yes",),
    "permituserenvironment": ("yes",),
    "allowtcpforwarding": ("yes", "all", "remote"),
    "gatewayports": ("yes", "clientspecified"),
    "x11forwarding": ("yes",),
    "usepam": ("no",),
    "challengeresponseauthentication": ("yes",),
    "kbdinteractiveauthentication": ("yes",),
    "hostbasedauthentication": ("yes",),
    "ignorerhosts": ("no",),
    "strictmodes": ("no",),
    "permittunnel": ("yes", "point-to-point", "ethernet"),
}


class SSHModule(DetectionModule):
    name = "ssh"
    version = "1.1"
    title = "SSH and remote access"
    description = (
        "Reviews effective sshd configuration, authorized_keys across accounts, "
        "key permissions and other remote access services."
    )
    quick = True

    def check(self, ctx: AuditContext, result: ModuleResult) -> None:
        config, config_files, gaps = self._load_sshd_config(ctx)
        for path, reason in gaps:
            result.gap(path, reason, "SSH settings from this file were not evaluated",
                       needs_root=not ctx.facts.is_root)

        effective = self._effective_config(ctx, result, config)
        result.facts["sshd_config"] = effective
        result.facts["sshd_config_files"] = config_files

        if not config and not effective:
            result.gap("sshd", "no sshd configuration found or readable",
                       "SSH exposure could not be assessed")
        else:
            self._check_settings(ctx, result, effective, config_files)

        self._check_authorized_keys(ctx, result, effective)
        self._check_key_permissions(ctx, result)
        self._check_host_keys(ctx, result)
        self._check_other_remote_access(ctx, result)

    # ------------------------------------------------------------- config

    def _load_sshd_config(self, ctx, path: str = "/etc/ssh/sshd_config",
                          depth: int = 0) -> Tuple[Dict[str, List[str]], List[str], List[Tuple[str, str]]]:
        """Parse sshd_config and any Include files. First value wins, which is
        how sshd itself resolves duplicate keywords."""
        config: Dict[str, List[str]] = {}
        seen_files: List[str] = []
        gaps: List[Tuple[str, str]] = []
        if depth > 4:
            return config, seen_files, gaps

        lines, err = ctx.host.read_lines(path)
        if err:
            if err != "not found":
                gaps.append((path, err))
            return config, seen_files, gaps
        seen_files.append(path)

        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.replace("=", " ", 1).split(None, 1)
            if not parts:
                continue
            key = parts[0].lower()
            value = parts[1].strip() if len(parts) > 1 else ""
            if key == "include":
                for pattern in value.split():
                    for inc in self._expand_include(ctx, pattern, path):
                        sub, subfiles, subgaps = self._load_sshd_config(ctx, inc, depth + 1)
                        for k, v in sub.items():
                            config.setdefault(k, []).extend(v)
                        seen_files.extend(subfiles)
                        gaps.extend(subgaps)
                continue
            config.setdefault(key, []).append(value)
        return config, seen_files, gaps

    @staticmethod
    def _expand_include(ctx, pattern: str, parent: str) -> List[str]:
        if not pattern.startswith("/"):
            pattern = os.path.join(os.path.dirname(parent), pattern)
        directory, _, name_pattern = pattern.rpartition("/")
        entries, err = ctx.host.listdir(directory)
        if err:
            return []
        import fnmatch
        return [os.path.join(directory, e) for e in entries
                if fnmatch.fnmatch(e, name_pattern)]

    def _effective_config(self, ctx, result, parsed) -> Dict[str, str]:
        """Prefer `sshd -T` (the daemon's own view) when it is available and we
        are root; fall back to the parsed files. Report a disagreement rather
        than silently trusting one source."""
        effective = {k: v[0] for k, v in parsed.items() if v}
        result.checks_run += 1

        if not ctx.facts.is_root or not ctx.host.has("sshd"):
            if not ctx.facts.is_root:
                result.gap("sshd -T", "requires root to dump effective configuration",
                           "settings come from parsing config files, which may miss Match blocks",
                           needs_root=True)
            return effective

        res = ctx.host.run(["sshd", "-T"], timeout=10)
        if not res.ok:
            result.gap("sshd -T", f"command failed: {res.error or res.stderr.strip()[:120]}",
                       "settings come from parsing config files only")
            return effective

        dumped: Dict[str, str] = {}
        for line in res.stdout.splitlines():
            key, _, value = line.partition(" ")
            if key:
                dumped.setdefault(key.strip().lower(), value.strip())

        disagreements = []
        for key in set(dumped) & set(effective):
            if dumped[key].lower() != effective[key].lower():
                disagreements.append(f"{key}: file={effective[key]} effective={dumped[key]}")
        if disagreements:
            result.add(make_finding(
                module=self.name, rule_id="SSH-CONFIG-DISAGREEMENT",
                title="sshd's effective configuration differs from the configuration files",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                category=Category.REMOTE_ACCESS, target="/etc/ssh/sshd_config",
                why=(
                    "`sshd -T` reports settings that do not match what the configuration "
                    "files say. Usually this means a Match block or an Include you have not "
                    "noticed; it can also mean the running daemon loaded a different file, or "
                    "that the binary is not the one the package installed."
                ),
                impact="The access policy actually in force is not the one the files describe.",
                recommendation=(
                    "Run `sshd -T` yourself and read the Match blocks in the config. Verify "
                    "the sshd binary against the package manager."
                ),
                evidence=[Evidence(source="derived", locator="sshd -T vs sshd_config",
                                   content="\n".join(sorted(disagreements)[:40]))],
                tags=["ssh", "configuration-discrepancy"],
            ))
        dumped.update({k: v for k, v in effective.items() if k not in dumped})
        return dumped

    def _check_settings(self, ctx, result, config, config_files):
        result.checks_run += 1
        for key, risky_values in RISKY_SETTINGS.items():
            value = config.get(key)
            if value is None:
                continue
            if value.lower() not in [v.lower() for v in risky_values]:
                continue

            severity, confidence, why, impact = self._describe_setting(key, value)
            state = baseline_state_for(ctx, "sshd_config", key, value)
            severity, confidence = adjust_for_baseline(severity, confidence, state)
            result.add(make_finding(
                module=self.name, rule_id=f"SSH-SETTING-{key.upper()}",
                title=f"sshd setting {key} is {value}",
                severity=severity, confidence=confidence,
                category=Category.REMOTE_ACCESS, target=f"sshd_config:{key}",
                why=why,
                impact=impact,
                recommendation=(
                    f"Decide whether this matches the configuration your team intends for "
                    f"this host, then change it in the config file and reload sshd. This is "
                    f"a hardening decision, not proof of compromise on its own."
                ),
                evidence=[Evidence(
                    source="file",
                    locator=config_files[0] if config_files else "/etc/ssh/sshd_config",
                    content=f"{key} {value}",
                    meta={"source": "sshd -T or parsed config", "files_parsed": config_files})],
                remediation_risk=(
                    "Changing SSH access settings can lock your own team out. Keep an active "
                    "session open and test from a second terminal before closing the first."
                ),
                tags=["ssh", "configuration"],
                baseline_state=state,
            ))

        # AuthorizedKeysCommand: a legitimate feature, a strong backdoor when planted.
        akc = config.get("authorizedkeyscommand")
        if akc and akc.lower() not in ("none", ""):
            info = ctx.host.stat(akc.split()[0])
            result.add(make_finding(
                module=self.name, rule_id="SSH-AUTHORIZEDKEYSCOMMAND",
                title=f"sshd obtains authorized keys from an external command: {akc}",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                category=Category.REMOTE_ACCESS, target=f"sshd_config:AuthorizedKeysCommand",
                why=(
                    f"AuthorizedKeysCommand makes sshd run `{akc}` and accept whatever public "
                    f"keys it prints. On hosts using central identity (SSSD, LDAP, AD) this is "
                    f"normal. Where it is not expected, it is an effective backdoor, because "
                    f"the key granting access never appears in any authorized_keys file."
                ),
                impact="Access can be granted without any on-disk key file to find.",
                recommendation=(
                    f"Read the script at {akc.split()[0]} and confirm it belongs to your "
                    f"identity stack. Check its ownership and modification time."
                ),
                evidence=[
                    Evidence(source="file", locator="sshd_config",
                             content=f"AuthorizedKeysCommand {akc}"),
                    stat_evidence(akc.split()[0], info) if info.exists else
                    Evidence(source="file", locator=akc.split()[0],
                             content="", error="not found"),
                ],
                tags=["ssh", "persistence", "backdoor-capable"],
                correlation_key="ssh:authorizedkeyscommand",
            ))

        force = config.get("forcecommand")
        if force and force.lower() != "none":
            inds = scan(force)
            result.add(make_finding(
                module=self.name, rule_id="SSH-FORCECOMMAND",
                title=f"sshd ForceCommand is set: {redact(force)[:120]}",
                severity=Severity.HIGH if inds else Severity.MEDIUM,
                confidence=Confidence.MEDIUM if inds else Confidence.LOW,
                category=Category.REMOTE_ACCESS, target="sshd_config:ForceCommand",
                why=(
                    f"Every SSH session on this host runs `{redact(force)[:200]}` instead of "
                    f"the user's shell. This is a legitimate way to restrict access, and also "
                    f"a way to run attacker code on every login."
                    + (f" The command matches known-bad patterns: {summarize(inds)}." if inds else "")
                ),
                impact="Attacker-controlled code may execute on every SSH connection.",
                recommendation="Read the command and confirm your team configured it.",
                evidence=[Evidence(source="file", locator="sshd_config",
                                   content=f"ForceCommand {redact(force)}")],
                tags=["ssh", "persistence"],
            ))

        port_values = [p for p in (config.get("port"), ) if p]
        if port_values:
            result.facts["ssh_ports"] = port_values

    @staticmethod
    def _describe_setting(key, value):
        table = {
            "permitemptypasswords": (
                Severity.CRITICAL, Confidence.HIGH,
                "PermitEmptyPasswords yes lets an account with an empty password field "
                "authenticate over the network with no credential at all. Combined with any "
                "account that has an empty password, this is unauthenticated remote access.",
                "Remote access with no credential.",
            ),
            "permitrootlogin": (
                Severity.MEDIUM, Confidence.HIGH,
                "Root may log in directly over SSH. This is a common default on cloud and "
                "competition images rather than evidence of tampering, but it means a single "
                "stolen or guessed credential yields root with no intermediate step, and it "
                "removes the audit trail that sudo provides.",
                "One credential compromise becomes immediate root access.",
            ),
            "passwordauthentication": (
                Severity.MEDIUM, Confidence.HIGH,
                "Password authentication is enabled, so the host is exposed to credential "
                "guessing. During a competition the red team usually starts with credentials "
                "they already hold from the image, which makes this the most likely re-entry "
                "path after you rotate keys.",
                "Allows brute-force and reuse of pre-seeded credentials.",
            ),
            "permituserenvironment": (
                Severity.HIGH, Confidence.MEDIUM,
                "PermitUserEnvironment yes makes sshd honour ~/.ssh/environment and "
                "environment= options in authorized_keys. An attacker who can write either "
                "can set LD_PRELOAD and execute code in the context of every login.",
                "Code execution on login via environment injection.",
            ),
            "usepam": (
                Severity.MEDIUM, Confidence.MEDIUM,
                "UsePAM no bypasses the PAM stack, which is where account locking, access "
                "restrictions and session logging are enforced on most distributions.",
                "Account restrictions and session auditing may not apply to SSH logins.",
            ),
            "strictmodes": (
                Severity.HIGH, Confidence.MEDIUM,
                "StrictModes no tells sshd to accept key files regardless of their ownership "
                "and permissions. A world-writable authorized_keys file would then be honoured, "
                "letting any local user grant themselves remote access as that account.",
                "Local users can add their own SSH access to other accounts.",
            ),
            "hostbasedauthentication": (
                Severity.MEDIUM, Confidence.MEDIUM,
                "Host-based authentication trusts the client machine's identity rather than a "
                "user credential. It is rarely used intentionally and widens the trust boundary.",
                "Access depends on a trusted host rather than a user secret.",
            ),
            "ignorerhosts": (
                Severity.MEDIUM, Confidence.MEDIUM,
                "IgnoreRhosts no re-enables .rhosts and .shosts files, a legacy trust mechanism "
                "that lets a user file grant passwordless access.",
                "User-writable files can grant remote access.",
            ),
            "gatewayports": (
                Severity.MEDIUM, Confidence.LOW,
                "GatewayPorts allows remote-forwarded ports to bind on all interfaces, which "
                "turns this host into a pivot reachable by third parties.",
                "The host can relay traffic for others.",
            ),
            "permittunnel": (
                Severity.MEDIUM, Confidence.LOW,
                "PermitTunnel allows layer-2/3 tunnelling over SSH, which is a route to "
                "network pivoting.",
                "Supports tunnelling into the internal network.",
            ),
            "allowtcpforwarding": (
                Severity.LOW, Confidence.LOW,
                "TCP forwarding is enabled. This is the default and is required by many "
                "legitimate workflows, but it is also how an SSH session becomes a pivot into "
                "the rest of the network.",
                "Enables pivoting through this host.",
            ),
        }
        default = (
            Severity.LOW, Confidence.LOW,
            f"The setting {key} is {value}, which widens the remote access surface.",
            "Increases remote attack surface.",
        )
        return table.get(key, default)

    # ------------------------------------------------------ authorized keys

    def _check_authorized_keys(self, ctx, result, config):
        result.checks_run += 1
        patterns = config.get("authorizedkeysfile", ".ssh/authorized_keys .ssh/authorized_keys2")
        rel_paths = [p for p in patterns.split() if p]
        all_keys: Dict[str, List[Dict]] = {}

        targets: List[Tuple[str, str, int]] = list(ctx.host.home_dirs())
        if not any(h == "/root" for _n, h, _u in targets):
            if ctx.host.is_dir("/root"):
                targets.append(("root", "/root", 0))

        baseline_keys = ctx.baseline_section("ssh_authorized_keys")
        baseline_items = (baseline_keys or {}).get("items", baseline_keys or {})

        for username, home, uid in targets:
            for rel in rel_paths:
                if rel.startswith("/"):
                    path = (rel.replace("%h", home).replace("%u", username)
                               .replace("%%", "%"))
                else:
                    path = os.path.join(home, rel.replace("%u", username))
                info = ctx.host.stat(path)
                if not info.exists:
                    continue
                lines, err = ctx.host.read_lines(path)
                if err:
                    result.gap(path, f"unreadable: {err}",
                               f"SSH keys for '{username}' were not reviewed",
                               needs_root=not ctx.facts.is_root)
                    continue
                keys = self._parse_authorized_keys(lines)
                if keys:
                    all_keys[f"{username}:{path}"] = [
                        {k: v for k, v in key.items() if k != "blob"} for key in keys
                    ]
                self._evaluate_keys(ctx, result, username, uid, path, info, keys,
                                    baseline_items)
                self._check_authkeys_perms(ctx, result, username, uid, path, info)

        result.facts["ssh_authorized_keys"] = all_keys
        if not all_keys:
            result.facts["ssh_authorized_keys"] = {}

    @staticmethod
    def _parse_authorized_keys(lines: List[str]) -> List[Dict]:
        keys = []
        for i, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            options = ""
            rest = line
            # An options field may precede the key type.
            first = line.split(None, 1)[0]
            if not any(first.startswith(t) for t in KEY_TYPES) and not first.isdigit():
                # Options are comma separated and may contain quoted commas.
                match = re.match(r'^((?:[^ "]|"(?:[^"\\]|\\.)*")+)\s+(.*)$', line)
                if match:
                    options, rest = match.group(1), match.group(2)
            parts = rest.split(None, 2)
            if len(parts) < 2:
                continue
            keytype, blob = parts[0], parts[1]
            comment = parts[2] if len(parts) > 2 else ""
            entry = {
                "line": i, "type": keytype, "comment": comment.strip(),
                "options": options, "fingerprint": _fingerprint(blob),
                "bits_hint": len(blob), "blob": blob,
            }
            keys.append(entry)
        return keys

    def _evaluate_keys(self, ctx, result, username, uid, path, info, keys, baseline_items):
        if not keys:
            return
        known_fps = set()
        if baseline_items:
            entry = baseline_items.get(f"{username}:{path}") or baseline_items.get(username)
            if isinstance(entry, list):
                known_fps = {k.get("fingerprint") for k in entry if isinstance(k, dict)}

        privileged = username == "root" or uid == 0

        for key in keys:
            fp = key["fingerprint"]
            state = (
                "known" if fp in known_fps else ("new" if baseline_items else "unknown")
            )
            bstate = {
                "known": BaselineState.KNOWN, "new": BaselineState.NEW,
                "unknown": BaselineState.NO_BASELINE,
            }[state]

            if state == "known":
                continue   # fingerprint matches the baseline; nothing new here

            opts = key["options"] or ""
            risky_opts = []
            if "command=" in opts.lower():
                risky_opts.append("forces a command on connection")
            if "environment=" in opts.lower():
                risky_opts.append("sets environment variables (LD_PRELOAD risk)")
            if "no-pty" not in opts.lower() and privileged:
                pass
            restricted = any(
                o in opts.lower() for o in ("from=", "restrict", "no-pty", "command=")
            )

            if privileged:
                severity, confidence = Severity.CRITICAL, Confidence.MEDIUM
                why = (
                    f"An SSH public key is authorised for direct login as '{username}', a "
                    f"root-equivalent account. Anyone holding the matching private key can "
                    f"log in as root without a password and without appearing in any "
                    f"credential rotation you perform. Rotating passwords does not revoke it."
                )
                sev_note = "Direct root access that survives password changes."
            else:
                severity, confidence = Severity.HIGH, Confidence.MEDIUM
                why = (
                    f"An SSH public key is authorised for login as '{username}'. Key-based "
                    f"access is unaffected by password rotation, so a key placed before you "
                    f"received the host remains usable until the key file is cleaned."
                )
                sev_note = f"Password-independent access as '{username}'."

            if state == "new":
                confidence = Confidence.HIGH
                why += " This fingerprint is not in the saved baseline."
            else:
                why += (
                    " No baseline is available to say whether this key is yours, so it is "
                    "reported for verification rather than as confirmed unauthorised access."
                )
            if risky_opts:
                severity = Severity.CRITICAL if privileged else Severity.HIGH
                why += " Key options: " + "; ".join(risky_opts) + "."

            comment = key["comment"]
            display = f"{key['type']} {fp}" + (f" comment={comment!r}" if comment else "")

            result.add(make_finding(
                module=self.name, rule_id="SSH-AUTHORIZED-KEY",
                title=f"SSH key authorised for '{username}': {fp}",
                severity=severity, confidence=confidence,
                category=Category.REMOTE_ACCESS, target=f"{path}#{fp}",
                why=why,
                impact=sev_note,
                recommendation=(
                    f"Compare this fingerprint against the keys your team installed. Any key "
                    f"you cannot account for should be removed from {path} - but capture the "
                    f"file first, and check for other access paths before you revoke it, or "
                    f"you will simply tell the attacker you are watching."
                ),
                evidence=[
                    Evidence(
                        source="file", locator=path,
                        content=f"line {key['line']}: {display}"
                                + (f"\noptions: {redact(opts)}" if opts else ""),
                        meta={"fingerprint": fp, "key_type": key["type"],
                              "comment": comment, "options_present": bool(opts),
                              "note": "public key material is fingerprinted, not reproduced"}),
                    stat_evidence(path, info),
                ],
                timestamps={"authorized_keys_mtime_utc": iso_from_epoch(info.mtime)},
                remediation_risk=(
                    "Removing a key that your team or a scoring engine uses will break "
                    "automated access. Confirm ownership first."
                ),
                tags=["ssh", "persistence", "key-based-access"]
                     + (["root-access"] if privileged else []),
                correlation_key=f"account:{username}",
                baseline_state=bstate,
            ))

    def _check_authkeys_perms(self, ctx, result, username, uid, path, info):
        mode = (info.mode or 0) & 0o7777
        problems = []
        if mode & 0o022:
            problems.append(f"writable by group or world (mode {info.mode_octal})")
        if info.uid is not None and info.uid != uid and info.uid != 0:
            problems.append(f"owned by UID {info.uid} ({info.owner}) rather than '{username}'")
        if not problems:
            return
        result.add(make_finding(
            module=self.name, rule_id="SSH-AUTHKEYS-PERMS",
            title=f"{path} has unsafe permissions: {', '.join(problems)}",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            category=Category.REMOTE_ACCESS, target=path,
            why=(
                f"{path} controls who may log in as '{username}' without a password. Because "
                f"it is {', '.join(problems)}, another account can append its own key and "
                f"gain that access. sshd's StrictModes normally refuses such a file - check "
                f"whether StrictModes has also been disabled."
            ),
            impact=f"Another local account can grant itself SSH access as '{username}'.",
            recommendation=f"`chown {username} {path}` and `chmod 600 {path}` after recording evidence.",
            evidence=[stat_evidence(path, info)],
            tags=["ssh", "file-permissions"],
            correlation_key=f"account:{username}",
        ))

    def _check_key_permissions(self, ctx, result):
        """Private keys are located and permission-checked. Contents are never read."""
        result.checks_run += 1
        for username, home, uid in ctx.host.home_dirs():
            ssh_dir = os.path.join(home, ".ssh")
            if not ctx.host.is_dir(ssh_dir):
                continue
            dir_info = ctx.host.stat(ssh_dir)
            if (dir_info.mode or 0) & 0o022:
                result.add(make_finding(
                    module=self.name, rule_id="SSH-DIR-PERMS",
                    title=f"{ssh_dir} is writable beyond its owner (mode {dir_info.mode_octal})",
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    category=Category.REMOTE_ACCESS, target=ssh_dir,
                    why=(
                        f"Another account can create or replace files in {ssh_dir}, including "
                        f"authorized_keys and the known_hosts file. That is enough to take "
                        f"over SSH access for '{username}'."
                    ),
                    impact=f"Local account takeover of '{username}' via SSH.",
                    recommendation=f"`chmod 700 {ssh_dir}`.",
                    evidence=[stat_evidence(ssh_dir, dir_info)],
                    tags=["ssh", "file-permissions"],
                    correlation_key=f"account:{username}",
                ))
            names, err = ctx.host.listdir(ssh_dir)
            if err:
                result.gap(ssh_dir, err, f"SSH key files for '{username}' were not reviewed",
                           needs_root=not ctx.facts.is_root)
                continue
            for entry in names:
                looks_private = (
                    entry in PRIVATE_KEY_NAMES
                    or (entry.startswith("id_") and not entry.endswith(".pub"))
                )
                if not looks_private:
                    continue
                key_path = os.path.join(ssh_dir, entry)
                key_info = ctx.host.stat(key_path)
                mode = (key_info.mode or 0) & 0o7777
                if mode & 0o077:
                    result.add(make_finding(
                        module=self.name, rule_id="SSH-PRIVKEY-PERMS",
                        title=f"Private key {key_path} is readable beyond its owner (mode {key_info.mode_octal})",
                        severity=Severity.HIGH, confidence=Confidence.HIGH,
                        category=Category.REMOTE_ACCESS, target=key_path,
                        why=(
                            f"A private key readable by other accounts is a credential "
                            f"available to any local user, and to any service running as "
                            f"another account. Where that key is trusted, this is lateral "
                            f"movement into another host or account."
                        ),
                        impact="The key should be considered compromised and rotated.",
                        recommendation=(
                            f"`chmod 600 {key_path}`. Treat the key as exposed: generate a new "
                            f"pair and remove the old public key from every authorized_keys "
                            f"file that trusts it."
                        ),
                        evidence=[stat_evidence(
                            key_path, key_info,
                            note="key contents are never read or stored by this tool")],
                        tags=["ssh", "credential-exposure", "file-permissions"],
                        correlation_key=f"account:{username}",
                    ))

    def _check_host_keys(self, ctx, result):
        result.checks_run += 1
        names, err = ctx.host.listdir("/etc/ssh")
        if err:
            return
        for entry in names:
            if not entry.startswith("ssh_host_") or entry.endswith(".pub"):
                continue
            path = os.path.join("/etc/ssh", entry)
            info = ctx.host.stat(path)
            mode = (info.mode or 0) & 0o7777
            if mode & 0o077:
                result.add(make_finding(
                    module=self.name, rule_id="SSH-HOSTKEY-PERMS",
                    title=f"SSH host key {path} is readable by non-root (mode {info.mode_octal})",
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    category=Category.REMOTE_ACCESS, target=path,
                    why=(
                        "The host private key proves this server's identity. Any local user "
                        "who can read it can impersonate the host and run a convincing "
                        "man-in-the-middle against your team's own SSH sessions without "
                        "triggering a host key warning."
                    ),
                    impact="Host impersonation and interception of SSH sessions.",
                    recommendation=f"`chmod 600 {path}`; regenerate host keys if exposure is suspected.",
                    evidence=[stat_evidence(path, info)],
                    tags=["ssh", "credential-exposure"],
                ))

    def _check_other_remote_access(self, ctx, result):
        result.checks_run += 1
        found = []
        candidates = {
            "/etc/xrdp": "xrdp (remote desktop)",
            "/etc/vnc": "VNC server configuration",
            "/root/.vnc": "VNC server for root",
            "/etc/telnetd": "telnet daemon",
            "/etc/rsh": "legacy rsh service",
            "/etc/tigervnc": "TigerVNC",
            "/etc/guacamole": "Apache Guacamole",
            "/etc/teamviewer": "TeamViewer",
            "/etc/anydesk": "AnyDesk",
            "/etc/rustdesk": "RustDesk",
        }
        for path, label in candidates.items():
            if ctx.host.exists(path):
                found.append((path, label))
        legacy_files = []
        for username, home, _uid in ctx.host.home_dirs():
            for legacy in (".rhosts", ".shosts", ".netrc"):
                p = os.path.join(home, legacy)
                if ctx.host.exists(p):
                    legacy_files.append((username, p))

        for username, path in legacy_files:
            result.add(make_finding(
                module=self.name, rule_id="SSH-LEGACY-TRUST-FILE",
                title=f"Legacy trust file {path} exists",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                category=Category.REMOTE_ACCESS, target=path,
                why=(
                    f"{os.path.basename(path)} files grant access or store credentials based "
                    f"on host trust rather than a per-session secret. They are essentially "
                    f"never created by modern tooling, so their presence suggests either a "
                    f"very old configuration or deliberate placement."
                ),
                impact=f"May grant passwordless access as '{username}' or expose stored credentials.",
                recommendation=(
                    f"Read {path} (it is short), confirm nobody on your team created it, and "
                    f"remove it. Verify sshd has IgnoreRhosts set to yes."
                ),
                evidence=[file_evidence(ctx, path, max_chars=1000)],
                tags=["ssh", "legacy-trust"],
                correlation_key=f"account:{username}",
            ))

        if found:
            result.facts["other_remote_access"] = [p for p, _ in found]
            result.add(make_finding(
                module=self.name, rule_id="SSH-OTHER-REMOTE-SERVICE",
                title=f"{len(found)} additional remote access service configuration(s) present",
                severity=Severity.LOW, confidence=Confidence.LOW,
                category=Category.REMOTE_ACCESS, target="remote-access-inventory",
                why=(
                    "Configuration for remote access software other than SSH was found. This "
                    "is inventory, not an accusation: these may be scored services. They are "
                    "listed so that hardening SSH does not leave a second door open."
                ),
                impact="Additional remote entry points to secure or monitor.",
                recommendation=(
                    "For each one, confirm whether it is a required service, whether it is "
                    "running (see the network module findings) and who can authenticate to it."
                ),
                evidence=[Evidence(source="derived", locator="filesystem",
                                   content="\n".join(f"{p} - {label}" for p, label in found))],
                tags=["remote-access", "inventory"],
            ))


def _fingerprint(blob: str) -> str:
    """OpenSSH-style SHA256 fingerprint of a base64 public key blob."""
    try:
        raw = base64.b64decode(blob, validate=True)
    except Exception:  # noqa: BLE001 - malformed key material is expected input
        return "SHA256:<unparseable-key>"
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")



# ============================================================================
# bulwark/detection/persistence.py
# detection: persistence mechanisms
# ============================================================================

# Persistence mechanisms.
#
# The highest-value module for a competition: on a prebaked host, persistence is
# usually already installed before the blue team logs in for the first time.
#
# Nothing discovered here is ever executed. Scripts are read as text and matched
# against the indicator library.




SYSTEMD_UNIT_DIRS = [
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/usr/local/lib/systemd/system",
]

CRON_SYSTEM_FILES = ["/etc/crontab"]
CRON_DIRS = [
    "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
    "/etc/cron.weekly", "/etc/cron.monthly",
]
CRON_SPOOL_DIRS = [
    "/var/spool/cron/crontabs",   # Debian/Ubuntu
    "/var/spool/cron",            # RHEL/Fedora
]
AT_SPOOL_DIRS = ["/var/spool/cron/atjobs", "/var/spool/at", "/var/spool/atjobs"]

SHELL_INIT_SYSTEM = [
    "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/zshrc",
    "/etc/zsh/zprofile", "/etc/csh.cshrc", "/etc/environment",
]
SHELL_INIT_USER = [
    ".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_logout",
    ".zshrc", ".zprofile", ".zlogin", ".kshrc", ".cshrc", ".login",
    ".config/fish/config.fish",
]

PAM_SUSPECT_MODULES = {
    "pam_exec.so": "runs an arbitrary external program during authentication",
    "pam_python.so": "runs Python code during authentication",
    "pam_script.so": "runs shell scripts during authentication",
}


class PersistenceModule(DetectionModule):
    name = "persistence"
    version = "1.1"
    title = "Persistence mechanisms"
    description = (
        "Enumerates systemd units and timers, cron and at jobs, init scripts, "
        "shell initialisation files, PAM modules, dynamic linker preloads, "
        "kernel modules and container restart policies."
    )
    quick = True

    def check(self, ctx: AuditContext, result: ModuleResult) -> None:
        self._check_systemd(ctx, result)
        self._check_cron(ctx, result)
        self._check_at(ctx, result)
        self._check_init_scripts(ctx, result)
        self._check_shell_init(ctx, result)
        self._check_ld_preload(ctx, result)
        self._check_pam(ctx, result)
        self._check_motd_and_udev(ctx, result)
        self._check_kernel_modules(ctx, result)
        self._check_containers(ctx, result)

    # ------------------------------------------------------------- systemd

    def _check_systemd(self, ctx, result):
        result.checks_run += 1
        if ctx.facts.init_system != "systemd" and not any(
            ctx.host.is_dir(d) for d in SYSTEMD_UNIT_DIRS
        ):
            result.gap("systemd", "no systemd unit directories found",
                       "unit-based persistence was not assessed")
            return

        units: Dict[str, Dict] = {}
        enabled = self._enabled_units(ctx)

        # On merged-/usr systems /lib/systemd/system is a symlink to
        # /usr/lib/systemd/system. Scanning both reports every unit twice.
        for directory in self._distinct_unit_dirs(ctx):
            entries, err = ctx.host.listdir(directory)
            if err:
                if err not in ("not found",):
                    result.gap(directory, err, "units in this directory were not reviewed")
                continue
            for entry in entries:
                if not entry.endswith((".service", ".timer", ".socket", ".path")):
                    continue
                path = os.path.join(directory, entry)
                info = ctx.host.stat(path)
                if info.is_dir:
                    continue
                if info.is_symlink and directory == "/etc/systemd/system":
                    # enablement symlink into another unit dir; recorded, not parsed twice
                    units.setdefault(entry, {})["enabled_link"] = info.symlink_target
                    continue
                parsed = self._parse_unit(ctx, path)
                if parsed is None:
                    continue
                record = {
                    "path": path,
                    "exec": parsed.get("ExecStart", ""),
                    "user": parsed.get("User", "root"),
                    "enabled": entry in enabled,
                    "mtime_utc": iso_from_epoch(info.mtime),
                    "owner": info.owner,
                    "mode": info.mode_octal,
                }
                units.setdefault(entry, {}).update(record)
                self._evaluate_unit(ctx, result, entry, path, info, parsed,
                                    entry in enabled, directory)

        result.facts["systemd_units"] = units

        # User units - a frequently missed persistence location.
        for username, home, _uid in ctx.host.home_dirs():
            user_dir = os.path.join(home, ".config/systemd/user")
            entries, err = ctx.host.listdir(user_dir)
            if err:
                continue
            for entry in entries:
                if not entry.endswith((".service", ".timer")):
                    continue
                path = os.path.join(user_dir, entry)
                info = ctx.host.stat(path)
                parsed = self._parse_unit(ctx, path)
                if parsed is None:
                    continue
                self._evaluate_unit(ctx, result, entry, path, info, parsed,
                                    enabled=True, directory=user_dir, user_unit=username)

    @staticmethod
    def _distinct_unit_dirs(ctx) -> List[str]:
        """Unit directories with merged-/usr duplicates collapsed."""
        seen: Dict[str, str] = {}
        ordered: List[str] = []
        for directory in SYSTEMD_UNIT_DIRS:
            if not ctx.host.is_dir(directory):
                continue
            info = ctx.host.stat(directory)
            try:
                import os as _os
                key = _os.path.realpath(ctx.host.real(directory))
            except (OSError, ValueError):
                key = directory
            if key in seen:
                continue
            seen[key] = directory
            ordered.append(directory)
        return ordered

    def _enabled_units(self, ctx) -> set:
        enabled = set()
        for directory in self._distinct_unit_dirs(ctx):
            entries, err = ctx.host.listdir(directory)
            if err:
                continue
            for entry in entries:
                if not entry.endswith(".wants") and not entry.endswith(".requires"):
                    continue
                sub, suberr = ctx.host.listdir(os.path.join(directory, entry))
                if suberr:
                    continue
                enabled.update(sub)
        return enabled

    def _parse_unit(self, ctx, path) -> Optional[Dict[str, str]]:
        lines, err = ctx.host.read_lines(path, max_bytes=256 * 1024)
        if err:
            return None
        out: Dict[str, str] = {}
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith(("#", ";", "[")):
                continue
            key, sep, value = line.partition("=")
            if not sep:
                continue
            key = key.strip()
            value = value.strip()
            if key in out:
                out[key] = out[key] + " ; " + value
            else:
                out[key] = value
        return out

    def _evaluate_unit(self, ctx, result, unit_name, path, info, parsed,
                       enabled: bool, directory: str, user_unit: Optional[str] = None):
        exec_fields = " ; ".join(
            parsed.get(k, "") for k in
            ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecReload",
             "ExecStop", "ExecStopPost", "ExecCondition")
            if parsed.get(k)
        )
        if not exec_fields:
            return

        reasons: List[str] = []
        indicators = scan(exec_fields)
        severity = None
        confidence = Confidence.MEDIUM

        binary = self._exec_binary(parsed.get("ExecStart", "") or exec_fields)
        suspicious_dir = in_suspicious_dir(binary)

        if indicators:
            reasons.append(f"the command matches known-bad patterns ({summarize(indicators)})")
            severity = Severity.CRITICAL if score(indicators) >= 3 else Severity.HIGH
            confidence = Confidence.HIGH if score(indicators) >= 3 else Confidence.MEDIUM

        if in_strong_suspicious_dir(binary):
            reasons.append(
                f"it executes {binary}, which lives in a temporary directory that is cleared "
                f"on reboot and is world-writable - no packaged service installs itself there"
            )
            severity = Severity.CRITICAL if severity is None or severity.rank < 4 else severity
            confidence = Confidence.HIGH
        elif suspicious_dir:
            reasons.append(f"it executes from {suspicious_dir}, an unusual location for a system service")
            severity = severity or Severity.MEDIUM

        # Writable unit file or writable target binary
        if (info.mode or 0) & 0o022:
            reasons.append(f"the unit file itself is writable beyond root (mode {info.mode_octal})")
            severity = Severity.HIGH if severity is None or severity.rank < 3 else severity
            confidence = Confidence.HIGH

        notes: List[str] = []
        if binary and "%" not in binary:
            bin_info = ctx.host.stat(binary)
            if bin_info.exists and (bin_info.mode or 0) & 0o022:
                reasons.append(
                    f"the executable {binary} is writable by non-root users (mode "
                    f"{bin_info.mode_octal}), so any local user can change what this "
                    f"service runs as root"
                )
                severity = Severity.CRITICAL
                confidence = Confidence.HIGH
            elif not bin_info.exists and binary.startswith("/"):
                # Never a finding on its own: template units, optional
                # components and units for uninstalled packages all look like
                # this on a perfectly healthy system.
                notes.append(f"its executable {binary} is not present on disk")

        if info.owner not in (None, "root") and directory.startswith("/etc"):
            reasons.append(f"the unit file is owned by {info.owner} rather than root")
            severity = Severity.HIGH if severity is None or severity.rank < 3 else severity

        if not reasons:
            return
        reasons.extend(notes)

        # Package provenance raises or lowers confidence.
        owned_by_package = self._package_owner(ctx, path)
        if owned_by_package:
            reasons.append(f"note: the package manager reports this file belongs to {owned_by_package}")
            if severity and severity.rank < Severity.CRITICAL.rank:
                confidence = Confidence.LOW if confidence is Confidence.MEDIUM else confidence
        elif ctx.facts.package_manager in ("dpkg", "rpm"):
            reasons.append("no installed package claims this unit file")

        severity = severity or Severity.MEDIUM
        state = baseline_state_for(ctx, "systemd_units", unit_name,
                                   parsed.get("ExecStart", ""))
        severity, confidence = adjust_for_baseline(severity, confidence, state)

        scope = f"user unit for '{user_unit}'" if user_unit else (
            "enabled at boot" if enabled else "present but not enabled")

        result.add(make_finding(
            module=self.name, rule_id="PERS-SYSTEMD-UNIT",
            title=f"Suspicious systemd unit {unit_name} ({scope})",
            severity=severity, confidence=confidence, category=Category.PERSISTENCE,
            target=path,
            why=(
                f"The unit {unit_name} at {path} runs `{redact(exec_fields)[:300]}` as "
                f"{parsed.get('User', 'root')}. It was flagged because " +
                "; ".join(reasons) + ". A systemd unit survives reboots and restarts "
                "automatically, which makes it one of the most durable footholds available."
            ),
            impact=(
                f"Code of the operator's choosing runs as {parsed.get('User', 'root')} at "
                f"boot and is restarted if killed."
            ),
            recommendation=(
                f"Read the unit file and its target binary without executing them "
                f"(`cat {path}`, then `file` and `strings` on the binary). Check "
                f"`systemctl status {unit_name}` and `journalctl -u {unit_name}` for when it "
                f"first started. Do not simply kill the process: the unit will restart it. "
                f"Disable the unit only after you have captured the binary as evidence."
            ),
            evidence=[
                file_evidence(ctx, path, note=f"{scope}; enabled={enabled}"),
                stat_evidence(path, info),
            ],
            timestamps={"unit_mtime_utc": iso_from_epoch(info.mtime),
                        "unit_ctime_utc": iso_from_epoch(info.ctime)},
            remediation_risk=(
                "Disabling a unit that turns out to be a scored service costs points. "
                "Confirm the service is not one of your required services first."
            ),
            tags=["persistence", "systemd"] + (["user-unit"] if user_unit else []),
            correlation_key=(f"path:{binary}" if binary else f"unit:{unit_name}"),
            baseline_state=state,
        ))

    @staticmethod
    def _exec_binary(exec_line: str) -> Optional[str]:
        if not exec_line:
            return None
        token = exec_line.strip().split(";")[0].strip()
        # systemd prefixes: - @ + ! !!
        token = token.lstrip("-@+!").strip()
        parts = token.split()
        if not parts:
            return None
        candidate = parts[0]
        # /bin/sh -c "payload" - the interesting part is the payload, handled by
        # indicator scanning; still return the interpreter for location checks.
        return candidate if candidate.startswith("/") else candidate

    def _package_owner(self, ctx, path) -> Optional[str]:
        if ctx.host.is_synthetic:
            return None
        if ctx.facts.package_manager == "dpkg" and ctx.host.has("dpkg"):
            res = ctx.host.run(["dpkg", "-S", path], timeout=10)
            if res.ok and ":" in res.stdout:
                return res.stdout.split(":")[0].strip()
        elif ctx.facts.package_manager == "rpm" and ctx.host.has("rpm"):
            res = ctx.host.run(["rpm", "-qf", path], timeout=10)
            if res.ok and "not owned" not in res.stdout:
                return res.stdout.strip().splitlines()[0]
        return None

    # ---------------------------------------------------------------- cron

    def _check_cron(self, ctx, result):
        result.checks_run += 1
        entries: List[Dict] = []

        for path in CRON_SYSTEM_FILES:
            entries.extend(self._read_cron_file(ctx, result, path, system_format=True))

        for directory in CRON_DIRS:
            names, err = ctx.host.listdir(directory)
            if err:
                if err not in ("not found",):
                    result.gap(directory, err, "cron jobs here were not reviewed",
                               needs_root=not ctx.facts.is_root)
                continue
            is_dropin = directory == "/etc/cron.d"
            for name in names:
                if name.endswith((".dpkg-old", ".dpkg-dist", ".rpmsave", "~")):
                    continue
                path = os.path.join(directory, name)
                if is_dropin:
                    entries.extend(self._read_cron_file(ctx, result, path, system_format=True))
                else:
                    self._check_cron_periodic_script(ctx, result, path)

        for spool in CRON_SPOOL_DIRS:
            names, err = ctx.host.listdir(spool)
            if err:
                if err == "permission denied":
                    result.gap(spool, err, "per-user crontabs were not reviewed",
                               needs_root=True)
                continue
            for name in names:
                path = os.path.join(spool, name)
                if ctx.host.is_dir(path):
                    continue
                entries.extend(self._read_cron_file(ctx, result, path,
                                                    system_format=False, owner=name))

        result.facts["cron_entries"] = [
            {k: v for k, v in e.items() if k != "indicators"} for e in entries
        ]
        for entry in entries:
            self._evaluate_cron_entry(ctx, result, entry)

    def _read_cron_file(self, ctx, result, path, system_format: bool,
                        owner: Optional[str] = None) -> List[Dict]:
        info = ctx.host.stat(path)
        if not info.exists or info.is_dir:
            return []
        lines, err = ctx.host.read_lines(path, max_bytes=256 * 1024)
        if err:
            result.gap(path, f"unreadable: {err}", "cron entries here were not reviewed",
                       needs_root=not ctx.facts.is_root)
            return []
        out = []
        for i, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if re.match(r"^[A-Z_][A-Z0-9_]*\s*=", line):
                # environment assignment: PATH=, MAILTO=, SHELL=
                if line.upper().startswith(("PATH=", "SHELL=")):
                    out.append({
                        "file": path, "line": i, "schedule": "", "user": owner or "root",
                        "command": line, "kind": "env", "owner_file": info.owner,
                        "mode": info.mode_octal, "mtime_utc": iso_from_epoch(info.mtime),
                    })
                continue
            parsed = self._parse_cron_line(line, system_format)
            if parsed is None:
                continue
            schedule, user, command = parsed
            out.append({
                "file": path, "line": i, "schedule": schedule,
                "user": user or owner or "root", "command": command, "kind": "job",
                "owner_file": info.owner, "mode": info.mode_octal,
                "mtime_utc": iso_from_epoch(info.mtime),
            })
        return out

    @staticmethod
    def _parse_cron_line(line: str, system_format: bool):
        if line.startswith("@"):
            parts = line.split(None, 2 if system_format else 1)
            if system_format and len(parts) >= 3:
                return parts[0], parts[1], parts[2]
            if not system_format and len(parts) >= 2:
                return parts[0], None, parts[1]
            return None
        fields = line.split(None, 6 if system_format else 5)
        needed = 6 if system_format else 5
        if len(fields) <= needed:
            return None
        schedule = " ".join(fields[:5])
        if system_format:
            return schedule, fields[5], fields[6]
        return schedule, None, fields[5]

    def _evaluate_cron_entry(self, ctx, result, entry):
        command = entry["command"]
        if entry["kind"] == "env":
            if command.upper().startswith("PATH="):
                value = command.split("=", 1)[1]
                writable = [p for p in value.split(":")
                            if p in ("", ".") or p.startswith(("/tmp", "/var/tmp", "/dev/shm"))]
                if writable:
                    result.add(make_finding(
                        module=self.name, rule_id="PERS-CRON-PATH",
                        title=f"cron PATH in {entry['file']} includes a writable directory",
                        severity=Severity.HIGH, confidence=Confidence.HIGH,
                        category=Category.PERSISTENCE,
                        target=f"{entry['file']}:{entry['line']}",
                        why=(
                            f"The PATH used for cron jobs in {entry['file']} contains "
                            f"{', '.join(repr(w) for w in writable)}. Any local user can place "
                            f"a file named after a command the cron job calls and have it run "
                            f"with the job's privileges, usually root."
                        ),
                        impact="Local privilege escalation to the cron job's user.",
                        recommendation="Set PATH to a fixed list of root-owned directories.",
                        evidence=[lines_evidence(entry["file"], [command],
                                                 note=f"line {entry['line']}")],
                        tags=["persistence", "cron", "path-hijack"],
                    ))
            return

        indicators = scan(command)
        binary = command.strip().split()[0] if command.strip() else ""
        reasons = []
        severity = None
        confidence = Confidence.MEDIUM

        if indicators:
            reasons.append(f"the command matches known-bad patterns ({summarize(indicators)})")
            severity = Severity.CRITICAL if score(indicators) >= 3 else Severity.HIGH
            confidence = Confidence.HIGH if score(indicators) >= 3 else Confidence.MEDIUM

        if in_strong_suspicious_dir(binary) or any(
            d in command for d in ("/tmp/", "/dev/shm/", "/var/tmp/")
        ):
            reasons.append(
                "it references a temporary directory, which is writable by every local user "
                "and cleared on reboot - legitimate scheduled jobs do not live there"
            )
            severity = Severity.CRITICAL if severity is None else severity
            confidence = Confidence.HIGH

        schedule = entry["schedule"]
        if schedule.startswith("@reboot"):
            reasons.append("it runs at every boot (@reboot), giving it reboot persistence")
            severity = severity or Severity.MEDIUM
        if re.match(r"^\*/[1-5]\s", schedule) or schedule.startswith("* * * * *"):
            reasons.append(
                f"it runs very frequently ({schedule}), which is typical of a beacon or a "
                f"watchdog that reinstalls other persistence"
            )
            severity = severity or Severity.MEDIUM

        mode = entry.get("mode") or ""
        if mode and len(mode) >= 3 and int(mode[-1]) & 0o2:
            reasons.append(f"the cron file is world-writable (mode {mode})")
            severity = Severity.HIGH if severity is None or severity.rank < 3 else severity
            confidence = Confidence.HIGH

        if not reasons:
            return

        severity = severity or Severity.MEDIUM
        state = baseline_state_for(ctx, "cron_entries",
                                   f"{entry['file']}:{entry['line']}", command)
        severity, confidence = adjust_for_baseline(severity, confidence, state)

        result.add(make_finding(
            module=self.name, rule_id="PERS-CRON-JOB",
            title=f"Suspicious cron job in {os.path.basename(entry['file'])} (runs as {entry['user']})",
            severity=severity, confidence=confidence, category=Category.PERSISTENCE,
            target=f"{entry['file']}:{entry['line']}",
            why=(
                f"Schedule `{schedule}` runs `{redact(command)[:300]}` as {entry['user']}. "
                f"Flagged because " + "; ".join(reasons) + "."
            ),
            impact=f"Repeated code execution as {entry['user']} on the host's own schedule.",
            recommendation=(
                f"Open {entry['file']} and read the entry in full. Inspect any script it "
                f"calls without running it. If the job re-creates other artifacts you have "
                f"removed, this is the mechanism doing it - neutralise the cron entry before "
                f"cleaning what it drops."
            ),
            evidence=[lines_evidence(entry["file"], [f"{schedule} {entry['user']} {redact(command)}"],
                                     note=f"line {entry['line']}")],
            timestamps={"cron_file_mtime_utc": entry.get("mtime_utc")},
            remediation_risk=(
                "Scheduled jobs sometimes perform required maintenance for scored services. "
                "Read the job before disabling it."
            ),
            tags=["persistence", "cron"],
            correlation_key=f"path:{binary}" if binary.startswith("/") else None,
            baseline_state=state,
        ))

    def _check_cron_periodic_script(self, ctx, result, path):
        info = ctx.host.stat(path)
        if not info.exists or info.is_dir:
            return
        text, _trunc, err = ctx.host.read_text(path, max_bytes=256 * 1024)
        if err or text is None:
            return
        indicators = scan(text)
        if not indicators and not ((info.mode or 0) & 0o022):
            return
        reasons = []
        severity = Severity.MEDIUM
        confidence = Confidence.MEDIUM
        if indicators:
            reasons.append(f"its contents match known-bad patterns ({summarize(indicators)})")
            severity = Severity.CRITICAL if score(indicators) >= 3 else Severity.HIGH
            confidence = Confidence.HIGH if score(indicators) >= 3 else Confidence.MEDIUM
        if (info.mode or 0) & 0o022:
            reasons.append(f"it is writable by non-root users (mode {info.mode_octal})")
            severity = Severity.CRITICAL
            confidence = Confidence.HIGH
        result.add(make_finding(
            module=self.name, rule_id="PERS-CRON-PERIODIC-SCRIPT",
            title=f"Suspicious periodic cron script {path}",
            severity=severity, confidence=confidence, category=Category.PERSISTENCE,
            target=path,
            why=(
                f"{path} is executed by run-parts on a fixed schedule as root. It was flagged "
                f"because " + "; ".join(reasons) + "."
            ),
            impact="Scheduled root code execution.",
            recommendation=f"Read {path} in full without executing it; verify package ownership.",
            evidence=[file_evidence(ctx, path), stat_evidence(path, info)],
            timestamps={"mtime_utc": iso_from_epoch(info.mtime)},
            tags=["persistence", "cron"],
            correlation_key=f"path:{path}",
        ))

    def _check_at(self, ctx, result):
        result.checks_run += 1
        for spool in AT_SPOOL_DIRS:
            names, err = ctx.host.listdir(spool)
            if err:
                if err == "permission denied":
                    result.gap(spool, err, "at jobs were not reviewed", needs_root=True)
                continue
            jobs = [n for n in names if not n.startswith(".") and n not in (".SEQ", "spool")]
            if not jobs:
                continue
            details = []
            for name in jobs[:20]:
                path = os.path.join(spool, name)
                info = ctx.host.stat(path)
                text, _t, read_err = ctx.host.read_text(path, max_bytes=64 * 1024)
                indicators = scan(text or "")
                details.append(
                    f"{name} owner={info.owner} mtime={iso_from_epoch(info.mtime)}"
                    + (f" indicators: {summarize(indicators)}" if indicators else "")
                )
            result.add(make_finding(
                module=self.name, rule_id="PERS-AT-JOBS",
                title=f"{len(jobs)} queued at job(s) found in {spool}",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                category=Category.PERSISTENCE, target=spool,
                why=(
                    "`at` queues one-shot commands that run later as the submitting user. "
                    "Queued jobs are easy to miss because they do not appear in crontabs or "
                    "systemd, and a job can simply re-queue itself to persist indefinitely."
                ),
                impact="Delayed or repeating code execution outside cron and systemd.",
                recommendation=(
                    "Run `atq` to list jobs and `at -c <id>` to print one without running it. "
                    "Confirm each job is yours."
                ),
                evidence=[Evidence(source="file", locator=spool,
                                   content=redact("\n".join(details)))],
                tags=["persistence", "at"],
            ))

    # -------------------------------------------------------- init scripts

    def _check_init_scripts(self, ctx, result):
        result.checks_run += 1
        for path in ("/etc/rc.local", "/etc/rc.d/rc.local"):
            info = ctx.host.stat(path)
            if not info.exists:
                continue
            text, _t, err = ctx.host.read_text(path, max_bytes=128 * 1024)
            if err or text is None:
                continue
            meaningful = [
                l for l in text.splitlines()
                if l.strip() and not l.strip().startswith("#")
                and l.strip() not in ("exit 0", "#!/bin/sh", "#!/bin/bash")
            ]
            indicators = scan(text)
            if not meaningful:
                continue
            severity = Severity.HIGH if indicators else Severity.MEDIUM
            confidence = Confidence.HIGH if score(indicators) >= 3 else Confidence.MEDIUM
            result.add(make_finding(
                module=self.name, rule_id="PERS-RC-LOCAL",
                title=f"{path} contains commands that run at boot",
                severity=severity, confidence=confidence,
                category=Category.PERSISTENCE, target=path,
                why=(
                    f"{path} runs as root at the end of the boot sequence. It is empty on a "
                    f"stock install of most distributions, so any content is operator-added. "
                    f"It currently holds {len(meaningful)} active line(s)."
                    + (f" Contents match known-bad patterns: {summarize(indicators)}."
                       if indicators else
                       " Nothing in it matched a known-bad pattern, so confirm the lines are yours.")
                ),
                impact="Arbitrary root commands execute on every boot.",
                recommendation=f"Read {path} and confirm each line with your team.",
                evidence=[file_evidence(ctx, path), stat_evidence(path, info)],
                timestamps={"mtime_utc": iso_from_epoch(info.mtime)},
                tags=["persistence", "boot"],
            ))

        names, err = ctx.host.listdir("/etc/init.d")
        if err:
            return
        for name in names:
            if name in ("README", "skeleton", ".depend.boot", ".depend.start", ".depend.stop"):
                continue
            path = os.path.join("/etc/init.d", name)
            info = ctx.host.stat(path)
            if info.is_dir:
                continue
            text, _t, read_err = ctx.host.read_text(path, max_bytes=128 * 1024)
            if read_err or not text:
                continue
            indicators = scan(text)
            writable = (info.mode or 0) & 0o022
            if not indicators and not writable:
                continue
            result.add(make_finding(
                module=self.name, rule_id="PERS-INITD-SCRIPT",
                title=f"Suspicious SysV init script /etc/init.d/{name}",
                severity=Severity.CRITICAL if score(indicators) >= 3 else Severity.HIGH,
                confidence=Confidence.HIGH if score(indicators) >= 3 else Confidence.MEDIUM,
                category=Category.PERSISTENCE, target=path,
                why=(
                    f"{path} runs as root during boot on systems that use SysV init, and is "
                    f"still honoured through systemd's generator on most systemd distributions. "
                    + (f"Its contents match known-bad patterns: {summarize(indicators)}. "
                       if indicators else "")
                    + (f"It is writable by non-root users (mode {info.mode_octal}). " if writable else "")
                ),
                impact="Root code execution at boot.",
                recommendation=f"Read {path} without executing it and verify package ownership.",
                evidence=[file_evidence(ctx, path), stat_evidence(path, info)],
                timestamps={"mtime_utc": iso_from_epoch(info.mtime)},
                tags=["persistence", "sysvinit"],
                correlation_key=f"path:{path}",
            ))

    # ----------------------------------------------------------- shell init

    def _check_shell_init(self, ctx, result):
        result.checks_run += 1
        targets: List[Tuple[str, str]] = [("system", p) for p in SHELL_INIT_SYSTEM]
        names, err = ctx.host.listdir("/etc/profile.d")
        if not err:
            targets += [("system", os.path.join("/etc/profile.d", n))
                        for n in names if n.endswith((".sh", ".bash", ".csh"))]
        for username, home, _uid in ctx.host.home_dirs():
            for rel in SHELL_INIT_USER:
                targets.append((username, os.path.join(home, rel)))

        for owner, path in targets:
            info = ctx.host.stat(path)
            if not info.exists or info.is_dir:
                continue
            text, _t, read_err = ctx.host.read_text(path, max_bytes=256 * 1024)
            if read_err or text is None:
                continue
            indicators = scan(text)
            writable = (info.mode or 0) & 0o022
            if not indicators and not writable:
                continue
            reasons = []
            severity = Severity.MEDIUM
            confidence = Confidence.MEDIUM
            if indicators:
                reasons.append(f"its contents match known-bad patterns ({summarize(indicators)})")
                severity = Severity.HIGH if score(indicators) >= 3 else Severity.MEDIUM
                confidence = Confidence.HIGH if score(indicators) >= 3 else Confidence.MEDIUM
            if writable:
                reasons.append(f"it is writable by non-root users (mode {info.mode_octal})")
                severity = Severity.HIGH
                confidence = Confidence.HIGH
            matching_lines = [
                l.strip() for l in text.splitlines()
                if any(ind.pattern.search(l) for ind in indicators)
            ][:12]

            result.add(make_finding(
                module=self.name, rule_id="PERS-SHELL-INIT",
                title=f"Suspicious content in shell startup file {path}",
                severity=severity, confidence=confidence,
                category=Category.PERSISTENCE, target=path,
                why=(
                    f"{path} is sourced every time "
                    + ("any user starts a shell" if owner == "system"
                       else f"'{owner}' starts a shell")
                    + ". It was flagged because " + "; ".join(reasons) + ". Shell startup "
                    "files are a favourite persistence location because they re-run on every "
                    "login, including yours."
                ),
                impact=(
                    "Code runs under the identity of whoever opens a shell - potentially your "
                    "own session, with your privileges."
                ),
                recommendation=(
                    f"Read {path}. Be careful: opening a shell on this host re-executes it. "
                    f"Inspect with `cat`, not by sourcing."
                ),
                evidence=[
                    lines_evidence(path, matching_lines, note="lines matching indicators")
                    if matching_lines else file_evidence(ctx, path, max_chars=2000),
                    stat_evidence(path, info),
                ],
                timestamps={"mtime_utc": iso_from_epoch(info.mtime)},
                tags=["persistence", "shell-init"],
                correlation_key=f"account:{owner}" if owner != "system" else None,
            ))

    # ------------------------------------------------------- dynamic linker

    def _check_ld_preload(self, ctx, result):
        result.checks_run += 1
        path = "/etc/ld.so.preload"
        info = ctx.host.stat(path)
        if info.exists:
            text, _t, err = ctx.host.read_text(path, max_bytes=16384)
            entries = [l.strip() for l in (text or "").splitlines() if l.strip()] if text else []
            if entries or err:
                lib_details = []
                for lib in entries:
                    lib_info = ctx.host.stat(lib)
                    lib_details.append(
                        f"{lib} exists={lib_info.exists} owner={lib_info.owner} "
                        f"mode={lib_info.mode_octal} mtime={iso_from_epoch(lib_info.mtime)}"
                    )
                result.add(make_finding(
                    module=self.name, rule_id="PERS-LD-PRELOAD",
                    title=f"/etc/ld.so.preload is present with {len(entries)} library entry/entries",
                    severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                    category=Category.PERSISTENCE, target=path,
                    why=(
                        "Every library listed in /etc/ld.so.preload is loaded into every "
                        "dynamically linked process that starts on this host, including the "
                        "tools you are using to investigate. This is the standard mechanism "
                        "for userland rootkits: the preloaded library hooks libc functions so "
                        "that ls, ps, netstat and find omit the attacker's files, processes "
                        "and connections. The file does not exist on a stock Linux install."
                    ),
                    impact=(
                        "Every process on the host may be subverted, and the output of your "
                        "own investigation tools cannot be trusted."
                    ),
                    recommendation=(
                        "Treat the host as compromised at root level. Do not rely on local "
                        "tooling for further triage: compare findings against /proc directly, "
                        "and verify from a known-good environment or external media. Capture "
                        "the listed libraries as evidence before removing the preload entry; "
                        "removing it may crash processes that depend on the hooked library."
                    ),
                    evidence=[
                        file_evidence(ctx, path),
                        stat_evidence(path, info),
                        Evidence(source="derived", locator="preloaded libraries",
                                 content="\n".join(lib_details) or "(none listed)"),
                    ],
                    timestamps={"mtime_utc": iso_from_epoch(info.mtime)},
                    remediation_risk=(
                        "Removing a preloaded library that a running service depends on can "
                        "crash that service. Capture first, remove during a controlled window."
                    ),
                    tags=["persistence", "rootkit", "ld-preload", "integrity-doubt"],
                    correlation_key="rootkit:ld-preload",
                ))

        names, err = ctx.host.listdir("/etc/ld.so.conf.d")
        if err:
            return
        for name in names:
            conf_path = os.path.join("/etc/ld.so.conf.d", name)
            text, _t, read_err = ctx.host.read_text(conf_path, max_bytes=16384)
            if read_err or not text:
                continue
            bad = [l.strip() for l in text.splitlines()
                   if l.strip() and not l.strip().startswith("#")
                   and (l.strip().startswith(("/tmp", "/var/tmp", "/dev/shm", "/home"))
                        or not l.strip().startswith("/"))]
            if not bad:
                continue
            result.add(make_finding(
                module=self.name, rule_id="PERS-LD-CONF-WRITABLE",
                title=f"Dynamic linker search path {conf_path} includes a user-writable directory",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                category=Category.PERSISTENCE, target=conf_path,
                why=(
                    f"{conf_path} adds {', '.join(bad)} to the system library search path. Any "
                    f"user who can write there can supply a malicious replacement for a shared "
                    f"library and have it loaded by privileged processes."
                ),
                impact="Library hijacking against any process on the host, including root services.",
                recommendation=(
                    f"Remove the entry and run `ldconfig`. Check the directory for planted "
                    f".so files first and capture them as evidence."
                ),
                evidence=[file_evidence(ctx, conf_path)],
                tags=["persistence", "library-hijack"],
                correlation_key="rootkit:ld-path",
            ))

    # ------------------------------------------------------------------ PAM

    def _check_pam(self, ctx, result):
        result.checks_run += 1
        names, err = ctx.host.listdir("/etc/pam.d")
        if err:
            if err != "not found":
                result.gap("/etc/pam.d", err, "PAM persistence was not assessed",
                           needs_root=not ctx.facts.is_root)
            return
        for name in names:
            path = os.path.join("/etc/pam.d", name)
            info = ctx.host.stat(path)
            if info.is_dir:
                continue
            lines, read_err = ctx.host.read_lines(path, max_bytes=128 * 1024)
            if read_err:
                continue
            for i, raw in enumerate(lines, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                for module_name, reason in PAM_SUSPECT_MODULES.items():
                    if module_name in line:
                        result.add(make_finding(
                            module=self.name, rule_id="PERS-PAM-EXEC",
                            title=f"PAM stack {name} invokes {module_name}",
                            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                            category=Category.PERSISTENCE, target=f"{path}:{i}",
                            why=(
                                f"The line `{redact(line)}` in {path} {reason}. PAM runs during "
                                f"every authentication, so a module here executes with root "
                                f"privileges on every login attempt and can capture the "
                                f"credentials being presented. There are legitimate uses (home "
                                f"directory creation, notifications), so read the referenced "
                                f"program before concluding."
                            ),
                            impact=(
                                "Code execution as root on every authentication, with access to "
                                "the submitted credentials."
                            ),
                            recommendation=(
                                "Identify the program the module runs, check its ownership and "
                                "modification time, and read it without executing it. Compare "
                                "the PAM file against the packaged version."
                            ),
                            evidence=[lines_evidence(path, [redact(line)], note=f"line {i}"),
                                      stat_evidence(path, info)],
                            timestamps={"mtime_utc": iso_from_epoch(info.mtime)},
                            remediation_risk=(
                                "A malformed PAM configuration can lock every account out of "
                                "the system, including root. Keep a root session open and test "
                                "authentication from a second terminal before closing it."
                            ),
                            tags=["persistence", "pam", "credential-access"],
                            correlation_key="pam:module",
                        ))
                # nullok allows empty passwords through PAM
                if "pam_unix.so" in line and "nullok" in line:
                    result.add(make_finding(
                        module=self.name, rule_id="PERS-PAM-NULLOK",
                        title=f"PAM stack {name} permits empty passwords (nullok)",
                        severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                        category=Category.AUTHENTICATION, target=f"{path}:{i}",
                        why=(
                            f"`nullok` in {path} tells pam_unix to accept an empty password as "
                            f"valid. Any account whose shadow entry has an empty password field "
                            f"can then authenticate with no credential at all. Debian and "
                            f"Ubuntu ship this in common-auth by default, so on its own it is a "
                            f"hardening item rather than evidence of tampering - it becomes "
                            f"serious when combined with an account that actually has an empty "
                            f"password field (rule ACCT-EMPTY-PASSWORD)."
                        ),
                        impact="Password-free authentication for accounts with empty hashes.",
                        recommendation=(
                            "Remove `nullok` and confirm no account has an empty password field. "
                            "Test authentication before closing your session."
                        ),
                        evidence=[lines_evidence(path, [redact(line)], note=f"line {i}")],
                        tags=["authentication", "pam"],
                        correlation_key="pam:nullok",
                    ))
            if (info.mode or 0) & 0o022:
                result.add(make_finding(
                    module=self.name, rule_id="PERS-PAM-WRITABLE",
                    title=f"PAM configuration {path} is writable by non-root (mode {info.mode_octal})",
                    severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                    category=Category.PRIVESC, target=path,
                    why=(
                        "A writable PAM file lets any local user rewrite the authentication "
                        "stack - for example by inserting a rule that always succeeds."
                    ),
                    impact="Complete bypass of authentication for the affected service.",
                    recommendation=f"`chown root:root {path}` and `chmod 644 {path}`.",
                    evidence=[stat_evidence(path, info)],
                    tags=["pam", "file-permissions"],
                ))

    # ------------------------------------------------------- motd and udev

    def _check_motd_and_udev(self, ctx, result):
        result.checks_run += 1
        names, err = ctx.host.listdir("/etc/update-motd.d")
        if not err:
            for name in names:
                path = os.path.join("/etc/update-motd.d", name)
                text, _t, read_err = ctx.host.read_text(path, max_bytes=64 * 1024)
                if read_err or not text:
                    continue
                indicators = scan(text)
                if not indicators:
                    continue
                result.add(make_finding(
                    module=self.name, rule_id="PERS-MOTD-SCRIPT",
                    title=f"MOTD script {path} contains suspicious commands",
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    category=Category.PERSISTENCE, target=path,
                    why=(
                        f"Scripts in /etc/update-motd.d run as root every time a user logs in "
                        f"over SSH, to build the message of the day. This one matches "
                        f"known-bad patterns ({summarize(indicators)}). It is a quiet "
                        f"persistence location because the output is cosmetic and nobody reads "
                        f"these scripts."
                    ),
                    impact="Root code execution on every SSH login, including yours.",
                    recommendation=f"Read {path} without executing it; compare against the package version.",
                    evidence=[file_evidence(ctx, path)],
                    tags=["persistence", "motd"],
                    correlation_key=f"path:{path}",
                ))

        for udev_dir in ("/etc/udev/rules.d", "/lib/udev/rules.d", "/usr/lib/udev/rules.d"):
            entries, uerr = ctx.host.listdir(udev_dir)
            if uerr:
                continue
            for name in entries:
                path = os.path.join(udev_dir, name)
                text, _t, read_err = ctx.host.read_text(path, max_bytes=64 * 1024)
                if read_err or not text:
                    continue
                run_lines = [l.strip() for l in text.splitlines()
                             if "RUN" in l and "+=" in l and not l.strip().startswith("#")]
                flagged = [l for l in run_lines
                           if scan(l) or any(d in l for d in ("/tmp/", "/dev/shm/", "/var/tmp/", "/home/"))]
                if not flagged:
                    continue
                result.add(make_finding(
                    module=self.name, rule_id="PERS-UDEV-RULE",
                    title=f"udev rule {path} runs a program from an unusual location",
                    severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                    category=Category.PERSISTENCE, target=path,
                    why=(
                        "udev rules with RUN+= execute as root when a matching device event "
                        "occurs, which can be as routine as a loopback device appearing at "
                        "boot. The flagged rule points at a writable or temporary location."
                    ),
                    impact="Root code execution triggered by device events.",
                    recommendation=f"Read {path} and verify the referenced program.",
                    evidence=[lines_evidence(path, flagged[:10])],
                    tags=["persistence", "udev"],
                ))

    # -------------------------------------------------------- kernel modules

    def _check_kernel_modules(self, ctx, result):
        result.checks_run += 1
        text, _t, err = ctx.host.read_text("/proc/modules", max_bytes=256 * 1024)
        if err or not text:
            result.gap("/proc/modules", err or "empty",
                       "loaded kernel modules were not enumerated")
            return
        modules = []
        for line in text.splitlines():
            parts = line.split()
            if parts:
                modules.append(parts[0])
        result.facts["kernel_modules"] = sorted(modules)

        # Modules loaded at boot from configuration files.
        for conf_dir in ("/etc/modules-load.d", "/etc/modprobe.d"):
            names, lerr = ctx.host.listdir(conf_dir)
            if lerr:
                continue
            for name in names:
                path = os.path.join(conf_dir, name)
                ltext, _t2, rerr = ctx.host.read_text(path, max_bytes=32768)
                if rerr or not ltext:
                    continue
                install_lines = [l.strip() for l in ltext.splitlines()
                                 if l.strip().startswith("install ") and "/bin/" in l]
                if install_lines:
                    result.add(make_finding(
                        module=self.name, rule_id="PERS-MODPROBE-INSTALL",
                        title=f"modprobe configuration {path} runs a shell command",
                        severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                        category=Category.PERSISTENCE, target=path,
                        why=(
                            "An `install` directive in modprobe configuration replaces module "
                            "loading with an arbitrary command run as root. Triggering it can "
                            "be as simple as any process causing the named module to load. "
                            "Some legitimate configurations use `install <mod> /bin/true` to "
                            "blacklist a module, so read the directive before concluding."
                        ),
                        impact="Root code execution on module load events.",
                        recommendation=f"Read {path}; confirm each install directive.",
                        evidence=[lines_evidence(path, install_lines[:10])],
                        tags=["persistence", "kernel"],
                    ))

        # Out-of-tree modules: no corresponding file under the running kernel's
        # module tree is a reasonable signal, with caveats for DKMS.
        kernel = ctx.facts.kernel
        if not kernel:
            return
        unresolved = []
        for mod in modules:
            if self._module_file_exists(ctx, kernel, mod):
                continue
            unresolved.append(mod)
        if unresolved:
            result.add(make_finding(
                module=self.name, rule_id="PERS-KMOD-UNRESOLVED",
                title=f"{len(unresolved)} loaded kernel module(s) have no file under /lib/modules/{kernel}",
                severity=Severity.HIGH, confidence=Confidence.LOW,
                category=Category.PERSISTENCE, target="kernel-modules",
                why=(
                    f"These modules are loaded ({', '.join(unresolved[:12])}"
                    + ("..." if len(unresolved) > 12 else "")
                    + f") but no matching .ko file was found under /lib/modules/{kernel}. "
                    "A kernel-mode rootkit loaded from a deleted or relocated file looks "
                    "exactly like this. So do built-in modules on some kernels and modules "
                    "whose file naming this check does not predict, which is why confidence "
                    "is low - treat it as a lead to verify, not a conclusion."
                ),
                impact=(
                    "A kernel module can hide processes, files and connections from every "
                    "userland tool, including this one."
                ),
                recommendation=(
                    "Check `modinfo <name>` for each module. Compare the loaded module list "
                    "against an identical clean host. If a module cannot be accounted for, "
                    "verification requires an out-of-band environment - a kernel rootkit can "
                    "defeat any check performed on the running system."
                ),
                evidence=[Evidence(source="file", locator="/proc/modules",
                                   content="\n".join(unresolved[:50]))],
                tags=["persistence", "kernel", "integrity-doubt"],
                partial_evidence=True,
                correlation_key="rootkit:kernel",
            ))

    @staticmethod
    def _module_file_exists(ctx, kernel: str, module: str) -> bool:
        base = f"/lib/modules/{kernel}"
        if not ctx.host.is_dir(base):
            return True   # cannot evaluate; do not flag
        candidates = [module, module.replace("_", "-"), module.replace("-", "_")]
        files, _errs, _limit = ctx.host.walk(base, max_depth=8, max_entries=40000)
        names = {os.path.basename(f).split(".")[0] for f in files}
        return any(c in names for c in candidates)

    # -------------------------------------------------------------- containers

    def _check_containers(self, ctx, result):
        result.checks_run += 1
        if not (ctx.host.has("docker") or ctx.host.has("podman")):
            return
        tool = "docker" if ctx.host.has("docker") else "podman"
        res = ctx.host.run(
            [tool, "ps", "-a", "--format",
             "{{.Names}}\t{{.Image}}\t{{.Command}}\t{{.Status}}"], timeout=20)
        if not res.ok:
            result.gap(f"{tool} ps", res.error or res.stderr.strip()[:120],
                       "container persistence was not assessed",
                       needs_root=not ctx.facts.is_root)
            return
        rows = [r for r in res.stdout.splitlines() if r.strip()]
        if not rows:
            return
        result.facts["containers"] = rows
        suspicious = [r for r in rows if scan(r)]

        inspect = ctx.host.run(
            [tool, "ps", "-a", "--format", "{{.Names}}"], timeout=15)
        privileged = []
        if inspect.ok:
            for cname in [c.strip() for c in inspect.stdout.splitlines() if c.strip()][:30]:
                det = ctx.host.run(
                    [tool, "inspect", "--format",
                     "{{.Name}} privileged={{.HostConfig.Privileged}} "
                     "restart={{.HostConfig.RestartPolicy.Name}} "
                     "pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}} "
                     "binds={{.HostConfig.Binds}}", cname], timeout=15)
                if det.ok and ("privileged=true" in det.stdout
                               or "/:/." in det.stdout
                               or ":/host" in det.stdout):
                    privileged.append(det.stdout.strip())

        if privileged:
            result.add(make_finding(
                module=self.name, rule_id="PERS-CONTAINER-PRIVILEGED",
                title=f"{len(privileged)} container(s) run privileged or mount the host filesystem",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                category=Category.PERSISTENCE, target=f"{tool}:privileged-containers",
                why=(
                    "A privileged container, or one that bind-mounts the host root, is not "
                    "isolated from the host: anyone who can execute inside it can modify the "
                    "host filesystem and reach root. A container with a restart policy also "
                    "survives reboots, making it durable persistence that lives outside the "
                    "host's own init system."
                ),
                impact="Container escape to host root, with reboot persistence.",
                recommendation=(
                    f"Review each container with `{tool} inspect` and confirm it is a required "
                    f"service. Check the image source and the entrypoint command."
                ),
                evidence=[Evidence(source="command", locator=f"{tool} inspect",
                                   content=redact("\n".join(privileged[:20])))],
                remediation_risk="Stopping a container that provides a scored service costs points.",
                tags=["persistence", "container"],
            ))
        if suspicious:
            result.add(make_finding(
                module=self.name, rule_id="PERS-CONTAINER-COMMAND",
                title=f"{len(suspicious)} container(s) have suspicious entrypoint commands",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                category=Category.PERSISTENCE, target=f"{tool}:containers",
                why=(
                    "The listed containers run commands matching known-bad patterns. "
                    "Containers are an easy place to hide a listener because `ps` on the host "
                    "shows the process but not the image it came from."
                ),
                impact="Attacker-controlled code running with container restart persistence.",
                recommendation=f"Inspect each image and entrypoint; check `{tool} logs` for activity.",
                evidence=[Evidence(source="command", locator=f"{tool} ps -a",
                                   content=redact("\n".join(suspicious[:20])))],
                tags=["persistence", "container"],
            ))



# ============================================================================
# bulwark/detection/processes.py
# detection: processes
# ============================================================================

# Running process analysis, read directly from /proc.
#
# Reading /proc rather than shelling out to `ps` matters here: a userland rootkit
# that hooks libc or replaces /bin/ps will lie to `ps` but usually not to a
# direct read of /proc. Both are collected and compared, and a disagreement is
# reported rather than resolved silently.
#
# No process is ever signalled, traced or terminated.




WEB_SERVER_NAMES = {
    "apache2", "httpd", "nginx", "php-fpm", "php-fpm7.4", "php-fpm8.1",
    "php-fpm8.2", "lighttpd", "caddy", "tomcat", "java", "gunicorn", "uwsgi",
    "node",
}
SHELL_NAMES = {"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "busybox"}
NETWORK_TOOL_NAMES = {
    "nc", "ncat", "netcat", "nc.traditional", "socat", "curl", "wget",
    "telnet", "ssh", "python", "python3", "perl", "ruby", "php",
}


class Process:
    __slots__ = (
        "pid", "ppid", "name", "state", "uid", "gid", "user", "exe",
        "exe_deleted", "cmdline", "cwd", "start_time", "threads",
        "exe_info", "is_kernel_thread",
    )

    def __init__(self, pid):
        self.pid = pid
        self.ppid: Optional[int] = None
        self.name = ""
        self.state = ""
        self.uid: Optional[int] = None
        self.gid: Optional[int] = None
        self.user: Optional[str] = None
        self.exe: Optional[str] = None
        self.exe_deleted = False
        self.cmdline = ""
        self.cwd: Optional[str] = None
        self.start_time: Optional[float] = None
        self.threads: Optional[int] = None
        self.exe_info = None
        self.is_kernel_thread = False

    def to_dict(self):
        return {
            "pid": self.pid, "ppid": self.ppid, "name": self.name,
            "uid": self.uid, "user": self.user, "exe": self.exe,
            "exe_deleted": self.exe_deleted,
            "cmdline": redact(self.cmdline)[:400],
            "cwd": self.cwd,
            "start_time_utc": iso_from_epoch(self.start_time),
        }


class ProcessesModule(DetectionModule):
    name = "processes"
    version = "1.1"
    title = "Processes and runtime activity"
    description = (
        "Builds a process table from /proc, flags execution from temporary "
        "directories, deleted binaries, webserver-spawned shells and "
        "suspicious command lines, and cross-checks /proc against ps."
    )
    quick = True

    def check(self, ctx: AuditContext, result: ModuleResult) -> None:
        processes, errors = self._read_proc(ctx)
        if not processes:
            result.gap("/proc", "no processes could be read",
                       "runtime activity was not assessed")
            return
        if errors:
            result.gap("/proc", f"{len(errors)} process entries were partially unreadable",
                       "some process attributes are missing",
                       needs_root=not ctx.facts.is_root)

        ctx.share("processes", processes)
        result.facts["process_count"] = len(processes)
        result.facts["processes"] = [
            p.to_dict() for p in processes.values()
            if not p.is_kernel_thread
        ][:500]

        by_pid = processes
        self._check_deleted_binaries(ctx, result, by_pid)
        self._check_suspicious_locations(ctx, result, by_pid)
        self._check_command_lines(ctx, result, by_pid)
        self._check_masquerading(ctx, result, by_pid)
        self._check_webserver_children(ctx, result, by_pid)
        self._check_writable_executables(ctx, result, by_pid)
        self._compare_with_ps(ctx, result, by_pid)

    # --------------------------------------------------------------- /proc

    def _read_proc(self, ctx) -> Tuple[Dict[int, Process], List[str]]:
        processes: Dict[int, Process] = {}
        errors: List[str] = []
        entries, err = ctx.host.listdir("/proc")
        if err:
            return processes, [f"/proc: {err}"]

        boot_time = boot_time_of(ctx.host)
        clock_ticks = clock_ticks_of(ctx.host)

        for entry in entries:
            if not entry.isdigit():
                continue
            pid = int(entry)
            proc, pid_errors = read_process(ctx.host, pid, boot_time, clock_ticks)
            errors.extend(pid_errors)
            processes[pid] = proc
        return processes, errors


    # -------------------------------------------------------------- checks

    def _check_deleted_binaries(self, ctx, result, processes):
        result.checks_run += 1
        for proc in sorted(processes.values(), key=lambda p: p.pid):
            if not proc.exe_deleted:
                continue
            severity = Severity.CRITICAL if proc.uid == 0 else Severity.HIGH
            result.add(make_finding(
                module=self.name, rule_id="PROC-DELETED-BINARY",
                title=f"PID {proc.pid} ({proc.name}) is running from a deleted executable",
                severity=severity, confidence=Confidence.HIGH,
                category=Category.PROCESS, target=f"pid:{proc.pid}:{proc.name}",
                why=(
                    f"The executable this process was started from ({proc.exe}) no longer "
                    f"exists on disk. Deleting the binary after launch is a deliberate "
                    f"anti-forensic step: the code keeps running but there is nothing left for "
                    f"you to hash, scan or submit for analysis. A package upgrade can also "
                    f"produce this state for a service that has not been restarted, so check "
                    f"whether a recent upgrade explains it."
                    + (f" It runs as UID {proc.uid} ({proc.user})." if proc.uid is not None else "")
                ),
                impact=(
                    "The running code cannot be examined on disk, and the process survives "
                    "any filesystem cleanup."
                ),
                recommendation=(
                    f"Recover the running image before it exits - `cp /proc/{proc.pid}/exe "
                    f"/path/to/evidence/pid{proc.pid}.bin` reads the in-memory file and works "
                    f"even though the path is deleted. Capture `ls -l /proc/{proc.pid}/fd`, "
                    f"the command line and the parent chain, then check the package manager "
                    f"log for a recent upgrade of {proc.name}."
                ),
                evidence=[
                    Evidence(source="proc", locator=f"/proc/{proc.pid}",
                             content=(
                                 f"name={proc.name}\npid={proc.pid} ppid={proc.ppid}\n"
                                 f"uid={proc.uid} ({proc.user})\n"
                                 f"exe={proc.exe} (deleted)\n"
                                 f"cwd={proc.cwd}\n"
                                 f"cmdline={redact(proc.cmdline)[:400]}\n"
                                 f"started={iso_from_epoch(proc.start_time)}"),
                             meta={"pid": proc.pid, "ppid": proc.ppid}),
                ],
                timestamps={"process_start_utc": iso_from_epoch(proc.start_time)},
                remediation_risk=(
                    "Killing the process destroys the only copy of the executable. Capture "
                    "/proc/<pid>/exe first."
                ),
                tags=["process", "anti-forensics", "deleted-binary"],
                correlation_key=f"path:{proc.exe}" if proc.exe else f"pid:{proc.pid}",
            ))

    def _check_suspicious_locations(self, ctx, result, processes):
        result.checks_run += 1
        for proc in sorted(processes.values(), key=lambda p: p.pid):
            if not proc.exe or proc.exe_deleted:
                continue
            strong = in_strong_suspicious_dir(proc.exe)
            weak = in_suspicious_dir(proc.exe)
            if not weak:
                continue
            severity = Severity.CRITICAL if (strong and proc.uid == 0) else (
                Severity.HIGH if strong else Severity.MEDIUM)
            confidence = Confidence.HIGH if strong else Confidence.MEDIUM
            info = ctx.host.stat(proc.exe)
            result.add(make_finding(
                module=self.name, rule_id="PROC-EXEC-FROM-TEMP",
                title=f"PID {proc.pid} ({proc.name}) is executing from {proc.exe}",
                severity=severity, confidence=confidence,
                category=Category.PROCESS, target=f"path:{proc.exe}",
                why=(
                    f"The running executable is {proc.exe}"
                    + (" , which is in a world-writable temporary directory that is cleared "
                       "on reboot. Packaged software is never installed there, so a long-lived "
                       "process running from it was placed by hand."
                       if strong else
                       ", which is outside the directories where packaged software is "
                       "installed. This may be a legitimate locally built application - check "
                       "provenance.")
                    + (f" It runs as UID {proc.uid} ({proc.user})." if proc.uid is not None else "")
                ),
                impact=(
                    f"Attacker-controlled code running as {proc.user or proc.uid}"
                    + (" with full root privileges." if proc.uid == 0 else ".")
                ),
                recommendation=(
                    f"Hash the binary (`sha256sum {proc.exe}`) and record it, then inspect it "
                    f"statically with `file` and `strings` - do not run it. Check the parent "
                    f"process (PID {proc.ppid}) to learn how it was started, and look for the "
                    f"persistence mechanism that relaunches it before you kill anything."
                ),
                evidence=[
                    Evidence(source="proc", locator=f"/proc/{proc.pid}",
                             content=(
                                 f"name={proc.name} pid={proc.pid} ppid={proc.ppid}\n"
                                 f"uid={proc.uid} ({proc.user})\nexe={proc.exe}\n"
                                 f"cwd={proc.cwd}\ncmdline={redact(proc.cmdline)[:400]}\n"
                                 f"started={iso_from_epoch(proc.start_time)}")),
                    stat_evidence(proc.exe, info) if info.exists else
                    Evidence(source="file", locator=proc.exe, content="", error="not found"),
                ],
                timestamps={"process_start_utc": iso_from_epoch(proc.start_time),
                            "binary_mtime_utc": iso_from_epoch(info.mtime)},
                remediation_risk=(
                    "Killing the process without removing its persistence mechanism means it "
                    "comes straight back, and tells the operator you are watching."
                ),
                tags=["process", "suspicious-location"],
                correlation_key=f"path:{proc.exe}",
            ))

    def _check_command_lines(self, ctx, result, processes):
        result.checks_run += 1
        for proc in sorted(processes.values(), key=lambda p: p.pid):
            if proc.is_kernel_thread or not proc.cmdline:
                continue
            indicators = scan(proc.cmdline)
            if not indicators:
                continue
            total = score(indicators)
            severity = Severity.CRITICAL if total >= 5 else (
                Severity.HIGH if total >= 3 else Severity.MEDIUM)
            confidence = Confidence.HIGH if total >= 3 else Confidence.MEDIUM
            if proc.uid == 0 and severity.rank < Severity.CRITICAL.rank and total >= 3:
                severity = Severity.CRITICAL
            result.add(make_finding(
                module=self.name, rule_id="PROC-SUSPICIOUS-CMDLINE",
                title=f"PID {proc.pid} ({proc.name}) has a suspicious command line",
                severity=severity, confidence=confidence,
                category=Category.PROCESS, target=f"pid:{proc.pid}:{proc.name}",
                why=(
                    f"The command line matches {len(indicators)} known-bad pattern(s): "
                    f"{summarize(indicators)}. The process runs as "
                    f"{proc.user or proc.uid} from {proc.exe or 'an unreadable path'}. "
                    f"These patterns describe mechanism, not intent - read the full command "
                    f"line before acting, since administrators occasionally use the same "
                    f"constructs."
                ),
                impact=(
                    "Depending on the pattern: an active backdoor channel, code being "
                    "downloaded and run, or defensive controls being disabled."
                ),
                recommendation=(
                    f"Read the full command line from /proc/{proc.pid}/cmdline, identify the "
                    f"parent (PID {proc.ppid}), and check /proc/{proc.pid}/fd for open sockets "
                    f"and files. Correlate with the network module findings for this PID."
                ),
                evidence=[
                    Evidence(source="proc", locator=f"/proc/{proc.pid}/cmdline",
                             content=redact_argv(proc.cmdline)[:1200],
                             meta={"indicators": [i.key for i in indicators],
                                   "indicator_score": total,
                                   "note": "command line is recorded as data and never executed"}),
                    Evidence(source="proc", locator=f"/proc/{proc.pid}",
                             content=(f"ppid={proc.ppid} uid={proc.uid} ({proc.user}) "
                                      f"exe={proc.exe} cwd={proc.cwd} "
                                      f"started={iso_from_epoch(proc.start_time)}")),
                ],
                timestamps={"process_start_utc": iso_from_epoch(proc.start_time)},
                tags=["process", "indicator-match"] + [i.key for i in indicators[:5]],
                correlation_key=f"path:{proc.exe}" if proc.exe else f"pid:{proc.pid}",
            ))

    def _check_masquerading(self, ctx, result, processes):
        """Kernel threads have no executable and no command line. A userland
        process wearing a kernel thread's name is deliberately hiding."""
        result.checks_run += 1
        for proc in sorted(processes.values(), key=lambda p: p.pid):
            looks_kernel = proc.name.startswith("[") or re.match(
                r"^(kworker|ksoftirqd|kthreadd|migration|rcu_|watchdog|kswapd|"
                r"kcompactd|khugepaged|kintegrityd|kblockd|irq/)", proc.name or "")
            if not looks_kernel:
                continue
            # A genuine kernel thread has no command line and no resolvable
            # executable: /proc/<pid>/exe exists as a link but has no target.
            # Only positive evidence of a userland process counts here, so an
            # unreadable link is never treated as a disguise.
            has_real_exe = bool(proc.exe) and proc.exe.startswith("/")
            if not has_real_exe and not proc.cmdline:
                continue
            result.add(make_finding(
                module=self.name, rule_id="PROC-KTHREAD-MASQUERADE",
                title=f"PID {proc.pid} uses a kernel-thread name but is a userland process",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                category=Category.PROCESS, target=f"pid:{proc.pid}:{proc.name}",
                why=(
                    f"'{proc.name}' is a name pattern used by kernel threads. Real kernel "
                    f"threads have no executable file and no command line, and their parent is "
                    f"kthreadd (PID 2). This process has "
                    + (f"exe={proc.exe} " if proc.exe else "")
                    + (f"cmdline={redact(proc.cmdline)[:200]!r} " if proc.cmdline else "")
                    + f"and parent PID {proc.ppid}. Borrowing a kernel thread name is a "
                    f"deliberate attempt to look unremarkable in `ps` output."
                ),
                impact="A disguised process, almost certainly hostile.",
                recommendation=(
                    f"Capture /proc/{proc.pid}/exe, the command line, the open file "
                    f"descriptors and the parent chain before doing anything else. Treat this "
                    f"host as compromised."
                ),
                evidence=[Evidence(
                    source="proc", locator=f"/proc/{proc.pid}",
                    content=(f"name={proc.name}\nppid={proc.ppid}\nuid={proc.uid} ({proc.user})\n"
                             f"exe={proc.exe}\ncmdline={redact(proc.cmdline)[:400]}\n"
                             f"started={iso_from_epoch(proc.start_time)}"))],
                timestamps={"process_start_utc": iso_from_epoch(proc.start_time)},
                tags=["process", "masquerade", "high-value"],
                correlation_key=f"pid:{proc.pid}",
            ))

    def _check_webserver_children(self, ctx, result, processes):
        """A shell or network tool whose parent is a web server is the classic
        web shell signature."""
        result.checks_run += 1
        for proc in sorted(processes.values(), key=lambda p: p.pid):
            if proc.ppid is None or proc.ppid not in processes:
                continue
            parent = processes[proc.ppid]
            parent_base = (parent.name or "").lower()
            child_base = (proc.name or "").lower()
            if parent_base not in WEB_SERVER_NAMES:
                continue
            if child_base not in SHELL_NAMES and child_base not in NETWORK_TOOL_NAMES:
                continue
            indicators = scan(proc.cmdline)
            severity = Severity.CRITICAL if indicators else Severity.HIGH
            result.add(make_finding(
                module=self.name, rule_id="PROC-WEBSHELL-CHILD",
                title=f"{proc.name} (PID {proc.pid}) was spawned by web server {parent.name} (PID {parent.pid})",
                severity=severity, confidence=Confidence.HIGH,
                category=Category.PROCESS, target=f"pid:{proc.pid}:{proc.name}",
                why=(
                    f"A web server process started a {child_base}. Web servers serve content; "
                    f"they do not normally spawn interactive shells or network utilities. This "
                    f"parent-child relationship is the standard signature of a web shell - a "
                    f"script dropped into the web root that passes attacker input to the "
                    f"system. Some applications do legitimately shell out, so check the "
                    f"application before concluding."
                    + (f" The child's command line also matches: {summarize(indicators)}."
                       if indicators else "")
                ),
                impact=(
                    f"Remote command execution as {proc.user or proc.uid} through the web "
                    f"service, bypassing SSH entirely."
                ),
                recommendation=(
                    f"Find the web shell: check the web server's access log around "
                    f"{iso_from_epoch(proc.start_time)} for the request that triggered this, "
                    f"then look for recently modified files under the document root. Capture "
                    f"the script before removing it."
                ),
                evidence=[
                    Evidence(source="proc", locator=f"/proc/{proc.pid}",
                             content=(f"child: {proc.name} pid={proc.pid} uid={proc.uid} "
                                      f"({proc.user})\ncmdline={redact(proc.cmdline)[:400]}\n"
                                      f"cwd={proc.cwd}\nstarted={iso_from_epoch(proc.start_time)}")),
                    Evidence(source="proc", locator=f"/proc/{parent.pid}",
                             content=(f"parent: {parent.name} pid={parent.pid} "
                                      f"exe={parent.exe}\ncmdline={redact(parent.cmdline)[:300]}")),
                ],
                timestamps={"process_start_utc": iso_from_epoch(proc.start_time)},
                tags=["process", "webshell", "high-value"],
                correlation_key=f"webshell:{parent.pid}",
            ))

    def _check_writable_executables(self, ctx, result, processes):
        result.checks_run += 1
        seen = set()
        for proc in sorted(processes.values(), key=lambda p: p.pid):
            if not proc.exe or proc.exe_deleted or proc.exe in seen:
                continue
            if proc.uid != 0:
                continue
            seen.add(proc.exe)
            info = ctx.host.stat(proc.exe)
            if not info.exists:
                continue
            mode = (info.mode or 0) & 0o7777
            if not (mode & 0o022) and info.uid in (0, None):
                continue
            problems = []
            if mode & 0o002:
                problems.append("world-writable")
            elif mode & 0o020:
                problems.append("group-writable")
            if info.uid not in (0, None):
                problems.append(f"owned by {info.owner} rather than root")
            if not problems:
                continue
            result.add(make_finding(
                module=self.name, rule_id="PROC-ROOT-WRITABLE-EXE",
                title=f"Root process {proc.name} runs from {proc.exe}, which is {', '.join(problems)}",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                category=Category.PRIVESC, target=f"path:{proc.exe}",
                why=(
                    f"{proc.exe} executes with UID 0 but can be modified by a non-root "
                    f"account ({', '.join(problems)}). Any local user can replace the file "
                    f"and have their code run as root the next time the service starts - and "
                    f"they can force a restart simply by crashing it."
                ),
                impact="Reliable local privilege escalation to root.",
                recommendation=(
                    f"Record the current hash, then `chown root:root {proc.exe}` and "
                    f"`chmod 755 {proc.exe}`. Verify the file against the package manager - if "
                    f"it has already been replaced, restoring permissions is not enough."
                ),
                evidence=[stat_evidence(proc.exe, info),
                          Evidence(source="proc", locator=f"/proc/{proc.pid}",
                                   content=f"pid={proc.pid} name={proc.name} uid=0")],
                tags=["privilege-escalation", "file-permissions"],
                correlation_key=f"path:{proc.exe}",
            ))

    def _compare_with_ps(self, ctx, result, processes):
        """Disagreement between /proc and ps is reported, not resolved."""
        result.checks_run += 1
        if not ctx.host.has("ps"):
            result.gap("ps", "not installed", "no cross-check against /proc was possible")
            return
        res = ctx.host.run(["ps", "-eo", "pid="], timeout=20)
        if not res.ok:
            result.gap("ps", res.error or res.stderr.strip()[:120],
                       "no cross-check against /proc was possible")
            return
        ps_pids = set()
        for line in res.stdout.split():
            if line.strip().isdigit():
                ps_pids.add(int(line.strip()))
        proc_pids = set(processes)

        # `ps` itself and this audit's own children appear and vanish between
        # the two reads, so only treat a sizeable, one-directional gap as signal.
        hidden_from_ps = proc_pids - ps_pids
        missing_from_proc = ps_pids - proc_pids

        result.facts["proc_vs_ps"] = {
            "proc_count": len(proc_pids),
            "ps_count": len(ps_pids),
            "in_proc_not_ps": sorted(hidden_from_ps)[:50],
            "in_ps_not_proc": sorted(missing_from_proc)[:50],
        }

        if len(missing_from_proc) > 3:
            result.add(make_finding(
                module=self.name, rule_id="PROC-PS-DISCREPANCY",
                title=f"ps reports {len(missing_from_proc)} PIDs that are absent from /proc",
                severity=Severity.HIGH, confidence=Confidence.LOW,
                category=Category.INTEGRITY, target="proc-vs-ps",
                why=(
                    f"Processes listed by `ps` ({sorted(missing_from_proc)[:15]}) have no "
                    f"corresponding /proc entry. Short-lived processes exiting between the two "
                    f"reads explain a small difference, which is why confidence is low. A "
                    f"large or persistent gap is worth pursuing, because it means one of the "
                    f"two views of the system is wrong."
                ),
                impact="One of the two process views is unreliable.",
                recommendation=(
                    "Re-run the audit and see whether the same PIDs differ. Verify the `ps` "
                    "binary against the package manager, and check /etc/ld.so.preload findings."
                ),
                evidence=[Evidence(source="derived", locator="ps -eo pid vs /proc",
                                   content=f"in ps only: {sorted(missing_from_proc)[:50]}")],
                tags=["integrity", "rootkit-indicator"],
                partial_evidence=True,
                correlation_key="rootkit:proc-view",
            ))


# --------------------------------------------------------------------------
# Module-level readers, shared with the network module so that listening
# sockets can be attributed to processes even when this module did not run.
# --------------------------------------------------------------------------

def _starttime_from_stat(stat_text: str) -> Optional[float]:
    """Field 22 of /proc/<pid>/stat.

    The comm field can contain spaces and parentheses, so everything is
    counted from the final ')' rather than from the start of the line.
    """
    close = stat_text.rfind(")")
    if close == -1:
        return None
    rest = stat_text[close + 2:].split()
    # rest[0] is state; starttime is overall field 22, index 19 here.
    if len(rest) < 20:
        return None
    try:
        return float(rest[19])
    except ValueError:
        return None


def boot_time_of(host) -> Optional[float]:
    text, _t, _err = host.read_text("/proc/stat", max_bytes=256 * 1024)
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("btime "):
            try:
                return float(line.split()[1])
            except (ValueError, IndexError):
                return None
    return None


def clock_ticks_of(host) -> float:
    if host.is_synthetic:
        return 100.0
    try:
        return float(os.sysconf("SC_CLK_TCK"))
    except (ValueError, OSError, AttributeError):
        return 100.0


def read_process(host, pid: int, boot_time: Optional[float] = None,
                 clock_ticks: float = 100.0) -> Tuple[Process, List[str]]:
    """Read one process's attributes from /proc. Never signals the process."""
    proc = Process(pid)
    errors: List[str] = []
    base = f"/proc/{pid}"

    status, _t, serr = host.read_text(f"{base}/status", max_bytes=65536)
    if serr or not status:
        errors.append(f"{base}/status: {serr or 'empty'}")
    else:
        for line in status.splitlines():
            key, _, value = line.partition(":")
            value = value.strip()
            if key == "Name":
                proc.name = value
            elif key == "State":
                proc.state = value.split()[0] if value else ""
            elif key == "PPid":
                proc.ppid = int(value) if value.lstrip("-").isdigit() else None
            elif key == "Uid":
                parts = value.split()
                if parts and parts[0].isdigit():
                    proc.uid = int(parts[0])
            elif key == "Gid":
                parts = value.split()
                if parts and parts[0].isdigit():
                    proc.gid = int(parts[0])
            elif key == "Threads":
                proc.threads = int(value) if value.isdigit() else None

    cmdline_raw, _t2, _cerr = host.read_text(f"{base}/cmdline", max_bytes=65536)
    if cmdline_raw:
        proc.cmdline = cmdline_raw.replace("\x00", " ").strip()

    exe_info = host.stat(f"{base}/exe")
    if exe_info.is_symlink and exe_info.symlink_target:
        target = exe_info.symlink_target
        if target.endswith(" (deleted)"):
            proc.exe_deleted = True
            target = target[: -len(" (deleted)")]
        proc.exe = target
    elif exe_info.error == "permission denied":
        errors.append(f"{base}/exe: permission denied")

    cwd_info = host.stat(f"{base}/cwd")
    if cwd_info.is_symlink:
        proc.cwd = cwd_info.symlink_target

    stat_text, _t3, _e3 = host.read_text(f"{base}/stat", max_bytes=8192)
    if stat_text and boot_time is not None:
        starttime = _starttime_from_stat(stat_text)
        if starttime is not None:
            proc.start_time = boot_time + (starttime / clock_ticks)

    proc.user = host.user_name(proc.uid) if proc.uid is not None else None
    # A kernel thread has no command line, no readable executable, and hangs
    # off kthreadd. All three must hold.
    proc.is_kernel_thread = (
        not proc.cmdline and proc.exe is None
        and (proc.ppid in (0, 2) or pid == 2)
    )
    return proc, errors


def read_processes(host, pids=None) -> Dict[int, Process]:
    """Read a set of processes (all of them when `pids` is None)."""
    boot_time = boot_time_of(host)
    ticks = clock_ticks_of(host)
    if pids is None:
        entries, err = host.listdir("/proc")
        if err:
            return {}
        pids = [int(e) for e in entries if e.isdigit()]
    out: Dict[int, Process] = {}
    for pid in pids:
        proc, _errors = read_process(host, pid, boot_time, ticks)
        out[pid] = proc
    return out



# ============================================================================
# bulwark/detection/network.py
# detection: network exposure
# ============================================================================

# Network exposure: listening sockets, established connections, firewall state.
#
# Sockets are read from /proc/net directly rather than from `ss` or `netstat`,
# so the result does not depend on those binaries being present or honest. Socket
# inodes are mapped back to owning processes through /proc/<pid>/fd.
#
# This module assesses the local host only. It never scans, probes or contacts
# another machine, and never changes a firewall rule.




TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}


class Socket:
    __slots__ = ("proto", "local_ip", "local_port", "remote_ip", "remote_port",
                 "state", "uid", "inode", "pid", "process")

    def __init__(self, proto, local_ip, local_port, remote_ip, remote_port,
                 state, uid, inode):
        self.proto = proto
        self.local_ip, self.local_port = local_ip, local_port
        self.remote_ip, self.remote_port = remote_ip, remote_port
        self.state, self.uid, self.inode = state, uid, inode
        self.pid: Optional[int] = None
        self.process = None

    @property
    def listening(self) -> bool:
        return self.state == "LISTEN" or (self.proto.startswith("udp") and self.remote_port == 0)

    def to_dict(self):
        return {
            "proto": self.proto, "local": f"{self.local_ip}:{self.local_port}",
            "remote": f"{self.remote_ip}:{self.remote_port}",
            "state": self.state, "uid": self.uid, "pid": self.pid,
            "process": self.process.name if self.process else None,
            "exe": self.process.exe if self.process else None,
        }


class NetworkModule(DetectionModule):
    name = "network"
    version = "1.1"
    title = "Network connections and exposure"
    description = (
        "Enumerates listening and established sockets from /proc/net, maps "
        "them to processes, and reviews firewall and forwarding configuration."
    )
    quick = True

    def check(self, ctx: AuditContext, result: ModuleResult) -> None:
        sockets, gaps = self._read_sockets(ctx)
        for area, reason in gaps:
            result.gap(area, reason, "some sockets were not enumerated")

        inode_map, map_gap = self._socket_inode_map(ctx)
        if map_gap:
            result.gap("/proc/<pid>/fd", map_gap,
                       "listening ports could not be attributed to processes",
                       needs_root=not ctx.facts.is_root)

        # The processes module shares its table when it has already run. When
        # this module runs on its own (`--modules network`), the owning
        # processes are read directly so attribution does not silently degrade
        # depending on which modules were selected.
        processes = dict(ctx.shared("processes") or {})
        owning_pids = {pid for inode, pid in inode_map.items()
                       if any(s.inode == inode for s in sockets)}
        missing = sorted(owning_pids - set(processes))
        if missing:
            processes.update(read_processes(ctx.host, missing))

        for sock in sockets:
            pid = inode_map.get(sock.inode)
            if pid is not None:
                sock.pid = pid
                sock.process = processes.get(pid)

        ctx.share("sockets", sockets)
        listening = [s for s in sockets if s.listening]
        established = [s for s in sockets
                       if s.state == "ESTABLISHED" and s.proto.startswith("tcp")]

        # Keyed as "listening_ports" to match the baseline section name.
        result.facts["listening_ports"] = [s.to_dict() for s in listening]
        result.facts["established_count"] = len(established)

        self._check_listening(ctx, result, listening)
        self._check_established(ctx, result, established)
        self._check_firewall(ctx, result)
        self._check_forwarding(ctx, result)
        self._check_dns_and_hosts(ctx, result)
        self._cross_check_ss(ctx, result, sockets)

    # ------------------------------------------------------------ /proc/net

    def _read_sockets(self, ctx) -> Tuple[List[Socket], List[Tuple[str, str]]]:
        sockets: List[Socket] = []
        gaps: List[Tuple[str, str]] = []
        for proto, path, v6 in (
            ("tcp", "/proc/net/tcp", False), ("tcp6", "/proc/net/tcp6", True),
            ("udp", "/proc/net/udp", False), ("udp6", "/proc/net/udp6", True),
        ):
            lines, err = ctx.host.read_lines(path, max_bytes=4 * 1024 * 1024)
            if err:
                if err != "not found":
                    gaps.append((path, err))
                continue
            for line in lines[1:]:
                parsed = self._parse_socket_line(proto, line, v6)
                if parsed:
                    sockets.append(parsed)
        if not sockets and not gaps:
            gaps.append(("/proc/net", "no socket entries found"))
        return sockets, gaps

    @staticmethod
    def _parse_socket_line(proto: str, line: str, v6: bool) -> Optional[Socket]:
        fields = line.split()
        if len(fields) < 10:
            return None
        try:
            local, remote, state_hex = fields[1], fields[2], fields[3]
            uid = int(fields[7])
            inode = int(fields[9])
        except (ValueError, IndexError):
            return None
        local_ip, local_port = _parse_addr(local, v6)
        remote_ip, remote_port = _parse_addr(remote, v6)
        if local_ip is None:
            return None
        state = TCP_STATES.get(state_hex.upper(), state_hex)
        if proto.startswith("udp"):
            state = "LISTEN" if remote_port == 0 else "ACTIVE"
        return Socket(proto, local_ip, local_port, remote_ip, remote_port,
                      state, uid, inode)

    def _socket_inode_map(self, ctx) -> Tuple[Dict[int, int], Optional[str]]:
        """inode -> pid, by reading every process's file descriptors."""
        mapping: Dict[int, int] = {}
        entries, err = ctx.host.listdir("/proc")
        if err:
            return mapping, err
        denied = 0
        total = 0
        for entry in entries:
            if not entry.isdigit():
                continue
            total += 1
            pid = int(entry)
            fds, fd_err = ctx.host.listdir(f"/proc/{pid}/fd")
            if fd_err:
                if fd_err == "permission denied":
                    denied += 1
                continue
            for fd in fds:
                info = ctx.host.stat(f"/proc/{pid}/fd/{fd}")
                target = info.symlink_target or ""
                match = re.match(r"socket:\[(\d+)\]", target)
                if match:
                    mapping.setdefault(int(match.group(1)), pid)
        if denied and denied >= max(1, total // 2):
            return mapping, (
                f"file descriptors unreadable for {denied} of {total} processes "
                f"(run as root for full attribution)"
            )
        return mapping, None

    # --------------------------------------------------------------- checks

    def _check_listening(self, ctx, result, listening):
        result.checks_run += 1
        baseline_ports = ctx.baseline_section("listening_ports")
        baseline_items = (baseline_ports or {}).get("items", baseline_ports or {})

        for sock in sorted(listening, key=lambda s: (s.local_port, s.proto)):
            port = sock.local_port
            proc = sock.process
            exe = proc.exe if proc else None
            name = proc.name if proc else None
            all_interfaces = sock.local_ip in ("0.0.0.0", "::")
            loopback_only = sock.local_ip in ("127.0.0.1", "::1")

            key = f"{sock.proto}/{port}"
            current = {"exe": exe, "bind": sock.local_ip}
            state = (
                baseline_state_for(ctx, "listening_ports", key, current)
                if baseline_items else None
            )

            reasons: List[str] = []
            severity: Optional[Severity] = None
            confidence = Confidence.MEDIUM

            if port in SUSPECT_PORTS:
                reasons.append(
                    f"port {port} is a {SUSPECT_PORTS[port]}; that alone is weak evidence, "
                    f"but it is an odd choice for a production service"
                )
                severity = Severity.HIGH
                confidence = Confidence.MEDIUM

            if exe and in_strong_suspicious_dir(exe):
                reasons.append(
                    f"the listening process runs from {exe}, a world-writable temporary "
                    f"directory where no packaged service is installed"
                )
                severity = Severity.CRITICAL
                confidence = Confidence.HIGH

            if proc and proc.exe_deleted:
                reasons.append("the listening process runs from a deleted executable")
                severity = Severity.CRITICAL
                confidence = Confidence.HIGH

            if proc and proc.cmdline:
                inds = scan(proc.cmdline)
                if inds:
                    reasons.append(
                        f"the owning process's command line matches known-bad patterns "
                        f"({summarize(inds)})")
                    severity = Severity.CRITICAL if score(inds) >= 3 else Severity.HIGH
                    confidence = Confidence.HIGH

            if name and name.lower() in ("nc", "ncat", "netcat", "socat", "bash", "sh",
                                         "python", "python3", "perl", "ruby", "busybox"):
                reasons.append(
                    f"the listening process is '{name}', a general-purpose interpreter or "
                    f"network utility rather than a service daemon"
                )
                severity = Severity.CRITICAL if severity is None else severity
                confidence = Confidence.HIGH

            if state is not None and state.name == "NEW" and port not in COMMON_SERVICE_PORTS:
                reasons.append("this port is not present in the saved baseline")
                severity = severity or Severity.MEDIUM
                confidence = Confidence.HIGH if severity and severity.rank >= 3 else confidence

            if severity is None:
                # Not suspicious; record as inventory only.
                if all_interfaces and port not in COMMON_SERVICE_PORTS and not loopback_only:
                    result.add(make_finding(
                        module=self.name, rule_id="NET-UNEXPECTED-LISTENER",
                        title=f"Unrecognised service listening on {sock.proto}/{port} (all interfaces)",
                        severity=Severity.LOW, confidence=Confidence.LOW,
                        category=Category.NETWORK, target=f"{sock.proto}/{port}",
                        why=(
                            f"A process is accepting connections on {sock.local_ip}:{port} "
                            f"from any network. The port is not one of the common service "
                            f"ports this tool recognises"
                            + (f" and is owned by {name} ({exe})." if name else
                               " and could not be attributed to a process.")
                            + " Unusual port numbers are routine for application servers, so "
                              "this is inventory for you to confirm, not an accusation."
                        ),
                        impact="Additional network attack surface.",
                        recommendation=(
                            f"Confirm this is a service your team needs. If it is not one of "
                            f"the scored services, consider binding it to localhost or closing "
                            f"it at the firewall."
                        ),
                        evidence=[self._socket_evidence(sock)],
                        tags=["network", "inventory"],
                        baseline_state=state if state else
                            baseline_state_for(ctx, "listening_ports", key),
                    ))
                continue

            if state:
                severity, confidence = adjust_for_baseline(severity, confidence, state)

            exposure = ("reachable from any network" if all_interfaces else
                        ("bound to loopback only, so it is reachable only from this host"
                         if loopback_only else f"bound to {sock.local_ip}"))

            result.add(make_finding(
                module=self.name, rule_id="NET-SUSPICIOUS-LISTENER",
                title=(f"Suspicious listener on {sock.proto}/{port}"
                       + (f" ({name}, PID {sock.pid})" if name else "")),
                severity=severity, confidence=confidence, category=Category.NETWORK,
                target=f"{sock.proto}/{port}",
                why=(
                    f"A process is listening on {sock.local_ip}:{port} ({exposure}). "
                    f"Flagged because " + "; ".join(reasons) + "."
                ),
                impact=(
                    "An inbound channel an attacker can connect to directly, independent of "
                    "SSH and of any credential you rotate."
                ),
                recommendation=(
                    f"Identify the owning process"
                    + (f" (PID {sock.pid}, {exe})" if sock.pid else
                       " - run the audit as root to attribute the socket")
                    + ". Capture the binary and its command line as evidence, find the "
                      "persistence mechanism that starts it, and only then consider blocking "
                      "the port and stopping the process."
                ),
                evidence=[self._socket_evidence(sock)] + (
                    [Evidence(source="proc", locator=f"/proc/{sock.pid}",
                              content=(f"name={name} exe={exe}\n"
                                       f"cmdline={redact(proc.cmdline)[:400]}\n"
                                       f"uid={proc.uid} ({proc.user})\n"
                                       f"started={iso_from_epoch(proc.start_time)}"))]
                    if proc else []
                ),
                timestamps={"process_start_utc": iso_from_epoch(proc.start_time)} if proc else {},
                remediation_risk=(
                    "Blocking a port that a scored service uses costs points. Confirm the "
                    "service inventory before changing firewall rules."
                ),
                tags=["network", "listener"],
                correlation_key=f"path:{exe}" if exe else f"pid:{sock.pid}" if sock.pid else None,
                baseline_state=state if state else
                    baseline_state_for(ctx, "listening_ports", key),
            ))

    def _check_established(self, ctx, result, established):
        result.checks_run += 1
        external = []
        for sock in established:
            if is_private_address(sock.remote_ip):
                continue
            external.append(sock)

        suspicious = []
        for sock in external:
            proc = sock.process
            reasons = []
            if proc and proc.exe and in_strong_suspicious_dir(proc.exe):
                reasons.append(f"the local process runs from {proc.exe}")
            if proc and proc.exe_deleted:
                reasons.append("the local process runs from a deleted executable")
            if proc and proc.cmdline and scan(proc.cmdline):
                reasons.append(f"its command line matches {summarize(scan(proc.cmdline))}")
            if sock.remote_port in SUSPECT_PORTS:
                reasons.append(f"the remote port {sock.remote_port} is a {SUSPECT_PORTS[sock.remote_port]}")
            if reasons:
                suspicious.append((sock, reasons))

        for sock, reasons in suspicious:
            proc = sock.process
            result.add(make_finding(
                module=self.name, rule_id="NET-SUSPICIOUS-OUTBOUND",
                title=f"Suspicious outbound connection to {sock.remote_ip}:{sock.remote_port}",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                category=Category.NETWORK,
                target=f"{sock.remote_ip}:{sock.remote_port}",
                why=(
                    f"An established connection runs from {sock.local_ip}:{sock.local_port} "
                    f"to the external address {sock.remote_ip}:{sock.remote_port}. Flagged "
                    f"because " + "; ".join(reasons) + ". An outbound channel is how most "
                    f"implants call home, and it works through firewalls that block inbound "
                    f"traffic."
                ),
                impact="Likely command-and-control or data egress.",
                recommendation=(
                    f"Record the remote endpoint and the owning process before acting. Do not "
                    f"connect to or probe the remote address. Once captured, block the "
                    f"endpoint and investigate what the local process has accessed."
                ),
                evidence=[self._socket_evidence(sock)] + (
                    [Evidence(source="proc", locator=f"/proc/{sock.pid}",
                              content=(f"name={proc.name} exe={proc.exe}\n"
                                       f"cmdline={redact(proc.cmdline)[:400]}"))]
                    if proc else []),
                tags=["network", "c2-suspected"],
                correlation_key=f"path:{proc.exe}" if proc and proc.exe else None,
            ))

        if external and not suspicious:
            sample = [f"{s.local_ip}:{s.local_port} -> {s.remote_ip}:{s.remote_port}"
                      + (f" ({s.process.name})" if s.process else "")
                      for s in external[:25]]
            result.add(make_finding(
                module=self.name, rule_id="NET-EXTERNAL-CONNECTIONS",
                title=f"{len(external)} established connection(s) to non-private addresses",
                severity=Severity.INFO, confidence=Confidence.LOW,
                category=Category.NETWORK, target="established-external",
                why=(
                    "These connections leave the local network. None of them matched a "
                    "suspicious indicator, and outbound traffic is normal for package "
                    "managers, time sync and monitoring. They are listed so you can confirm "
                    "each one belongs to a service you expect."
                ),
                impact="Context for the host's outbound traffic.",
                recommendation="Review the endpoint list; investigate anything unfamiliar.",
                evidence=[Evidence(source="file", locator="/proc/net/tcp",
                                   content="\n".join(sample))],
                tags=["network", "inventory"],
            ))

    def _socket_evidence(self, sock: Socket) -> Evidence:
        return Evidence(
            source="file", locator=f"/proc/net/{sock.proto}",
            content=(
                f"proto={sock.proto} local={sock.local_ip}:{sock.local_port} "
                f"remote={sock.remote_ip}:{sock.remote_port} state={sock.state} "
                f"uid={sock.uid} inode={sock.inode} pid={sock.pid}"
                + (f" process={sock.process.name} exe={sock.process.exe}"
                   if sock.process else " process=<unattributed>")),
            meta={"port": sock.local_port, "proto": sock.proto,
                  "bind_address": sock.local_ip, "pid": sock.pid},
        )

    # ------------------------------------------------------------- firewall

    def _check_firewall(self, ctx, result):
        result.checks_run += 1
        backends = []
        details = []

        if ctx.host.has("nft"):
            res = ctx.host.run(["nft", "list", "ruleset"], timeout=20)
            if res.ok:
                rules = [l for l in res.stdout.splitlines() if l.strip()]
                backends.append(("nftables", len(rules), res.stdout))
                details.append(f"nftables: {len(rules)} line(s) of ruleset")
            elif res.error != "not-found":
                result.gap("nft list ruleset", res.error or res.stderr.strip()[:100],
                           "nftables rules were not read", needs_root=not ctx.facts.is_root)

        if ctx.host.has("iptables"):
            res = ctx.host.run(["iptables", "-S"], timeout=20)
            if res.ok:
                rules = [l for l in res.stdout.splitlines() if l.strip()]
                non_default = [r for r in rules if not r.startswith("-P ")]
                backends.append(("iptables", len(non_default), res.stdout))
                details.append(f"iptables: {len(non_default)} rule(s) beyond chain policies")
            elif res.error != "not-found":
                result.gap("iptables -S", res.error or res.stderr.strip()[:100],
                           "iptables rules were not read", needs_root=True)

        if ctx.host.has("ufw"):
            res = ctx.host.run(["ufw", "status", "verbose"], timeout=15)
            if res.ok:
                active = "Status: active" in res.stdout
                backends.append(("ufw", 1 if active else 0, res.stdout))
                details.append(f"ufw: {'active' if active else 'inactive'}")

        if ctx.host.has("firewall-cmd"):
            res = ctx.host.run(["firewall-cmd", "--state"], timeout=15)
            if res.ran:
                running = "running" in (res.stdout + res.stderr).lower()
                backends.append(("firewalld", 1 if running else 0, res.stdout))
                details.append(f"firewalld: {'running' if running else 'not running'}")

        result.facts["firewall_backends"] = [
            {"backend": b, "rule_count": n} for b, n, _ in backends
        ]

        if not backends:
            result.add(make_finding(
                module=self.name, rule_id="NET-NO-FIREWALL-TOOL",
                title="No firewall management utility is available on this host",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                category=Category.POSTURE, target="firewall",
                why=(
                    "None of nft, iptables, ufw or firewall-cmd is installed, so this tool "
                    "cannot read the host's packet filtering rules, and you have no "
                    "straightforward way to add them during the round. The kernel may still "
                    "have rules loaded; their absence here is a visibility gap as much as a "
                    "posture finding."
                ),
                impact="No host-level network filtering and no visibility into any that exists.",
                recommendation=(
                    "Check whether a firewall package is installed but not in PATH. If network "
                    "filtering is required and no tooling exists, plan to control exposure by "
                    "stopping unnecessary services instead."
                ),
                evidence=[Evidence(source="derived", locator="firewall tooling",
                                   content="nft, iptables, ufw, firewall-cmd: none present")],
                tags=["network", "firewall", "posture"],
            ))
            result.gap("firewall", "no firewall utility present",
                       "packet filtering rules could not be read")
            return

        total_rules = sum(n for _b, n, _o in backends)
        if total_rules == 0:
            result.add(make_finding(
                module=self.name, rule_id="NET-FIREWALL-EMPTY",
                title="A firewall is available but no filtering rules are in force",
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                category=Category.POSTURE, target="firewall",
                why=(
                    "Firewall tooling is present (" + ", ".join(d for d in details) + ") but "
                    "no rules beyond default chain policies were found. Every listening "
                    "service on this host is therefore reachable from anywhere that can route "
                    "to it. This is a common starting state for a competition image rather "
                    "than evidence of tampering - but it is also what a flushed ruleset looks "
                    "like, so check your auth and system logs for a flush command."
                ),
                impact="Every open port is exposed to the full network.",
                recommendation=(
                    "Decide your required inbound ports from the service list, then apply a "
                    "default-deny inbound policy with explicit allows. Keep SSH open from your "
                    "own network, and test from a second session before you commit."
                ),
                evidence=[Evidence(source="command", locator="firewall status",
                                   content="\n".join(details))],
                remediation_risk=(
                    "A default-deny policy applied without allowing your own management "
                    "access will lock your team out of the host."
                ),
                tags=["network", "firewall", "posture"],
            ))
        else:
            result.facts["firewall_rules_present"] = True
            for backend, count, output in backends:
                if count:
                    result.facts.setdefault("firewall_rules", {})[backend] = output[:20000]

    def _check_forwarding(self, ctx, result):
        result.checks_run += 1
        for path, label, why in (
            ("/proc/sys/net/ipv4/ip_forward", "IPv4 forwarding",
             "the host will route packets between its interfaces, which turns it into a "
             "pivot into other network segments"),
            ("/proc/sys/net/ipv4/conf/all/accept_redirects", "ICMP redirect acceptance",
             "the host will update its routing table based on ICMP redirects from the "
             "network, which can be used to reroute its traffic"),
            ("/proc/sys/net/ipv4/conf/all/rp_filter", "reverse path filtering", ""),
        ):
            text, _t, err = ctx.host.read_text(path, max_bytes=256)
            if err or text is None:
                continue
            value = text.strip()
            result.facts.setdefault("sysctl", {})[path] = value
            if path.endswith("rp_filter"):
                continue
            if value != "0":
                severity = Severity.MEDIUM if "forward" in path else Severity.LOW
                result.add(make_finding(
                    module=self.name, rule_id="NET-FORWARDING",
                    title=f"{label} is enabled ({path} = {value})",
                    severity=severity, confidence=Confidence.HIGH,
                    category=Category.NETWORK, target=path,
                    why=(
                        f"{label} is on, which means {why}. Hosts running containers, VPNs or "
                        f"NAT enable IPv4 forwarding legitimately, so check whether one of "
                        f"those applies before changing it."
                    ),
                    impact="The host can relay traffic into other network segments.",
                    recommendation=(
                        f"If no container runtime, VPN or routing role requires it, set it to "
                        f"0 in /etc/sysctl.d and apply with `sysctl -p`."
                    ),
                    evidence=[Evidence(source="file", locator=path, content=value)],
                    remediation_risk=(
                        "Disabling forwarding breaks Docker networking and any VPN or NAT "
                        "function on this host."
                    ),
                    tags=["network", "routing"],
                ))

    def _check_dns_and_hosts(self, ctx, result):
        result.checks_run += 1
        text, _t, err = ctx.host.read_text("/etc/resolv.conf", max_bytes=32768)
        if text:
            servers = [l.split()[1] for l in text.splitlines()
                       if l.strip().startswith("nameserver") and len(l.split()) > 1]
            result.facts["dns_servers"] = servers
            external = [s for s in servers if not is_private_address(s)]
            if external:
                result.add(make_finding(
                    module=self.name, rule_id="NET-EXTERNAL-DNS",
                    title=f"Resolver uses non-private DNS server(s): {', '.join(external)}",
                    severity=Severity.LOW, confidence=Confidence.LOW,
                    category=Category.NETWORK, target="/etc/resolv.conf",
                    why=(
                        "The host resolves names using a server outside the private address "
                        "ranges. Public resolvers are an ordinary configuration, but if your "
                        "environment runs its own DNS, a changed resolver is a way to redirect "
                        "the host's traffic without touching any service configuration."
                    ),
                    impact="Name resolution may be controlled by an unexpected party.",
                    recommendation="Confirm the resolver matches your environment's intended DNS.",
                    evidence=[file_evidence(ctx, "/etc/resolv.conf", max_chars=1500)],
                    tags=["network", "dns"],
                ))

        hosts_text, _t2, _e2 = ctx.host.read_text("/etc/hosts", max_bytes=131072)
        if hosts_text:
            entries = [l.strip() for l in hosts_text.splitlines()
                       if l.strip() and not l.strip().startswith("#")]
            security_domains = re.compile(
                r"(clamav|virustotal|\bavast\b|sophos|kaspersky|defender|"
                r"security\.(ubuntu|debian)|archive\.ubuntu|deb\.debian|"
                r"mirrorlist\.centos|fedoraproject|updates\.|cve\.|nvd\.)",
                re.IGNORECASE)
            blocked = [e for e in entries if security_domains.search(e)]
            if blocked:
                result.add(make_finding(
                    module=self.name, rule_id="NET-HOSTS-TAMPERING",
                    title="/etc/hosts contains entries for update or security domains",
                    severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                    category=Category.NETWORK, target="/etc/hosts",
                    why=(
                        "Entries in /etc/hosts override DNS. Overriding update mirrors or "
                        "security vendor domains - commonly by pointing them at 127.0.0.1 - "
                        "prevents the host from fetching patches or signatures while leaving "
                        "no trace in any service configuration. Some environments do run local "
                        "mirrors, so check what the addresses actually point at."
                    ),
                    impact="Patching and security tooling may be silently disabled.",
                    recommendation=(
                        "Review each entry and confirm it points at a mirror your environment "
                        "actually runs."
                    ),
                    evidence=[Evidence(source="file", locator="/etc/hosts",
                                       content="\n".join(blocked[:30]))],
                    tags=["network", "dns", "defence-evasion"],
                ))
            result.facts["hosts_entries"] = len(entries)

    def _cross_check_ss(self, ctx, result, sockets):
        """Compare /proc/net against ss or netstat. A port that one sees and
        the other does not is worth knowing about."""
        result.checks_run += 1
        tool = None
        if ctx.host.has("ss"):
            tool, argv = "ss", ["ss", "-Hlntup"]
        elif ctx.host.has("netstat"):
            tool, argv = "netstat", ["netstat", "-lntup"]
        if tool is None:
            result.gap("ss/netstat", "neither utility is installed",
                       "no cross-check of /proc/net was possible")
            return
        res = ctx.host.run(argv, timeout=20)
        if not res.ok:
            result.gap(tool, res.error or res.stderr.strip()[:120],
                       "no cross-check of /proc/net was possible")
            return

        tool_ports = set(int(m) for m in re.findall(r"[:\]]([0-9]{1,5})\s", res.stdout)
                         if m.isdigit() and 0 < int(m) < 65536)
        proc_ports = {s.local_port for s in sockets if s.listening}
        only_in_proc = sorted(proc_ports - tool_ports)
        if only_in_proc:
            result.add(make_finding(
                module=self.name, rule_id="NET-PROC-TOOL-DISCREPANCY",
                title=f"{len(only_in_proc)} listening port(s) appear in /proc/net but not in `{tool}`",
                severity=Severity.HIGH, confidence=Confidence.LOW,
                category=Category.INTEGRITY, target="proc-vs-" + tool,
                why=(
                    f"Ports {only_in_proc[:15]} are present in /proc/net but absent from "
                    f"`{tool}` output. A userland rootkit that filters socket listings "
                    f"produces exactly this pattern. Parsing differences between the two "
                    f"sources also produce it, which is why confidence is low - this is a "
                    f"lead to verify, not a conclusion."
                ),
                impact="Network tooling on this host may be hiding connections from you.",
                recommendation=(
                    f"Read /proc/net/tcp directly and compare by hand. Verify the `{tool}` "
                    f"binary against the package manager and check for /etc/ld.so.preload "
                    f"findings."
                ),
                evidence=[
                    Evidence(source="derived", locator=f"/proc/net vs {tool}",
                             content=f"present only in /proc/net: {only_in_proc[:50]}"),
                    Evidence(source="command", locator=" ".join(argv),
                             content=redact(res.stdout)[:3000]),
                ],
                tags=["integrity", "rootkit-indicator"],
                partial_evidence=True,
                correlation_key="rootkit:socket-view",
            ))


def _parse_addr(hex_addr: str, v6: bool) -> Tuple[Optional[str], int]:
    """Decode the hex address:port pairs used in /proc/net/{tcp,udp}."""
    if ":" not in hex_addr:
        return None, 0
    host_hex, _, port_hex = hex_addr.rpartition(":")
    try:
        port = int(port_hex, 16)
    except ValueError:
        return None, 0
    try:
        if v6:
            if len(host_hex) != 32:
                return None, port
            words = [host_hex[i:i + 8] for i in range(0, 32, 8)]
            raw = b"".join(struct.pack("<I", int(w, 16)) for w in words)
            import ipaddress
            addr = str(ipaddress.IPv6Address(raw))
            # ::ffff:a.b.c.d is an IPv4 socket on a v6 listener
            mapped = ipaddress.IPv6Address(raw)
            if mapped.ipv4_mapped:
                addr = str(mapped.ipv4_mapped)
            return addr, port
        if len(host_hex) != 8:
            return None, port
        raw = struct.pack("<I", int(host_hex, 16))
        return ".".join(str(b) for b in raw), port
    except (ValueError, struct.error):
        return None, port



# ============================================================================
# bulwark/detection/filesystem.py
# detection: filesystem integrity
# ============================================================================

# Filesystem integrity: critical file metadata, SUID binaries, dropped payloads.
#
# Hashes recorded here are *references for future comparison*, not proof of
# integrity. A hash computed on a compromised host tells you only that the file
# has not changed since you last looked at it with the same possibly-subverted
# tools. Verification against package metadata is a separate, stronger check and
# lives in the packages module.
#
# Scanning is bounded: fixed directory list, limited depth, no symlink traversal,
# no crossing filesystem boundaries.




# SUID on any of these is a direct root shell. None ships SUID on a stock system.
NEVER_SUID = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "busybox",
    "python", "python2", "python3", "perl", "ruby", "php", "lua", "node",
    "awk", "gawk", "mawk", "sed", "vi", "vim", "nvim", "nano", "emacs", "ed",
    "less", "more", "man", "find", "cp", "mv", "dd", "tar", "zip", "unzip",
    "rsync", "nmap", "socat", "nc", "ncat", "netcat", "gdb", "strace", "ltrace",
    "env", "xargs", "make", "tee", "chmod", "chown", "docker", "systemctl",
    "tclsh", "expect", "openssl", "git", "ftp", "scp",
}

# Expected SUID binaries on mainstream distributions.
EXPECTED_SUID = {
    "su", "sudo", "mount", "umount", "passwd", "gpasswd", "chsh", "chfn",
    "newgrp", "pkexec", "ping", "ping6", "fusermount", "fusermount3",
    "ssh-agent", "pppd", "unix_chkpwd", "chage", "expiry", "at", "crontab",
    "dbus-daemon-launch-helper", "polkit-agent-helper-1", "snap-confine",
    "sg", "write", "wall", "screen", "mount.nfs", "umount.nfs", "vmware-user-suid-wrapper",
    "utempter", "ksu", "staprun", "Xorg", "exim4", "lockfile", "dotlockfile",
}

EXECUTABLE_MAGIC = (b"\x7fELF", b"#!/", b"#! ")

TEMP_DIRS = ["/tmp", "/var/tmp", "/dev/shm", "/run/shm"]


class FilesystemModule(DetectionModule):
    name = "filesystem"
    version = "1.1"
    title = "System integrity and critical files"
    description = (
        "Records metadata and hashes for security-relevant files, scans a "
        "bounded set of directories for SUID binaries and dropped payloads, "
        "and compares against a baseline when one exists."
    )
    quick = False

    def check(self, ctx: AuditContext, result: ModuleResult) -> None:
        self._critical_file_inventory(ctx, result)
        self._check_suid(ctx, result)
        self._check_temp_payloads(ctx, result)
        self._check_world_writable_system_files(ctx, result)
        self._check_recent_etc_changes(ctx, result)
        self._check_hidden_paths(ctx, result)
        self._check_mounts(ctx, result)

    # ---------------------------------------------------- critical files

    def _critical_file_inventory(self, ctx, result):
        result.checks_run += 1
        inventory: Dict[str, Dict] = {}
        baseline = ctx.baseline_section("critical_files")
        baseline_items = (baseline or {}).get("items", baseline or {})
        changed: List[Tuple[str, str, str]] = []
        unreadable = 0

        paths = list(CRITICAL_PATHS)
        for directory in CRITICAL_DIRS:
            names, err = ctx.host.listdir(directory)
            if err:
                continue
            for name in names[:200]:
                full = os.path.join(directory, name)
                if not ctx.host.is_dir(full):
                    paths.append(full)

        for path in paths:
            info = ctx.host.stat(path, hash_file=ctx.config.hash_critical_files)
            if not info.exists:
                continue
            if info.error:
                unreadable += 1
                continue
            record = {
                "sha256": info.sha256,
                "mode": info.mode_octal,
                "owner": info.owner,
                "group": info.group,
                "uid": info.uid,
                "gid": info.gid,
                "size": info.size,
                "mtime_utc": iso_from_epoch(info.mtime),
            }
            inventory[path] = record

            prior = baseline_items.get(path) if isinstance(baseline_items, dict) else None
            if prior:
                if prior.get("sha256") and record["sha256"] and prior["sha256"] != record["sha256"]:
                    changed.append((path, "content", f"{prior['sha256'][:16]}... -> {record['sha256'][:16]}..."))
                elif prior.get("mode") != record["mode"]:
                    changed.append((path, "permissions", f"{prior.get('mode')} -> {record['mode']}"))
                elif prior.get("owner") != record["owner"]:
                    changed.append((path, "ownership", f"{prior.get('owner')} -> {record['owner']}"))

        result.facts["critical_files"] = inventory
        if unreadable:
            result.gap("critical files", f"{unreadable} path(s) were unreadable",
                       "integrity of those files could not be recorded",
                       needs_root=not ctx.facts.is_root)

        for path, kind, detail in changed:
            severity = Severity.HIGH
            if path in ("/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config"):
                severity = Severity.CRITICAL
            info = ctx.host.stat(path)
            result.add(make_finding(
                module=self.name, rule_id="FS-CRITICAL-FILE-CHANGED",
                title=f"{path} has changed since the baseline ({kind})",
                severity=severity, confidence=Confidence.HIGH,
                category=Category.INTEGRITY, target=path,
                why=(
                    f"The recorded {kind} of {path} differs from the saved baseline: {detail}. "
                    f"This file is security-relevant, so an unexplained change deserves "
                    f"investigation. If your team edited it after the baseline was taken, "
                    f"that fully accounts for the difference."
                ),
                impact="A security-relevant configuration file was modified.",
                recommendation=(
                    f"Diff the file against the packaged version where one exists, and check "
                    f"the auth and package logs for the time of the change. Re-take the "
                    f"baseline once you have accounted for every difference."
                ),
                evidence=[
                    file_evidence(ctx, path, max_chars=3000),
                    stat_evidence(path, info),
                ],
                timestamps={"mtime_utc": iso_from_epoch(info.mtime),
                            "ctime_utc": iso_from_epoch(info.ctime)},
                tags=["integrity", "baseline-diff"],
                baseline_state=BaselineState.CHANGED,
                correlation_key=f"path:{path}",
            ))

        if not baseline_items and inventory:
            result.add(make_finding(
                module=self.name, rule_id="FS-HASH-REFERENCE-ONLY",
                title=f"Recorded hashes for {len(inventory)} security-relevant file(s) with no baseline to compare against",
                severity=Severity.INFO, confidence=Confidence.HIGH,
                category=Category.INTEGRITY, target="critical-file-inventory",
                why=(
                    "File hashes and metadata were recorded so that a later run can detect "
                    "change. No baseline exists yet, so nothing has been verified: these "
                    "hashes describe the host as it is now, including any modification made "
                    "before you received it. A hash computed on a potentially compromised "
                    "host cannot establish that a file is legitimate - only that it has not "
                    "changed since this moment."
                ),
                impact="Establishes a change-detection reference point.",
                recommendation=(
                    "Run `bulwark snap` once you have reviewed the findings from "
                    "this audit, so the baseline records a state you have actually examined. "
                    "For true verification, compare against package metadata (see the "
                    "packages module) or a known-good image."
                ),
                evidence=[Evidence(
                    source="derived", locator="critical-file-inventory",
                    content=f"{len(inventory)} files hashed; see the JSON report for the full table")],
                tags=["integrity", "baseline"],
            ))

    # ------------------------------------------------------------- SUID

    def _check_suid(self, ctx, result):
        result.checks_run += 1
        found: List[Tuple[str, object]] = []
        limits_hit = []
        for directory in SCAN_DIRS:
            if not ctx.host.is_dir(directory):
                continue
            files, errors, hit_limit = ctx.host.walk(
                directory, max_depth=5, max_entries=8000,
                skip_dirs=("/proc", "/sys", "/dev/pts", "/run/user"))
            if hit_limit:
                limits_hit.append(directory)
            for path in files:
                info = ctx.host.stat(path)
                if not info.exists or info.is_symlink or not info.is_file:
                    continue
                if info.setuid or info.setgid:
                    found.append((path, info))

        if limits_hit:
            result.gap("suid scan", f"entry limit reached in: {', '.join(limits_hit)}",
                       "the SUID scan did not cover these directories completely")

        baseline = ctx.baseline_section("suid_binaries")
        baseline_items = (baseline or {}).get("items", baseline or {})
        result.facts["suid_binaries"] = {
            p: {"mode": i.mode_octal, "owner": i.owner, "sha256": None}
            for p, i in found
        }

        for path, info in found:
            base = os.path.basename(path)
            root_owned_suid = info.setuid and info.uid == 0
            in_temp = any(path.startswith(d + "/") for d in TEMP_DIRS)
            in_home = path.startswith("/home/") or path.startswith("/root/")

            state = (BaselineState.KNOWN if isinstance(baseline_items, dict)
                     and path in baseline_items else
                     (BaselineState.NEW if baseline_items else BaselineState.NO_BASELINE))

            if base in NEVER_SUID and root_owned_suid:
                result.add(make_finding(
                    module=self.name, rule_id="FS-SUID-SHELL",
                    title=f"SUID root is set on {path}, which can be used to obtain a root shell",
                    severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                    category=Category.PRIVESC, target=path,
                    why=(
                        f"{base} is SUID root (mode {info.mode_octal}, owner {info.owner}). "
                        f"This binary either is a shell or can spawn one, so any local user "
                        f"can execute it and obtain a root shell immediately. No Linux "
                        f"distribution ships {base} with the SUID bit set; this was done "
                        f"deliberately, and it is one of the most common CCDC backdoors "
                        f"precisely because it is invisible in process listings until used."
                    ),
                    impact="Instant, reliable privilege escalation to root for any local user.",
                    recommendation=(
                        f"Record the hash and metadata now, then remove the SUID bit with "
                        f"`chmod u-s {path}`"
                        + (f". The file is in a temporary directory, so also preserve a copy "
                           f"before it is cleared." if in_temp else
                           f". Verify the binary against the package manager - if {base} "
                           f"itself was replaced, clearing the bit is not enough.")
                    ),
                    evidence=[stat_evidence(path, info, note="SUID root binary")],
                    timestamps={"mtime_utc": iso_from_epoch(info.mtime),
                                "ctime_utc": iso_from_epoch(info.ctime)},
                    remediation_risk="Minimal. No legitimate workflow depends on this bit.",
                    tags=["privilege-escalation", "suid", "high-value"],
                    correlation_key=f"path:{path}",
                    baseline_state=state,
                ))
            elif (in_temp or in_home) and info.setuid:
                result.add(make_finding(
                    module=self.name, rule_id="FS-SUID-UNUSUAL-LOCATION",
                    title=f"SUID binary in an unusual location: {path}",
                    severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                    category=Category.PRIVESC, target=path,
                    why=(
                        f"A SUID binary owned by {info.owner} sits in "
                        f"{'a temporary directory' if in_temp else 'a home directory'}. "
                        f"Packaged SUID binaries live in /usr/bin and /usr/sbin. A SUID file "
                        f"here was placed by hand, and its purpose is to let whoever runs it "
                        f"assume the owner's identity."
                    ),
                    impact=f"Any local user can execute code as {info.owner}.",
                    recommendation=(
                        f"Preserve the file as evidence (copy it out of the temporary "
                        f"directory first), then remove the SUID bit and the file."
                    ),
                    evidence=[stat_evidence(path, info)],
                    timestamps={"mtime_utc": iso_from_epoch(info.mtime)},
                    tags=["privilege-escalation", "suid"],
                    correlation_key=f"path:{path}",
                    baseline_state=state,
                ))
            elif base not in EXPECTED_SUID and root_owned_suid and state is BaselineState.NEW:
                result.add(make_finding(
                    module=self.name, rule_id="FS-SUID-NEW",
                    title=f"SUID root binary {path} is not present in the baseline",
                    severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                    category=Category.PRIVESC, target=path,
                    why=(
                        f"{path} is SUID root and does not appear in the saved baseline, so "
                        f"the bit was set, or the file created, after the baseline was taken. "
                        f"Third-party software does install SUID helpers, so confirm "
                        f"provenance rather than assuming the worst."
                    ),
                    impact="Possible new privilege escalation path.",
                    recommendation=(
                        f"Check package ownership (`dpkg -S {path}` or `rpm -qf {path}`) and "
                        f"whether a package was installed recently."
                    ),
                    evidence=[stat_evidence(path, info)],
                    timestamps={"mtime_utc": iso_from_epoch(info.mtime)},
                    tags=["privilege-escalation", "suid", "baseline-diff"],
                    correlation_key=f"path:{path}",
                    baseline_state=state,
                ))

    # -------------------------------------------------------- temp payloads

    def _check_temp_payloads(self, ctx, result):
        result.checks_run += 1
        payloads = []
        for directory in TEMP_DIRS:
            if not ctx.host.is_dir(directory):
                continue
            files, _errors, _hit = ctx.host.walk(directory, max_depth=4, max_entries=4000)
            for path in files:
                info = ctx.host.stat(path)
                if not info.exists or not info.is_file or info.is_symlink:
                    continue
                executable = bool((info.mode or 0) & 0o111)
                magic = self._magic(ctx, path)
                is_program = magic in ("elf", "script")
                if not executable and not is_program:
                    continue
                payloads.append((path, info, magic, executable))

        for path, info, magic, executable in payloads[:60]:
            indicators = []
            if magic == "script":
                text, _t, err = ctx.host.read_text(path, max_bytes=128 * 1024)
                if text:
                    indicators = scan(text)
            severity = Severity.HIGH
            confidence = Confidence.MEDIUM
            if indicators and score(indicators) >= 3:
                severity, confidence = Severity.CRITICAL, Confidence.HIGH
            if magic == "elf" and executable:
                confidence = Confidence.HIGH

            result.add(make_finding(
                module=self.name, rule_id="FS-TEMP-EXECUTABLE",
                title=f"Executable {'binary' if magic == 'elf' else 'script'} in a temporary directory: {path}",
                severity=severity, confidence=confidence,
                category=Category.INTEGRITY, target=path,
                why=(
                    f"{path} is "
                    + ("an ELF binary" if magic == "elf" else "a script")
                    + (" with the execute bit set" if executable else "")
                    + f", owned by {info.owner}, in a world-writable temporary directory. "
                    f"Temporary directories are the standard staging area for downloaded "
                    f"payloads because every user can write there and the contents disappear "
                    f"on reboot. Build systems and installers also use them, so check what "
                    f"the file is before concluding."
                    + (f" Its contents match known-bad patterns: {summarize(indicators)}."
                       if indicators else "")
                ),
                impact="A ready-to-run payload staged on the host.",
                recommendation=(
                    f"Do not execute it. Copy it to your evidence directory, then inspect "
                    f"with `file`, `strings` and `sha256sum`. Check which process created it "
                    f"by correlating the modification time against the auth and service logs."
                ),
                evidence=[stat_evidence(path, info, note=f"detected type: {magic}")]
                         + ([file_evidence(ctx, path, max_chars=2000)] if magic == "script" else []),
                timestamps={"mtime_utc": iso_from_epoch(info.mtime),
                            "ctime_utc": iso_from_epoch(info.ctime)},
                remediation_risk=(
                    "The file may be a legitimate build or installer artifact. Capture before "
                    "deleting."
                ),
                tags=["payload", "temp-directory"],
                correlation_key=f"path:{path}",
            ))

        if len(payloads) > 60:
            result.gap("temp payload scan",
                       f"{len(payloads)} candidates found; only the first 60 are reported",
                       "review the temporary directories manually")

    @staticmethod
    def _magic(ctx, path: str) -> Optional[str]:
        try:
            real = ctx.host.real(path)
            with open(real, "rb") as fh:
                head = fh.read(4)
        except (OSError, ValueError):
            return None
        if head.startswith(b"\x7fELF"):
            return "elf"
        if head.startswith(b"#!"):
            return "script"
        return None

    # ------------------------------------------------- writable system files

    def _check_world_writable_system_files(self, ctx, result):
        result.checks_run += 1
        offenders = []
        for directory in ("/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
                          "/usr/local/bin", "/usr/local/sbin", "/usr/lib", "/lib"):
            if not ctx.host.is_dir(directory):
                continue
            files, _errors, _hit = ctx.host.walk(directory, max_depth=4, max_entries=12000)
            for path in files:
                info = ctx.host.stat(path)
                if not info.exists or info.is_symlink or not info.is_file:
                    continue
                if (info.mode or 0) & 0o002:
                    offenders.append((path, info))

        for path, info in offenders[:40]:
            is_binary_dir = any(path.startswith(d + "/") for d in
                                ("/usr/bin", "/usr/sbin", "/bin", "/sbin",
                                 "/usr/local/bin", "/usr/local/sbin", "/usr/lib", "/lib"))
            result.add(make_finding(
                module=self.name, rule_id="FS-WORLD-WRITABLE-SYSTEM-FILE",
                title=f"World-writable system file: {path} (mode {info.mode_octal})",
                severity=Severity.CRITICAL if is_binary_dir else Severity.HIGH,
                confidence=Confidence.HIGH, category=Category.PRIVESC, target=path,
                why=(
                    f"{path} can be modified by any local user. "
                    + ("It is an executable or library in a system binary directory, so "
                       "replacing it gives an attacker code execution as whichever account "
                       "next runs it - frequently root."
                       if is_binary_dir else
                       "It is system configuration, so a local user can change how the host "
                       "behaves.")
                ),
                impact="Local privilege escalation or persistence through file replacement.",
                recommendation=(
                    f"Record the hash, then `chmod o-w {path}`. Verify the file against the "
                    f"package manager in case it has already been modified."
                ),
                evidence=[stat_evidence(path, info)],
                timestamps={"mtime_utc": iso_from_epoch(info.mtime)},
                tags=["file-permissions", "privilege-escalation"],
                correlation_key=f"path:{path}",
            ))
        if len(offenders) > 40:
            result.gap("world-writable scan",
                       f"{len(offenders)} world-writable files found; first 40 reported",
                       "review the remainder manually")

    def _check_recent_etc_changes(self, ctx, result):
        result.checks_run += 1
        cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(
            hours=ctx.config.log_lookback_hours)
        cutoff_epoch = cutoff.timestamp()
        recent = []
        files, _errors, _hit = ctx.host.walk("/etc", max_depth=4, max_entries=12000)
        for path in files:
            info = ctx.host.stat(path)
            if not info.exists or info.mtime is None or info.is_symlink:
                continue
            if info.mtime >= cutoff_epoch:
                recent.append((path, info))
        recent.sort(key=lambda t: t[1].mtime or 0, reverse=True)
        if not recent:
            return
        listing = "\n".join(
            f"{iso_from_epoch(i.mtime)}  {i.owner or '?':<10} {i.mode_octal or '?':<5} {p}"
            for p, i in recent[:80])
        result.add(make_finding(
            module=self.name, rule_id="FS-ETC-RECENT-CHANGES",
            title=f"{len(recent)} file(s) under /etc modified in the last {ctx.config.log_lookback_hours} hours",
            severity=Severity.LOW, confidence=Confidence.LOW,
            category=Category.INTEGRITY, target="/etc",
            why=(
                "Recent changes under /etc are listed as a timeline so you can see what was "
                "touched and when. Your own hardening work appears here too. File timestamps "
                "are trivially forged by anyone with root, so treat this as a starting point "
                "for correlation with logs rather than as reliable history."
            ),
            impact="Shows which configuration changed inside the review window.",
            recommendation=(
                "Compare the timeline against your team's change log and against the auth and "
                "package manager logs for the same period. Investigate anything you cannot "
                "attribute."
            ),
            evidence=[Evidence(source="derived", locator="/etc", content=listing,
                               truncated=len(recent) > 80,
                               meta={"total": len(recent),
                                     "window_hours": ctx.config.log_lookback_hours})],
            tags=["integrity", "timeline", "timestamp-evidence"],
            partial_evidence=True,
        ))

    def _check_hidden_paths(self, ctx, result):
        """Hidden directories at the root of a filesystem, and oddly named
        entries in temporary directories."""
        result.checks_run += 1
        suspicious = []
        for directory in ["/", "/var", "/usr", "/opt"] + TEMP_DIRS:
            names, err = ctx.host.listdir(directory)
            if err:
                continue
            for name in names:
                if not name.startswith("."):
                    continue
                if name in (".", "..", ".autorelabel", ".dockerenv", ".bash_history",
                            ".cache", ".config", ".local", ".ssh", ".profile",
                            ".bashrc", ".viminfo", ".X11-unix", ".ICE-unix",
                            ".font-unix", ".XIM-unix", ".Test-unix", ".build-id"):
                    continue
                path = os.path.join(directory, name)
                info = ctx.host.stat(path)
                if not info.exists:
                    continue
                # Names made of dots/spaces are a classic concealment trick.
                weird = (
                    set(name) <= set(". ") or
                    name.startswith("...") or
                    directory in TEMP_DIRS
                )
                if weird:
                    suspicious.append((path, info))

        for path, info in suspicious[:30]:
            result.add(make_finding(
                module=self.name, rule_id="FS-HIDDEN-PATH",
                title=f"Hidden entry in an unusual place: {path}",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                category=Category.INTEGRITY, target=path,
                why=(
                    f"{path} is a hidden entry (its name begins with a dot) in a location "
                    f"where hidden files are not usual. Names consisting of dots and spaces "
                    f"are specifically chosen to be easy to miss in a directory listing and "
                    f"awkward to type. Some applications do create hidden state in temporary "
                    f"directories, so confirm what this is."
                ),
                impact="A concealed staging or storage location.",
                recommendation=(
                    f"List it explicitly with `ls -la '{path}'` and inspect the contents "
                    f"without executing anything found inside."
                ),
                evidence=[stat_evidence(path, info)],
                timestamps={"mtime_utc": iso_from_epoch(info.mtime)},
                tags=["concealment"],
                correlation_key=f"path:{path}",
            ))

    def _check_mounts(self, ctx, result):
        result.checks_run += 1
        text, _t, err = ctx.host.read_text("/proc/mounts", max_bytes=256 * 1024)
        if err or not text:
            result.gap("/proc/mounts", err or "empty", "mount options were not reviewed")
            return
        mounts = []
        risky = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            device, mountpoint, fstype, options = parts[0], parts[1], parts[2], parts[3]
            mounts.append({"device": device, "mountpoint": mountpoint,
                           "fstype": fstype, "options": options})
            opts = set(options.split(","))
            if mountpoint in ("/tmp", "/var/tmp", "/dev/shm", "/home"):
                missing = [o for o in ("noexec", "nosuid", "nodev") if o not in opts]
                if missing:
                    risky.append((mountpoint, fstype, missing, options))
        result.facts["mounts"] = mounts

        for mountpoint, fstype, missing, options in risky:
            result.add(make_finding(
                module=self.name, rule_id="FS-MOUNT-OPTIONS",
                title=f"{mountpoint} is mounted without {', '.join(missing)}",
                severity=Severity.LOW, confidence=Confidence.HIGH,
                category=Category.POSTURE, target=mountpoint,
                why=(
                    f"{mountpoint} is writable by all users and is mounted with options "
                    f"`{options}`. Without "
                    + ("noexec, binaries dropped there can be executed directly; "
                       if "noexec" in missing else "")
                    + ("nosuid, a SUID binary placed there takes effect; "
                       if "nosuid" in missing else "")
                    + "this is the default on most distributions rather than a sign of "
                      "tampering, but it is what makes a payload dropped in /tmp immediately "
                      "runnable."
                ),
                impact="Payloads staged in writable directories can be executed in place.",
                recommendation=(
                    f"Consider remounting with `mount -o remount,{','.join(missing)} "
                    f"{mountpoint}` and making it permanent in /etc/fstab. Verify first that "
                    f"no scored service runs or installs from this path - package managers "
                    f"and some installers use /tmp for scripts."
                ),
                evidence=[Evidence(source="file", locator="/proc/mounts",
                                   content=f"{mountpoint} {fstype} {options}")],
                remediation_risk=(
                    "noexec on /tmp or /var/tmp breaks some package installers and build "
                    "steps. Test before making it permanent."
                ),
                tags=["posture", "mount-options"],
            ))



# ============================================================================
# bulwark/detection/logs.py
# detection: logs and authentication
# ============================================================================

# Authentication and system log review.
#
# Logs are the weakest evidence source on a potentially compromised host: they
# can be edited, truncated or rotated away by anyone with root. This module
# records which sources it could read, reports apparent tampering, and states
# plainly that a quiet log does not mean a quiet host.
#
# Log text is untrusted data. It is parsed, redacted and stored; it is never
# executed, and no command is ever constructed from its contents.




AUTH_LOG_PATHS = [
    "/var/log/auth.log", "/var/log/secure", "/var/log/authlog",
]
SYSTEM_LOG_PATHS = [
    "/var/log/syslog", "/var/log/messages",
]
PACKAGE_LOG_PATHS = [
    "/var/log/dpkg.log", "/var/log/apt/history.log", "/var/log/yum.log",
    "/var/log/dnf.rpm.log",
]
BINARY_LOGS = {
    "/var/log/wtmp": "successful login records (`last`)",
    "/var/log/btmp": "failed login records (`lastb`)",
    "/var/log/lastlog": "most recent login per account (`lastlog`)",
}

RE_FAILED = re.compile(
    r"Failed (?:password|publickey|none) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F.:]+)")
RE_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive(?:/pam)?|gssapi-with-mic|none) "
    r"for (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)")
RE_INVALID_USER = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)")
RE_SUDO_COMMAND = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:.*?(?:USER=(?P<target>\S+))?\s*;\s*COMMAND=(?P<command>.+)$")
RE_SUDO_FAIL = re.compile(r"sudo:.*(authentication failure|NOT in the sudoers|incorrect password)")
RE_USERADD = re.compile(
    r"(?:useradd|adduser)\[\d+\]:\s+new (?:user|account):\s+name=(?P<user>[^,]+)")
RE_GROUPADD = re.compile(r"(?:groupadd|addgroup)\[\d+\]:\s+new group:\s+name=(?P<group>[^,]+)")
RE_GROUP_MEMBER = re.compile(
    r"(?:usermod|gpasswd)\[\d+\]:\s+add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")
RE_SESSION_ROOT = re.compile(r"session opened for user (?P<user>\S+?)(?:\(uid=(?P<uid>\d+)\))? by")
RE_SSHD_KEY = re.compile(r"Accepted publickey for (?P<user>\S+) from (?P<ip>\S+).*?(?P<fp>SHA256:\S+)")

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

BRUTE_FORCE_THRESHOLD = 5


class AuthEvent:
    __slots__ = ("kind", "user", "ip", "method", "timestamp", "raw", "source")

    def __init__(self, kind, user, ip, method, timestamp, raw, source):
        self.kind, self.user, self.ip = kind, user, ip
        self.method, self.timestamp = method, timestamp
        self.raw, self.source = raw, source


class LogsModule(DetectionModule):
    name = "logs"
    version = "1.1"
    title = "Logs and authentication events"
    description = (
        "Reads journald and traditional auth/system logs, correlates failed "
        "and successful authentication, surfaces account and group changes, "
        "and reports log gaps or apparent tampering."
    )
    quick = True

    def check(self, ctx: AuditContext, result: ModuleResult) -> None:
        lines, sources, coverage = self._collect(ctx, result)
        result.facts["log_sources"] = coverage

        if not lines:
            result.add(make_finding(
                module=self.name, rule_id="LOG-NO-SOURCES",
                title="No authentication log source could be read",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                category=Category.LOGGING, target="auth-logs",
                why=(
                    "Neither journald nor any traditional auth log file was readable. "
                    "Without authentication history there is no way to tell who has logged "
                    "in, when, or from where. This may simply be a permissions problem - run "
                    "as root - or it may mean logging is broken or has been disabled."
                ),
                impact=(
                    "Login activity, privilege escalation and account changes are invisible "
                    "for this host."
                ),
                recommendation=(
                    "Re-run as root. If logs are still unavailable, check that rsyslog or "
                    "systemd-journald is running, and treat the absence of login evidence as "
                    "a gap rather than as a clean result."
                ),
                evidence=[Evidence(source="derived", locator="log sources",
                                   content="\n".join(f"{k}: {v}" for k, v in coverage.items()))],
                tags=["logging", "visibility-gap"],
            ))
            result.gap("authentication logs", "no readable source",
                       "no login history is available",
                       needs_root=not ctx.facts.is_root)
            return

        events = self._parse_auth_events(lines)
        result.facts["auth_event_count"] = len(events)

        self._check_brute_force(ctx, result, events)
        self._check_successful_logins(ctx, result, events)
        self._check_sudo_activity(ctx, result, lines)
        self._check_account_changes(ctx, result, lines)
        self._check_service_changes(ctx, result, lines)
        self._check_log_integrity(ctx, result, coverage)
        self._check_package_log(ctx, result)

    # ------------------------------------------------------------ collection

    def _collect(self, ctx, result) -> Tuple[List[Tuple[str, str]], List[str], Dict[str, str]]:
        """Returns [(source, line)], sources used, and a coverage map."""
        lines: List[Tuple[str, str]] = []
        sources: List[str] = []
        coverage: Dict[str, str] = {}
        limit = ctx.config.max_log_lines

        if ctx.host.has("journalctl") and not ctx.host.is_synthetic:
            since = f"-{ctx.config.log_lookback_hours}h"
            res = ctx.host.run(
                ["journalctl", "--no-pager", "--since", since,
                 "-o", "short-iso", "-n", str(limit)], timeout=60)
            if res.ok and res.stdout.strip():
                journal_lines = res.stdout.splitlines()
                lines.extend(("journald", l) for l in journal_lines)
                sources.append("journald")
                coverage["journald"] = f"{len(journal_lines)} line(s) over the last {ctx.config.log_lookback_hours}h"
            else:
                coverage["journald"] = (
                    f"unavailable: {res.error or (res.stderr.strip()[:100] or 'no output')}")
                if not ctx.facts.is_root:
                    result.gap("journald", "journal not readable without root",
                               "systemd journal events are missing", needs_root=True)

        for path in AUTH_LOG_PATHS + SYSTEM_LOG_PATHS:
            info = ctx.host.stat(path)
            if not info.exists:
                continue
            tail, err = ctx.host.tail_lines(path, lines=limit)
            if err:
                coverage[path] = f"unreadable: {err}"
                result.gap(path, err, "authentication history from this file is missing",
                           needs_root=not ctx.facts.is_root)
                continue
            coverage[path] = f"{len(tail)} line(s), size={info.size}, mtime={iso_from_epoch(info.mtime)}"
            lines.extend((path, l) for l in tail)
            sources.append(path)

        for path, label in BINARY_LOGS.items():
            info = ctx.host.stat(path)
            if info.exists:
                coverage[path] = f"size={info.size}, mtime={iso_from_epoch(info.mtime)}"
            else:
                coverage[path] = "not present"

        return lines, sources, coverage

    def _parse_auth_events(self, lines) -> List[AuthEvent]:
        events: List[AuthEvent] = []
        for source, line in lines:
            ts = self._parse_timestamp(line)
            m = RE_FAILED.search(line)
            if m:
                events.append(AuthEvent("failed", m.group("user"), m.group("ip"),
                                        "password", ts, line, source))
                continue
            m = RE_ACCEPTED.search(line)
            if m:
                events.append(AuthEvent("accepted", m.group("user"), m.group("ip"),
                                        m.group("method"), ts, line, source))
                continue
            m = RE_INVALID_USER.search(line)
            if m:
                events.append(AuthEvent("invalid-user", m.group("user"), m.group("ip"),
                                        None, ts, line, source))
        return events

    @staticmethod
    def _parse_timestamp(line: str) -> Optional[_dt.datetime]:
        # ISO-ish prefix (journald short-iso, rsyslog RFC3339)
        m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})", line)
        if m:
            try:
                return _dt.datetime(
                    *(int(g) for g in m.groups()), tzinfo=_dt.timezone.utc)
            except ValueError:
                return None
        # Traditional syslog: "Oct 22 11:59:01" - no year recorded
        m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", line)
        if m:
            month = MONTHS.get(m.group(1))
            if not month:
                return None
            now = _dt.datetime.now(_dt.timezone.utc)
            try:
                candidate = _dt.datetime(now.year, month, int(m.group(2)),
                                         int(m.group(3)), int(m.group(4)),
                                         int(m.group(5)), tzinfo=_dt.timezone.utc)
            except ValueError:
                return None
            # A date more than a day in the future means it is from last year.
            if candidate > now + _dt.timedelta(days=1):
                try:
                    candidate = candidate.replace(year=now.year - 1)
                except ValueError:
                    return None
            return candidate
        return None

    # --------------------------------------------------------------- checks

    def _check_brute_force(self, ctx, result, events):
        """Failures followed by a success from the same source is the single
        highest-value correlation in an auth log."""
        result.checks_run += 1
        by_ip: Dict[str, List[AuthEvent]] = defaultdict(list)
        for ev in events:
            if ev.ip:
                by_ip[ev.ip].append(ev)

        for ip, ip_events in sorted(by_ip.items()):
            failures = [e for e in ip_events if e.kind in ("failed", "invalid-user")]
            successes = [e for e in ip_events if e.kind == "accepted"]
            if len(failures) < BRUTE_FORCE_THRESHOLD:
                continue

            users_tried = sorted({e.user for e in failures})
            first_fail = min((e.timestamp for e in failures if e.timestamp), default=None)
            last_fail = max((e.timestamp for e in failures if e.timestamp), default=None)

            if successes:
                # Was the success after the failures started?
                later = [s for s in successes
                         if s.timestamp and first_fail and s.timestamp >= first_fail]
                target = later or successes
                succeeded_as = sorted({s.user for s in target})
                success_time = max((s.timestamp for s in target if s.timestamp), default=None)
                result.add(make_finding(
                    module=self.name, rule_id="LOG-BRUTEFORCE-SUCCESS",
                    title=f"Successful login from {ip} after {len(failures)} failed attempt(s)",
                    severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                    category=Category.AUTHENTICATION, target=f"ip:{ip}",
                    why=(
                        f"{ip} produced {len(failures)} failed authentication attempt(s) "
                        f"against {len(users_tried)} account name(s) "
                        f"({', '.join(users_tried[:8])}"
                        + ("..." if len(users_tried) > 8 else "")
                        + f") and then authenticated successfully as "
                        f"{', '.join(succeeded_as)} using "
                        f"{', '.join(sorted({s.method or 'unknown' for s in target}))}. "
                        f"Failures followed by a success from the same source is the "
                        f"signature of a password guessing attack that worked."
                        + ("" if not is_private_address(ip) else
                           " The source is on a private network, which may mean an internal "
                           "host is already compromised and being used to move laterally.")
                    ),
                    impact=(
                        f"The account(s) {', '.join(succeeded_as)} should be treated as "
                        f"compromised, along with anything they can reach."
                    ),
                    recommendation=(
                        f"Rotate the credentials for {', '.join(succeeded_as)} immediately and "
                        f"review what that account did after the successful login - check "
                        f"sudo events, new processes and new files. Block {ip} at the "
                        f"firewall. Assume persistence was established and review SSH keys "
                        f"and scheduled tasks for these accounts."
                    ),
                    evidence=[
                        Evidence(source="log", locator=failures[0].source,
                                 content=redact("\n".join(e.raw for e in failures[-10:])),
                                 meta={"note": "last 10 failed attempts from this source"}),
                        Evidence(source="log", locator=target[0].source,
                                 content=redact("\n".join(e.raw for e in target[:5])),
                                 meta={"note": "successful authentication events"}),
                    ],
                    timestamps={
                        "first_failure_utc": iso_from_epoch(first_fail.timestamp()) if first_fail else None,
                        "last_failure_utc": iso_from_epoch(last_fail.timestamp()) if last_fail else None,
                        "success_utc": iso_from_epoch(success_time.timestamp()) if success_time else None,
                    },
                    tags=["authentication", "brute-force", "high-value"],
                    correlation_key=f"ip:{ip}",
                ))
            else:
                result.add(make_finding(
                    module=self.name, rule_id="LOG-BRUTEFORCE-ATTEMPT",
                    title=f"{len(failures)} failed authentication attempt(s) from {ip}",
                    severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                    category=Category.AUTHENTICATION, target=f"ip:{ip}",
                    why=(
                        f"{ip} failed authentication {len(failures)} time(s) against "
                        f"{len(users_tried)} account name(s) with no successful login "
                        f"recorded in the window examined. Internet-facing hosts see constant "
                        f"background scanning, so this is often noise - but it identifies a "
                        f"source worth blocking, and the account names tried tell you what "
                        f"the attacker expects to find."
                    ),
                    impact="Credential guessing against this host is in progress.",
                    recommendation=(
                        f"Block {ip} and confirm that none of the attempted account names "
                        f"({', '.join(users_tried[:5])}) uses a weak or default password. "
                        f"Note that a success *outside* the log window would not appear here."
                    ),
                    evidence=[Evidence(
                        source="log", locator=failures[0].source,
                        content=redact("\n".join(e.raw for e in failures[-10:])))],
                    timestamps={
                        "first_failure_utc": iso_from_epoch(first_fail.timestamp()) if first_fail else None,
                        "last_failure_utc": iso_from_epoch(last_fail.timestamp()) if last_fail else None,
                    },
                    tags=["authentication", "brute-force"],
                    correlation_key=f"ip:{ip}",
                ))

    def _check_successful_logins(self, ctx, result, events):
        result.checks_run += 1
        accepted = [e for e in events if e.kind == "accepted"]
        if not accepted:
            return
        by_user: Dict[str, List[AuthEvent]] = defaultdict(list)
        for ev in accepted:
            by_user[ev.user].append(ev)
        result.facts["successful_logins"] = {
            user: sorted({e.ip for e in evs}) for user, evs in by_user.items()
        }

        root_logins = by_user.get("root", [])
        if root_logins:
            ips = sorted({e.ip for e in root_logins})
            methods = sorted({e.method or "unknown" for e in root_logins})
            result.add(make_finding(
                module=self.name, rule_id="LOG-ROOT-LOGIN",
                title=f"{len(root_logins)} direct root login(s) from {len(ips)} source address(es)",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                category=Category.AUTHENTICATION, target="user:root",
                why=(
                    f"root authenticated directly over SSH from {', '.join(ips[:10])} using "
                    f"{', '.join(methods)}. Direct root login removes the attribution that "
                    f"sudo provides - there is no record of which person was at the keyboard. "
                    f"Confirm each source address belongs to your team."
                ),
                impact="Unattributed root access to the host.",
                recommendation=(
                    "Verify each source address. Any address you do not recognise means the "
                    "root credential or an authorised key is compromised: rotate it and "
                    "review everything done in that session."
                ),
                evidence=[Evidence(
                    source="log", locator=root_logins[0].source,
                    content=redact("\n".join(e.raw for e in root_logins[-15:])))],
                timestamps={"most_recent_utc": iso_from_epoch(
                    max((e.timestamp for e in root_logins if e.timestamp),
                        default=_dt.datetime.now(_dt.timezone.utc)).timestamp())},
                tags=["authentication", "root-access"],
                correlation_key="account:root",
            ))

        # Logins from addresses outside private ranges
        external = [e for e in accepted if e.ip and not is_private_address(e.ip)]
        if external:
            pairs = sorted({f"{e.user}@{e.ip} ({e.method})" for e in external})
            result.add(make_finding(
                module=self.name, rule_id="LOG-EXTERNAL-LOGIN",
                title=f"{len(external)} successful login(s) from non-private source address(es)",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                category=Category.AUTHENTICATION, target="external-logins",
                why=(
                    "These successful logins came from addresses outside the private ranges. "
                    "Depending on how your competition network is addressed, that may be "
                    "entirely normal - or it may mean access from outside the environment."
                ),
                impact="Possible access from outside the expected network.",
                recommendation=(
                    "Confirm the source addresses against your team's own connectivity. "
                    "Restrict SSH to known management ranges if your scoring allows it."
                ),
                evidence=[Evidence(source="log", locator=external[0].source,
                                   content="\n".join(pairs[:30]))],
                tags=["authentication", "external-access"],
            ))

    def _check_sudo_activity(self, ctx, result, lines):
        result.checks_run += 1
        commands = []
        failures = []
        for source, line in lines:
            if "sudo" not in line:
                continue
            m = RE_SUDO_COMMAND.search(line)
            if m:
                commands.append((source, m.group("user"), m.group("command"), line))
            elif RE_SUDO_FAIL.search(line):
                failures.append((source, line))

        result.facts["sudo_command_count"] = len(commands)

        flagged = []
        for source, user, command, line in commands:
            indicators = scan(command)
            if indicators:
                flagged.append((user, command, indicators, line, source))

        if flagged:
            result.add(make_finding(
                module=self.name, rule_id="LOG-SUDO-SUSPICIOUS",
                title=f"{len(flagged)} sudo command(s) matched known-bad patterns",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                category=Category.PRIVESC, target="sudo-activity",
                why=(
                    "Commands executed through sudo matched indicator patterns: "
                    + "; ".join(
                        f"{user} ran a command matching {summarize(inds, 2)}"
                        for user, _c, inds, _l, _s in flagged[:5])
                    + ". sudo events are logged with the originating account, which makes "
                      "this some of the most attributable evidence available on the host."
                ),
                impact="Privileged commands consistent with attacker activity were executed.",
                recommendation=(
                    "Identify the accounts involved and treat them as compromised. Review "
                    "everything those sessions did and check for persistence installed by "
                    "these commands."
                ),
                evidence=[Evidence(
                    source="log", locator=flagged[0][4],
                    content=redact("\n".join(l for _u, _c, _i, l, _s in flagged[:15])),
                    meta={"note": "command text is recorded as data and never executed"})],
                tags=["privilege-escalation", "sudo", "high-value"],
                correlation_key=f"account:{flagged[0][0]}",
            ))

        if len(failures) >= 3:
            result.add(make_finding(
                module=self.name, rule_id="LOG-SUDO-FAILURES",
                title=f"{len(failures)} sudo authentication failure(s) recorded",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                category=Category.PRIVESC, target="sudo-failures",
                why=(
                    "Repeated sudo failures mean someone is attempting privilege escalation "
                    "without the right password, or an account not in sudoers is trying to "
                    "use it. Either is worth attributing: a user who legitimately mistypes a "
                    "password does not usually generate a run of failures."
                ),
                impact="Attempted privilege escalation.",
                recommendation=(
                    "Identify the accounts and terminals involved and confirm whether they "
                    "are your teammates."
                ),
                evidence=[Evidence(source="log", locator=failures[0][0],
                                   content=redact("\n".join(l for _s, l in failures[-15:])))],
                tags=["privilege-escalation", "sudo"],
            ))

    def _check_account_changes(self, ctx, result, lines):
        result.checks_run += 1
        created_users, created_groups, group_adds = [], [], []
        for source, line in lines:
            m = RE_USERADD.search(line)
            if m:
                created_users.append((m.group("user"), line, source))
                continue
            m = RE_GROUPADD.search(line)
            if m:
                created_groups.append((m.group("group"), line, source))
                continue
            m = RE_GROUP_MEMBER.search(line)
            if m:
                group_adds.append((m.group("user"), m.group("group"), line, source))

        if created_users:
            names = sorted({u for u, _l, _s in created_users})
            result.add(make_finding(
                module=self.name, rule_id="LOG-ACCOUNT-CREATED",
                title=f"Account creation recorded in logs: {', '.join(names)}",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                category=Category.ACCOUNT, target="account-creation",
                why=(
                    f"The logs record {len(created_users)} account creation event(s) within "
                    f"the review window ({', '.join(names)}). If your team did not create "
                    f"these accounts, someone with root did. Note that an attacker can also "
                    f"create an account by editing /etc/passwd directly, which produces no "
                    f"log entry at all - so this list is a floor, not a complete inventory."
                ),
                impact="New accounts may provide ongoing unauthorised access.",
                recommendation=(
                    "Confirm each account against your team's records. Cross-reference with "
                    "the accounts module findings, which inspect the passwd file directly."
                ),
                evidence=[Evidence(source="log", locator=created_users[0][2],
                                   content=redact("\n".join(l for _u, l, _s in created_users[:20])))],
                tags=["account", "account-creation"],
                correlation_key=f"account:{names[0]}",
            ))

        admin_adds = [(u, g, l, s) for u, g, l, s in group_adds
                      if g in ("sudo", "wheel", "admin", "root", "docker", "lxd")]
        if admin_adds:
            result.add(make_finding(
                module=self.name, rule_id="LOG-ADMIN-GROUP-ADD",
                title=f"{len(admin_adds)} account(s) added to an administrative group",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                category=Category.PRIVESC, target="group-membership-change",
                why=(
                    "The logs record accounts being added to privileged groups: "
                    + ", ".join(f"{u} -> {g}" for u, g, _l, _s in admin_adds[:8])
                    + ". Group membership changes are how an existing low-privilege foothold "
                      "is converted into persistent administrative access."
                ),
                impact="Accounts gained administrative privileges during the review window.",
                recommendation=(
                    "Confirm each change with your team. Remove any membership you did not "
                    "authorise, after checking what else that account has done."
                ),
                evidence=[Evidence(source="log", locator=admin_adds[0][3],
                                   content=redact("\n".join(l for _u, _g, l, _s in admin_adds[:20])))],
                tags=["privilege-escalation", "group-change"],
                correlation_key=f"account:{admin_adds[0][0]}",
            ))

    def _check_service_changes(self, ctx, result, lines):
        result.checks_run += 1
        patterns = [
            (re.compile(r"systemd\[1\]: (Started|Starting) (?P<unit>.+?)\."), "started"),
            (re.compile(r"systemd\[1\]: Reloading"), "reloaded"),
            (re.compile(r"Stopping (?P<unit>auditd|rsyslog|firewalld|ufw)"), "security-service-stopped"),
        ]
        stopped_security = []
        for source, line in lines:
            for pattern, kind in patterns:
                m = pattern.search(line)
                if m and kind == "security-service-stopped":
                    stopped_security.append((line, source))
        if stopped_security:
            result.add(make_finding(
                module=self.name, rule_id="LOG-SECURITY-SERVICE-STOPPED",
                title="A security or logging service was stopped during the review window",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                category=Category.LOGGING, target="security-services",
                why=(
                    "The logs record auditd, rsyslog, firewalld or ufw being stopped. "
                    "Disabling logging or filtering is a standard step before further "
                    "activity, and it is also something administrators do while "
                    "troubleshooting - confirm which applies here. Anything that happened "
                    "while the service was down will not appear in these logs."
                ),
                impact="Reduced visibility or filtering during an unknown period.",
                recommendation=(
                    "Confirm who stopped the service and when it restarted. Treat the gap as "
                    "a period with no evidence rather than a quiet period."
                ),
                evidence=[Evidence(source="log", locator=stopped_security[0][1],
                                   content=redact("\n".join(l for l, _s in stopped_security[:15])))],
                tags=["logging", "defence-evasion"],
            ))

    @staticmethod
    def _near_boot(ctx, mtime: Optional[float], window_seconds: int = 600) -> bool:
        """True when a file's last write falls close to this host's boot time."""
        if mtime is None or not ctx.facts.uptime_seconds:
            return False
        now = _dt.datetime.now(_dt.timezone.utc).timestamp()
        boot = now - ctx.facts.uptime_seconds
        return abs(mtime - boot) <= window_seconds

    def _check_log_integrity(self, ctx, result, coverage):
        result.checks_run += 1
        for path, label in BINARY_LOGS.items():
            info = ctx.host.stat(path)
            if not info.exists:
                result.add(make_finding(
                    module=self.name, rule_id="LOG-BINARY-MISSING",
                    title=f"{path} is missing ({label})",
                    severity=Severity.LOW if ctx.facts.container else Severity.MEDIUM,
                    confidence=Confidence.LOW if ctx.facts.container else Confidence.MEDIUM,
                    category=Category.LOGGING, target=path,
                    why=(
                        f"{path} holds {label}. It is absent. On a minimal or containerised "
                        f"image these files legitimately do not exist; on a normal server "
                        f"install, deleting them is a way to erase login history."
                    ),
                    impact="Login history for this host is unavailable.",
                    recommendation=(
                        f"Check whether a comparable host has this file. If it should exist, "
                        f"treat its absence as deliberate removal."
                    ),
                    evidence=[Evidence(source="file", locator=path, content="",
                                       error="not found")],
                    tags=["logging", "anti-forensics"],
                ))
            elif info.size == 0:
                # A file emptied at provisioning time looks the same as one
                # wiped by an attacker. The distinguishing evidence is whether
                # it was last written around boot or long afterwards.
                near_boot = self._near_boot(ctx, info.mtime)
                severity = Severity.LOW if near_boot else Severity.HIGH
                confidence = Confidence.LOW if near_boot else Confidence.MEDIUM
                result.add(make_finding(
                    module=self.name, rule_id="LOG-BINARY-TRUNCATED",
                    title=f"{path} is zero bytes ({label})",
                    severity=severity, confidence=confidence,
                    category=Category.LOGGING, target=path,
                    why=(
                        f"{path} exists but contains nothing, so {label} is empty. A freshly "
                        f"provisioned host can legitimately have an empty wtmp or btmp. On a "
                        f"host with uptime and login activity, an empty file means it was "
                        f"truncated - `> {path}` is the usual way, and it leaves the file in "
                        f"exactly this state."
                        + (" Its last write is close to this host's boot time, which points "
                           "at provisioning rather than a wipe, so this is reported at low "
                           "severity." if near_boot else
                           " Its last write is well after boot, which is the pattern a "
                           "deliberate wipe produces.")
                    ),
                    impact="Login history was erased or never recorded.",
                    recommendation=(
                        f"Compare the file's modification time ({iso_from_epoch(info.mtime)}) "
                        f"against the host's boot time. A truncation timestamp well after boot "
                        f"is strong evidence of deliberate clearing."
                    ),
                    evidence=[stat_evidence(path, info)],
                    timestamps={"mtime_utc": iso_from_epoch(info.mtime)},
                    tags=["logging", "anti-forensics"],
                    correlation_key="anti-forensics:log-wipe",
                ))

        for path in AUTH_LOG_PATHS:
            info = ctx.host.stat(path)
            if not info.exists:
                continue
            if info.size == 0:
                near_boot = self._near_boot(ctx, info.mtime)
                result.add(make_finding(
                    module=self.name, rule_id="LOG-AUTH-EMPTY",
                    title=f"Authentication log {path} is empty",
                    severity=Severity.MEDIUM if near_boot else Severity.HIGH,
                    confidence=Confidence.LOW if near_boot else Confidence.MEDIUM,
                    category=Category.LOGGING, target=path,
                    why=(
                        f"{path} exists but has zero length. Authentication events should "
                        f"appear here continuously on a running host. An empty file points to "
                        f"either a broken logging daemon or deliberate truncation."
                    ),
                    impact="No authentication history is available from this source.",
                    recommendation=(
                        "Check whether rsyslog is running, and compare against journald. "
                        "If the journal has events the file does not, the file was cleared."
                    ),
                    evidence=[stat_evidence(path, info)],
                    tags=["logging", "anti-forensics"],
                    correlation_key="anti-forensics:log-wipe",
                ))
                continue

            # A log whose newest entry predates recent boot activity is suspect.
            if info.mtime and ctx.facts.uptime_seconds:
                now = _dt.datetime.now(_dt.timezone.utc).timestamp()
                stale_hours = (now - info.mtime) / 3600.0
                if stale_hours > 24 and ctx.facts.uptime_seconds > 86400:
                    result.add(make_finding(
                        module=self.name, rule_id="LOG-AUTH-STALE",
                        title=f"{path} has not been written for {stale_hours:.0f} hours",
                        severity=Severity.MEDIUM, confidence=Confidence.LOW,
                        category=Category.LOGGING, target=path,
                        why=(
                            f"The host has been up for "
                            f"{ctx.facts.uptime_seconds / 3600:.0f} hours but {path} was last "
                            f"modified {stale_hours:.0f} hours ago. On a host with any login "
                            f"activity this suggests logging stopped. A host with genuinely no "
                            f"logins produces the same pattern, so confirm against journald."
                        ),
                        impact="Authentication events may not be recorded.",
                        recommendation="Check that rsyslog is running and compare with journald.",
                        evidence=[stat_evidence(path, info)],
                        timestamps={"mtime_utc": iso_from_epoch(info.mtime)},
                        tags=["logging"],
                        partial_evidence=True,
                    ))

        result.add(make_finding(
            module=self.name, rule_id="LOG-COVERAGE",
            title="Log source coverage for this assessment",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            category=Category.LOGGING, target="log-coverage",
            why=(
                "This records exactly which log sources were readable and how much was "
                "examined, so that the absence of a finding can be interpreted correctly. "
                "Logs on a host you do not yet trust are the weakest form of evidence: "
                "anyone with root can edit or delete them. A quiet log is not proof of a "
                "quiet host."
            ),
            impact="Defines the limits of what the log-based findings can tell you.",
            recommendation=(
                "Where a source is listed as unavailable, either fix the permission problem "
                "and re-run, or record it as a known gap in your incident notes."
            ),
            evidence=[Evidence(
                source="derived", locator="log-coverage",
                content="\n".join(f"{k}: {v}" for k, v in sorted(coverage.items())),
                meta={"lookback_hours": ctx.config.log_lookback_hours})],
            tags=["logging", "coverage"],
        ))

    def _check_package_log(self, ctx, result):
        result.checks_run += 1
        cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(
            hours=ctx.config.log_lookback_hours)
        for path in PACKAGE_LOG_PATHS:
            info = ctx.host.stat(path)
            if not info.exists:
                continue
            tail, err = ctx.host.tail_lines(path, lines=3000)
            if err:
                continue
            installs = [l for l in tail
                        if re.search(r"\b(install|upgrade|Installed:|Install:)\b", l)]
            if not installs:
                continue
            recent = []
            for line in installs:
                ts = self._parse_timestamp(line)
                if ts is None or ts >= cutoff:
                    recent.append(line)
            if not recent:
                continue
            result.add(make_finding(
                module=self.name, rule_id="LOG-RECENT-PACKAGE-ACTIVITY",
                title=f"{len(recent)} package install/upgrade record(s) in {os.path.basename(path)}",
                severity=Severity.LOW, confidence=Confidence.MEDIUM,
                category=Category.PACKAGE, target=path,
                why=(
                    "Package activity inside the review window is listed so you can confirm "
                    "it was yours. Installing a tool such as netcat, socat or a compiler is a "
                    "normal early step for an attacker who wants capability on the host, and "
                    "it is also a normal early step for a blue team. The log tells you what "
                    "happened, not who did it."
                ),
                impact="Shows what software changed on the host recently.",
                recommendation=(
                    "Review the list against your own installs. Investigate anything you did "
                    "not install, particularly networking and compiler packages."
                ),
                evidence=[Evidence(source="log", locator=path,
                                   content=redact("\n".join(recent[-40:])))],
                tags=["package", "timeline"],
            ))



# ============================================================================
# bulwark/detection/packages.py
# detection: package integrity
# ============================================================================

# Package and software integrity.
#
# Package verification is the strongest integrity evidence available locally,
# because it compares against hashes recorded at build time rather than against
# the host's own state. It is still not proof: the package database itself lives
# on the host and can be rewritten by root.




# Binaries whose integrity matters most: these are what an operator uses to
# investigate, and what a userland rootkit replaces first.
HIGH_VALUE_BINARIES = [
    "/bin/ls", "/usr/bin/ls", "/bin/ps", "/usr/bin/ps", "/bin/netstat",
    "/usr/bin/netstat", "/usr/bin/ss", "/bin/login", "/usr/bin/login",
    "/usr/sbin/sshd", "/usr/bin/ssh", "/bin/su", "/usr/bin/su",
    "/usr/bin/sudo", "/usr/bin/passwd", "/bin/bash", "/usr/bin/bash",
    "/bin/sh", "/usr/bin/find", "/usr/bin/top", "/usr/bin/w", "/usr/bin/who",
    "/usr/bin/last", "/usr/bin/lsof", "/usr/bin/stat", "/usr/bin/md5sum",
    "/usr/bin/sha256sum", "/usr/bin/crontab", "/usr/sbin/useradd",
    "/usr/bin/systemctl", "/usr/bin/journalctl", "/usr/bin/dpkg", "/usr/bin/rpm",
]

# dpkg -V / rpm -Va flag letters that indicate content change rather than
# benign configuration drift.
DPKG_CONTENT_CHANGE = "5"      # md5 mismatch
RPM_CONTENT_CHANGE = "5"


class PackagesModule(DetectionModule):
    name = "packages"
    version = "1.1"
    title = "Package and software integrity"
    description = (
        "Verifies installed files against package metadata, lists recently "
        "changed packages, and finds executables in system directories that no "
        "package claims."
    )
    quick = False

    def check(self, ctx: AuditContext, result: ModuleResult) -> None:
        manager = ctx.facts.package_manager
        if manager not in ("dpkg", "rpm"):
            result.status = result.status.UNSUPPORTED
            result.reason = (
                f"package manager '{manager}' is not supported for verification; "
                "only dpkg and rpm based systems are handled"
            )
            result.gap("package verification", result.reason,
                       "no package-based integrity evidence is available")
            return
        if ctx.host.is_synthetic:
            result.status = result.status.SKIPPED
            result.reason = "package verification is not meaningful against a synthetic root"
            return

        self._inventory(ctx, result, manager)
        self._verify(ctx, result, manager)
        self._unowned_binaries(ctx, result, manager)

    # ----------------------------------------------------------- inventory

    def _inventory(self, ctx, result, manager):
        result.checks_run += 1
        if manager == "dpkg":
            res = ctx.host.run(
                ["dpkg-query", "-W", "-f", "${Package} ${Version} ${Status}\n"], timeout=60)
        else:
            res = ctx.host.run(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"],
                               timeout=60)
        if not res.ok:
            result.gap("package inventory", res.error or res.stderr.strip()[:120],
                       "the installed package list is unavailable")
            return
        packages = [l for l in res.stdout.splitlines() if l.strip()]
        result.facts["package_count"] = len(packages)
        result.facts["packages"] = packages[:5000]

    # -------------------------------------------------------- verification

    def _verify(self, ctx, result, manager):
        result.checks_run += 1
        if manager == "dpkg":
            res = ctx.host.run(["dpkg", "-V"], timeout=240)
            # dpkg -V exits non-zero when discrepancies exist, which is normal.
            if not res.ran:
                result.gap("dpkg -V", res.error or "could not run",
                           "package verification was not performed",
                           needs_root=not ctx.facts.is_root)
                return
            changed = self._parse_dpkg_verify(res.stdout)
        else:
            res = ctx.host.run(["rpm", "-Va", "--nomtime", "--nordev", "--nouser",
                                "--nogroup"], timeout=300)
            if not res.ran:
                result.gap("rpm -Va", res.error or "could not run",
                           "package verification was not performed",
                           needs_root=not ctx.facts.is_root)
                return
            changed = self._parse_rpm_verify(res.stdout)

        if res.error == "timeout":
            result.gap("package verification", "timed out",
                       "verification results are incomplete")

        result.facts["package_verify_failures"] = [
            {"path": p, "flags": f} for p, f in changed
        ][:2000]

        if not changed:
            result.add(make_finding(
                module=self.name, rule_id="PKG-VERIFY-CLEAN",
                title="Package verification reported no modified files",
                severity=Severity.INFO, confidence=Confidence.MEDIUM,
                category=Category.PACKAGE, target="package-verification",
                why=(
                    "Every packaged file this check examined matches the hash recorded when "
                    "the package was built. This is meaningful evidence, but not a clean bill "
                    "of health: it says nothing about files no package owns, and the package "
                    "database lives on this host, so root-level tampering could have updated "
                    "it to match a modified file."
                ),
                impact="Baseline integrity evidence for packaged files.",
                recommendation=(
                    "Treat this as one evidence source among several. Compare with the "
                    "filesystem and persistence module findings."
                ),
                evidence=[Evidence(source="command", locator=res.argv_str(),
                                   content="(no discrepancies reported)")],
                tags=["package", "integrity"],
            ))
            return

        high_value = [(p, f) for p, f in changed
                      if p in HIGH_VALUE_BINARIES or self._is_binary_path(p)]
        config_only = [(p, f) for p, f in changed if p.startswith("/etc/")]
        other = [(p, f) for p, f in changed
                 if (p, f) not in high_value and (p, f) not in config_only]

        if high_value:
            listing = "\n".join(
                f"{flags}  {path}  (mtime={iso_from_epoch(ctx.host.stat(path).mtime)})"
                for path, flags in high_value[:40])
            result.add(make_finding(
                module=self.name, rule_id="PKG-BINARY-MODIFIED",
                title=f"{len(high_value)} packaged system binary/binaries differ from their package",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                category=Category.INTEGRITY, target="modified-system-binaries",
                why=(
                    f"The package manager reports that these executables no longer match the "
                    f"content recorded when their package was built. System binaries are not "
                    f"edited in normal operation. Replacing them is how a userland rootkit "
                    f"hides: a modified `ls`, `ps` or `netstat` simply omits the attacker's "
                    f"files, processes and connections from its output - including from the "
                    f"output you are reading during this investigation."
                ),
                impact=(
                    "Core system tooling may be subverted, and any investigation that relies "
                    "on these binaries produces results you cannot trust."
                ),
                recommendation=(
                    "Do not rely on these binaries. Verify a few findings against /proc "
                    "directly. Capture the modified files as evidence, then restore from the "
                    "package (`apt-get install --reinstall <pkg>` or `rpm -Uvh --replacepkgs`) "
                    "only after capture - and only if you accept that a root-level compromise "
                    "may simply reinstate them. Independent verification from external media "
                    "is the only reliable confirmation."
                ),
                evidence=[
                    Evidence(source="command", locator=res.argv_str(), content=listing,
                             meta={"note": "flag '5' means the file's checksum differs"}),
                ],
                tags=["integrity", "rootkit", "high-value"],
                correlation_key="rootkit:binary-replacement",
            ))

        if config_only:
            result.add(make_finding(
                module=self.name, rule_id="PKG-CONFIG-MODIFIED",
                title=f"{len(config_only)} packaged configuration file(s) have been modified",
                severity=Severity.LOW, confidence=Confidence.MEDIUM,
                category=Category.PACKAGE, target="modified-config-files",
                why=(
                    "These configuration files differ from the packaged version. Editing "
                    "configuration is routine administration - including your own hardening - "
                    "so this is a review list rather than a finding of compromise. Pay "
                    "particular attention to any security-relevant file you did not edit."
                ),
                impact="Shows which packaged configuration has been customised.",
                recommendation=(
                    "Review the list for files you did not change, especially under "
                    "/etc/ssh, /etc/pam.d, /etc/sudoers.d and /etc/systemd."
                ),
                evidence=[Evidence(source="command", locator=res.argv_str(),
                                   content="\n".join(f"{f}  {p}" for p, f in config_only[:60]))],
                tags=["package", "configuration-drift"],
            ))

        if other:
            result.add(make_finding(
                module=self.name, rule_id="PKG-FILES-MODIFIED",
                title=f"{len(other)} other packaged file(s) differ from their package",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                category=Category.PACKAGE, target="modified-package-files",
                why=(
                    "These files no longer match their package. Causes range from an "
                    "interrupted upgrade to deliberate replacement. Review for anything "
                    "executable or security-relevant."
                ),
                impact="Files on the host differ from what the distribution shipped.",
                recommendation="Review the list; reinstall affected packages after capturing evidence.",
                evidence=[Evidence(source="command", locator=res.argv_str(),
                                   content="\n".join(f"{f}  {p}" for p, f in other[:60]))],
                tags=["package", "integrity"],
            ))

    @staticmethod
    def _parse_dpkg_verify(output: str) -> List[Tuple[str, str]]:
        """dpkg -V emits lines like: `??5??????   /usr/bin/ls`"""
        changed = []
        for line in output.splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            flags, path = parts[0], parts[1].strip()
            if not path.startswith("/"):
                continue
            if DPKG_CONTENT_CHANGE in flags:
                changed.append((path, flags))
        return changed

    @staticmethod
    def _parse_rpm_verify(output: str) -> List[Tuple[str, str]]:
        """rpm -Va emits lines like: `S.5....T.  c /etc/sudoers`"""
        changed = []
        for line in output.splitlines():
            if not line.strip() or line.startswith("warning:"):
                continue
            match = re.match(r"^(\S{8,9})\s+(?:([a-zA-Z])\s+)?(/.+)$", line)
            if not match:
                continue
            flags, _kind, path = match.group(1), match.group(2), match.group(3).strip()
            if RPM_CONTENT_CHANGE in flags:
                changed.append((path, flags))
        return changed

    @staticmethod
    def _is_binary_path(path: str) -> bool:
        return any(path.startswith(d + "/") for d in
                   ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/libexec", "/lib", "/usr/lib"))

    # --------------------------------------------------- unowned executables

    def _unowned_binaries(self, ctx, result, manager):
        result.checks_run += 1
        candidates: List[str] = []
        for directory in PACKAGE_MANAGED_BIN_DIRS:
            if not ctx.host.is_dir(directory):
                continue
            files, _errors, _hit = ctx.host.walk(directory, max_depth=2, max_entries=6000)
            for path in files:
                info = ctx.host.stat(path)
                if info.is_symlink or not info.is_file:
                    continue
                if (info.mode or 0) & 0o111:
                    candidates.append(path)

        if not candidates:
            return

        unowned: List[str] = []
        # Query in batches: one process per file would take minutes.
        batch_size = 200
        for i in range(0, len(candidates), batch_size):
            batch = candidates[i:i + batch_size]
            if manager == "dpkg":
                res = ctx.host.run(["dpkg", "-S"] + batch, timeout=60, cache=False)
            else:
                res = ctx.host.run(["rpm", "-qf"] + batch, timeout=60, cache=False)
            if not res.ran:
                result.gap("unowned binary scan", res.error or "query failed",
                           "executables could not be matched to packages")
                return
            combined = res.stdout + res.stderr
            for line in combined.splitlines():
                m = re.search(r"no path found matching pattern (\S+)", line)
                if m:
                    unowned.append(m.group(1))
                    continue
                m = re.match(r"file (\S+) is not owned by any package", line)
                if m:
                    unowned.append(m.group(1))
                    continue
                m = re.match(r"(\S+) is not owned by any package", line)
                if m:
                    unowned.append(m.group(1))

        unowned = sorted(set(unowned))
        result.facts["unowned_binaries"] = unowned[:500]
        if not unowned:
            return

        details = []
        for path in unowned[:50]:
            info = ctx.host.stat(path, hash_file=True)
            details.append(
                f"{path}  owner={info.owner} mode={info.mode_octal} "
                f"mtime={iso_from_epoch(info.mtime)} sha256={(info.sha256 or '')[:16]}...")

        result.add(make_finding(
            module=self.name, rule_id="PKG-UNOWNED-BINARY",
            title=f"{len(unowned)} executable(s) in system binary directories are not owned by any package",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            category=Category.INTEGRITY, target="unowned-binaries",
            why=(
                "These executables sit in directories managed by the package manager, but no "
                "installed package claims them. Software installed from source or by a "
                "vendor script produces the same result, which is why this is not conclusive. "
                "It is nonetheless the right list to review: dropping a binary into "
                "/usr/bin or /usr/sbin is a durable and unremarkable-looking way to leave a "
                "tool on the host."
            ),
            impact="Unaccounted-for executables with system-wide reach.",
            recommendation=(
                "For each one, check the modification time against the host's build date and "
                "inspect it statically with `file` and `strings`. Anything you cannot "
                "attribute to a known installation deserves full investigation."
            ),
            evidence=[Evidence(source="derived", locator="package ownership query",
                               content="\n".join(details),
                               truncated=len(unowned) > 50,
                               meta={"total": len(unowned)})],
            tags=["integrity", "unowned-binary"],
        ))



# ============================================================================
# bulwark/detection/security_controls.py
# detection: defensive controls
# ============================================================================

# Defensive visibility: which security controls exist, and which are working.
#
# A missing control is a posture finding, not evidence of an intrusion. The
# distinction matters: reporting "auditd is not installed" as red-team activity
# on an image that never had auditd wastes the one resource a competition team
# cannot get more of, which is attention.
#
# Nothing here is enabled, disabled or reconfigured. Status is read only.





class SecurityControlsModule(DetectionModule):
    name = "security-controls"
    version = "1.1"
    title = "Security controls and defensive visibility"
    description = (
        "Determines whether firewalling, auditing, logging, MAC enforcement, "
        "file integrity monitoring and automatic updates are installed and "
        "running."
    )
    quick = False

    def check(self, ctx: AuditContext, result: ModuleResult) -> None:
        status: Dict[str, Dict] = {}
        status["logging"] = self._check_logging(ctx, result)
        status["auditd"] = self._check_auditd(ctx, result)
        status["mac"] = self._check_mac(ctx, result)
        status["fim"] = self._check_fim(ctx, result)
        status["updates"] = self._check_updates(ctx, result)
        status["intrusion_prevention"] = self._check_fail2ban(ctx, result)
        result.facts["security_controls"] = status
        self._summary(ctx, result, status)

    # --------------------------------------------------------------- helpers

    def _service_active(self, ctx, unit: str) -> Optional[bool]:
        """True/False if determinable, None if it cannot be established."""
        if ctx.facts.init_system == "systemd" and ctx.host.has("systemctl"):
            res = ctx.host.run(["systemctl", "is-active", unit], timeout=10)
            if res.ran:
                return res.stdout.strip() == "active"
        if ctx.host.has("service"):
            res = ctx.host.run(["service", unit, "status"], timeout=10)
            if res.ran:
                return res.returncode == 0
        processes = ctx.shared("processes") or {}
        base = unit.replace(".service", "")
        for proc in processes.values():
            if proc.name == base:
                return True
        return None

    # ---------------------------------------------------------------- checks

    def _check_logging(self, ctx, result) -> Dict:
        result.checks_run += 1
        info: Dict = {"journald": None, "rsyslog": None, "syslog_ng": None}
        info["journald"] = self._service_active(ctx, "systemd-journald")
        info["rsyslog"] = self._service_active(ctx, "rsyslog")
        info["syslog_ng"] = self._service_active(ctx, "syslog-ng")

        any_active = any(v is True for v in info.values())
        undetermined = all(v is None for v in info.values())

        if undetermined:
            result.gap("logging services", "service status could not be determined",
                       "cannot confirm whether the host is recording events",
                       needs_root=not ctx.facts.is_root)
        elif not any_active:
            result.add(make_finding(
                module=self.name, rule_id="SEC-NO-LOGGING",
                title="No system logging service appears to be running",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                category=Category.LOGGING, target="logging",
                why=(
                    "Neither journald nor rsyslog nor syslog-ng is active. With no logging "
                    "daemon the host records nothing: authentication attempts, sudo use and "
                    "service changes all pass unrecorded. If logging was running earlier and "
                    "is now stopped, everything that happened since is invisible."
                ),
                impact="No evidence will exist for anything that happens from now on.",
                recommendation=(
                    "Start the logging service and confirm events appear. Check the logs for "
                    "a record of it being stopped, which would indicate deliberate action."
                ),
                evidence=[Evidence(source="derived", locator="logging services",
                                   content="\n".join(f"{k}: {v}" for k, v in info.items()))],
                remediation_risk="Minimal. Starting logging does not affect scored services.",
                tags=["logging", "posture"],
            ))
        return info

    def _check_auditd(self, ctx, result) -> Dict:
        result.checks_run += 1
        installed = ctx.host.has("auditctl") or ctx.host.exists("/etc/audit/auditd.conf")
        active = self._service_active(ctx, "auditd") if installed else False
        rule_count = None
        if installed and ctx.host.has("auditctl") and ctx.facts.is_root:
            res = ctx.host.run(["auditctl", "-l"], timeout=15)
            if res.ok:
                lines = [l for l in res.stdout.splitlines() if l.strip()]
                rule_count = 0 if (len(lines) == 1 and "No rules" in lines[0]) else len(lines)

        info = {"installed": installed, "active": active, "rules": rule_count}
        if not installed:
            result.add(make_finding(
                module=self.name, rule_id="SEC-NO-AUDITD",
                title="auditd is not installed",
                severity=Severity.LOW, confidence=Confidence.HIGH,
                category=Category.POSTURE, target="auditd",
                why=(
                    "The Linux audit daemon is not present, so there is no syscall-level "
                    "record of execution, file access or privilege use. Many distributions do "
                    "not install it by default, so its absence is a visibility limitation "
                    "rather than a sign of tampering. Without Internet access during a "
                    "competition you most likely cannot add it now."
                ),
                impact="No syscall-level audit trail is available for this host.",
                recommendation=(
                    "Rely on journald and auth logs for this host, and record in your incident "
                    "notes that syscall auditing was unavailable."
                ),
                evidence=[Evidence(source="derived", locator="auditd",
                                   content="auditctl not found; /etc/audit/auditd.conf absent")],
                tags=["posture", "visibility"],
            ))
        elif active is False:
            result.add(make_finding(
                module=self.name, rule_id="SEC-AUDITD-STOPPED",
                title="auditd is installed but not running",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                category=Category.LOGGING, target="auditd",
                why=(
                    "auditd is installed on this host but is not active. Something stopped it "
                    "or prevented it from starting. Since the package is present, the image "
                    "was built expecting it to run - which makes a stopped auditd more "
                    "interesting than an absent one."
                ),
                impact="Syscall auditing is not recording while the service is down.",
                recommendation=(
                    "Check the journal for why it stopped, then start it. Review `auditctl -l` "
                    "afterwards to confirm rules loaded."
                ),
                evidence=[Evidence(source="derived", locator="auditd",
                                   content=f"installed={installed} active={active}")],
                tags=["logging", "posture"],
            ))
        elif rule_count == 0:
            result.add(make_finding(
                module=self.name, rule_id="SEC-AUDITD-NO-RULES",
                title="auditd is running with no audit rules loaded",
                severity=Severity.LOW, confidence=Confidence.HIGH,
                category=Category.LOGGING, target="auditd",
                why=(
                    "auditd is active but `auditctl -l` reports no rules, so it is recording "
                    "almost nothing. This is the default state on several distributions."
                ),
                impact="auditd provides little visibility in its current configuration.",
                recommendation=(
                    "If time allows, add rules for execve, /etc/passwd, /etc/shadow, "
                    "/etc/sudoers and the SSH configuration directory."
                ),
                evidence=[Evidence(source="command", locator="auditctl -l",
                                   content="no rules loaded")],
                tags=["logging", "posture"],
            ))
        return info

    def _check_mac(self, ctx, result) -> Dict:
        result.checks_run += 1
        info: Dict = {"selinux": None, "apparmor": None}

        selinux_enforce, _t, _e = ctx.host.read_text("/sys/fs/selinux/enforce", max_bytes=16)
        if selinux_enforce is not None:
            info["selinux"] = "enforcing" if selinux_enforce.strip() == "1" else "permissive"
        elif ctx.host.exists("/etc/selinux/config"):
            text, _t2, _e2 = ctx.host.read_text("/etc/selinux/config", max_bytes=8192)
            for line in (text or "").splitlines():
                if line.strip().startswith("SELINUX="):
                    info["selinux"] = line.split("=", 1)[1].strip()
                    break

        if ctx.host.is_dir("/sys/kernel/security/apparmor"):
            profiles, err = ctx.host.read_text(
                "/sys/kernel/security/apparmor/profiles", max_bytes=256 * 1024)
            if profiles:
                enforce = sum(1 for l in profiles.splitlines() if "(enforce)" in l)
                complain = sum(1 for l in profiles.splitlines() if "(complain)" in l)
                info["apparmor"] = {"enforce": enforce, "complain": complain}
            else:
                info["apparmor"] = "present"

        selinux_off = info["selinux"] in ("disabled", "permissive", None)
        apparmor_off = info["apparmor"] in (None, "present") or (
            isinstance(info["apparmor"], dict) and info["apparmor"]["enforce"] == 0)

        if info["selinux"] == "permissive":
            result.add(make_finding(
                module=self.name, rule_id="SEC-SELINUX-PERMISSIVE",
                title="SELinux is in permissive mode",
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                category=Category.POSTURE, target="selinux",
                why=(
                    "SELinux is loaded but set to permissive, so it logs policy violations "
                    "without blocking them. The policy exists and is being evaluated; nothing "
                    "is being enforced. `setenforce 0` produces exactly this state and is a "
                    "standard early step after gaining root on an RHEL-family host."
                ),
                impact="Mandatory access control provides logging but no containment.",
                recommendation=(
                    "Check the audit log for AVC denials, which show what policy would have "
                    "blocked. Switching to enforcing with `setenforce 1` can break services "
                    "that have been running unconfined - test carefully during a round."
                ),
                evidence=[Evidence(source="file", locator="/sys/fs/selinux/enforce",
                                   content=str(info["selinux"]))],
                remediation_risk=(
                    "Enabling enforcement mid-round can break a scored service whose files "
                    "have the wrong labels."
                ),
                tags=["posture", "mac"],
            ))
        elif selinux_off and apparmor_off:
            result.add(make_finding(
                module=self.name, rule_id="SEC-NO-MAC",
                title="No mandatory access control is enforcing on this host",
                severity=Severity.LOW, confidence=Confidence.MEDIUM,
                category=Category.POSTURE, target="mac",
                why=(
                    "Neither SELinux nor AppArmor is enforcing. Standard Unix permissions are "
                    "the only access control in force, so a compromised service has whatever "
                    "its account can reach. Several distributions ship this way."
                ),
                impact="A compromised service is not confined beyond file permissions.",
                recommendation=(
                    "Enabling MAC mid-competition is risky and rarely worth it. Record it as "
                    "a known limitation and concentrate on reducing what each service account "
                    "can reach."
                ),
                evidence=[Evidence(source="derived", locator="mac",
                                   content=f"selinux={info['selinux']} apparmor={info['apparmor']}")],
                tags=["posture", "mac"],
            ))
        return info

    def _check_fim(self, ctx, result) -> Dict:
        result.checks_run += 1
        tools = {
            "aide": ctx.host.has("aide") or ctx.host.exists("/etc/aide/aide.conf")
                    or ctx.host.exists("/etc/aide.conf"),
            "tripwire": ctx.host.has("tripwire"),
            "ossec": ctx.host.is_dir("/var/ossec"),
            "wazuh": ctx.host.is_dir("/var/ossec/etc") or ctx.host.has("wazuh-control"),
            "samhain": ctx.host.has("samhain"),
            "osquery": ctx.host.has("osqueryi"),
            "auditbeat": ctx.host.has("auditbeat"),
            "falco": ctx.host.has("falco"),
            "clamav": ctx.host.has("clamscan") or ctx.host.has("freshclam"),
        }
        present = [k for k, v in tools.items() if v]
        if not present:
            result.add(make_finding(
                module=self.name, rule_id="SEC-NO-FIM",
                title="No file integrity monitoring or endpoint security tooling is installed",
                severity=Severity.LOW, confidence=Confidence.HIGH,
                category=Category.POSTURE, target="file-integrity-monitoring",
                why=(
                    "None of AIDE, Tripwire, OSSEC/Wazuh, Samhain, osquery, Falco or ClamAV is "
                    "present. Nothing on this host will notice a changed binary or a dropped "
                    "payload on its own. This is typical of a bare competition image."
                ),
                impact="Changes to the system will not be detected automatically.",
                recommendation=(
                    "Use this tool's baseline feature as the substitute: run "
                    "`bulwark snap` once you have reviewed the host, then `bulwark check` "
                    "periodically through the round."
                ),
                evidence=[Evidence(source="derived", locator="fim tooling",
                                   content="none of: " + ", ".join(sorted(tools)))],
                tags=["posture", "visibility"],
            ))
        return {"tools_present": present}

    def _check_updates(self, ctx, result) -> Dict:
        result.checks_run += 1
        info: Dict = {}
        if ctx.facts.package_manager == "dpkg":
            conf = "/etc/apt/apt.conf.d/20auto-upgrades"
            text, _t, _e = ctx.host.read_text(conf, max_bytes=8192)
            enabled = bool(text and 'Unattended-Upgrade "1"' in text)
            info = {"mechanism": "unattended-upgrades", "enabled": enabled}
        elif ctx.facts.package_manager == "rpm":
            enabled = self._service_active(ctx, "dnf-automatic.timer") is True
            info = {"mechanism": "dnf-automatic", "enabled": enabled}
        else:
            info = {"mechanism": "unknown", "enabled": None}

        if info.get("enabled") is True:
            result.add(make_finding(
                module=self.name, rule_id="SEC-AUTO-UPDATES-ON",
                title=f"Automatic updates are enabled ({info['mechanism']})",
                severity=Severity.INFO, confidence=Confidence.MEDIUM,
                category=Category.POSTURE, target="automatic-updates",
                why=(
                    "Automatic updates are configured. During a competition this is worth "
                    "knowing in both directions: it keeps packages patched without effort, "
                    "and it can also restart services or change configuration in the middle "
                    "of a round, which looks like an incident and can cost availability "
                    "points."
                ),
                impact="Packages may change without operator action during the round.",
                recommendation=(
                    "Decide deliberately whether to leave this on. If you turn it off, apply "
                    "security updates manually instead."
                ),
                evidence=[Evidence(source="derived", locator="automatic updates",
                                   content=str(info))],
                tags=["posture", "updates"],
            ))
        return info

    def _check_fail2ban(self, ctx, result) -> Dict:
        result.checks_run += 1
        installed = ctx.host.has("fail2ban-client") or ctx.host.exists("/etc/fail2ban/jail.conf")
        active = self._service_active(ctx, "fail2ban") if installed else False
        info = {"installed": installed, "active": active}
        if installed and active is False:
            result.add(make_finding(
                module=self.name, rule_id="SEC-FAIL2BAN-STOPPED",
                title="fail2ban is installed but not running",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                category=Category.POSTURE, target="fail2ban",
                why=(
                    "fail2ban is present on the host but inactive, so repeated failed logins "
                    "are not being blocked. The image was built expecting it to run, which "
                    "makes a stopped service more notable than an absent one."
                ),
                impact="Credential guessing against this host is unthrottled.",
                recommendation=(
                    "Start fail2ban and verify its jails with `fail2ban-client status`. "
                    "Confirm your own management addresses are allow-listed so you do not ban "
                    "your team."
                ),
                evidence=[Evidence(source="derived", locator="fail2ban", content=str(info))],
                remediation_risk="A misconfigured jail can ban your own team's addresses.",
                tags=["posture", "brute-force-protection"],
            ))
        return info

    def _summary(self, ctx, result, status):
        result.checks_run += 1
        lines = []
        for area, data in status.items():
            lines.append(f"{area}: {data}")
        result.add(make_finding(
            module=self.name, rule_id="SEC-POSTURE-SUMMARY",
            title="Defensive control inventory",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            category=Category.POSTURE, target="security-controls",
            why=(
                "A single view of which defensive controls exist on this host and which are "
                "working. Use it to decide where you have visibility and where you are "
                "operating blind. None of this is evidence of compromise."
            ),
            impact="Defines the detection and containment capability available on this host.",
            recommendation=(
                "Fix the cheap gaps first - starting a stopped logging or filtering service "
                "costs nothing and usually breaks nothing. Leave intrusive changes such as "
                "enabling MAC enforcement until you have time to test."
            ),
            evidence=[Evidence(source="derived", locator="security-controls",
                               content="\n".join(lines))],
            tags=["posture", "inventory"],
        ))



# ============================================================================
# bulwark/detection/__init__.py
# detection module registry
# ============================================================================

# Detection module registry.
#
# Adding a module means writing a `DetectionModule` subclass and appending it
# here. Nothing in the CLI or the report generators needs to change.




_MODULE_CLASSES = [
    AccountsModule,
    SSHModule,
    PersistenceModule,
    ProcessesModule,
    NetworkModule,
    FilesystemModule,
    LogsModule,
    PackagesModule,
    SecurityControlsModule,
]


def all_modules() -> List[DetectionModule]:
    return [cls() for cls in _MODULE_CLASSES]


def module_names() -> List[str]:
    return [cls.name for cls in _MODULE_CLASSES]


def select(names=None, skip=None, quick: bool = False) -> List[DetectionModule]:
    """Resolve the module set for a run."""
    modules = all_modules()
    if quick:
        modules = [m for m in modules if m.quick]
    if names:
        wanted = {n.strip().lower() for n in names}
        modules = [m for m in modules if m.name in wanted]
    if skip:
        unwanted = {n.strip().lower() for n in skip}
        modules = [m for m in modules if m.name not in unwanted]
    return modules


def describe() -> Dict[str, Dict[str, object]]:
    return {
        cls.name: {
            "version": cls.version,
            "title": cls.title,
            "quick": cls.quick,
            "requires_root": cls.requires_root,
            "description": cls.description,
        }
        for cls in _MODULE_CLASSES
    }



# ============================================================================
# bulwark/engine.py
# audit orchestration and exit codes
# ============================================================================

select_modules = select

# Audit orchestration: run modules, collect results, assemble an assessment.




# Exit codes. A completed audit and a clean host are deliberately different
# things, and the exit status says which.
EXIT_CLEAN = 0            # audit completed, nothing above informational
EXIT_ERROR = 1            # the audit itself failed to run
EXIT_USAGE = 2            # bad invocation
EXIT_FINDINGS_LOW = 10    # completed, highest severity is low or medium
EXIT_FINDINGS_HIGH = 20   # completed, at least one high or critical finding


@dataclass
class Assessment:
    tool_version: str
    schema_version: str
    started_at: str
    finished_at: Optional[str] = None
    duration_seconds: float = 0.0
    facts: Optional[HostFacts] = None
    config: Optional[Config] = None
    module_results: List[ModuleResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    incidents: List[Incident] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    baseline_path: Optional[str] = None
    baseline_created_at: Optional[str] = None
    incident_dir: Optional[str] = None
    integrity_warning: bool = False
    integrity_reasons: List[str] = field(default_factory=list)

    # ------------------------------------------------------------- summary

    @property
    def gaps(self) -> List[VisibilityGap]:
        out: List[VisibilityGap] = []
        for result in self.module_results:
            out.extend(result.gaps)
        return out

    @property
    def counts(self) -> Dict[str, int]:
        return severity_counts(self.findings)

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def module_status_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for result in self.module_results:
            counts[result.status.value] = counts.get(result.status.value, 0) + 1
        return counts

    def exit_code(self) -> int:
        if self.errors and not self.module_results:
            return EXIT_ERROR
        actionable = [f for f in self.findings if f.severity.rank >= Severity.LOW.rank]
        if not actionable:
            return EXIT_CLEAN
        top = max(f.severity.rank for f in actionable)
        if top >= Severity.HIGH.rank:
            return EXIT_FINDINGS_HIGH
        return EXIT_FINDINGS_LOW

    def status_label(self) -> str:
        code = self.exit_code()
        if code == EXIT_ERROR:
            return "FAILED"
        if code == EXIT_FINDINGS_HIGH:
            return "ACTION REQUIRED"
        if code == EXIT_FINDINGS_LOW:
            return "REVIEW NEEDED"
        return "NO FINDINGS ABOVE INFORMATIONAL"

    def facts_dict(self) -> Dict[str, Any]:
        return self.facts.to_dict() if self.facts else {}

    def collect_facts(self) -> Dict[str, Any]:
        """Merged per-module facts, used for baseline creation."""
        merged: Dict[str, Any] = {}
        for result in self.module_results:
            for key, value in result.facts.items():
                merged[key] = value
        return merged


def run_audit(config: Config, logger: Optional[Callable[[str, str], None]] = None,
              baseline: Optional[Dict[str, Any]] = None,
              progress: Optional[Callable[[str, int, int], None]] = None) -> Assessment:
    started = time.monotonic()
    host = Host(root=config.root, timeout=config.command_timeout)
    facts = detect_host_facts(host)

    assessment = Assessment(
        tool_version=__version__,
        schema_version=__schema_version__,
        started_at=iso(utc_now()),
        facts=facts,
        config=config,
    )
    if baseline:
        assessment.baseline_path = config.baseline_path
        assessment.baseline_created_at = baseline.get("created_at_utc")

    ctx = AuditContext(host=host, config=config, facts=facts,
                       baseline=baseline, logger=logger)

    modules = select_modules(names=config.modules, skip=config.skip_modules,
                             quick=config.quick)
    if not modules:
        assessment.errors.append("no detection modules selected")
        assessment.finished_at = iso(utc_now())
        return assessment

    total = len(modules)
    for index, module in enumerate(modules, 1):
        if progress:
            progress(module.name, index, total)
        if logger:
            logger("info", f"running module {module.name} ({index}/{total})")
        result = module.run(ctx)
        assessment.module_results.append(result)
        if result.status is ModuleStatus.FAILED:
            assessment.errors.append(f"{module.name}: {result.reason}")

    all_findings: List[Finding] = []
    for result in assessment.module_results:
        capped = _cap_per_rule(result.findings, config.max_findings_per_rule)
        all_findings.extend(capped)

    assessment.findings = dedupe(all_findings)
    if not config.include_informational:
        assessment.findings = [f for f in assessment.findings
                               if f.severity is not Severity.INFO]
    assessment.incidents = correlate(assessment.findings)
    _assess_trust(assessment)

    assessment.finished_at = iso(utc_now())
    assessment.duration_seconds = round(time.monotonic() - started, 2)
    return assessment


def _cap_per_rule(findings: List[Finding], cap: int) -> List[Finding]:
    """Stop one noisy rule from flooding the report."""
    seen: Dict[str, int] = {}
    out: List[Finding] = []
    for finding in findings:
        count = seen.get(finding.rule_id, 0)
        if count >= cap:
            continue
        seen[finding.rule_id] = count + 1
        out.append(finding)
    return out


# Findings that mean local tooling itself may be lying.
TRUST_BREAKING_RULES = {
    "PERS-LD-PRELOAD": "a library is preloaded into every process on the host",
    "PERS-LD-CONF-WRITABLE": "the library search path includes a writable directory",
    "PKG-BINARY-MODIFIED": "packaged system binaries no longer match their package",
    "PROC-PS-DISCREPANCY": "`ps` and /proc disagree about which processes exist",
    "NET-PROC-TOOL-DISCREPANCY": "socket listing tools and /proc/net disagree",
    "PERS-KMOD-UNRESOLVED": "a loaded kernel module has no file on disk",
    "PROC-KTHREAD-MASQUERADE": "a userland process is disguised as a kernel thread",
}


def _assess_trust(assessment: Assessment) -> None:
    reasons = []
    for finding in assessment.findings:
        reason = TRUST_BREAKING_RULES.get(finding.rule_id)
        if reason and reason not in reasons:
            reasons.append(f"{finding.id}: {reason}")
    if reasons:
        assessment.integrity_warning = True
        assessment.integrity_reasons = reasons


def recommended_actions(assessment: Assessment, limit: int = 6) -> List[str]:
    """Short, ordered next steps derived from the findings actually present."""
    actions: List[str] = []
    by_rule: Dict[str, List[Finding]] = {}
    for finding in assessment.findings:
        by_rule.setdefault(finding.rule_id, []).append(finding)

    if assessment.integrity_warning:
        actions.append(
            "Treat results from this host as unreliable: evidence suggests local tooling "
            "may be subverted. Verify key findings against /proc directly and plan "
            "out-of-band confirmation."
        )

    priority = [
        ("ACCT-UID0-EXTRA", "Verify and lock the unauthorised UID 0 account(s); they are root-equivalent."),
        ("ACCT-EMPTY-PASSWORD", "Set or lock passwords on account(s) with an empty password field."),
        ("LOG-BRUTEFORCE-SUCCESS", "Rotate credentials for the account(s) reached by password guessing and review what those sessions did."),
        ("FS-SUID-SHELL", "Remove the SUID bit from shell-capable binaries; this is a direct root escalation."),
        ("PERS-LD-PRELOAD", "Capture and investigate /etc/ld.so.preload; this subverts every process on the host."),
        ("PROC-WEBSHELL-CHILD", "Locate the web shell: review web server logs and recently modified files under the document root."),
        ("SSH-AUTHORIZED-KEY", "Audit every authorized_keys entry; key access survives password rotation."),
        ("PERS-SYSTEMD-UNIT", "Inspect the flagged systemd unit(s) and their binaries before disabling them."),
        ("PERS-CRON-JOB", "Inspect the flagged cron job(s); a watchdog job will undo your other cleanup."),
        ("NET-SUSPICIOUS-LISTENER", "Attribute the suspicious listening port(s) to a process and capture the binary."),
        ("NET-SUSPICIOUS-OUTBOUND", "Record the outbound endpoint before blocking it; this looks like command and control."),
        ("ACCT-SUDO-RULE", "Review the permissive sudo rule(s) and validate sudoers with `visudo -c` after any change."),
        ("PKG-BINARY-MODIFIED", "Capture the modified system binaries; your investigation tools may be compromised."),
    ]
    for rule_id, text in priority:
        if rule_id in by_rule and len(actions) < limit:
            actions.append(text)

    if len(actions) < limit and not assessment.baseline_path:
        actions.append(
            "Once you have reviewed these findings, run `bulwark snap` so later "
            "runs can tell new activity from the state you have already examined."
        )
    if len(actions) < limit:
        actions.append(
            "Preserve the evidence directory before making changes, and record every "
            "remediation step with its time so you can reconstruct the round afterwards."
        )
    return actions[:limit]



# ============================================================================
# bulwark/baseline/create.py
# baseline capture   [renamed to avoid collisions: load_create]
# ============================================================================

# Baseline capture.
#
# A baseline is a record of selected system state so that a later run can
# distinguish "this was already here when I looked" from "this appeared since".
#
# It is not a statement that the recorded state is good. A baseline taken from a
# host that was compromised before you received it records the compromise as
# normal. That is why `bulwark snap` marks a baseline unvalidated
# until an operator explicitly confirms they have reviewed the findings, and why
# critical findings are never suppressed on the strength of a baseline match.
#
# Creation is read-only: it runs the same detection modules the audit does and
# keeps their structured facts.




# Which module facts are kept, and how each is keyed for comparison.
BASELINE_SECTIONS = {
    "accounts": "local accounts with uid, gid, shell and home",
    "groups": "group membership",
    "admin_members": "members of administrative groups",
    "sudoers_rules": "sudo policy rules",
    "ssh_authorized_keys": "authorized SSH key fingerprints per account",
    "sshd_config": "effective sshd settings",
    "systemd_units": "systemd units and their ExecStart commands",
    "cron_entries": "scheduled cron jobs",
    "listening_ports": "listening sockets and their owning executables",
    "critical_files": "hashes and metadata for security-relevant files",
    "suid_binaries": "SUID and SGID binaries",
    "kernel_modules": "loaded kernel modules",
    "firewall_backends": "firewall tooling and rule counts",
    "security_controls": "state of defensive controls",
    "mounts": "mounted filesystems and options",
    "package_count": "number of installed packages",
}


def create_baseline(config: Config, logger=None,
                    note: str = "", validated: bool = False) -> Dict[str, Any]:
    """Run a full read-only assessment and distil it into a baseline document."""
    capture_config = Config(**{**config.to_dict(), "quick": False,
                               "include_informational": True})
    assessment = run_audit(capture_config, logger=logger)
    facts = assessment.collect_facts()

    sections: Dict[str, Any] = {}
    for name in BASELINE_SECTIONS:
        value = facts.get(name)
        if value is None:
            continue
        sections[name] = {"items": _normalise(name, value)}

    document = {
        "schema_version": __schema_version__,
        "tool_version": __version__,
        "created_at_utc": iso(utc_now()),
        "note": note,
        "validated": bool(validated),
        "validation_warning": (
            "This baseline records the host as it was at capture time. If the host was "
            "already compromised, that compromise is recorded here as normal state. "
            "A baseline is only a trustworthy reference after an operator has reviewed "
            "the findings from the audit taken alongside it. Local storage cannot protect "
            "this file from an attacker with root on this host."
        ),
        "host": assessment.facts_dict(),
        "audit_summary": {
            "findings": assessment.counts,
            "max_severity": (assessment.max_severity.label
                             if assessment.max_severity else None),
            "modules": assessment.module_status_counts(),
        },
        "sections": sections,
    }
    document["integrity"] = {
        "sha256": _document_hash(document),
        "note": (
            "This hash detects accidental modification of the baseline file. It does not "
            "prove authenticity: anyone who can edit the file can recompute the hash. "
            "Keep a copy off the host if the baseline matters."
        ),
    }
    return document


def _normalise(section: str, value: Any) -> Any:
    """Shape each section into a dict keyed for comparison."""
    if section == "sudoers_rules" and isinstance(value, list):
        return {f"{r['file']}:{r['rule']}": r.get("line") for r in value
                if isinstance(r, dict) and "file" in r and "rule" in r}
    if section == "cron_entries" and isinstance(value, list):
        return {f"{e['file']}:{e['line']}": e.get("command") for e in value
                if isinstance(e, dict) and "file" in e and "line" in e}
    if section == "listening_ports" and isinstance(value, list):
        out = {}
        for sock in value:
            if not isinstance(sock, dict):
                continue
            local = sock.get("local", "")
            port = local.rsplit(":", 1)[-1] if ":" in local else local
            key = f"{sock.get('proto')}/{port}"
            out[key] = {"exe": sock.get("exe"),
                        "bind": local.rsplit(":", 1)[0] if ":" in local else None}
        return out
    if section == "systemd_units" and isinstance(value, dict):
        return {name: data.get("exec", "") if isinstance(data, dict) else data
                for name, data in value.items()}
    if section == "kernel_modules" and isinstance(value, list):
        return {name: True for name in value}
    if section == "firewall_backends" and isinstance(value, list):
        return {b.get("backend"): b.get("rule_count") for b in value
                if isinstance(b, dict)}
    if section == "mounts" and isinstance(value, list):
        return {m.get("mountpoint"): f"{m.get('fstype')} {m.get('options')}"
                for m in value if isinstance(m, dict) and m.get("mountpoint")}
    if section == "package_count":
        return {"count": value}
    if isinstance(value, list):
        return {str(item): True for item in value}
    return value


def _document_hash(document: Dict[str, Any]) -> str:
    payload = {k: v for k, v in document.items() if k != "integrity"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def save(document: Dict[str, Any], path: str) -> str:
    """Write the baseline with restrictive permissions, never overwriting
    silently: an existing file is rotated aside first."""
    path = os.path.abspath(path)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    if os.path.exists(path):
        stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = f"{path}.{stamp}.bak"
        os.replace(path, backup)
    # O_EXCL: the rotation above guarantees nothing is here, and failing loudly
    # is better than racing another run and losing a baseline.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        handle = os.fdopen(fd, "w", encoding="utf-8")
    except Exception:
        os.close(fd)      # fdopen did not take ownership, so close it here
        raise
    with handle as fh:    # from here the file object owns the descriptor
        json.dump(document, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.chmod(path, 0o600)
    return path


def load_create(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        document = json.load(fh)
    return document


def verify_integrity(document: Dict[str, Any]) -> Optional[str]:
    """Returns None when the recorded hash matches, else a description."""
    recorded = (document.get("integrity") or {}).get("sha256")
    if not recorded:
        return "the baseline has no recorded integrity hash"
    actual = _document_hash(document)
    if actual != recorded:
        return (f"baseline content hash does not match the value stored in the file "
                f"(recorded {recorded[:16]}..., computed {actual[:16]}...)")
    return None


def validate_marker(path: str, note: str = "") -> Dict[str, Any]:
    """Mark an existing baseline as reviewed by an operator."""
    document = load_create(path)
    document["validated"] = True
    document["validated_at_utc"] = iso(utc_now())
    if note:
        document["validation_note"] = note
    document["integrity"] = {
        "sha256": _document_hash(document),
        "note": (document.get("integrity") or {}).get("note", ""),
    }
    save(document, path)
    return document



# ============================================================================
# bulwark/baseline/compare.py
# baseline comparison
# ============================================================================

# Baseline comparison.
#
# Produces findings for what appeared, disappeared or changed since the baseline
# was taken. Severity depends on what the item is: a new UID 0 account is not the
# same kind of event as a new listening port on 8080.




MODULE = "baseline-compare"

# section -> (added severity, removed severity, changed severity, category, noun)
SECTION_RULES = {
    "accounts": (Severity.HIGH, Severity.MEDIUM, Severity.HIGH,
                 Category.ACCOUNT, "local account"),
    "admin_members": (Severity.HIGH, Severity.MEDIUM, Severity.HIGH,
                      Category.PRIVESC, "administrative group membership"),
    "sudoers_rules": (Severity.HIGH, Severity.MEDIUM, Severity.HIGH,
                      Category.PRIVESC, "sudo rule"),
    "ssh_authorized_keys": (Severity.HIGH, Severity.LOW, Severity.HIGH,
                            Category.REMOTE_ACCESS, "authorized SSH key set"),
    "sshd_config": (Severity.MEDIUM, Severity.MEDIUM, Severity.HIGH,
                    Category.REMOTE_ACCESS, "sshd setting"),
    "systemd_units": (Severity.HIGH, Severity.LOW, Severity.HIGH,
                      Category.PERSISTENCE, "systemd unit"),
    "cron_entries": (Severity.HIGH, Severity.LOW, Severity.HIGH,
                     Category.PERSISTENCE, "cron entry"),
    "listening_ports": (Severity.MEDIUM, Severity.LOW, Severity.MEDIUM,
                        Category.NETWORK, "listening port"),
    "critical_files": (Severity.MEDIUM, Severity.MEDIUM, Severity.HIGH,
                       Category.INTEGRITY, "security-relevant file"),
    "suid_binaries": (Severity.HIGH, Severity.LOW, Severity.HIGH,
                      Category.PRIVESC, "SUID/SGID binary"),
    "kernel_modules": (Severity.MEDIUM, Severity.LOW, Severity.MEDIUM,
                       Category.PERSISTENCE, "loaded kernel module"),
    "groups": (Severity.MEDIUM, Severity.LOW, Severity.MEDIUM,
               Category.ACCOUNT, "group"),
    "firewall_backends": (Severity.LOW, Severity.MEDIUM, Severity.MEDIUM,
                          Category.POSTURE, "firewall backend"),
    "mounts": (Severity.LOW, Severity.LOW, Severity.LOW,
               Category.POSTURE, "mount"),
}

# Keys matching these are never downgraded, however the baseline looks.
ALWAYS_CRITICAL_HINTS = ("uid0", "root", "/etc/shadow", "/etc/passwd", "/etc/sudoers")


def compare_baseline(assessment: Assessment, baseline: Dict[str, Any],
                     exclusions: Optional[List[str]] = None) -> List[Finding]:
    """Diff a fresh assessment against a saved baseline."""

    findings: List[Finding] = []
    exclusions = [e.strip() for e in (exclusions or []) if e.strip()]
    current_facts = assessment.collect_facts()
    sections = baseline.get("sections") or {}
    validated = bool(baseline.get("validated"))
    created = baseline.get("created_at_utc", "unknown time")

    for section, rules in SECTION_RULES.items():
        prior_section = sections.get(section)
        if prior_section is None:
            continue
        prior = prior_section.get("items", prior_section)
        if not isinstance(prior, dict):
            continue
        raw_current = current_facts.get(section)
        if raw_current is None:
            continue
        current = _normalise(section, raw_current)
        if not isinstance(current, dict):
            continue

        added_sev, removed_sev, changed_sev, category, noun = rules

        added = sorted(set(current) - set(prior))
        removed = sorted(set(prior) - set(current))
        changed = sorted(
            key for key in (set(current) & set(prior))
            if current[key] != prior[key]
        )

        added = [k for k in added if not _excluded(k, exclusions)]
        removed = [k for k in removed if not _excluded(k, exclusions)]
        changed = [k for k in changed if not _excluded(k, exclusions)]

        if added:
            findings.append(_finding(
                section, "ADDED", noun, category, added_sev, added, prior, current,
                created, validated,
                why=(
                    f"{len(added)} {noun}(s) are present now that were not in the baseline "
                    f"taken at {created}. A new item is the clearest signal a baseline "
                    f"provides: unless your team added it, something else did."
                ),
                recommendation=(
                    f"Confirm each addition against your team's change log. Anything you "
                    f"cannot attribute should be investigated with the relevant detection "
                    f"module before you remove it."
                ),
            ))
        if removed:
            findings.append(_finding(
                section, "REMOVED", noun, category, removed_sev, removed, prior, current,
                created, validated,
                why=(
                    f"{len(removed)} {noun}(s) in the baseline are no longer present. Items "
                    f"disappearing can mean your own cleanup, or an attacker removing "
                    f"evidence or disabling a control."
                ),
                recommendation="Confirm each removal was intentional.",
            ))
        if changed:
            findings.append(_finding(
                section, "CHANGED", noun, category, changed_sev, changed, prior, current,
                created, validated,
                why=(
                    f"{len(changed)} {noun}(s) differ from the baseline. The item exists in "
                    f"both snapshots but its content, command, hash or configuration has "
                    f"changed."
                ),
                recommendation=(
                    "Compare the before and after values below. Investigate anything you "
                    "did not change yourself."
                ),
            ))

    if not validated and findings:
        findings.append(make_finding(
            module=MODULE, rule_id="BASE-UNVALIDATED",
            title="Comparison used a baseline that has not been marked as validated",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            category=Category.INTEGRITY, target="baseline",
            why=(
                f"The baseline taken at {created} has not been marked validated, which means "
                f"nobody has confirmed that the state it records was reviewed and accepted. "
                f"Anything already present when the baseline was captured - including a "
                f"red-team foothold installed before your team received the host - therefore "
                f"appears here as 'unchanged' rather than as a finding."
            ),
            impact="Pre-existing compromise is invisible to this comparison.",
            recommendation=(
                "Work through the full audit findings, then run "
                "`bulwark validate` to record that you have accepted the state. "
                "Until then, rely on the audit rather than on the diff."
            ),
            evidence=[Evidence(source="derived", locator="baseline",
                               content=f"created_at_utc={created} validated=false")],
            tags=["baseline", "methodology"],
        ))
    return findings


def _excluded(key: str, exclusions: List[str]) -> bool:
    return any(pattern in key for pattern in exclusions)


def _finding(section: str, kind: str, noun: str, category: Category,
             severity: Severity, keys: List[str], prior: Dict, current: Dict,
             created: str, validated: bool, why: str, recommendation: str) -> Finding:
    detail_lines = []
    for key in keys[:40]:
        if kind == "ADDED":
            detail_lines.append(f"+ {key}: {_render(current.get(key))}")
        elif kind == "REMOVED":
            detail_lines.append(f"- {key}: {_render(prior.get(key))}")
        else:
            detail_lines.append(
                f"~ {key}\n    baseline: {_render(prior.get(key))}\n"
                f"    current:  {_render(current.get(key))}")

    # Escalate when either the key or the value names something root-equivalent.
    # A new account called "svcmon" looks unremarkable in the key alone; the
    # fact that it carries uid 0 lives in the value.
    searchable = " ".join(
        [" ".join(keys)]
        + [_render(current.get(k)) for k in keys[:40]]
        + [_render(prior.get(k)) for k in keys[:40]]
    ).lower()
    if (kind in ("ADDED", "CHANGED")
            and severity.rank >= Severity.HIGH.rank
            and (any(hint in searchable for hint in ALWAYS_CRITICAL_HINTS)
                 or re.search(r"\buid[=:\s]*0\b", searchable))):
        severity = Severity.CRITICAL

    state = {"ADDED": BaselineState.NEW, "REMOVED": BaselineState.CHANGED,
             "CHANGED": BaselineState.CHANGED}[kind]

    return make_finding(
        module=MODULE,
        rule_id=f"BASE-{section.upper().replace('_', '-')}-{kind}",
        title=f"{len(keys)} {noun}(s) {kind.lower()} since the baseline",
        severity=severity,
        confidence=Confidence.HIGH if validated else Confidence.MEDIUM,
        category=category,
        target=f"baseline:{section}:{kind.lower()}",
        why=why + ("" if validated else
                   " The baseline is not marked validated, so confidence is reduced."),
        impact=f"The host's {noun} inventory differs from the recorded reference.",
        recommendation=recommendation,
        evidence=[Evidence(
            source="derived", locator=f"baseline section '{section}'",
            content="\n".join(detail_lines),
            truncated=len(keys) > 40,
            meta={"total": len(keys), "baseline_created_at_utc": created,
                  "baseline_validated": validated})],
        tags=["baseline", "diff", section],
        baseline_state=state,
    )


def _render(value: Any) -> str:
    if value is None:
        return "(absent)"
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in sorted(value.items()))[:300]
    return str(value)[:300]



# ============================================================================
# bulwark/baseline/__init__.py
# baseline package exports
# ============================================================================

# Baseline creation and comparison.



# ============================================================================
# bulwark/reporting/json_report.py
# reporting: structured JSON   [renamed to avoid collisions: build_json_report, write_json_report]
# ============================================================================

# Structured JSON report.
#
# Schema (version 1.0)
# --------------------
# {
#   "schema_version": str,          # report format version
#   "tool": {"name","version"},
#   "assessment": {
#       "status": str,              # human label
#       "exit_code": int,
#       "started_at_utc": str,      # all machine-readable times are UTC with Z
#       "finished_at_utc": str,
#       "duration_seconds": float,
#       "local_timezone": str,      # the host's local zone, recorded for context
#       "quick_mode": bool
#   },
#   "host": {...},                  # identity and capability facts
#   "configuration": {...},         # the options this run used
#   "integrity_warning": {          # present when local tooling may be subverted
#       "triggered": bool, "reasons": [str]
#   },
#   "summary": {
#       "counts_by_severity": {...},
#       "max_severity": str|null,
#       "total_findings": int,
#       "modules": {"ok":n,...},
#       "recommended_actions": [str]
#   },
#   "modules": [ {name,version,status,reason,checks_run,duration_ms,
#                 finding_ids,gaps} ],
#   "visibility_gaps": [ {area,reason,impact,needs_root} ],
#   "incidents": [ {key,title,severity,finding_ids} ],
#   "findings": [ Finding ],        # see models.Finding.to_dict
#   "evidence_integrity": {...}     # hashes of the files written by this run
# }
#
# All timestamps in this document are UTC. The host's local timezone is recorded
# once, under assessment.local_timezone.




REPORT_SCHEMA_VERSION = "1.0"


def build_json_report(assessment: Assessment,
          baseline_findings: Optional[List] = None) -> Dict[str, Any]:
    findings = list(assessment.findings)
    if baseline_findings:
        findings = findings + list(baseline_findings)
        findings.sort(key=lambda f: f.sort_key())

    facts = assessment.facts_dict()
    config = assessment.config.to_dict() if assessment.config else {}

    document: Dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": {
            "name": TOOL_NAME,
            "version": assessment.tool_version,
            "model_schema_version": assessment.schema_version,
        },
        "assessment": {
            "status": assessment.status_label(),
            "exit_code": assessment.exit_code(),
            "started_at_utc": assessment.started_at,
            "finished_at_utc": assessment.finished_at,
            "duration_seconds": assessment.duration_seconds,
            "local_timezone": facts.get("local_timezone", ""),
            "quick_mode": bool(config.get("quick")),
            "baseline_path": assessment.baseline_path,
            "baseline_created_at_utc": assessment.baseline_created_at,
        },
        "host": facts,
        "configuration": config,
        "integrity_warning": {
            "triggered": assessment.integrity_warning,
            "reasons": assessment.integrity_reasons,
            "note": (
                "When triggered, evidence collected on this host - including this report - "
                "may have been produced by subverted tooling. Confirm critical findings from "
                "a known-good environment or external media."
            ) if assessment.integrity_warning else "",
        },
        "summary": {
            "counts_by_severity": severity_counts(findings),
            "max_severity": _max_severity(findings),
            "total_findings": len(findings),
            "modules": assessment.module_status_counts(),
            "recommended_actions": recommended_actions(assessment),
            "errors": assessment.errors,
        },
        "modules": [m.to_dict() for m in assessment.module_results],
        "visibility_gaps": [g.to_dict() for g in assessment.gaps],
        "incidents": [i.to_dict() for i in assessment.incidents],
        "findings": [f.to_dict() for f in findings],
        "notes": {
            "read_only": (
                "This assessment made no changes to the system: no process was signalled, "
                "no file discovered during the audit was executed, no service, account, "
                "permission or firewall rule was modified."
            ),
            "hash_meaning": (
                "Hashes recorded here detect change between runs. They were computed on the "
                "host under assessment, so they cannot establish that a file is legitimate - "
                "only that it matches what this host reported at this time."
            ),
            "clean_result": (
                "An assessment that produces no findings does not prove the host is "
                "uncompromised. Read visibility_gaps to see what could not be examined."
            ),
        },
    }
    return document



def _max_severity(findings) -> Optional[str]:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: s.rank).label


def write_json_report(document: Dict[str, Any], path: str) -> str:
    """Write the report with restrictive permissions. Reports can contain
    sensitive system detail, so they are not world-readable."""
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=False)
        fh.write("\n")
    os.chmod(path, 0o600)
    return path


def file_hash(path: str) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(262144), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def append_evidence_integrity(path: str, files: Dict[str, str]) -> None:
    """Record hashes of the completed evidence files inside the JSON report."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            document = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return
    document["evidence_integrity"] = {
        "files": files,
        "note": (
            "These hashes detect accidental modification of the evidence files after the "
            "run. They were generated on the host under assessment and do not establish "
            "authenticity: anyone with root here could regenerate both the files and these "
            "hashes. Copy the evidence directory off the host to preserve it."
        ),
    }
    write_json_report(document, path)



# ============================================================================
# bulwark/reporting/markdown_report.py
# reporting: Markdown   [renamed to avoid collisions: build_markdown_report, write_markdown_report]
# ============================================================================

# Human-readable Markdown report.
#
# Written for a teammate who did not write_markdown_report the tool and is reading under time
# pressure: status first, then what to do, then the evidence behind each finding.




SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                  Severity.LOW, Severity.INFO]

SEVERITY_MEANING = {
    Severity.CRITICAL: "Strong evidence of root-level compromise or a credible malicious persistence mechanism. Act now.",
    Severity.HIGH: "Strong evidence of unauthorised privileged access, risky remote access, or a mechanism capable of maintaining access.",
    Severity.MEDIUM: "Suspicious, with meaningful but incomplete evidence. Investigate when the critical items are handled.",
    Severity.LOW: "A weakness or anomaly that deserves review but is not urgent.",
    Severity.INFO: "Context and inventory. Not a problem in itself.",
}


def build_markdown_report(assessment: Assessment, baseline_findings: Optional[List[Finding]] = None) -> str:
    findings = list(assessment.findings)
    if baseline_findings:
        findings = findings + list(baseline_findings)
        findings.sort(key=lambda f: f.sort_key())

    facts = assessment.facts_dict()
    out: List[str] = []
    w = out.append

    w(f"# Bulwark assessment - {facts.get('hostname', 'unknown host')}")
    w("")
    w(f"**Status: {assessment.status_label()}**")
    w("")
    w("| | |")
    w("|---|---|")
    w(f"| Host | `{facts.get('hostname','?')}` ({facts.get('fqdn','') or 'no FQDN'}) |")
    w(f"| Operating system | {facts.get('os_name','?')} {facts.get('os_version','')} |")
    w(f"| Kernel / arch | {facts.get('kernel','?')} / {facts.get('architecture','?')} |")
    w(f"| Init / packages | {facts.get('init_system','?')} / {facts.get('package_manager','?')} |")
    w(f"| Started (UTC) | {assessment.started_at} |")
    w(f"| Finished (UTC) | {assessment.finished_at} |")
    w(f"| Duration | {assessment.duration_seconds}s |")
    w(f"| Run as | {facts.get('user','?')} (uid {facts.get('euid','?')}"
      f"{', root' if facts.get('is_root') else ', not root'}) |")
    w(f"| Local timezone | {facts.get('local_timezone','?')} |")
    w(f"| Mode | {'quick' if (assessment.config and assessment.config.quick) else 'full'} |")
    if assessment.baseline_path:
        w(f"| Baseline | `{assessment.baseline_path}` taken {assessment.baseline_created_at} |")
    else:
        w("| Baseline | none - findings cannot be classified as new or pre-existing |")
    w(f"| Tool version | {assessment.tool_version} |")
    w("")

    if assessment.integrity_warning:
        w("> ## Results from this host may be unreliable")
        w("> ")
        w("> Evidence suggests that tooling on this host may have been subverted, which")
        w("> means this report was produced using sources that could be lying:")
        w("> ")
        for reason in assessment.integrity_reasons:
            w(f"> - {reason}")
        w("> ")
        w("> Confirm the critical findings against `/proc` directly, and arrange")
        w("> verification from a known-good environment or external media before you")
        w("> conclude the host is clean.")
        w("")

    counts = severity_counts(findings)
    w("## Findings by severity")
    w("")
    w("| Severity | Count | What it means |")
    w("|---|---:|---|")
    for severity in SEVERITY_ORDER:
        w(f"| {severity.label.capitalize()} | {counts[severity.label]} | {SEVERITY_MEANING[severity]} |")
    w("")
    w("Severity and confidence are independent. A critical finding with low confidence "
      "means the consequence would be severe *if* the evidence holds up - verify it "
      "before acting.")
    w("")

    actions = recommended_actions(assessment)
    if actions:
        w("## Recommended next actions")
        w("")
        for i, action in enumerate(actions, 1):
            w(f"{i}. {action}")
        w("")

    if assessment.incidents:
        w("## Correlated incidents")
        w("")
        w("Several findings point at the same underlying activity:")
        w("")
        for incident in assessment.incidents:
            w(f"- **{incident.title}** ({incident.severity.label}) - "
              f"{', '.join(incident.finding_ids)}")
        w("")

    gaps = assessment.gaps
    if gaps:
        w("## Visibility gaps")
        w("")
        w("These are the things this assessment could **not** examine. A finding cannot "
          "come from an area that could not be read, so treat each gap as unknown rather "
          "than clear.")
        w("")
        w("| Area | Reason | Consequence | Root needed |")
        w("|---|---|---|---|")
        for gap in gaps:
            w(f"| `{gap.area}` | {gap.reason} | {gap.impact or '-'} | "
              f"{'yes' if gap.needs_root else 'no'} |")
        w("")

    w("## Module execution")
    w("")
    w("| Module | Version | Status | Checks | Findings | Duration | Note |")
    w("|---|---|---|---:|---:|---:|---|")
    for result in assessment.module_results:
        w(f"| {result.name} | {result.version} | {result.status.value} | "
          f"{result.checks_run} | {len(result.findings)} | {result.duration_ms}ms | "
          f"{result.reason or '-'} |")
    w("")

    if findings:
        w("## Findings")
        w("")
        for severity in SEVERITY_ORDER:
            group = [f for f in findings if f.severity is severity]
            if not group:
                continue
            w(f"### {severity.label.capitalize()} ({len(group)})")
            w("")
            for finding in group:
                _render_finding(w, finding)
    else:
        w("## Findings")
        w("")
        w("No findings were produced.")
        w("")

    w("---")
    w("")
    w("## How to read this report")
    w("")
    w("- **A clean report does not prove the host is uncompromised.** This is a "
      "host-based tool running on the system it is assessing. A sufficiently "
      "privileged attacker can hide from it, and the visibility gaps above list what "
      "was never examined at all.")
    w("- **Hashes recorded here detect change, not legitimacy.** They were computed on "
      "this host. Compare against package metadata or a known-good image for real "
      "verification.")
    w("- **Timestamps are supporting evidence.** Anyone with root can set a file's "
      "modification time to anything.")
    w("- **Nothing was changed and nothing discovered was executed.** This release is "
      "read-only by design.")
    w("")
    return "\n".join(out) + "\n"


def _render_finding(w, finding: Finding) -> None:
    w(f"#### `{finding.id}` {finding.title}")
    w("")
    w(f"- **Severity:** {finding.severity.label} | **Confidence:** "
      f"{finding.confidence.label} | **Category:** {finding.category.value}")
    w(f"- **Affected:** `{finding.target}`")
    w(f"- **Relative to baseline:** {finding.baseline_state.value}")
    if finding.partial_evidence:
        w("- **Note:** based on incomplete evidence")
    if finding.tags:
        w(f"- **Tags:** {', '.join(sorted(set(finding.tags)))}")
    w("")
    w(f"**Why this matters.** {finding.why}")
    w("")
    if finding.impact:
        w(f"**Potential impact.** {finding.impact}")
        w("")
    if finding.recommendation:
        w(f"**Recommended next step.** {finding.recommendation}")
        w("")
    if finding.remediation_risk:
        w(f"**Operational risk of remediation.** {finding.remediation_risk}")
        w("")
    stamps = {k: v for k, v in (finding.timestamps or {}).items() if v}
    if stamps:
        w("**Timestamps (UTC).** " + ", ".join(f"{k} = {v}" for k, v in stamps.items()))
        w("")
    if finding.evidence:
        w("<details><summary>Evidence</summary>")
        w("")
        for item in finding.evidence:
            w(f"*Source:* `{item.source}` | *Locator:* `{item.locator}`"
              + (f" | *Error:* {item.error}" if item.error else "")
              + (" | truncated" if item.truncated else ""))
            if item.meta:
                meta = ", ".join(f"{k}={v}" for k, v in item.meta.items()
                                 if k not in ("note",) and v not in (None, ""))
                if meta:
                    w(f"*Metadata:* {meta}")
                if item.meta.get("note"):
                    w(f"*Note:* {item.meta['note']}")
            if item.content:
                w("")
                w("```")
                w(item.content)
                w("```")
            w("")
        w("</details>")
        w("")



def write_markdown_report(markdown: str, path: str) -> str:
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(markdown)
    os.chmod(path, 0o600)
    return path



# ============================================================================
# bulwark/reporting/terminal.py
# reporting: terminal summary
# ============================================================================

# Terminal summary.
#
# The first thing an operator sees. Kept to roughly one screen: status, the
# highest-priority findings, what to do next, and what could not be seen.




RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
COLORS = {
    Severity.CRITICAL: "\033[1;37;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}


class Printer:
    def __init__(self, stream: Optional[TextIO] = None, no_color: bool = False,
                 force_color: bool = False):
        self.stream = stream or sys.stdout
        self.color = self._color_enabled(no_color, force_color)
        self.width = min(shutil.get_terminal_size((100, 24)).columns, 100)

    def _color_enabled(self, no_color: bool, force_color: bool = False) -> bool:
        if no_color or os.environ.get("NO_COLOR"):
            return False
        # When output goes through a pager the stream is a pipe, not a
        # terminal, so isatty() says no even though a person is reading it on
        # a screen. The caller knows better and says so with force_color.
        if force_color:
            return True
        return hasattr(self.stream, "isatty") and self.stream.isatty()

    def c(self, text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def line(self, text: str = "") -> None:
        self.stream.write(text + "\n")

    def rule(self, char: str = "-") -> None:
        self.line(char * self.width)

    def wrap(self, text: str, indent: int = 0, width: Optional[int] = None) -> None:
        import textwrap
        width = width or self.width
        prefix = " " * indent
        for para in text.split("\n"):
            if not para.strip():
                self.line()
                continue
            for wrapped in textwrap.wrap(para, width=max(30, width - indent),
                                         initial_indent=prefix,
                                         subsequent_indent=prefix):
                self.line(wrapped)


def render(assessment: Assessment, printer: Optional[Printer] = None,
           baseline_findings: Optional[List[Finding]] = None,
           top_n: int = 10, verbosity: int = 0) -> None:
    p = printer or Printer()
    findings = list(assessment.findings)
    if baseline_findings:
        findings = findings + list(baseline_findings)
        findings.sort(key=lambda f: f.sort_key())
    facts = assessment.facts_dict()

    p.line()
    p.rule("=")
    p.line(p.c(f" BULWARK ASSESSMENT  -  {facts.get('hostname','unknown')}", BOLD))
    p.rule("=")

    status = assessment.status_label()
    status_color = {
        "ACTION REQUIRED": COLORS[Severity.CRITICAL],
        "REVIEW NEEDED": COLORS[Severity.MEDIUM],
        "FAILED": COLORS[Severity.HIGH],
    }.get(status, "\033[1;32m")
    p.line(f" Status      : {p.c(' ' + status + ' ', status_color)}")
    p.line(f" System      : {facts.get('os_name','?')} {facts.get('os_version','')}"
           f"  kernel {facts.get('kernel','?')}  {facts.get('architecture','')}")
    p.line(f" Privileges  : {facts.get('user','?')} (uid {facts.get('euid','?')})"
           f"{'  [root]' if facts.get('is_root') else '  [not root - some checks limited]'}")
    p.line(f" Window      : {assessment.started_at} -> {assessment.finished_at}"
           f"  ({assessment.duration_seconds}s)")
    mode = "quick" if (assessment.config and assessment.config.quick) else "full"
    p.line(f" Mode        : {mode}"
           + (f"   Baseline: {assessment.baseline_path}" if assessment.baseline_path
              else "   Baseline: none"))
    if assessment.incident_dir:
        p.line(f" Evidence    : {assessment.incident_dir}")
    p.line()

    if assessment.integrity_warning:
        p.line(p.c(" !! RESULTS FROM THIS HOST MAY BE UNRELIABLE !!",
                   COLORS[Severity.CRITICAL]))
        for reason in assessment.integrity_reasons:
            p.wrap(f"- {reason}", indent=4)
        p.wrap("Local tooling may be subverted. Verify critical findings against /proc "
               "directly and arrange out-of-band confirmation.", indent=4)
        p.line()

    counts = severity_counts(findings)
    parts = []
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                     Severity.LOW, Severity.INFO):
        count = counts[severity.label]
        label = f"{severity.label}={count}"
        parts.append(p.c(label, COLORS[severity]) if count else p.c(label, DIM))
    p.line(" Findings    : " + "  ".join(parts))

    statuses = assessment.module_status_counts()
    p.line(" Modules     : " + "  ".join(f"{k}={v}" for k, v in sorted(statuses.items())))
    gaps = assessment.gaps
    p.line(f" Gaps        : {len(gaps)} area(s) could not be fully examined")
    p.line()

    actionable = [f for f in findings if f.severity.rank >= Severity.LOW.rank]
    if actionable:
        p.rule()
        p.line(p.c(f" HIGHEST PRIORITY FINDINGS (showing {min(top_n, len(actionable))} "
                   f"of {len(actionable)})", BOLD))
        p.rule()
        for finding in actionable[:top_n]:
            badge = p.c(f" {finding.severity.label.upper():8}", COLORS[finding.severity])
            p.line(f"{badge} {p.c(finding.id, BOLD)}  conf={finding.confidence.label}"
                   f"  [{finding.category.value}]")
            p.wrap(finding.title, indent=10)
            p.wrap(f"target: {finding.target}", indent=10)
            if verbosity >= 1:
                p.wrap(f"why: {finding.why}", indent=10)
                if finding.recommendation:
                    p.wrap(f"next: {finding.recommendation}", indent=10)
            p.line()
        if len(actionable) > top_n:
            p.line(p.c(f"   ... {len(actionable) - top_n} more finding(s) in the full report.",
                       DIM))
            p.line()
    else:
        p.rule()
        p.line(p.c(" No findings above informational.", BOLD))
        p.wrap("This does not mean the host is clean. It means nothing matched the "
               "checks that ran, within the evidence that was readable. Read the "
               "visibility gaps below.", indent=1)
        p.line()

    if assessment.incidents:
        p.rule()
        p.line(p.c(" CORRELATED INCIDENTS", BOLD))
        p.rule()
        for incident in assessment.incidents[:6]:
            p.wrap(f"- [{incident.severity.label}] {incident.title}", indent=1)
            p.wrap(f"  {', '.join(incident.finding_ids)}", indent=3)
        p.line()

    actions = recommended_actions(assessment)
    if actions:
        p.rule()
        p.line(p.c(" RECOMMENDED NEXT ACTIONS", BOLD))
        p.rule()
        for i, action in enumerate(actions, 1):
            p.wrap(f"{i}. {action}", indent=1)
        p.line()

    if gaps:
        p.rule()
        p.line(p.c(" VISIBILITY GAPS - these areas were not fully examined", BOLD))
        p.rule()
        shown = gaps[:8]
        for gap in shown:
            marker = " (needs root)" if gap.needs_root else ""
            p.wrap(f"- {gap.area}: {gap.reason}{marker}", indent=1)
        if len(gaps) > len(shown):
            p.line(p.c(f"   ... {len(gaps) - len(shown)} more in the full report.", DIM))
        p.line()

    if assessment.errors:
        p.rule()
        p.line(p.c(" MODULE ERRORS", BOLD))
        p.rule()
        for error in assessment.errors[:10]:
            p.wrap(f"- {error}", indent=1)
        p.line()

    p.rule("=")
    p.wrap("A completed assessment is not a clean bill of health. This tool runs on the "
           "host it is assessing; an attacker with root can hide from it. Use the "
           "evidence, not the absence of findings.", indent=1)
    p.rule("=")
    p.line()


# --------------------------------------------------------------------------
# Pager
# --------------------------------------------------------------------------

DEFAULT_PAGERS = ("less", "more")

# Program names acceptable as a pager. Anything else named by the environment
# is refused: see pager_command for why that matters in this tool.
ALLOWED_PAGERS = frozenset({"less", "more", "most", "pg", "cat"})

# Flags applied only when this tool picked `less` itself and the operator has
# not set LESS. A person who exported their own LESS or PAGER gets exactly
# what they asked for.
#   F  quit immediately if the output fits on one screen
#   R  pass ANSI colour through instead of printing escape codes
#   X  do not clear the screen on exit, so the report stays visible
LESS_DEFAULT_FLAGS = "FRX"


def pager_command(explicit: Optional[str] = None) -> Optional[List[str]]:
    """Which pager to use, or None to write straight to the terminal.

    Order: an explicit choice, then $BULWARK_PAGER, then $PAGER, then less,
    then more. A pager set to "cat" or "" is how a person turns paging off
    through the environment, and that is honoured.

    The program name is checked against ALLOWED_PAGERS, and anything else is
    ignored rather than run. This matters more here than in an ordinary CLI:
    Bulwark runs as root on a host its operator suspects is compromised, and
    an attacker who can write to a profile script can set PAGER. Without this
    check, `PAGER=/tmp/payload` would get root the next time an admin paged
    anything - which is precisely the shell-initialisation tampering the
    persistence module exists to find. Honouring an arbitrary environment
    variable would make this tool the escalation path.
    """
    for candidate in (explicit, os.environ.get("BULWARK_PAGER"),
                      os.environ.get("PAGER")):
        if candidate is None:
            continue
        candidate = candidate.strip()
        if not candidate or candidate == "cat":
            return None
        try:
            argv = shlex.split(candidate)
        except ValueError:
            continue              # unbalanced quotes; treat as unset
        if not argv:
            continue
        program = os.path.basename(argv[0])
        if program not in ALLOWED_PAGERS:
            sys.stderr.write(
                f"warning: ignoring pager {argv[0]!r}: not one of "
                f"{', '.join(sorted(ALLOWED_PAGERS))}. Bulwark runs as root "
                f"and will not execute an arbitrary program named by the "
                f"environment.\n")
            continue
        resolved = shutil.which(argv[0]) if "/" not in argv[0] else argv[0]
        if not resolved or not os.access(resolved, os.X_OK):
            continue
        return [resolved] + argv[1:]
    for name in DEFAULT_PAGERS:
        found = shutil.which(name)
        if found:
            return [found]
    return None


@contextlib.contextmanager
def paged_output(enabled: bool = True, explicit: Optional[str] = None,
                 stream: Optional[TextIO] = None):
    """Yield (stream_to_write_to, force_color).

    Pages only when it makes sense: paging is skipped when the destination is
    not a terminal, so piping into a file, grep or a script behaves exactly as
    before and nothing hangs waiting for a keypress in cron.

    The caller's exit code is never touched. If the reader quits the pager
    early the resulting broken pipe is swallowed, because quitting a pager is
    a normal thing to do and not an error in the assessment.
    """
    target = stream or sys.stdout
    is_tty = hasattr(target, "isatty") and target.isatty()
    command = pager_command(explicit) if (enabled and is_tty) else None

    if command is None:
        yield target, False
        return

    environment = dict(os.environ)
    if os.path.basename(command[0]) == "less":
        if "LESS" not in environment:
            environment["LESS"] = LESS_DEFAULT_FLAGS
        # Refuse shell escapes from inside the pager: an operator reading a
        # report as root should not be one `!` away from executing something.
        environment["LESSSECURE"] = "1"

    try:
        process = subprocess.Popen(  # noqa: S603 - argv list, shell=False
            command, stdin=subprocess.PIPE, env=environment,
            universal_newlines=True, shell=False)
    except (OSError, ValueError):
        # No usable pager after all; the report matters more than the paging.
        yield target, is_tty
        return

    try:
        yield process.stdin, is_tty
    except BrokenPipeError:
        pass
    finally:
        try:
            if process.stdin:
                process.stdin.close()
        except BrokenPipeError:
            pass
        except OSError:
            pass
        try:
            process.wait()
        except KeyboardInterrupt:
            # Ctrl-C while reading belongs to the pager, not to us.
            pass



# ============================================================================
# bulwark/reporting/__init__.py
# reporting package exports
# ============================================================================

# Report generation: JSON, Markdown and terminal.



# ============================================================================
# bulwark/investigate.py
# deeper evidence collection
# ============================================================================

# Deeper, still read-only, evidence collection for a single finding.
#
# `bulwark look ID` re-opens the sources behind a stored finding
# and gathers more context than the audit records by default: fuller file
# contents, current process state, directory listings, related findings.
#
# Nothing here executes a discovered file, and nothing is modified.




MAX_EXTRA_CHARS = 8000


def investigate_finding(document: Dict[str, Any], finding_id: str,
                        root: str, printer: Printer,
                        incident_dir: str) -> int:
    findings = document.get("findings", [])
    match = _find(findings, finding_id)
    if match is None:
        printer.line(f"No finding with ID '{finding_id}' in {incident_dir}.")
        printer.line()
        _suggest(findings, printer)
        return EXIT_USAGE

    _print_stored(match, printer)

    host = Host(root=root)
    printer.rule("=")
    printer.line(printer.c(" ADDITIONAL READ-ONLY EVIDENCE COLLECTED NOW", BOLD))
    printer.rule("=")
    printer.wrap(
        "Collected at investigation time, so it reflects the host's current state "
        "rather than the state during the audit. Differences between the two are "
        "themselves worth noting.", indent=1)
    printer.line()

    collected = False
    for path in _paths_from(match):
        collected |= _investigate_path(host, path, printer)
    for pid in _pids_from(match):
        collected |= _investigate_pid(host, pid, printer)
    for account in _accounts_from(match):
        collected |= _investigate_account(host, account, printer)
    for port in _ports_from(match):
        collected |= _investigate_port(host, port, printer)

    if not collected:
        printer.wrap("No additional automated collection applies to this finding type. "
                     "Use the evidence recorded in the report above as your starting "
                     "point.", indent=1)
        printer.line()

    related = _related(findings, match)
    if related:
        printer.rule("=")
        printer.line(printer.c(" RELATED FINDINGS", BOLD))
        printer.rule("=")
        printer.wrap("These share a correlation key or target with this finding, which "
                     "usually means they describe one incident rather than several.",
                     indent=1)
        printer.line()
        for item in related:
            severity = Severity.from_label(item["severity"])
            badge = printer.c(f" {severity.label.upper():8}", COLORS[severity])
            printer.line(f"{badge} {item['id']}  {item['title']}")
        printer.line()

    return EXIT_CLEAN


# --------------------------------------------------------------------- lookup

def _find(findings: List[Dict], finding_id: str) -> Optional[Dict]:
    wanted = finding_id.strip().upper()
    for finding in findings:
        if finding.get("id", "").upper() == wanted:
            return finding
    # Allow the short hash suffix alone.
    for finding in findings:
        if finding.get("id", "").upper().endswith(wanted):
            return finding
    return None


def _suggest(findings: List[Dict], printer: Printer) -> None:
    actionable = [f for f in findings if f.get("severity") != "info"][:15]
    if not actionable:
        printer.line("This assessment recorded no non-informational findings.")
        return
    printer.line("Available finding IDs (highest severity first):")
    printer.line()
    for finding in actionable:
        printer.line(f"   {finding['id']}  [{finding['severity']:<8}] {finding['title'][:70]}")
    printer.line()


def _print_stored(finding: Dict, printer: Printer) -> None:
    severity = Severity.from_label(finding["severity"])
    printer.line()
    printer.rule("=")
    printer.line(printer.c(f" {finding['id']}  {finding['title']}", BOLD))
    printer.rule("=")
    printer.line(f" Severity      : {printer.c(severity.label, COLORS[severity])}")
    printer.line(f" Confidence    : {finding['confidence']}")
    printer.line(f" Category      : {finding['category']}")
    printer.line(f" Module / rule : {finding['module']} / {finding['rule_id']}")
    printer.line(f" Target        : {finding['target']}")
    printer.line(f" Baseline      : {finding['baseline_state']}")
    if finding.get("tags"):
        printer.line(f" Tags          : {', '.join(finding['tags'])}")
    if finding.get("partial_evidence"):
        printer.line(" Evidence      : incomplete - treat conclusions with care")
    printer.line()
    printer.line(printer.c(" WHY THIS MATTERS", BOLD))
    printer.wrap(finding.get("why", ""), indent=1)
    printer.line()
    if finding.get("impact"):
        printer.line(printer.c(" POTENTIAL IMPACT", BOLD))
        printer.wrap(finding["impact"], indent=1)
        printer.line()
    if finding.get("recommendation"):
        printer.line(printer.c(" RECOMMENDED NEXT STEP", BOLD))
        printer.wrap(finding["recommendation"], indent=1)
        printer.line()
    if finding.get("remediation_risk"):
        printer.line(printer.c(" OPERATIONAL RISK OF REMEDIATION", BOLD))
        printer.wrap(finding["remediation_risk"], indent=1)
        printer.line()
    stamps = {k: v for k, v in (finding.get("timestamps") or {}).items() if v}
    if stamps:
        printer.line(printer.c(" TIMESTAMPS (UTC)", BOLD))
        for key, value in stamps.items():
            printer.line(f"   {key}: {value}")
        printer.line()
    if finding.get("evidence"):
        printer.line(printer.c(" EVIDENCE RECORDED DURING THE AUDIT", BOLD))
        for item in finding["evidence"]:
            printer.line(f"   source={item.get('source')} locator={item.get('locator')}"
                         + (f" error={item['error']}" if item.get("error") else "")
                         + (" [truncated]" if item.get("truncated") else ""))
            meta = item.get("meta") or {}
            if meta.get("note"):
                printer.wrap(f"note: {meta['note']}", indent=6)
            content = item.get("content") or ""
            for line in content.splitlines()[:40]:
                printer.line("      | " + line[:200])
            printer.line()


# ------------------------------------------------------------ target parsing

def _paths_from(finding: Dict) -> List[str]:
    paths: List[str] = []
    target = finding.get("target", "")
    if target.startswith("path:"):
        paths.append(target[5:])
    elif target.startswith("/"):
        paths.append(target.split("#")[0].split(":")[0]
                     if re.search(r":\d+$", target) else target.split("#")[0])
    for item in finding.get("evidence", []):
        locator = item.get("locator", "")
        if locator.startswith("/") and not locator.startswith("/proc/"):
            clean = locator.split("#")[0]
            if clean not in paths:
                paths.append(clean)
    return paths[:6]


def _pids_from(finding: Dict) -> List[int]:
    pids = []
    match = re.match(r"^pid:(\d+)", finding.get("target", ""))
    if match:
        pids.append(int(match.group(1)))
    for item in finding.get("evidence", []):
        meta = item.get("meta") or {}
        if isinstance(meta.get("pid"), int):
            pids.append(meta["pid"])
        m = re.match(r"^/proc/(\d+)", item.get("locator", ""))
        if m:
            pids.append(int(m.group(1)))
    return sorted(set(pids))[:5]


def _accounts_from(finding: Dict) -> List[str]:
    accounts = []
    target = finding.get("target", "")
    match = re.match(r"^user:([^|]+)", target)
    if match:
        accounts.append(match.group(1))
    key = finding.get("correlation_key") or ""
    if key.startswith("account:"):
        accounts.append(key.split(":", 1)[1])
    return sorted(set(accounts))[:3]


def _ports_from(finding: Dict) -> List[str]:
    ports = []
    match = re.match(r"^(tcp6?|udp6?)/(\d+)$", finding.get("target", ""))
    if match:
        ports.append(finding["target"])
    return ports


# --------------------------------------------------------------- collection

def _investigate_path(host: Host, path: str, printer: Printer) -> bool:
    info = host.stat(path, hash_file=True)
    printer.line(printer.c(f" PATH  {path}", BOLD))
    if not info.exists:
        printer.wrap("does not exist now. If the audit saw it, it has been removed "
                     "since - which is itself worth recording.", indent=4)
        printer.line()
        return True
    printer.line(f"    mode={info.mode_octal} owner={info.owner}:{info.group} "
                 f"size={info.size} links={info.nlink}")
    printer.line(f"    mtime={iso_from_epoch(info.mtime)}  "
                 f"ctime={iso_from_epoch(info.ctime)}  "
                 f"atime={iso_from_epoch(info.atime)}")
    if info.sha256:
        printer.line(f"    sha256={info.sha256}")
    if info.is_symlink:
        printer.line(f"    symlink -> {info.symlink_target}")
    if info.setuid or info.setgid:
        printer.line(printer.c("    SETUID/SETGID bit is set", COLORS[Severity.HIGH]))

    if info.is_dir:
        names, err = host.listdir(path)
        if err:
            printer.line(f"    listing failed: {err}")
        else:
            printer.line(f"    {len(names)} entries:")
            for name in names[:40]:
                child = host.stat(os.path.join(path, name))
                printer.line(f"      {child.mode_octal or '?':<5} "
                             f"{(child.owner or '?'):<10} "
                             f"{iso_from_epoch(child.mtime) or '?':<21} {name}")
    elif info.is_file:
        text, truncated, err = host.read_text(path, max_bytes=MAX_EXTRA_CHARS * 2)
        if err:
            printer.line(f"    unreadable: {err}")
        elif text is not None:
            if "\x00" in text[:1024]:
                printer.line("    binary content; not displayed. Inspect with "
                             "`file` and `strings` - do not execute it.")
            else:
                body, cut = truncate(redact(text), MAX_EXTRA_CHARS)
                indicators = scan(text)
                if indicators:
                    printer.line(printer.c(
                        f"    indicator matches: {summarize(indicators, 6)}",
                        COLORS[Severity.HIGH]))
                printer.line("    content (redacted):")
                for line in body.splitlines()[:120]:
                    printer.line("      | " + line[:200])
                if cut:
                    printer.line("      | ...[truncated]")
    printer.line()
    return True


def _investigate_pid(host: Host, pid: int, printer: Printer) -> bool:
    base = f"/proc/{pid}"
    printer.line(printer.c(f" PROCESS  pid {pid}", BOLD))
    if not host.exists(base):
        printer.wrap("no longer running. If it was present during the audit it has "
                     "since exited - note the time, and check whether a persistence "
                     "mechanism will restart it.", indent=4)
        printer.line()
        return True

    status, _t, err = host.read_text(f"{base}/status", max_bytes=16384)
    if status:
        wanted = ("Name", "State", "Pid", "PPid", "Uid", "Gid", "Threads", "TracerPid")
        for line in status.splitlines():
            if line.split(":")[0] in wanted:
                printer.line("    " + line.strip())
    cmdline, _t2, _e2 = host.read_text(f"{base}/cmdline", max_bytes=16384)
    if cmdline:
        printer.wrap("cmdline: " + redact(cmdline.replace("\x00", " ").strip())[:600],
                     indent=4)
    exe = host.stat(f"{base}/exe")
    if exe.symlink_target:
        printer.line(f"    exe -> {exe.symlink_target}")
        real = exe.symlink_target.replace(" (deleted)", "")
        if not exe.symlink_target.endswith("(deleted)"):
            target_info = host.stat(real, hash_file=True)
            if target_info.exists:
                printer.line(f"    exe mode={target_info.mode_octal} "
                             f"owner={target_info.owner} "
                             f"mtime={iso_from_epoch(target_info.mtime)}")
                if target_info.sha256:
                    printer.line(f"    exe sha256={target_info.sha256}")
        else:
            printer.line(printer.c(
                "    the executable has been deleted from disk; recover it with "
                f"`cp {base}/exe ./pid{pid}.bin` before the process exits",
                COLORS[Severity.HIGH]))
    cwd = host.stat(f"{base}/cwd")
    if cwd.symlink_target:
        printer.line(f"    cwd -> {cwd.symlink_target}")

    fds, fd_err = host.listdir(f"{base}/fd")
    if fd_err:
        printer.line(f"    file descriptors: {fd_err}")
    else:
        printer.line(f"    {len(fds)} open file descriptor(s):")
        for fd in fds[:30]:
            link = host.stat(f"{base}/fd/{fd}")
            printer.line(f"      {fd:>4} -> {link.symlink_target}")

    # Parent chain gives the "how did this start" answer.
    printer.line("    parent chain:")
    current, depth = pid, 0
    while depth < 8:
        text, _t3, _e3 = host.read_text(f"/proc/{current}/status", max_bytes=8192)
        if not text:
            break
        name = ppid = None
        for line in text.splitlines():
            if line.startswith("Name:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("PPid:"):
                ppid = line.split(":", 1)[1].strip()
        printer.line(f"      {'  ' * depth}{current} {name}")
        if not ppid or ppid in ("0", str(current)):
            break
        current = int(ppid)
        depth += 1
    printer.line()
    return True


def _investigate_account(host: Host, account: str, printer: Printer) -> bool:
    printer.line(printer.c(f" ACCOUNT  {account}", BOLD))
    lines, _err = host.read_lines("/etc/passwd")
    entry = None
    for line in lines:
        if line.split(":")[0] == account:
            entry = line
            break
    if entry is None:
        printer.line("    not present in /etc/passwd")
    else:
        parts = entry.split(":")
        printer.line(f"    uid={parts[2]} gid={parts[3]} home={parts[5]} shell={parts[6]}")

    groups = []
    group_lines, _ = host.read_lines("/etc/group")
    for line in group_lines:
        fields = line.split(":")
        if len(fields) >= 4 and account in [m for m in fields[3].split(",") if m]:
            groups.append(fields[0])
    printer.line(f"    supplementary groups: {', '.join(groups) or 'none'}")

    shadow_lines, shadow_err = host.read_lines("/etc/shadow")
    if shadow_err:
        printer.line(f"    /etc/shadow: {shadow_err} (run as root for password status)")
    else:
        for line in shadow_lines:
            fields = line.split(":")
            if fields and fields[0] == account:
                pw = fields[1] if len(fields) > 1 else ""
                state = ("EMPTY - no password required" if pw == ""
                         else "locked" if pw.startswith(("!", "*"))
                         else "active password set")
                printer.line(f"    password status: {state} "
                             f"(hash never displayed by this tool)")
                if len(fields) > 2 and fields[2].isdigit():
                    printer.line(f"    last change: day {fields[2]} since epoch")
                break

    if entry:
        home = entry.split(":")[5]
        for rel in (".ssh/authorized_keys", ".bashrc", ".profile", ".bash_history"):
            path = os.path.join(home, rel)
            info = host.stat(path)
            if info.exists:
                printer.line(f"    {path}: mode={info.mode_octal} owner={info.owner} "
                             f"size={info.size} mtime={iso_from_epoch(info.mtime)}")
    printer.line()
    return True


def _investigate_port(host: Host, port_key: str, printer: Printer) -> bool:
    proto, _, port = port_key.partition("/")
    printer.line(printer.c(f" SOCKET  {port_key}", BOLD))
    path = f"/proc/net/{proto}"
    lines, err = host.read_lines(path)
    if err:
        printer.line(f"    {path}: {err}")
        printer.line()
        return True
    try:
        wanted_hex = f"{int(port):04X}"
    except ValueError:
        printer.line()
        return True
    matches = [l for l in lines[1:] if f":{wanted_hex} " in l]
    printer.line(f"    {len(matches)} matching entry/entries in {path}:")
    for line in matches[:10]:
        printer.line("      | " + line.strip()[:200])
    printer.line()
    return True


def _related(findings: List[Dict], match: Dict) -> List[Dict]:
    key = match.get("correlation_key")
    target = match.get("target")
    out = []
    for finding in findings:
        if finding["id"] == match["id"]:
            continue
        if key and finding.get("correlation_key") == key:
            out.append(finding)
        elif target and finding.get("target") == target:
            out.append(finding)
    return out[:15]



# ============================================================================
# bulwark/cli.py
# command-line interface
# ============================================================================

describe_modules = describe

# Command-line interface.




# Marker for `--baseline` given with no value: use whatever the settings say.
USE_CONFIGURED_BASELINE = "\x00use-configured\x00"

EPILOG = f"""
the four commands you actually need:
  sudo {TOOL_NAME} quick        fast triage, high-value checks only
  sudo {TOOL_NAME} audit        full assessment
  sudo {TOOL_NAME} snap         record the state you have accepted
  sudo {TOOL_NAME} check        what has changed since then  <- run this on a loop

everything else:
  sudo {TOOL_NAME} validate            accept the baseline as your reference
  {TOOL_NAME} baseline                 summarise the saved baseline
  {TOOL_NAME} look BW-PERS-1a2b3c4d    dig into one finding
  {TOOL_NAME} report                   redisplay the most recent assessment
  {TOOL_NAME} status                   platform, privileges, modules, settings

Set output_dir and baseline once in {SYSTEM_CONFIG} instead of passing -o and
a path every time. `{TOOL_NAME} status` shows what is in effect and where each
value came from.

exit codes:
  {EXIT_CLEAN}   assessment completed, no findings above informational
  {EXIT_ERROR}   the assessment itself failed to run
  {EXIT_USAGE}   invalid invocation
  {EXIT_FINDINGS_LOW}  assessment completed, highest severity is low or medium
  {EXIT_FINDINGS_HIGH}  assessment completed, at least one high or critical finding

A successful run is not the same as a clean host. Exit code 0 means the checks
that ran found nothing above informational, within the evidence that was
readable. Read the visibility gaps in the report.
"""


def _add_common(parser: argparse.ArgumentParser) -> None:
    """Options every command accepts. Defaults are None so that the settings
    layer can tell "not given" from "given the same as the default"."""
    parser.add_argument("-o", "--output-dir", default=None, metavar="DIR",
                        help="where evidence directories are written "
                             "(config: output_dir)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="more detail in terminal output; repeat for module progress")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress the terminal summary; reports are still written")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colour (also honours NO_COLOR)")
    parser.add_argument("--color", action="store_true", dest="force_color",
                        help="keep colour even when output is piped, for "
                             "`| less -R`")
    parser.add_argument("--no-pager", action="store_true",
                        help="do not page long output through less. Paging is "
                             "skipped automatically when output is piped or "
                             "redirected (config: pager)")
    parser.add_argument("--timeout", type=int, default=None, metavar="SECONDS",
                        help="per-command timeout for external utilities (config: timeout)")
    parser.add_argument("--config", default=None, metavar="FILE",
                        help=f"read settings from this file instead of "
                             f"{SYSTEM_CONFIG} and the user config")
    parser.add_argument("--root", default="/", metavar="PATH",
                        help="assess a synthetic root filesystem instead of this host. "
                             "For testing and training only: external commands are "
                             "disabled and findings describe that tree, not this machine")


def _add_audit_options(parser: argparse.ArgumentParser, with_quick: bool = True) -> None:
    if with_quick:
        parser.add_argument("--quick", action="store_true",
                            help="high-value checks only (same as the `quick` command)")
    parser.add_argument("-m", "--modules", metavar="NAME",
                        help="comma-separated module allow-list "
                             f"({', '.join(module_names())})")
    parser.add_argument("--skip", metavar="NAME", default="",
                        help="comma-separated modules to skip")
    parser.add_argument("--lookback-hours", type=int, default=None, metavar="N",
                        help="how far back to read logs and look for recent changes "
                             "(config: lookback_hours)")
    parser.add_argument("--max-log-lines", type=int, default=None, metavar="N",
                        help="cap on log lines read per source (config: max_log_lines)")
    parser.add_argument("-b", "--baseline", nargs="?", const=USE_CONFIGURED_BASELINE,
                        default=None, metavar="PATH",
                        help="compare against a baseline and include the diff; "
                             "with no value, uses the configured baseline")
    parser.add_argument("--no-hash", action="store_true",
                        help="skip hashing of critical files (faster)")
    parser.add_argument("--no-info", action="store_true",
                        help="omit informational findings from the output")
    parser.add_argument("-n", "--top", type=int, default=None, metavar="N",
                        help="findings to show in the terminal summary (config: top)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Bulwark - read-only Linux incident response and threat detection for "
            "blue teams. Discovers suspicious activity, collects evidence, "
            "prioritises findings and verifies them against a baseline. This "
            "release makes no changes to the system."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    _add_common(common)

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ------------------------------------------------------------- audit
    audit = subparsers.add_parser(
        "audit", aliases=["a"], parents=[common],
        help="full read-only assessment",
        description=(
            "Collects system state, runs the detection modules, correlates and "
            "prioritises findings, and writes a terminal summary plus JSON and "
            "Markdown reports into a timestamped evidence directory. Makes no "
            "changes and never executes a file it discovers."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    _add_audit_options(audit)

    # ------------------------------------------------------------- quick
    quick = subparsers.add_parser(
        "quick", aliases=["q"], parents=[common],
        help="fast triage: the checks worth having in the first 30 seconds",
        description=(
            "An audit restricted to the high-value modules: accounts, SSH, "
            "persistence, processes, listening ports and recent authentication. "
            "Identical to `audit --quick`."
        ))
    _add_audit_options(quick, with_quick=False)

    # ---------------------------------------------------------- investigate
    investigate = subparsers.add_parser(
        "look", aliases=["i"], parents=[common],
        help="collect extra read-only evidence for one finding",
        description=(
            "Re-reads the sources behind a finding and gathers additional "
            "context: file metadata and contents, process detail, directory "
            "listings, related findings. Still read-only."
        ))
    investigate.add_argument("finding_id", nargs="?", metavar="ID",
                             help="finding ID, e.g. BW-PERS-1a2b3c4d")
    investigate.add_argument("--incident", metavar="DIR",
                             help="incident directory to read (default: the most recent)")

    # --------------------------------------------------------------- snap
    snap = subparsers.add_parser(
        "snap", parents=[common],
        help="record the current state as a baseline",
        description=(
            "Captures selected system state so a later `check` can tell what has "
            "changed. A baseline does not record that the state is good: one "
            "taken from an already-compromised host records the compromise as "
            "normal, which is why it starts unvalidated."
        ))
    _add_baseline_path(snap)
    snap.add_argument("--note", default="", metavar="TEXT",
                      help="free-text note recorded in the baseline")
    snap.add_argument("--validated", action="store_true",
                      help="mark as validated immediately; only do this if you have "
                           "already reviewed an audit of this host")

    # -------------------------------------------------------------- check
    check = subparsers.add_parser(
        "check", aliases=["c"], parents=[common],
        help="what has changed since the baseline (run this on a loop)",
        description=(
            "Runs a fresh assessment and diffs it against the saved baseline. "
            "This is the command to re-run periodically through an incident or "
            "a competition round."
        ))
    _add_check_options(check)

    # ----------------------------------------------------------- validate
    validate = subparsers.add_parser(
        "validate", parents=[common],
        help="mark the baseline as reviewed and accepted",
        description=(
            "Records that an operator has read the audit findings and accepts "
            "the baselined state as the reference. Until this is done, `check` "
            "reports its diffs at lower confidence, because an unvalidated "
            "baseline may have recorded a pre-existing compromise as normal."
        ))
    _add_baseline_path(validate)
    validate.add_argument("--note", default="", metavar="TEXT",
                          help="who validated it and what they checked")

    # ----------------------------------------------------------- baseline
    baseline = subparsers.add_parser(
        "baseline", aliases=["b"], parents=[common],
        help="summarise the saved baseline",
        description=(
            "Prints what the saved baseline holds: when it was taken, whether "
            "it has been validated, which sections it covers and how many "
            "items are in each."
        ))
    _add_baseline_path(baseline)

    # ------------------------------------------------------------- report
    report = subparsers.add_parser(
        "report", aliases=["last", "r"], parents=[common],
        help="redisplay a stored assessment (the most recent by default)",
        description=(
            "Re-renders a previously stored assessment from its JSON report, "
            "without re-scanning. With no options it shows the most recent."
        ))
    _add_report_options(report)

    # ------------------------------------------------------------ status
    status = subparsers.add_parser(
        "status", aliases=["s"], parents=[common],
        help="platform, privileges, modules and settings in effect",
        description="Reports the tool version, detected platform, available "
                    "detection modules, current privileges, the resolved "
                    "settings and recent assessments.")
    status.add_argument("--json", action="store_true", dest="as_json",
                        help="machine-readable output")

    return parser


def _add_baseline_path(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("baseline_path", nargs="?", metavar="FILE",
                        help="baseline file; defaults to the configured path")


def _add_check_options(parser: argparse.ArgumentParser) -> None:
    _add_baseline_path(parser)
    parser.add_argument("-x", "--exclude", default="", metavar="TEXT",
                        help="comma-separated substrings; matching keys are ignored "
                             "(for known legitimate applications and services)")
    parser.add_argument("--lookback-hours", type=int, default=None, metavar="N",
                        help="log and change window for the fresh assessment")
    parser.add_argument("-n", "--top", type=int, default=None, metavar="N",
                        help="findings to show in the terminal summary")


def _add_report_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--incident", metavar="DIR", help="a specific incident directory")
    group.add_argument("-l", "--list", action="store_true", dest="list_incidents",
                       help="list stored incident directories")
    parser.add_argument("--format", choices=("terminal", "json", "markdown"),
                        default="terminal", help="output format (default: %(default)s)")
    parser.add_argument("-n", "--top", type=int, default=None, metavar="N")


# --------------------------------------------------------------------------
# Command implementations
# --------------------------------------------------------------------------

def _printer_for(args, stream=None, force_color=False) -> "Printer":
    return Printer(stream, no_color=args.no_color,
                            force_color=force_color or getattr(args, "force_color", False))


def _paged(args):
    """Context manager yielding a Printer whose output goes through a pager.

    Paging is on unless --no-pager or the config turns it off, and is skipped
    automatically when the destination is not a terminal, so piping into a
    file or grep behaves exactly as before.
    """
    import contextlib

    @contextlib.contextmanager
    def wrapper():
        with paged_output(enabled=not getattr(args, "no_pager", False)) \
                as (stream, force_color):
            yield _printer_for(args, stream, force_color)
    return wrapper()


def resolve_settings(args) -> Settings:
    """Fill in anything not given on the command line from config and
    environment, so the resolved values can be read straight off `args`."""
    resolved = load_settings(getattr(args, "config", None))

    args.output_dir = resolved.get("output_dir", getattr(args, "output_dir", None))
    args.timeout = resolved.get("timeout", getattr(args, "timeout", None))
    if hasattr(args, "lookback_hours"):
        args.lookback_hours = resolved.get("lookback_hours", args.lookback_hours)
    if hasattr(args, "max_log_lines"):
        args.max_log_lines = resolved.get("max_log_lines", args.max_log_lines)
    if hasattr(args, "top"):
        args.top = resolved.get("top", args.top)
    if not getattr(args, "no_color", False) and resolved.get("no_color"):
        args.no_color = True
    # --no-pager on the command line wins; otherwise the config decides.
    if not getattr(args, "no_pager", False) and not resolved.get("pager", True):
        args.no_pager = True

    # Baseline path: the positional argument wins, otherwise the configured
    # one. `args.path` is the name the handlers use internally.
    if hasattr(args, "baseline_path"):
        args.baseline_path = resolved.get("baseline", args.baseline_path)
        args.path = args.baseline_path
    if getattr(args, "baseline", None) == USE_CONFIGURED_BASELINE:
        args.baseline = resolved.get("baseline")

    args._settings = resolved
    return resolved


def _config_from_args(args, **overrides) -> Config:
    config = Config(
        output_dir=getattr(args, "output_dir", "./bulwark-evidence"),
        log_lookback_hours=getattr(args, "lookback_hours", 72),
        max_log_lines=getattr(args, "max_log_lines", 20000),
        quick=getattr(args, "quick", False),
        modules=([m.strip() for m in args.modules.split(",")]
                 if getattr(args, "modules", None) else None),
        skip_modules=([m.strip() for m in args.skip.split(",") if m.strip()]
                      if getattr(args, "skip", "") else []),
        verbosity=getattr(args, "verbose", 0),
        no_color=getattr(args, "no_color", False),
        command_timeout=getattr(args, "timeout", 15),
        hash_critical_files=not getattr(args, "no_hash", False),
        root=getattr(args, "root", "/"),
        include_informational=not getattr(args, "no_info", False),
        baseline_path=getattr(args, "baseline", None),
    )
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _make_logger(verbosity: int, stream=sys.stderr):
    def log(level: str, message: str) -> None:
        if level == "error" or verbosity >= 1:
            stream.write(f"[{level}] {message}\n")
    return log


def _progress(verbosity: int, stream=sys.stderr):
    if verbosity < 1:
        return None

    def report(name: str, index: int, total: int) -> None:
        stream.write(f"[{index}/{total}] {name}\n")
        stream.flush()
    return report


def cmd_audit(args) -> int:
    config = _config_from_args(args)
    logger = _make_logger(args.verbose)

    baseline_doc = None
    baseline_findings = []
    if args.baseline:
        if not os.path.exists(args.baseline):
            sys.stderr.write(f"error: baseline not found: {args.baseline}\n")
            return EXIT_USAGE
        baseline_doc = load_create(args.baseline)
        problem = verify_integrity(baseline_doc)
        if problem:
            sys.stderr.write(f"warning: {problem}\n")

    try:
        assessment = run_audit(config, logger=logger, baseline=baseline_doc,
                               progress=_progress(args.verbose))
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted; no report written\n")
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"error: assessment failed: {type(exc).__name__}: {exc}\n")
        return EXIT_ERROR

    if baseline_doc:
        baseline_findings = compare_baseline(assessment, baseline_doc)

    try:
        incident_dir = create_incident_dir(
            config.output_dir, assessment.facts_dict().get("hostname", "host"))
        assessment.incident_dir = incident_dir
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"error: cannot create evidence directory: {exc}\n")
        incident_dir = None

    written: Dict[str, str] = {}
    if incident_dir:
        written = _write_reports(assessment, incident_dir, baseline_findings)

    if not args.quiet:
        with _paged(args) as printer:
            render(assessment, printer=printer,
                            baseline_findings=baseline_findings,
                            top_n=args.top, verbosity=args.verbose)
            if written:
                printer.line(f"  Reports written to: {incident_dir}")
                for label, path in sorted(written.items()):
                    printer.line(f"    {label:<10} {os.path.basename(path)}")
                printer.line()

    code = assessment.exit_code()
    if baseline_findings and code == EXIT_CLEAN:
        top = max((f.severity.rank for f in baseline_findings), default=0)
        if top >= Severity.HIGH.rank:
            code = EXIT_FINDINGS_HIGH
        elif top >= Severity.LOW.rank:
            code = EXIT_FINDINGS_LOW
    return code


def _write_reports(assessment: Assessment, incident_dir: str,
                   baseline_findings) -> Dict[str, str]:
    written: Dict[str, str] = {}
    try:
        document = build_json_report(assessment, baseline_findings)
        written["json"] = write_json_report(
            document, os.path.join(incident_dir, "report.json"))
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"warning: JSON report failed: {type(exc).__name__}: {exc}\n")
    try:
        markdown = build_markdown_report(assessment, baseline_findings)
        written["markdown"] = write_markdown_report(
            markdown, os.path.join(incident_dir, "report.md"))
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"warning: Markdown report failed: {type(exc).__name__}: {exc}\n")
    try:
        import io
        buffer = io.StringIO()
        render(assessment, printer=Printer(buffer, no_color=True),
                        baseline_findings=baseline_findings, top_n=25, verbosity=1)
        written["summary"] = write_text(
            os.path.join(incident_dir, "summary.txt"), buffer.getvalue())
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"warning: summary failed: {type(exc).__name__}: {exc}\n")

    hashes = {}
    for label, path in written.items():
        if label == "json":
            continue
        digest = file_hash(path)
        if digest:
            hashes[os.path.basename(path)] = digest
    if "json" in written:
        try:
            append_evidence_integrity(written["json"], hashes)
            hashes[os.path.basename(written["json"])] = file_hash(written["json"])
        except Exception:  # noqa: BLE001
            pass
    try:
        write_manifest(incident_dir, {
            "tool_version": assessment.tool_version,
            "hostname": assessment.facts_dict().get("hostname"),
            "status": assessment.status_label(),
            "exit_code": assessment.exit_code(),
            "findings": assessment.counts,
            "files": {label: os.path.basename(p) for label, p in written.items()},
            "sha256": hashes,
            "integrity_note": (
                "Hashes detect accidental modification. They do not prove authenticity "
                "when generated on a host that may be compromised."
            ),
        })
    except Exception:  # noqa: BLE001
        pass
    return written


def cmd_investigate(args) -> int:
    finding_id = getattr(args, "finding_id", None)
    if not finding_id:
        sys.stderr.write(
            f"error: which finding? Give its ID, for example:\n"
            f"  {TOOL_NAME} look BW-PERS-1a2b3c4d\n"
            f"Run `{TOOL_NAME} last` to see the IDs from the most recent assessment.\n")
        return EXIT_USAGE
    args.finding = finding_id

    incident_dir = args.incident or latest_incident_dir(args.output_dir)
    if not incident_dir:
        sys.stderr.write(
            f"error: no stored assessment found under {args.output_dir}. "
            f"Run `{TOOL_NAME} audit` first.\n")
        return EXIT_USAGE
    try:
        document = load_report(incident_dir)
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"error: cannot read report in {incident_dir}: {exc}\n")
        return EXIT_ERROR

    with _paged(args) as printer:
        code = investigate_finding(document, args.finding, args.root, printer,
                                   incident_dir)
    return code


def cmd_baseline(args) -> int:

    action = args.baseline_command
    if action is None:
        sys.stderr.write(f"error: unknown baseline action: {action}\n")
        return EXIT_USAGE

    if action == "create":
        config = _config_from_args(args)
        logger = _make_logger(args.verbose)
        print(f"Capturing baseline (read-only full assessment)...")
        try:
            document = create_baseline(
                config, logger=logger, note=args.note, validated=args.validated)
            path = save(document, args.path)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"error: baseline creation failed: {type(exc).__name__}: {exc}\n")
            return EXIT_ERROR
        sections = document.get("sections", {})
        print(f"\nBaseline written to {path} (mode 0600)")
        print(f"  Captured at : {document['created_at_utc']}")
        print(f"  Host        : {document['host'].get('hostname')}")
        print(f"  Sections    : {len(sections)}")
        for name, data in sorted(sections.items()):
            items = data.get("items", {})
            count = len(items) if hasattr(items, "__len__") else 1
            print(f"      {name:<22} {count} item(s)")
        summary = document.get("audit_summary", {})
        print(f"  Audit alongside this capture found: {summary.get('findings')}")
        print()
        if document.get("validated"):
            print("  Marked VALIDATED as requested.")
        else:
            print("  Marked NOT VALIDATED.")
            print("  A baseline records this host as it is now, including anything an")
            print("  attacker installed before you received it. Review the findings from")
            print(f"  `{TOOL_NAME} audit`, then run `{TOOL_NAME} validate` to")
            print("  record that you have accepted this state as your reference.")
        print()
        print("  Keep a copy off this host. Local storage cannot protect this file")
        print("  from someone with root here.")
        return EXIT_CLEAN

    if action == "compare":
        if not os.path.exists(args.path):
            sys.stderr.write(
                f"error: baseline not found: {args.path}\n"
                f"Create one with `{TOOL_NAME} snap`.\n")
            return EXIT_USAGE
        try:
            document = load_create(args.path)
        except (OSError, json.JSONDecodeError) as exc:
            sys.stderr.write(f"error: cannot read baseline: {exc}\n")
            return EXIT_ERROR
        problem = verify_integrity(document)
        if problem:
            sys.stderr.write(f"warning: {problem}\n")

        config = _config_from_args(args, baseline_path=args.path)
        logger = _make_logger(args.verbose)
        try:
            assessment = run_audit(config, logger=logger, baseline=document,
                                   progress=_progress(args.verbose))
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"error: assessment failed: {type(exc).__name__}: {exc}\n")
            return EXIT_ERROR

        exclusions = [e.strip() for e in (args.exclude or "").split(",") if e.strip()]
        diff_findings = compare_baseline(assessment, document, exclusions)

        try:
            incident_dir = create_incident_dir(
                config.output_dir, assessment.facts_dict().get("hostname", "host"))
            assessment.incident_dir = incident_dir
            written = _write_reports(assessment, incident_dir, diff_findings)
        except (OSError, ValueError) as exc:
            sys.stderr.write(f"warning: cannot write evidence: {exc}\n")
            written = {}

        if not args.quiet:
            with _paged(args) as printer:
                render(assessment, printer=printer,
                                baseline_findings=diff_findings, top_n=args.top,
                                verbosity=args.verbose)
                printer.line(f"  Baseline    : {args.path} "
                             f"(taken {document.get('created_at_utc')}, "
                             f"validated={document.get('validated')})")
                printer.line(f"  Diff findings: {len(diff_findings)}")
                if written:
                    printer.line(f"  Reports written to: {assessment.incident_dir}")
                printer.line()

        combined = list(assessment.findings) + list(diff_findings)
        actionable = [f for f in combined if f.severity.rank >= Severity.LOW.rank]
        if not actionable:
            return EXIT_CLEAN
        return (EXIT_FINDINGS_HIGH
                if max(f.severity.rank for f in actionable) >= Severity.HIGH.rank
                else EXIT_FINDINGS_LOW)

    if action == "validate":
        if not os.path.exists(args.path):
            sys.stderr.write(f"error: baseline not found: {args.path}\n")
            return EXIT_USAGE
        try:
            document = validate_marker(args.path, args.note)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"error: {type(exc).__name__}: {exc}\n")
            return EXIT_ERROR
        print(f"Baseline {args.path} marked validated at {document['validated_at_utc']}.")
        print("Future comparisons will treat the recorded state as your accepted reference.")
        print("Critical findings are still reported even when they match this baseline.")
        return EXIT_CLEAN

    if action == "show":
        if not os.path.exists(args.path):
            sys.stderr.write(f"error: baseline not found: {args.path}\n")
            return EXIT_USAGE
        document = load_create(args.path)
        problem = verify_integrity(document)
        print(f"Baseline    : {args.path}")
        print(f"Created     : {document.get('created_at_utc')}")
        print(f"Tool version: {document.get('tool_version')}")
        print(f"Validated   : {document.get('validated')}"
              + (f" at {document['validated_at_utc']}" if document.get("validated_at_utc") else ""))
        if document.get("note"):
            print(f"Note        : {document['note']}")
        print(f"Integrity   : {problem or 'recorded hash matches file content'}")
        host = document.get("host", {})
        print(f"Host        : {host.get('hostname')} - {host.get('os_name')} "
              f"{host.get('os_version')} (kernel {host.get('kernel')})")
        print("Sections    :")
        for name, data in sorted((document.get("sections") or {}).items()):
            items = data.get("items", {})
            count = len(items) if hasattr(items, "__len__") else 1
            print(f"    {name:<22} {count} item(s)")
        print()
        print(document.get("validation_warning", ""))
        return EXIT_CLEAN

    sys.stderr.write(f"error: unknown baseline action: {action}\n")
    return EXIT_USAGE


def cmd_report(args) -> int:
    if args.list_incidents:
        rows = list_incident_dirs(args.output_dir)
        if not rows:
            print(f"No stored assessments under {args.output_dir}")
            return EXIT_CLEAN
        print(f"Stored assessments under {args.output_dir}:\n")
        for path, created in rows:
            print(f"  {created or '?':<22} {path}")
        print()
        return EXIT_CLEAN

    incident_dir = args.incident
    if not incident_dir:
        incident_dir = latest_incident_dir(args.output_dir)
    if not incident_dir:
        sys.stderr.write(
            f"error: no stored assessment found under {args.output_dir}. "
            f"Run `{TOOL_NAME} audit` first.\n")
        return EXIT_USAGE

    try:
        document = load_report(incident_dir)
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"error: cannot read report: {exc}\n")
        return EXIT_ERROR

    if args.format == "json":
        json.dump(document, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif args.format == "markdown":
        path = os.path.join(incident_dir, "report.md")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                sys.stdout.write(fh.read())
        else:
            sys.stderr.write("error: no Markdown report stored for this assessment\n")
            return EXIT_ERROR
    else:
        with _paged(args) as printer:
            _render_stored_summary(document, incident_dir, args, printer)

    return int(document.get("assessment", {}).get("exit_code", EXIT_CLEAN))


def _render_stored_summary(document: Dict[str, Any], incident_dir: str, args,
                           printer=None) -> None:
    printer = printer or _printer_for(args)
    assessment_meta = document.get("assessment", {})
    host = document.get("host", {})
    summary = document.get("summary", {})

    printer.line()
    printer.rule("=")
    printer.line(printer.c(f" STORED ASSESSMENT  -  {host.get('hostname','unknown')}",
                           BOLD))
    printer.rule("=")
    printer.line(f" Directory   : {incident_dir}")
    printer.line(f" Status      : {assessment_meta.get('status')}")
    printer.line(f" Started     : {assessment_meta.get('started_at_utc')}")
    printer.line(f" Finished    : {assessment_meta.get('finished_at_utc')}")
    printer.line(f" System      : {host.get('os_name','?')} {host.get('os_version','')}"
                 f"  kernel {host.get('kernel','?')}")
    printer.line(f" Mode        : {'quick' if assessment_meta.get('quick_mode') else 'full'}")
    counts = summary.get("counts_by_severity", {})
    printer.line(" Findings    : " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    printer.line()

    warning = document.get("integrity_warning", {})
    if warning.get("triggered"):
        printer.line(printer.c(" !! RESULTS FROM THIS HOST MAY BE UNRELIABLE !!",
                               COLORS[Severity.CRITICAL]))
        for reason in warning.get("reasons", []):
            printer.wrap(f"- {reason}", indent=4)
        printer.line()

    findings = document.get("findings", [])
    actionable = [f for f in findings if f.get("severity") != "info"]
    if actionable:
        printer.rule()
        printer.line(printer.c(f" HIGHEST PRIORITY FINDINGS "
                               f"(showing {min(args.top, len(actionable))} of "
                               f"{len(actionable)})", BOLD))
        printer.rule()
        for finding in actionable[:args.top]:
            severity = Severity.from_label(finding["severity"])
            badge = printer.c(f" {severity.label.upper():8}", COLORS[severity])
            printer.line(f"{badge} {printer.c(finding['id'], BOLD)}"
                         f"  conf={finding['confidence']}  [{finding['category']}]")
            printer.wrap(finding["title"], indent=10)
            printer.wrap(f"target: {finding['target']}", indent=10)
            printer.line()

    actions = summary.get("recommended_actions", [])
    if actions:
        printer.rule()
        printer.line(printer.c(" RECOMMENDED NEXT ACTIONS", BOLD))
        printer.rule()
        for i, action in enumerate(actions, 1):
            printer.wrap(f"{i}. {action}", indent=1)
        printer.line()

    gaps = document.get("visibility_gaps", [])
    if gaps:
        printer.rule()
        printer.line(printer.c(" VISIBILITY GAPS", BOLD))
        printer.rule()
        for gap in gaps[:10]:
            marker = " (needs root)" if gap.get("needs_root") else ""
            printer.wrap(f"- {gap.get('area')}: {gap.get('reason')}{marker}", indent=1)
        printer.line()
    printer.line(f" Full detail: {os.path.join(incident_dir, 'report.md')}")
    printer.line()


def cmd_status(args) -> int:
    host = Host(root=args.root, timeout=args.timeout)
    facts = detect_host_facts(host)
    modules = describe_modules()
    incidents = list_incident_dirs(args.output_dir, limit=5)

    resolved = getattr(args, "_settings", None)

    if args.as_json:
        json.dump({
            "tool": {"name": TOOL_NAME, "version": __version__},
            "host": facts.to_dict(),
            "modules": modules,
            "recent_assessments": [{"path": p, "started_at_utc": c} for p, c in incidents],
            "output_dir": os.path.abspath(args.output_dir),
            "settings": {
                "values": resolved.values if resolved else {},
                "sources": resolved.sources if resolved else {},
                "config_files_read": resolved.files_read if resolved else [],
                "warnings": resolved.warnings if resolved else [],
            },
        }, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return EXIT_CLEAN

    with _paged(args) as printer:
        printer.line()
        printer.rule("=")
        printer.line(printer.c(f" {TOOL_NAME.upper()} {__version__}  -  status", BOLD))
        printer.rule("=")
        printer.line(f" Host          : {facts.hostname}")
        printer.line(f" OS            : {facts.os_name} {facts.os_version} (id={facts.os_id or '?'})")
        printer.line(f" Kernel        : {facts.kernel}  {facts.architecture}")
        printer.line(f" Init system   : {facts.init_system}")
        printer.line(f" Packages      : {facts.package_manager}")
        printer.line(f" Container     : {facts.container or 'not detected'}")
        printer.line(f" Running as    : {facts.user} (uid {facts.euid})"
                     f"{'  [root]' if facts.is_root else ''}")
        printer.line(f" Python        : {facts.python_version}")
        printer.line(f" Timezone      : {facts.local_timezone}   (reports use UTC)")
        printer.line(f" Evidence dir  : {os.path.abspath(args.output_dir)}")
        printer.line()

        if not facts.is_root:
            printer.wrap("Not running as root. /etc/shadow, other users' process details, "
                         "firewall rules and most of the journal will be unreadable. The "
                         "audit still runs and reports each gap explicitly, but run with "
                         "sudo for full visibility.", indent=1)
            printer.line()

        printer.rule()
        printer.line(printer.c(" DETECTION MODULES", BOLD))
        printer.rule()
        printer.line(f" {'module':<20} {'ver':<5} {'quick':<6} description")
        for name, data in modules.items():
            printer.line(f" {name:<20} {data['version']:<5} "
                         f"{'yes' if data['quick'] else 'no':<6} {data['title']}")
        printer.line()

        printer.rule()
        printer.line(printer.c(" AVAILABLE UTILITIES", BOLD))
        printer.rule()
        present = sorted(k for k, v in facts.available_commands.items() if v)
        missing = sorted(k for k, v in facts.available_commands.items() if not v)
        printer.wrap("present: " + (", ".join(present) or "none"), indent=1)
        printer.line()
        printer.wrap("missing: " + (", ".join(missing) or "none"), indent=1)
        printer.wrap("Missing utilities are handled: affected checks are marked "
                     "unsupported rather than failing.", indent=1)
        printer.line()

        printer.rule()
        printer.line(printer.c(" SETTINGS IN EFFECT", BOLD))
        printer.rule()
        if resolved:
            for line in resolved.describe():
                printer.line(f"   {line}")
            if resolved.files_read:
                printer.line()
                printer.line(f"   read from: {', '.join(resolved.files_read)}")
            else:
                printer.line()
                printer.wrap(
                    f"No config file found. Create {SYSTEM_CONFIG} to set output_dir and "
                    f"baseline once instead of passing -o and a path on every run.",
                    indent=3)
            for warning in resolved.warnings:
                printer.wrap(f"warning: {warning}", indent=3)
        printer.line()

        printer.rule()
        printer.line(printer.c(" RECENT ASSESSMENTS", BOLD))
        printer.rule()
        if incidents:
            for path, created in incidents:
                printer.line(f"   {created or '?':<22} {path}")
        else:
            printer.line(f"   none under {os.path.abspath(args.output_dir)}")
        printer.line()
        return EXIT_CLEAN


# command (and alias) -> (handler, attributes to force before dispatch)
#
# One name per job. The single-letter entries are typing shortcuts for the
# same command, not second ways of doing the thing.
COMMANDS: Dict[str, Any] = {
    "audit":    (cmd_audit, {}),
    "a":        (cmd_audit, {}),
    "quick":    (cmd_audit, {"quick": True}),
    "q":        (cmd_audit, {"quick": True}),
    "look":     (cmd_investigate, {}),
    "i":        (cmd_investigate, {}),
    "snap":     (cmd_baseline, {"baseline_command": "create"}),
    "check":    (cmd_baseline, {"baseline_command": "compare"}),
    "c":        (cmd_baseline, {"baseline_command": "compare"}),
    "validate": (cmd_baseline, {"baseline_command": "validate"}),
    "baseline": (cmd_baseline, {"baseline_command": "show"}),
    "b":        (cmd_baseline, {"baseline_command": "show"}),
    "report":   (cmd_report, {}),
    "last":     (cmd_report, {}),
    "r":        (cmd_report, {}),
    "status":   (cmd_status, {}),
    "s":        (cmd_status, {}),
}

# Commands that read the live system and so only make sense on Linux.
LINUX_ONLY = {"audit", "a", "quick", "q", "snap", "check", "c"}


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    entry = COMMANDS.get(args.command)
    if entry is None:
        parser.print_help()
        return EXIT_USAGE
    handler, forced = entry

    if sys.platform != "linux" and args.command in LINUX_ONLY:
        sys.stderr.write(
            f"error: {TOOL_NAME} targets Linux; detected platform '{sys.platform}'.\n"
            "The detection modules read /proc, /etc and distribution-specific paths "
            "that do not exist here.\n")
        return EXIT_USAGE

    for key, value in forced.items():
        setattr(args, key, value)

    resolved = resolve_settings(args)
    emit_warnings(resolved)

    try:
        return handler(args)
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return EXIT_ERROR



# ============================================================================
# entry point
# ============================================================================

if __name__ == "__main__":
    if sys.version_info < (3, 8):
        sys.stderr.write(
            "bulwark needs Python 3.8 or newer; this interpreter is %s.\n"
            "Try: python3 %s\n"
            % (sys.version.split()[0], sys.argv[0]))
        raise SystemExit(2)
    raise SystemExit(main())
