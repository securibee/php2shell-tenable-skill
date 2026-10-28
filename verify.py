"""Give every PHP install in a run folder one evidence-backed verdict.

load_run(run_dir) reads the run folder. judge(run) groups findings by asset and
settles each install by the first rule that applies (rules 1 > 2 > 3 > 4 > 4a > 5
> 6 > 7 > 8). Every rule's evidence is gathered; the order sets precedence only,
and positive evidence beats absence. "Patched" needs positive evidence: a
same-channel vendor fix for every run CVE at or below the installed package on the
same upstream version, or an upstream release at or above the fixed one where no
vendor fix applies (non-OS installs, Windows, and OS-packaged builds on another
upstream line than the vendor's, such as third-party repositories).
"""
from __future__ import annotations

import json
import re
from functools import cmp_to_key
from pathlib import Path
from typing import NamedTuple, Optional
from urllib.parse import urlparse

from advisories import OTHER_CHANNEL, Advisories
from inventory import (UNPATCHED_PREFIXES, Distro, Install, classify, coverage,
                       coverage_published, distro_for, parse_installs, stream_of)
from versions import compare_apk, compare_dpkg, compare_rpm, parse_nevra, upstream_version

FAQ_URL = ("https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-"
           "frequently-asked-questions-about-critical-php-remote")
DEFAULT_CVES = ["CVE-2026-109618", "CVE-2026-109619"]
DEFAULT_FIXED = {"8.5": "8.5.12", "8.4": "8.4.27", "8.3": "8.3.36", "8.2": "8.2.35"}
BACKPORT_ONLY = {"7.4", "8.0", "8.1"}
WAS_BRANCH = {"115719": "8.5", "115720": "8.4", "115721": "8.3", "115722": "8.2"}

# Authentication plugins: presence only, never their output. 110723 (no
# credentials provided) is in neither set, so it reads as not credentialed.
SUCCESS_IDS = {141118, 110095, 97993, 12634, 22869, 10394, 10400, 20811, 24269}
FAILURE_IDS = {104410, 110385, 21745, 117885, 24786, 10428, 26917}

VERDICTS = {
    "vulnerable": "Vulnerable",
    "no-vendor-fix": "Vulnerable – no vendor fix",
    "no-stream-fix": "Vulnerable – no fix for this stream",
    "backport-only": "Vulnerable – backport only",
    "eol": "Vulnerable – EOL",
    "patched": "Patched",
    "likely-patched": "Likely patched – Tenable distro check clean",
    "not-affected": "Not affected",
    "conflict": "Conflict – verify",
    "unverified-credentials": "Unverified – credentials",
    "unverified-no-data": "Unverified – no package data",
}
ACTIONABLE = {"vulnerable", "no-vendor-fix", "no-stream-fix", "backport-only", "eol"}
VERIFY_FIRST = {"conflict", "likely-patched", "unverified-credentials", "unverified-no-data"}
ASSET_FIELDS = ("name", "ips", "fqdns", "os", "sensors", "auth_plugins", "unpatched_scan",
                "http_service", "aes", "acr", "apa_level", "owner_tag", "last_seen")
_LISTS = {"ips", "fqdns", "sensors", "auth_plugins"}

_FORMAT = dict.fromkeys(("rhel", "oracle", "alma", "rocky", "suse", "amazon", "fedora",
                         "centos"), "rpm")
_FORMAT.update(ubuntu="dpkg", debian="dpkg", alpine="apk")
_COMPARE = {"rpm": compare_rpm, "dpkg": compare_dpkg, "apk": compare_apk}
_FEED = dict.fromkeys(("ubuntu", "debian", "alma", "rocky", "suse"), "osv")
_FEED.update(rhel="redhat", alpine="alpine")
_OSV_PREFIX = {"ubuntu": "UBUNTU-", "debian": "DEBIAN-"}
_UPSTREAM_AFFECTED = {"vulnerable", "backport-only", "eol"}
# Families whose PHP can come from a module stream: rule 6 needs the stream known.
_MODULE_FAMILIES = {"rhel", "oracle", "alma", "rocky", "centos"}
# Families with no vendor feed the skill reads: rule 6 applies with a known package too.
NO_FEED_FAMILIES = {"oracle", "amazon", "centos", "fedora"}
# Rule 8 evidence wording, which plan.next_step reads.
PACKAGE_UNKNOWN = "installed package version unknown"
FEED_FAILED = "vendor feed fetch failed"
# Version-only plugins, for rows whose plugin is not in plugins.json.
_VERSION_ONLY_IDS = {"369483", "115719", "115720", "115721", "115722"}

_NEVRA = re.compile(r"^\S+-[^-\s]+-[^-\s]+\.[A-Za-z0-9_]+$")
_APK = re.compile(r"^(\S+?)-(\d[^-\s]*-r\d+)$")
_VERSION = re.compile(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b")
_ADVISORY = re.compile(r"\(([^()]+)\)\s*$")
_DEBIAN_ADVISORY = re.compile(r"\b(?:dsa|dla)-\d+(?:-\d+)?\b", re.I)
_VENDOR_NAME = re.compile(r"\b(?:RHSA|ELSA|ALSA|RLSA|USN|DSA|DLA|SUSE-SU|ALAS)[-:\d]"
                          r"|^[A-Za-z][A-Za-z ]*\d+(?:\.\d+)?\b[^:]*\s:", re.I)


class Evidence(NamedTuple):
    type: str            # tenable-plugin | vendor-feed | upstream-version | credential | absence
    source: str
    reference_id: str
    url: str = ""
    observed: str = ""
    expected: str = ""
    fetched_at: str = ""


class Verdict(NamedTuple):
    code: str
    label: str
    rule: str            # "1".."8", "4a"; "1+3"/"2+3" when rule 3 also settled; "5+3" WAS conflict
    evidence: list
    action: str          # patch | vendor-update | upgrade-stream | isolate-or-upgrade | ""
    fix_target: str


class AssetResult(NamedTuple):
    key: str
    asset: dict
    installs: list       # [(Install, Verdict)]
    credential_state: str
    output_truncated: bool
    sources: set
    urls: list


class Run(NamedTuple):
    findings: list
    assets: dict
    catalog: list
    faq: dict
    advisories: Advisories


class _Slot(NamedTuple):
    install: Install
    rows: list           # vulnerable rows that bear on this install


def _s(value) -> str:
    return "" if value is None else str(value).strip()


def _vtuple(s: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", s or ""))


def _branch(version: str) -> str:
    m = _VERSION.search(version or "")
    return "%s.%s" % m.group(1, 2) if m else ""


def _verdict(code, rule, evidence, action="", target="") -> Verdict:
    return Verdict(code, VERDICTS[code], rule, list(dict.fromkeys(evidence)), action, target)


# --- loading ---

def _read(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if default is None:
            raise
        return default


def load_run(run_dir) -> Run:
    """findings.json and assets.json are required; the rest default to empty."""
    d = Path(run_dir)
    return Run(_read(d / "findings.json"), _read(d / "assets.json"),
               _read(d / "plugins.json", []), _read(d / "faq.json", {}), Advisories.load(d))


# --- credentials ---

def _ids(values) -> set:
    out = set()
    for v in values or []:
        try:
            out.add(int(v))
        except (TypeError, ValueError):
            pass
    return out


def _is_url(key: str) -> bool:
    return (key or "").lower().startswith(("http://", "https://"))


def _vm_sensor(s: str) -> bool:
    return s == "vm" or any(t in s for t in ("nessus", "agent", "scanner",
                                             "vulnerability management"))


def credential_state(asset: dict, key: str = "") -> str:
    """credentialed | not-credentialed | failed | not-applicable (WAS URL, image)."""
    sensors = [_s(x).lower() for x in asset.get("sensors") or []]
    auth = _ids(asset.get("auth_plugins"))
    if _is_url(key) or not (auth or any(_vm_sensor(x) for x in sensors)):
        return "not-applicable"
    if any("agent" in x for x in sensors) or (auth & SUCCESS_IDS and not auth & FAILURE_IDS):
        return "credentialed"
    return "failed" if auth & FAILURE_IDS else "not-credentialed"


# --- evidence ---

def _plugin_ev(row: dict) -> Evidence:
    pid, src = _s(row.get("plugin_id")), _s(row.get("source")) or "VM"
    url = "https://www.tenable.com/plugins/%s/%s" % (
        "was" if src.upper() == "WAS" else "nessus", pid) if pid else ""
    return Evidence("tenable-plugin", "Tenable " + src, pid or _s(row.get("plugin_name")), url,
                    _s(row.get("plugin_name")))


def _cred_ev(asset: dict, state: str) -> Evidence:
    ids = ",".join(str(i) for i in sorted(_ids(asset.get("auth_plugins"))))
    return Evidence("credential", "Tenable VM", ids, "", state, "credentialed")


def _feed_ev(rec, installed: str) -> Evidence:
    ref = "%s (%s)" % (rec.advisory_id, rec.cve) if rec.advisory_id and rec.cve else (
        rec.advisory_id or rec.cve)
    return Evidence("vendor-feed", rec.source, ref, rec.url, installed,
                    rec.fixed_version or rec.status, rec.fetched_at)


def _advisory(row: dict) -> str:
    if _s(row.get("source")).upper() == "CLOUD":
        return ""
    name = _s(row.get("plugin_name"))
    m = _ADVISORY.search(name)
    if m:
        return m.group(1)
    m = _DEBIAN_ADVISORY.search(name)
    return m.group().upper() if m else name


# --- context ---

class _Ctx:
    def __init__(self, run: Run):
        faq = run.faq if isinstance(run.faq, dict) else {}
        catalog = [p for p in run.catalog or [] if isinstance(p, dict)]
        self.cves = [_s(c).upper() for c in faq.get("cves") or DEFAULT_CVES]
        self.fixed = {_s(k): _s(v) for k, v in (faq.get("fixed") or DEFAULT_FIXED).items()}
        self.lowest = min(self.fixed.values(), key=_vtuple, default="")
        self.faq = (("Tenable Research FAQ", _s(faq.get("url")) or FAQ_URL, _s(faq.get("read_at")))
                    if faq else ("Default fixed releases", FAQ_URL, ""))
        self.catalog = {_s(p.get("plugin_id")): p for p in catalog}
        self.cov, self.pub = coverage(catalog), coverage_published(catalog)
        self.adv = run.advisories

    def kind(self, row: dict) -> str:
        """vendor | unpatched | version (version-only and anything unrecognised)."""
        src = _s(row.get("source")).upper()
        if src in ("CLOUD", "WAS"):
            return "vendor" if src == "CLOUD" else "version"
        pid, name = _s(row.get("plugin_id")), _s(row.get("plugin_name"))
        if pid in self.catalog:
            k = classify(self.catalog[pid])
            return k if k in ("vendor", "unpatched") else "version"
        # Not in plugins.json: judge by name; a fired plugin counts as distro-aware
        # unless it is a known version-only plugin.
        if name.startswith(UNPATCHED_PREFIXES):
            return "unpatched"
        if _VENDOR_NAME.search(name):
            return "vendor"
        return "version" if pid in _VERSION_ONLY_IDS else "vendor"

    def upstream(self, version: str) -> tuple:
        """(status, target) from the upstream version alone."""
        br = _branch(version)
        if not br or not _VERSION.search(version).group(3):
            return "unknown", ""
        if br in self.fixed:
            fixed = self.fixed[br]
            return ("patched" if _vtuple(_VERSION.search(version).group()) >= _vtuple(fixed)
                    else "vulnerable"), fixed
        if br in BACKPORT_ONLY:
            return "backport-only", self.lowest
        if (5, 4) <= _vtuple(br) <= (7, 3):
            return "eol", self.lowest
        return ("not-affected", "") if _vtuple(br) < (5, 4) else ("unknown", "")

    def upstream_ev(self, version: str, target: str, status: str) -> Evidence:
        name, url, read_at = self.faq
        return Evidence("upstream-version", name, _branch(version), url, version,
                        target or status, read_at)

    def rule5(self, version: str, fired: bool, hint: str = ""):
        """(code, action, target) by upstream branch, or None when the version is unknown."""
        status, target = self.upstream(version)
        if fired and status in ("patched", "not-affected", "unknown"):
            status, target = "vulnerable", target or self.fixed.get(hint, "")
        if status == "unknown":
            return None
        action = {"vulnerable": "patch", "backport-only": "isolate-or-upgrade",
                  "eol": "isolate-or-upgrade"}.get(status, "")
        return status, action, target

    def failed_feeds(self, distro: Optional[Distro]) -> list:
        src = _FEED.get(distro.family) if distro else None
        pre = _OSV_PREFIX.get(distro.family) if distro else None
        out = []
        for e in self.adv.failed_sources():
            url = (e.get("url") or "").upper()
            if e["source"] == src and (pre in url if pre else
                                       not any(p in url for p in _OSV_PREFIX.values())):
                out.append(e.get("url") or e["source"])
        return out


def _cov(table: dict, distro: Distro, rest: tuple = ()):
    for major in (distro.major, "*"):
        hit = table.get((distro.family, major) + rest)
        if hit is not None:
            return hit
    return None


def _stream_label(s: str) -> str:
    return s if s == "base" else "php:" + s


# --- package versions ---

def _package(distro: Optional[Distro], package: str):
    """(binary name, installed version) for the distro's format, or None if unknown."""
    fmt = _FORMAT.get(distro.family) if distro else None
    p = (package or "").strip()
    parts = p.split()
    if not fmt or not p:
        return None
    if fmt != "rpm" and len(parts) == 2:
        return parts[0], parts[1]
    if fmt == "rpm" and _NEVRA.match(p):
        n = parse_nevra(p)
        return n.name, ("%d:" % n.epoch if n.epoch else "") + "%s-%s" % (n.version, n.release)
    m = _APK.match(p) if fmt == "apk" else None
    return (m.group(1), m.group(2)) if m else None


# _rule3's result when the install is at or above the vendor fix but on another
# upstream version: a build from outside the vendor (a third-party repository), so
# rule 3 does not settle it and rule 5 judges it by upstream version.
OTHER_UPSTREAM = ("other-upstream", "")


def _rule3(family: str, pkg: tuple, recs: dict):
    """("vulnerable", fixed package) | ("patched", "") | OTHER_UPSTREAM | None when unsettled.

    Patched only when, for every CVE, the install is at or above each same-channel fix
    and its upstream version equals the highest fix's upstream version (R42)."""
    fmt = _FORMAT[family]
    cmp = _COMPARE[fmt]
    binary, installed = pkg
    below, settled, other_line = [], bool(recs), False
    try:
        mine = upstream_version(fmt, installed)
        for rs in recs.values():
            fixes = [r for r in rs if r.status == "fixed" and r.fixed_version]
            same = [r for r in fixes if not r.advisory_id.endswith(OTHER_CHANNEL)]
            if same:
                low = [r for r in same if cmp(installed, r.fixed_version) < 0]
                top = max(same, key=cmp_to_key(lambda a, b: cmp(a.fixed_version,
                                                                 b.fixed_version)))
                if not low and upstream_version(fmt, top.fixed_version) != mine:
                    other_line = True
            else:  # another channel's fix only shows vulnerable when below every fix
                low = [r for r in fixes if cmp(installed, r.fixed_version) < 0]
                low = low if fixes and len(low) == len(fixes) else []
            below += low
            settled = settled and bool(same) and not low
    except ValueError:
        return None
    if below:
        top = max(below, key=cmp_to_key(lambda a, b: cmp(a.fixed_version, b.fixed_version)))
        label = binary + (" " if _FORMAT[family] == "dpkg" else "-") + top.fixed_version
        return "vulnerable", label + (" (%s)" % top.advisory_id if top.advisory_id else "")
    if other_line:
        return OTHER_UPSTREAM
    return ("patched", "") if settled else None


# --- one install ---

def _judge(ctx: _Ctx, asset: dict, state: str, slot: _Slot) -> Verdict:
    inst, managed = slot.install, slot.install.managed_by_os
    os_name = _s(asset.get("os"))
    windows = "windows" in os_name.lower()
    distro = None if windows else distro_for(os_name, inst.package)
    distro_pkg = bool(managed and distro)  # OS-packaged on a recognised distro
    stream, last = stream_of(inst.package), _s(asset.get("last_seen"))
    on_os = managed is not False
    vendor = [r for r in slot.rows if on_os and ctx.kind(r) == "vendor"]
    unpatched = [r for r in slot.rows if on_os and ctx.kind(r) == "unpatched"]
    fired = any(ctx.kind(r) == "version" for r in slot.rows)
    ev_plugin = [_plugin_ev(r) for r in slot.rows]
    ev_cred = [_cred_ev(asset, state)] if state != "not-applicable" else []
    pkg = _package(distro, inst.package)
    recs = {c: ctx.adv.lookup(distro, inst.package, stream, c)
            for c in ctx.cves} if distro_pkg and inst.package else {}
    ev_feed = [_feed_ev(r, pkg[1] if pkg else inst.package) for rs in recs.values() for r in rs]
    r3 = _rule3(distro.family, pkg, recs) if pkg and recs and state == "credentialed" else None
    other_upstream = r3 == OTHER_UPSTREAM  # not the vendor's build: judged by rule 5
    r3 = None if other_upstream else r3

    def done(code, rule, first, action="", target=""):
        return _verdict(code, rule, first + ev_plugin + ev_feed + ev_cred, action, target)

    if vendor or unpatched:  # rules 1 and 2, with rule 3 agreeing or conflicting
        rule = ("1" if vendor else "2") + ("+3" if r3 else "")
        first = [_plugin_ev(r) for r in vendor + unpatched]
        if r3 and r3[0] == "patched":
            return done("conflict", rule, first + ev_feed)
        if vendor:
            ids = [a for a in dict.fromkeys(_advisory(r) for r in vendor) if a]
            targets = ids + ([r3[1]] if r3 else [])
            if not targets:  # Cloud finding: no advisory, so name the CVEs
                named = [_s(c).upper() for r in vendor for c in r.get("cves") or []]
                targets = [", ".join(dict.fromkeys(c for c in named if c))]
                targets = [t for t in targets if t]
            return done("vulnerable", rule, first, "vendor-update", "; ".join(targets))
        return done("no-vendor-fix", rule, first, "isolate-or-upgrade")
    if r3:
        return done(r3[0], "3", ev_feed, "vendor-update" if r3[1] else "", r3[1])

    statuses = {r.status for rs in recs.values() for r in rs}
    if "affected-no-fix" in statuses:
        unfixed = [e for e in ev_feed if e.expected == "affected-no-fix"]
        return done("no-vendor-fix", "4", unfixed, "isolate-or-upgrade")
    where = "%s %s %s" % (distro.family, distro.major, _stream_label(stream)) if distro else ""
    fixed = _cov(ctx.cov, distro) if distro_pkg else None
    no_record = (distro_pkg and not statuses and state == "credentialed" and fixed is not None
                 and stream not in fixed and ctx.upstream(inst.version)[0] in _UPSTREAM_AFFECTED)
    if distro_pkg and ("out-of-support" in statuses or no_record):  # rule 4a, else 4
        branch = stream if stream != "base" else _branch(inst.version)
        nums = sorted((s for s in fixed or () if re.fullmatch(r"\d+\.\d+", s)), key=_vtuple)
        target = next((s for s in nums if branch and _vtuple(s) > _vtuple(branch)), "")
        ev = [Evidence("absence", "Tenable plugin catalog", where, "", _stream_label(stream),
                       ", ".join(_stream_label(s) for s in sorted(fixed, key=_vtuple)))
              ] if fixed else []
        ev += [e for e in ev_feed if e.expected == "out-of-support"]
        if target:
            return done("no-stream-fix", "4a", ev, "upgrade-stream", "php:%s stream" % target)
        return done("no-vendor-fix", "4", ev, "isolate-or-upgrade")
    r5 = ctx.rule5(inst.version, fired) if managed is False or windows or other_upstream else None
    if r5:
        return done(r5[0], "5", [ctx.upstream_ev(inst.version, r5[2], r5[0])], r5[1], r5[2])
    # A module-stream family with no package has no known stream, so no rule 6.
    stream_known = distro_pkg and (distro.family not in _MODULE_FAMILIES or bool(
        re.search(r"php:\d+\.\d+", inst.package) or _NEVRA.match(inst.package)))
    pub = _cov(ctx.pub, distro, (stream,)) if stream_known else None
    published_before = bool(pub and last and pub <= last)
    no_feed = bool(distro) and distro.family in NO_FEED_FAMILIES
    if distro_pkg and state == "credentialed" and (not pkg or no_feed) and published_before:
        return done("likely-patched", "6", [Evidence(
            "absence", "Tenable plugin catalog", where, "",
            "no distro plugin fired; last seen %s" % last, "distro plugin published %s" % pub)])
    if state in ("not-credentialed", "failed"):
        return done("unverified-credentials", "7", ev_cred)

    if distro_pkg:
        missing = [PACKAGE_UNKNOWN] if not pkg else []
        if not stream_known:
            missing.append("module stream unknown (no package)")
        missing.append("vendor feed has no same-channel fix for every CVE" if statuses
                       else "no vendor feed the skill reads for this distro" if no_feed
                       else "no vendor feed record for this package")
        missing += ["%s: %s" % (FEED_FAILED, u) for u in ctx.failed_feeds(distro)]
        if not published_before:
            missing.append("no Tenable distro plugin published before the last scan")
    elif managed and not windows:
        missing = ["distro release not recognised"]
    elif managed is None and not windows:
        missing = ["not confirmed as distro-packaged (Managed by OS unknown)"]
    else:
        missing = ["PHP version unknown"]
    return done("unverified-no-data", "8", [Evidence(
        "absence", "verification rules", "", "", "; ".join(missing),
        "package version and vendor fix")])


# --- assets ---

def _key(row: dict) -> str:
    aid, name, ip = _s(row.get("asset_id")), _s(row.get("asset")), _s(row.get("ip"))
    return aid or ("%s|%s" % (name, ip) if name or ip else _s(row.get("url")))


def _asset(raw, rows: list) -> dict:
    """Contract fields only, so no stray field (such as auth output) is carried on."""
    raw = raw if isinstance(raw, dict) else {}
    a = {f: (list(raw.get(f) or []) if f in _LISTS else raw.get(f)) for f in ASSET_FIELDS}
    if not raw:
        a["name"] = _s(rows[0].get("asset")) or urlparse(_s(rows[0].get("url"))).hostname or ""
        a["ips"] = sorted({_s(r.get("ip")) for r in rows} - {""})
        a["fqdns"] = sorted({_s(r.get("fqdn")) for r in rows} - {""})
        a["sensors"] = sorted({_s(r.get("source")) for r in rows} - {""})
        a["os"] = ""
    if not a["last_seen"]:
        a["last_seen"] = max((_s(r.get("last_seen")) for r in rows), default="")
    return a


def _slots(ctx: _Ctx, rows: list) -> tuple:
    """Installs on a VM or Cloud asset, each with the vulnerable rows bearing on it."""
    installs, truncated = [], False
    inventory = [r for r in rows if r.get("role") == "inventory"]
    for r in inventory:
        got, cut = parse_installs(_s(r.get("plugin_output")))
        installs += got
        truncated = truncated or cut
    if not installs and inventory:  # detected, but no install blocks in the output
        installs = [Install("", _s(r.get("php_version")), "", None)
                    for r in inventory if _s(r.get("php_version"))] or [Install("", "", "", None)]
    vuln = [r for r in rows if r.get("role") == "vulnerable"]
    if not installs:  # no inventory: one synthetic install per vulnerable row
        installs = [Install("", _s(r.get("php_version")), "", None) for r in vuln]
    slots = [_Slot(i, []) for i in dict.fromkeys(installs)]
    for r in sorted(vuln, key=lambda r: ctx.kind(r) == "version"):  # distro-aware rows first
        if ctx.kind(r) == "version":
            hit = [s for s in slots if s.install.version == _s(r.get("php_version"))] or slots
        else:
            hit = [s for s in slots if s.install.managed_by_os is not False]
            if not hit:  # only non-OS installs: the distro plugin gets its own install
                own = Install("", _s(r.get("php_version")), "", None)
                hit = [_Slot(own, [])]
                slots.append(hit[0])
        for s in hit:
            s.rows.append(r)
    return slots, truncated


def _join(row: dict, vm: dict) -> Optional[str]:
    host = (urlparse(_s(row.get("url"))).hostname or _s(row.get("fqdn"))).lower()
    ip = _s(row.get("ip"))
    hits = [k for k, (names, ips) in vm.items()
            if (host and (host in names or host in ips)) or (ip and ip in ips)]
    return hits[0] if len(hits) == 1 else None


def _was_install(ctx: _Ctx, row: dict, conflict: bool, patched_ev: list) -> tuple:
    inst = Install("", _s(row.get("php_version")), "", None)
    hint = WAS_BRANCH.get(_s(row.get("plugin_id")), "")
    code, action, target = ctx.rule5(inst.version, True, hint)
    up = ctx.upstream_ev(inst.version, target, code)
    if conflict:
        return inst, _verdict("conflict", "5+3", [_plugin_ev(row), up] + patched_ev)
    return inst, _verdict(code, "5", [up, _plugin_ev(row)], action, target)


def judge(run: Run) -> list:
    """One AssetResult per asset key, sorted by key."""
    ctx = _Ctx(run)
    assets = run.assets if isinstance(run.assets, dict) else {}
    groups: dict = {}
    was = []
    for row in run.findings or []:
        if not isinstance(row, dict):
            continue
        if _s(row.get("source")).upper() == "WAS":
            was.append(row)
        else:
            groups.setdefault(_key(row), []).append(row)
    vm = {}  # VM asset key -> (fqdns, ips) a WAS row can join on
    for k, rows in groups.items():
        if any(_s(r.get("source")).upper() == "VM" for r in rows):
            a = _asset(assets.get(k), rows)
            vm[k] = ({_s(x).lower() for x in a["fqdns"] + [r.get("fqdn") for r in rows]} - {""},
                     {_s(x) for x in a["ips"] + [r.get("ip") for r in rows]} - {""})
    joined: dict = {}
    for row in was:
        k = _join(row, vm) or _s(row.get("url")) or _key(row)
        joined.setdefault(k, []).append(row)

    out = []
    for key in sorted(set(groups) | set(joined)):
        rows, was_rows = groups.get(key, []), joined.get(key, [])
        asset = _asset(assets.get(key), rows + was_rows)
        state = credential_state(asset, key)
        slots, truncated = _slots(ctx, rows)
        pairs = [(s.install, _judge(ctx, asset, state, s)) for s in slots]
        patched = bool(pairs) and all(v.code == "patched" for _, v in pairs)
        patched_ev = [v.evidence[0] for _, v in pairs if v.evidence] if patched else []
        pairs += [_was_install(ctx, r, patched, patched_ev) for r in was_rows]
        out.append(AssetResult(
            key, asset, pairs, state, truncated,
            {_s(r.get("source")) for r in rows + was_rows} - {""},
            sorted({_s(r.get("url")) for r in was_rows} - {""})))
    return out
