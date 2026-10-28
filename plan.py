"""Rank verified findings and write the action plan handoff (action-plan.json).

build_plan(results, run, owners, generated_at) turns verify.judge's results into
the dict schemas/action-plan.schema.json describes: assets that need action in
`items` (ranked FIRST > NEXT > SOON), assets that could not be verified in
`verify_first`, and counts in `coverage`. Assets with only patched or
not-affected installs appear in neither list but are still counted.
"""
from __future__ import annotations

import csv
import ipaddress
import re
from datetime import date, datetime
from pathlib import Path
from typing import Optional

from verify import (ACTIONABLE, DEFAULT_CVES, DEFAULT_FIXED, FAILURE_IDS, FAQ_URL, FEED_FAILED,
                    PACKAGE_UNKNOWN, VERDICTS, VERIFY_FIRST, _key, _s)

SKILL_VERSION = "2.0.0"
SCHEMA_VERSION = "1.0"
AUTH_URL = "https://exchange.tenable.com/skills/auth-failure-analyzer/"
DEFAULT_SINCE = "2026-10-17"
DEFAULT_MITIGATIONS = [
    "Set memory_limit=-1",
    "Set session.upload_progress.enabled=0",
    "On PHP 8.5 only, set fatal_error_backtraces=0",
    "Restart every PHP worker",
]
STALE_DAYS = 30
BUCKETS = ("FIRST", "NEXT", "SOON")

# The documentation ranges stand in for public addresses in fixtures and examples.
_PUBLIC_STANDINS = [ipaddress.ip_network(n) for n in
                    ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
# Worst first: the install whose verdict sets an item's action and fix target.
_WORST = ["eol", "no-vendor-fix", "no-stream-fix", "backport-only", "vulnerable"]
# A host's headline verdict for coverage counts: worst first.
_HEADLINE = _WORST + ["conflict", "unverified-credentials", "unverified-no-data",
                      "likely-patched", "patched", "not-affected"]
_CREDENTIAL_STATES = ("credentialed", "not-credentialed", "failed", "not-applicable")
_WEB_PHP = re.compile(r"fpm|cgi|mod_php|libphp")
_CLI_NAME = re.compile(r"^php(\d+(\.\d+)*)?(-cli)?(\.exe)?$")
_ACTIVITY = {"critical": 0, "high": 1}


# --- owners ---

_ID_COLUMNS = ("asset_id", "hostname", "fqdn", "ip")


def _norm(value) -> str:
    return _s(value).lower()


class Owners:
    """Owner file lookups: asset_id, then hostname, FQDN and IP; first non-blank owner wins."""

    def __init__(self, by_column: Optional[dict] = None, duplicates: int = 0):
        self._by = by_column or {}
        self.duplicates = duplicates

    def match(self, asset: dict, key: str) -> Optional[str]:
        wanted = [("asset_id", [key]), ("hostname", [asset.get("name")]),
                  ("fqdn", asset.get("fqdns") or []), ("ip", asset.get("ips") or [])]
        for column, values in wanted:
            table = self._by.get(column, {})
            for v in values:
                if _norm(v) and _norm(v) in table:
                    return table[_norm(v)]
        return None


def load_owners(path: Optional[Path]) -> Owners:
    """Read an owner CSV; Excel quirks are handled (BOM, header case, repeated rows)."""
    if path is None:
        return Owners()
    try:
        return _read_owners(path)
    except UnicodeDecodeError:
        raise ValueError("owner file is not UTF-8; save it as CSV UTF-8 (%s)" % path) from None


def _read_owners(path: Path) -> Owners:
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        header = [h.strip().lower() for h in next(reader, [])]
        if "owner" not in header:
            raise ValueError("owner file %s has no 'owner' column (headers: %s)"
                             % (path, ", ".join(header) or "none"))
        columns = [c for c in _ID_COLUMNS if c in header]
        if not columns:
            raise ValueError("owner file %s needs at least one of: %s"
                             % (path, ", ".join(_ID_COLUMNS)))
        at = {c: header.index(c) for c in columns}
        tables: dict = {c: {} for c in columns}
        duplicates = 0
        for row in reader:
            def cell(i):
                return _s(row[i]) if i < len(row) else ""
            owner = cell(header.index("owner"))
            if not owner:
                continue
            ids = {c: _norm(cell(i)) for c, i in at.items()}
            if any(v and v in tables[c] for c, v in ids.items()):
                duplicates += 1
            for c, v in ids.items():
                if v:
                    tables[c].setdefault(v, owner)
    return Owners(tables, duplicates)


def owner_for(result, owners: Owners) -> tuple:
    """(owner, owner_source): the owner file, then a Tenable tag, else unassigned."""
    hit = owners.match(result.asset, result.key)
    if hit:
        return hit, "owner-file"
    tag = result.asset.get("owner_tag")
    if isinstance(tag, dict) and _s(tag.get("value")):
        category = _s(tag.get("category")) or "Owner"
        return _s(tag.get("value")), "tag:" + category
    return "", "unassigned"


# --- classification ---

def _asset_id(result) -> str:
    """The Tenable asset ID, or "" when the key is a name|ip or URL stand-in."""
    key = result.key
    return "" if "|" in key or key.lower().startswith(("http://", "https://")) else key


def _analyzer_target(result) -> str:
    """What to name in "analyze auth failures on ...": asset ID, else hostname, else IP."""
    a = result.asset
    return _asset_id(result) or _s(a.get("name")) or next(iter(a.get("ips") or []), "")


def _score(value):
    """A number, or None for anything else (such as "N/A"); never estimated."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _apa(value):
    v = _s(value).lower()
    return v if v in _ACTIVITY else None


def _is_was(result) -> bool:
    return any(s.upper() == "WAS" for s in result.sources) or bool(result.urls)


def internet_facing(result) -> bool:
    """A WAS finding, or a public IP (documentation ranges count as public)."""
    if _is_was(result):
        return True
    for ip in result.asset.get("ips") or []:
        try:
            addr = ipaddress.ip_address(_s(ip))
        except ValueError:
            continue
        if addr.is_global or any(addr in net for net in _PUBLIC_STANDINS if addr.version == 4):
            return True
    return False


def _command_line(install) -> bool:
    name = re.split(r"[\\/]", install.path.strip())[-1].lower()
    return bool(name) and bool(_CLI_NAME.match(name)) and not _WEB_PHP.search(
        (install.path + " " + install.package).lower())


def serves_web(result) -> bool:
    """False only when there is no WAS finding, no HTTP service seen (10107; unknown counts
    as not seen), the install list is complete, and every install is command-line PHP."""
    if _is_was(result) or result.asset.get("http_service") is True or result.output_truncated:
        return True
    return not (result.installs and all(_command_line(i) for i, _ in result.installs))


def _actionable(result) -> bool:
    return any(v.code in ACTIONABLE for _, v in result.installs)


def bucket(result) -> str:
    if not _actionable(result):
        return "VERIFY"
    if internet_facing(result):
        return "FIRST"
    return "NEXT" if serves_web(result) else "SOON"


def _num(value) -> str:
    return "%g" % value if isinstance(value, (int, float)) else _s(value)


def reason(result) -> str:
    """One line on why this asset sits where it does; missing scores are left out."""
    a = result.asset
    if not _actionable(result):
        labels = list(dict.fromkeys(v.label for _, v in result.installs
                                    if v.code in VERIFY_FIRST))
        return "; ".join(labels) or "No PHP install to verify"
    if internet_facing(result):
        parts = ["internet-facing (%s)" % ("WAS" if _is_was(result) else "public IP")]
    else:
        where = "internal" if result.asset.get("ips") else "no public IP recorded"
        parts = [where if serves_web(result) else where + ", no sign PHP serves web requests"]
    if _apa(a.get("apa_level")):
        parts.append("%s attack path" % _apa(a.get("apa_level")))
    if _score(a.get("acr")) is not None:
        parts.append("ACR " + _num(_score(a.get("acr"))))
    return ", ".join(parts)


def _sort_key(result):
    a = result.asset
    def score(v):
        return (v is None, -(v or 0))
    return (_ACTIVITY.get(_apa(a.get("apa_level")), 2), score(_score(a.get("acr"))),
            score(_score(a.get("aes"))),
            _s(a.get("name")).lower(), result.key)


def _worst(result):
    codes = {v.code for _, v in result.installs}
    code = next((c for c in _WORST if c in codes), None)
    return next((v for _, v in result.installs if v.code == code), None)


def _headline(result) -> str:
    codes = {v.code for _, v in result.installs}
    return next((c for c in _HEADLINE if c in codes), "")


def _plugin_ids(result) -> list:
    ids = {e.reference_id for _, v in result.installs for e in v.evidence
           if e.type == "tenable-plugin" and e.reference_id.isdigit()}
    return sorted(ids)


def verification(result) -> dict:
    return {"rescan": True, "plugins_should_stop": _plugin_ids(result)}


def _feed_failed(result) -> bool:
    """A credentialed host with a known package left unverified because a feed fetch failed."""
    if result.credential_state != "credentialed":
        return False
    for inst, v in result.installs:
        notes = " ".join(e.observed for e in v.evidence if e.type == "absence")
        if (v.code == "unverified-no-data" and inst.package and FEED_FAILED in notes
                and PACKAGE_UNKNOWN not in notes):
            return True
    return False


def next_step(result) -> str:
    codes = {v.code for _, v in result.installs}
    if "unverified-credentials" in codes:
        text = ("Run Auth Failure Analyzer: analyze auth failures on "
                + _analyzer_target(result)
                if result.credential_state == "failed"
                else "Configure credentialed scans and rescan")
    elif "conflict" in codes:
        text = "Resolve conflicting evidence"
    elif "likely-patched" in codes:
        text = "Rescan with credentials after the next plugin update to confirm"
    elif _feed_failed(result):
        text = "Re-run fetch_advisories.py, then re-render with render.py"
    else:
        text = "Rescan with credentials to verify"
    if result.asset.get("unpatched_scan") is False:
        text += "; turn on Scan for Unpatched Vulnerabilities"
    return text


def _stale(asset: dict, generated_at: datetime) -> bool:
    try:
        seen = date.fromisoformat(_s(asset.get("last_seen"))[:10])
    except ValueError:
        return False
    return (generated_at.date() - seen).days > STALE_DAYS


# --- plan ---

def _vulnerability(run) -> dict:
    faq = run.faq if isinstance(run.faq, dict) else {}
    mitigations = [_s(m) for m in faq.get("mitigations") or [] if _s(m)] or list(DEFAULT_MITIGATIONS)
    out = {"cves": [_s(c).upper() for c in faq.get("cves") or DEFAULT_CVES],
           "fixed": {_s(k): _s(v) for k, v in (faq.get("fixed") or DEFAULT_FIXED).items()},
           "exploitation_since": _s(faq.get("exploitation_since")) or DEFAULT_SINCE,
           "faq_url": _s(faq.get("url")) or FAQ_URL,
           "interim_mitigations": mitigations}
    if isinstance(faq.get("cvss"), (int, float, str)) and not isinstance(faq.get("cvss"), bool):
        out["cvss"] = faq["cvss"]
    return out


def _sources(run) -> list:
    faq = run.faq if isinstance(run.faq, dict) else {}
    out = [{"source": "tenable-hexa", "cve": "", "url": "", "fetched_at": "",
            "status": "ok", "error": ""},
           {"source": "tenable-faq", "cve": "", "url": _s(faq.get("url")) or FAQ_URL,
            "fetched_at": _s(faq.get("read_at")),
            "status": "ok" if faq else "skipped",
            "error": "" if faq else "faq.json not read; default fixed releases used"}]
    for e in run.advisories.sources():
        out.append({"source": _s(e.get("source")), "cve": _s(e.get("cve")),
                    "url": _s(e.get("url")), "fetched_at": _s(e.get("fetched_at")),
                    "status": _s(e.get("status")), "error": _s(e.get("error"))})
    return out


def _rows_by_asset(run, results) -> dict:
    urls = {u: r.key for r in results for u in r.urls}
    rows: dict = {}
    for row in run.findings or []:
        if isinstance(row, dict):
            k = urls.get(_s(row.get("url")), "") if _s(row.get("source")).upper() == "WAS" \
                else _key(row)
            rows.setdefault(k, []).append(row)
    return rows


def _install(inst, verdict, rows: list, siblings: list) -> dict:
    ev = [_evidence(e) for e in verdict.evidence]
    plugin = next((e["reference_id"] for e in ev
                   if e["type"] == "tenable-plugin" and e["reference_id"].isdigit()), "")
    if not plugin:
        plugin = next((_s(r.get("plugin_id")) for r in rows if r.get("role") == "inventory"), "")
    same = [i for i in siblings if i.version == inst.version]
    ports = {_s(r.get("port")) for r in rows
             if r.get("role") == "vulnerable" and _s(r.get("php_version")) == inst.version} - {""}
    return {"version": inst.version, "package": inst.package, "path": inst.path,
            "port": ports.pop() if len(ports) == 1 and len(same) == 1 else "",
            "source_plugin": plugin, "verdict": verdict.code, "verdict_label": verdict.label,
            "rule": verdict.rule, "evidence": ev}


def _evidence(e) -> dict:
    return {"type": e.type, "source": e.source, "reference_id": e.reference_id, "url": e.url,
            "observed": e.observed, "expected": e.expected, "fetched_at": e.fetched_at}


def _entry(result, owners, rows, mitigations, since, generated_at) -> dict:
    a = result.asset
    owner, source = owner_for(result, owners)
    actionable = _actionable(result)
    web = internet_facing(result)
    compromise = web and actionable
    siblings = [i for i, _ in result.installs]
    return {
        "key": result.key, "asset_id": _asset_id(result),
        "hostname": _s(a.get("name")),
        "fqdn": next(iter(a.get("fqdns") or []), ""),
        "ip": next(iter(a.get("ips") or []), ""),
        "url": next(iter(result.urls), ""),
        "owner": owner, "owner_source": source,
        "bucket": bucket(result), "rank": None, "reason": reason(result),
        "compromise_note": ("Assume compromise; check for exploitation since %s." % since
                            if compromise else ""),
        "action": None, "fix_target": None,
        "php_installs": [_install(i, v, rows, siblings) for i, v in result.installs],
        "flags": {"internet_facing": web, "serves_web": serves_web(result),
                  "possible_compromise": compromise, "stale": _stale(a, generated_at),
                  "output_truncated": result.output_truncated,
                  "credential_state": result.credential_state,
                  "unpatched_scan": a.get("unpatched_scan")},
        "interim_mitigations": list(mitigations),
        "verification": verification(result),
        "context": {"aes": _score(a.get("aes")), "acr": _score(a.get("acr")),
                    "apa_level": _apa(a.get("apa_level")), "last_seen": _s(a.get("last_seen"))},
    }


def build_plan(results, run, owners: Owners, generated_at: datetime) -> dict:
    vuln = _vulnerability(run)
    rows = _rows_by_asset(run, results)
    coverage = {"by_credential_state": dict.fromkeys(_CREDENTIAL_STATES, 0),
                "by_verdict": dict.fromkeys(VERDICTS, 0),
                "by_owner_source": {"owner-file": 0, "unassigned": 0},
                "unassigned_actionable": 0, "output_truncated_assets": []}
    ranked: dict = {b: [] for b in BUCKETS}
    verify_first = []
    for r in results:
        entry = _entry(r, owners, rows.get(r.key, []), vuln["interim_mitigations"],
                       vuln["exploitation_since"], generated_at)
        counts = coverage["by_owner_source"]
        counts[entry["owner_source"]] = counts.get(entry["owner_source"], 0) + 1
        coverage["by_credential_state"][r.credential_state] += 1
        if _headline(r):
            coverage["by_verdict"][_headline(r)] += 1
        if r.output_truncated:
            coverage["output_truncated_assets"].append(r.key)
        if _actionable(r):
            worst = _worst(r)
            entry["action"], entry["fix_target"] = worst.action, worst.fix_target
            ranked[entry["bucket"]].append((_sort_key(r), entry))
            coverage["unassigned_actionable"] += entry["owner_source"] == "unassigned"
        elif any(v.code in VERIFY_FIRST for _, v in r.installs):
            entry["next_step"] = next_step(r)
            verify_first.append((_sort_key(r)[3:], entry))
    items = []
    for b in BUCKETS:
        for _, entry in sorted(ranked[b], key=lambda t: t[0]):
            entry["rank"] = len(items) + 1
            items.append(entry)
    return {"schema_version": SCHEMA_VERSION, "generated_at": generated_at.isoformat(),
            "skill_version": SKILL_VERSION, "vulnerability": vuln, "sources": _sources(run),
            "coverage": coverage, "items": items,
            "verify_first": [e for _, e in sorted(verify_first, key=lambda t: t[0])]}


# --- Auth Failure Analyzer handoff ---

def auth_followup(results) -> str:
    """Text for auth-followup.txt: the listing link, one example per plugin, then every host."""
    groups: dict = {}
    for r in results:
        if r.credential_state != "failed":
            continue
        ids = sorted({int(x) for x in r.asset.get("auth_plugins") or []
                      if str(x).isdigit()} & FAILURE_IDS)
        for pid in ids:
            groups.setdefault(pid, []).append(r)
    lines = [AUTH_URL, ""]
    if not groups:
        lines.append("No hosts with failed credentials.")
    for pid in sorted(groups):
        hosts = groups[pid]
        lines.append("Plugin %d, %d host%s. Example: analyze auth failures on %s"
                     % (pid, len(hosts), "" if len(hosts) == 1 else "s",
                      _analyzer_target(hosts[0])))
    if groups:
        lines.append("")
    for pid in sorted(groups):
        for r in groups[pid]:
            a = r.asset
            lines.append("\t".join([_asset_id(r), _s(a.get("name")),
                                    next(iter(a.get("ips") or []), ""), str(pid)]))
    return "\n".join(lines) + "\n"
