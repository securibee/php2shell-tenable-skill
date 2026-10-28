"""Offline lookup of vendor fixed versions in the feeds fetch_advisories.py saved.

Advisories.load(run_dir) reads advisories/index.json and every raw file the index
marks "ok". lookup(distro, package, stream, cve) answers: what does this distro's
own vendor say about this package, stream and CVE? Each vendor's feed is used only
for that vendor's packages, and a record is returned only when the package name,
the stream and (for RHEL) the minor-release channel line up.
"""
from __future__ import annotations

import json
import re
from functools import cmp_to_key
from pathlib import Path
from typing import NamedTuple, Optional

from inventory import Distro, stream_of
from versions import compare_rpm, dist_tag


class FixRecord(NamedTuple):
    source: str          # "osv" | "redhat" | "alpine"
    cve: str
    advisory_id: str     # RHEL: suffixed OTHER_CHANNEL when the fix is for another minor release
    url: str
    fetched_at: str
    status: str          # "fixed" | "affected-no-fix" | "not-affected" | "out-of-support"
    fixed_version: str   # "" unless status is "fixed"
    package: str         # package name as the vendor lists it


class _Candidate(NamedTuple):
    scope: tuple         # ("rhel", major) | ("osv", ecosystem) | ("alpine", release)
    cve: str
    name: str
    stream: str
    status: str
    fixed_version: str
    dist_tag: str
    advisory_id: str
    url: str
    source: str
    fetched_at: str


OTHER_CHANNEL = " (other channel)"
SOURCE_KEYS = ("source", "cve", "url", "fetched_at", "status", "error")
OSV_FAMILIES = {"ubuntu", "debian", "alma", "rocky", "suse"}
RPM_FAMILIES = {"rhel", "alma", "rocky", "suse"}
_OSV_RPM_ECOSYSTEMS = ("AlmaLinux", "Rocky Linux", "SUSE", "openSUSE")

_CVE = re.compile(r"CVE-\d{4}-\d+")
_EL_MAJOR = re.compile(r"el(\d+)")
# Installed packages: RPM NEVRA, dpkg "name version", apk "name-version-rN".
_NEVRA = re.compile(r"^(?P<name>\S+)-(?:\d+:)?[^-:\s]+-(?P<release>[^-:\s]+)\.[A-Za-z0-9_]+$")
_APK = re.compile(r"^(?P<name>\S+?)-\d[^-\s]*-r\d+$")
# Red Hat VEX components: "php-cli-0:8.2.35-1.module+el8.10.0+25110+f67151d2.x86_64::php:8.2"
# (the "::module:stream" suffix only on module builds) or unversioned "php-cli[::php:8.4]".
_RH_NEVRA = re.compile(
    r"^(?P<nevra>(?P<name>.+)-(?P<epoch>\d+):(?P<version>[^-:]+)-(?P<release>[^-:]+)"
    r"\.[A-Za-z0-9_]+)(?:::(?P<module>[^:]+):(?P<stream>[^:]+))?$")
_RH_NAME = re.compile(r"^(?P<name>[^:]+?)(?:::(?P<module>[^:]+):(?P<stream>[^:]+))?$")
_RH_ADVISORY = re.compile(r"RH[SBE]A-\d{4}:\d+")
_RH_CPE_MAJOR = re.compile(r"^cpe:/[ao]:redhat:(?:enterprise_linux|rhel)[a-z0-9_]*:(\d+)")
_ALPINE_FILE = re.compile(r"^alpine-v(\d+\.\d+)\.json$")


# --- Red Hat CSAF VEX ---

def _rh_platform_majors(tree: dict) -> dict:
    """Product ID -> RHEL major, from each product's CPE in the product tree."""
    out: dict = {}
    stack = list(tree.get("branches") or [])
    while stack:
        b = stack.pop()
        p = b.get("product") or {}
        cpe = (p.get("product_identification_helper") or {}).get("cpe") or ""
        m = _RH_CPE_MAJOR.match(cpe)
        if p.get("product_id") and m:
            out[p["product_id"]] = m.group(1)
        stack.extend(b.get("branches") or [])
    return out


def _rh_component(comp: str):
    """(name, stream, fixed_version, dist_tag) of a component, or None to skip it."""
    m = _RH_NEVRA.match(comp)
    if m:
        stream = stream_of(m["nevra"])
        if m["module"] and (m["module"] != "php" or m["stream"] != stream):
            return None
        evr = "%s-%s" % (m["version"], m["release"])
        if m["epoch"] != "0":
            evr = m["epoch"] + ":" + evr
        return m["name"], stream, evr, dist_tag(m["release"])
    m = _RH_NAME.match(comp)
    if not m or (m["module"] and m["module"] != "php"):
        return None
    return m["name"], m["stream"] or "base", "", ""


def _rh_advisory(rems: list, url: str) -> tuple:
    """(advisory ID, errata URL) from the vendor_fix remediation of a fixed product."""
    for r in rems:
        if r.get("category") == "vendor_fix":
            m = (_RH_ADVISORY.search(r.get("url") or "")
                 or _RH_ADVISORY.search(r.get("details") or ""))
            if m:
                return m.group(), r.get("url") or url
    return "", url


def _rh_unfixed(key: str, rems: list) -> str:
    if key == "known_not_affected":
        return "not-affected"
    words = " ".join("%s %s" % (r.get("category") or "", r.get("details") or "")
                     for r in rems).lower()
    return "out-of-support" if "out of support" in words else "affected-no-fix"


def _redhat(doc: dict, entry: dict) -> list:
    tree = doc.get("product_tree") or {}
    majors = _rh_platform_majors(tree)
    rels = {}
    for r in tree.get("relationships") or []:
        pid = (r.get("full_product_name") or {}).get("product_id")
        if pid:
            rels[pid] = (r.get("relates_to_product_reference") or "",
                         r.get("product_reference") or "")
    out = []
    for vuln in doc.get("vulnerabilities") or []:
        cve = str(vuln.get("cve") or "").upper()
        if not _CVE.fullmatch(cve):
            continue
        rems: dict = {}
        for r in vuln.get("remediations") or []:
            for pid in r.get("product_ids") or []:
                rems.setdefault(pid, []).append(r)
        status = vuln.get("product_status") or {}
        for key in ("fixed", "known_affected", "known_not_affected"):
            for pid in status.get(key) or []:
                if pid in rels:
                    platform, comp = rels[pid]
                else:  # "<platform>:<component>"
                    platform, _, comp = pid.partition(":")
                major = majors.get(platform)
                parsed = _rh_component(comp) if major else None
                if not parsed:
                    continue
                name, stream, evr, tag = parsed
                advisory, url = "", entry["url"]
                if key == "fixed":
                    el = _EL_MAJOR.match(re.sub(r"^module\+", "", tag))
                    if not evr or not el or el.group(1) != major:
                        continue  # a fix must carry this major's el dist tag
                    st = "fixed"
                    advisory, url = _rh_advisory(rems.get(pid, []), url)
                else:
                    st, evr, tag = _rh_unfixed(key, rems.get(pid, [])), "", ""
                out.append(_Candidate(("rhel", major), cve, name, stream, st, evr, tag,
                                      advisory, url, "redhat", entry["fetched_at"]))
    return out


# --- OSV ---

def _osv_advisory(doc: dict) -> str:
    rid = str(doc.get("id") or "")
    if _CVE.search(rid):  # CVE-keyed record (UBUNTU-CVE-..., DEBIAN-CVE-...)
        for r in doc.get("related") or []:
            if not _CVE.fullmatch(str(r).upper()):
                return str(r)
    return rid


def _osv(doc: dict, entry: dict) -> list:
    if doc.get("withdrawn"):
        return []
    ids = [doc.get("id")] + list(doc.get("aliases") or []) + list(doc.get("upstream") or []) \
        + list(doc.get("related") or [])
    cves = sorted({str(i).upper() for i in ids if _CVE.fullmatch(str(i or "").upper())})
    advisory = _osv_advisory(doc)
    url = entry["url"]
    keys = {advisory, advisory.replace(":", "-")} - {""}
    for ref in doc.get("references") or []:
        if ref.get("type") == "ADVISORY" and any(k in (ref.get("url") or "") for k in keys):
            url = ref["url"]
            break
    out = []
    for aff in doc.get("affected") or []:
        pkg = aff.get("package") or {}
        eco, name = pkg.get("ecosystem") or "", pkg.get("name") or ""
        if not eco or not name:
            continue
        rpm = eco.split(":")[0] in _OSV_RPM_ECOSYSTEMS
        fixed = [ev["fixed"] for rng in aff.get("ranges") or []
                 if rng.get("type") == "ECOSYSTEM"
                 for ev in rng.get("events") or [] if ev.get("fixed")]
        rows = [("fixed", v) for v in fixed]
        if not fixed and not rpm:
            rows = [("affected-no-fix", "")]  # listed as affected, no fixed event
        for st, ver in rows:
            stream = "base"
            if rpm:  # stream_of reads both "module_el8" (Alma) and "module+el8"
                stream = stream_of("%s-%s.noarch" % (name, ver))
            for cve in cves:
                out.append(_Candidate(("osv", eco), cve, name, stream, st, ver, "",
                                      advisory, url, "osv", entry["fetched_at"]))
    return out


# --- Alpine secdb ---

def _alpine(doc: dict, entry: dict) -> list:
    release = _ALPINE_FILE.match(entry["file"]).group(1)
    if doc.get("distroversion") not in (None, "v" + release):
        raise ValueError("distroversion %r in %s" % (doc.get("distroversion"), entry["file"]))
    advisory = "secdb v%s/%s" % (release, doc.get("reponame") or "")
    out = []
    for p in doc.get("packages") or []:
        pkg = p.get("pkg") or {}
        name = pkg.get("name") or ""
        for ver, fixes in (pkg.get("secfixes") or {}).items():
            st, ver = ("not-affected", "") if ver == "0" else ("fixed", ver)
            for cve in dict.fromkeys(c for s in fixes for c in _CVE.findall(str(s).upper())):
                out.append(_Candidate(("alpine", release), cve, name, "base", st, ver, "",
                                      advisory, entry["url"], "alpine", entry["fetched_at"]))
    return out


_BUILDERS = {"redhat": _redhat, "osv": _osv, "alpine": _alpine}


# --- matching ---

def _scope(distro: Distro) -> Optional[tuple]:
    if distro.family == "rhel":
        return ("rhel", distro.major)
    if distro.family in OSV_FAMILIES:
        return ("osv", distro.ecosystem) if distro.ecosystem else None
    if distro.family == "alpine":
        return ("alpine", distro.major)
    return None  # Oracle, Amazon, CentOS, Fedora: no feed


def _installed(distro: Distro, package: str):
    """(binary name, RPM release) of the installed package string."""
    pkg = (package or "").strip()
    m = None
    if distro.family in RPM_FAMILIES:
        m = _NEVRA.match(pkg)
    elif distro.family == "alpine":
        m = _APK.match(pkg)
    if m:
        return m["name"], m.groupdict().get("release") or ""
    return (pkg.split()[0] if pkg else ""), ""  # dpkg "name version", or a bare name


def _by_name(cands: list, binary: str) -> list:
    """Records for the exact binary name; else for its source name (up to the first -)."""
    exact = [c for c in cands if c.name == binary]
    if exact:
        return exact
    source = binary.split("-")[0]
    return [c for c in cands if c.name == source]


def _rhel_channel(cands: list, tag: str) -> list:
    """Same-channel fixes; else the lowest fix for the major, flagged as another channel."""
    fixes = [c for c in cands if c.status == "fixed"]
    rest = [c for c in cands if c.status != "fixed"]
    same = [c for c in fixes if tag and c.dist_tag == tag]
    if same or not fixes:
        return same + rest
    low = min(fixes, key=cmp_to_key(lambda a, b: compare_rpm(a.fixed_version, b.fixed_version)))
    return [low._replace(advisory_id=low.advisory_id + OTHER_CHANNEL)] + rest


class Advisories:
    def __init__(self, entries: list, candidates: list):
        self._entries = entries
        self._scopes: dict = {}
        for c in candidates:
            self._scopes.setdefault(c.scope, []).append(c)

    @classmethod
    def load(cls, run_dir) -> "Advisories":
        adv_dir = Path(run_dir) / "advisories"
        try:
            index = json.loads((adv_dir / "index.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls([], [])
        except (OSError, ValueError) as e:
            return cls([{"source": "index", "cve": "", "url": "", "fetched_at": "",
                         "status": "failed",
                         "error": "advisories/index.json unreadable: %s" % e}], [])
        entries, candidates = [], []
        for raw in index if isinstance(index, list) else []:
            if not isinstance(raw, dict):
                continue
            e = {k: raw.get(k) for k in SOURCE_KEYS}
            e["url"], e["fetched_at"] = e["url"] or "", e["fetched_at"] or ""
            e["cve"] = e["cve"] or ""
            entries.append(e)
            if e["status"] != "ok":
                continue
            fname = raw.get("file")
            builder = _BUILDERS.get(e["source"])
            if (not builder or not isinstance(fname, str) or Path(fname).name != fname
                    or fname.startswith(".")
                    or (e["source"] == "alpine" and not _ALPINE_FILE.match(fname))):
                e["status"], e["error"] = "failed", "saved file not usable: %r" % fname
                continue
            try:
                doc = json.loads((adv_dir / fname).read_text(encoding="utf-8"))
                candidates.extend(builder(doc, dict(e, file=fname)))
            except (OSError, ValueError) as err:
                e["status"], e["error"] = "failed", "saved file unreadable: %s" % err
            except (AttributeError, KeyError, TypeError) as err:
                e["status"] = "failed"
                e["error"] = "saved file not in the expected format: %r" % err
        return cls(entries, candidates)

    def sources(self) -> list:
        return [dict(e) for e in self._entries]

    def failed_sources(self) -> list:
        return [dict(e) for e in self._entries if e["status"] == "failed"]

    def lookup(self, distro: Distro, package: str, stream: str, cve: str) -> list:
        """Vendor records for this package; [] when stream disagrees with stream_of(package)."""
        scope = _scope(distro)
        binary, release = _installed(distro, package)
        if not scope or not binary or stream_of(package or "") != stream:
            return []  # a stream the package itself contradicts is never trusted
        cve = (cve or "").upper()
        cands = [c for c in self._scopes.get(scope, []) if c.cve == cve and c.stream == stream]
        cands = _by_name(cands, binary)
        if scope[0] == "rhel":
            cands = _rhel_channel(cands, dist_tag(release))
        recs = [FixRecord(c.source, c.cve, c.advisory_id, c.url, c.fetched_at, c.status,
                          c.fixed_version, c.name) for c in cands]
        return list(dict.fromkeys(recs))
