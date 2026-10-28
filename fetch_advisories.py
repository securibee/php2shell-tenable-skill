#!/usr/bin/env python3
"""Fetch vendor advisory feeds into a run folder (the only script that uses the network).

Usage: python3 fetch_advisories.py <run folder>

Reads faq.json (CVEs), plugins.json (vendor advisory IDs) and assets.json (Alpine
releases) when present; absent files count as empty. Writes advisories/index.json,
a list of {source, cve, url, fetched_at, status, file, error}, plus one raw JSON
file per successful fetch. Failures are recorded, never raised, and never stop the
other fetches. Prints one line per index entry; exits 0 even when fetches failed.
"""
from __future__ import annotations

import http.client
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from inventory import distro_for

USER_AGENT = "php2shell-tenable-skill/2.0.0"
TIMEOUT = 60
RETRY_WAIT = 5
DEFAULT_CVES = ["CVE-2026-109618", "CVE-2026-109619"]

OSV = "https://api.osv.dev/v1/vulns/"
REDHAT = "https://security.access.redhat.com/data/csaf/v2/vex/%s/%s.json"
ALPINE = "https://secdb.alpinelinux.org/v%s/community.json"

# An OSV advisory ID in the trailing parentheses of a vendor plugin name. The
# parentheses matter: some names fuse the ID into the package ("ALSA-2026:A011php:7.2").
_ADVISORY = re.compile(r"\(((?:ALSA|RLSA)-\d{4}:[A-Za-z0-9]+|SUSE-SU-\d{4}:\d+-\d+)\)")


def _load(run_dir: Path, name: str, empty):
    try:
        return json.loads((run_dir / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty


def _cves(run_dir: Path) -> list:
    faq = _load(run_dir, "faq.json", {})
    cves = faq.get("cves") if isinstance(faq, dict) else None
    return [str(c).upper() for c in cves] if cves else list(DEFAULT_CVES)


def _advisory_ids(run_dir: Path) -> list:
    ids: list = []
    for p in _load(run_dir, "plugins.json", []):
        for m in _ADVISORY.finditer(str(p.get("name", "")) if isinstance(p, dict) else ""):
            if m.group(1) not in ids:
                ids.append(m.group(1))
    return ids


def _alpine_releases(run_dir: Path) -> list:
    assets = _load(run_dir, "assets.json", {})
    rels: list = []
    for a in (assets.values() if isinstance(assets, dict) else []):
        d = distro_for(a.get("os", ""), "") if isinstance(a, dict) else None
        if d and d.family == "alpine" and d.major not in rels:
            rels.append(d.major)
    return sorted(rels)


def _get(url, opener, sleep) -> bytes:
    """GET with one retry after 5 s on HTTP 429 or 5xx. Raises on failure."""
    for attempt in (0, 1):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with opener(req, timeout=TIMEOUT) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            e.close()
            if attempt == 0 and (e.code == 429 or e.code >= 500):
                sleep(RETRY_WAIT)
                continue
            raise
    raise AssertionError("unreachable")


def fetch(run_dir, opener=urllib.request.urlopen, now=None, sleep=time.sleep) -> list:
    """Fetch every feed, write advisories/ and return the index.

    now: optional zero-argument callable returning an aware datetime (tests).
    sleep: injectable so the retry wait can be skipped in tests.
    """
    run_dir = Path(run_dir)
    out = run_dir / "advisories"
    out.mkdir(parents=True, exist_ok=True)
    clock = now or (lambda: datetime.now(timezone.utc))

    jobs = []  # (source, cve, url, file)
    cves = _cves(run_dir)
    for cve in cves:
        for prefix in ("UBUNTU", "DEBIAN"):
            jobs.append(("osv", cve, OSV + prefix + "-" + cve, "osv-%s-%s.json" % (prefix, cve)))
    for adv in _advisory_ids(run_dir):
        jobs.append(("osv", "", OSV + adv, "osv-%s.json" % adv.replace(":", "_")))
    for cve in cves:
        m = re.match(r"CVE-(\d{4})-", cve)
        if m:
            jobs.append(("redhat", cve, REDHAT % (m.group(1), cve.lower()),
                         "redhat-%s.json" % cve.lower()))
    rels = _alpine_releases(run_dir)
    for rel in rels:
        jobs.append(("alpine", "", ALPINE % rel, "alpine-v%s.json" % rel))

    index = []
    for source, cve, url, fname in jobs:
        entry = {"source": source, "cve": cve, "url": url, "fetched_at": "",
                 "status": "failed", "file": None, "error": None}
        try:
            body = _get(url, opener, sleep)
            json.loads(body)  # raw file is kept only if it parses
            (out / fname).write_bytes(body)
            entry["status"], entry["file"] = "ok", fname
        except urllib.error.HTTPError as e:
            entry["error"] = "HTTP %d" % e.code
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:  # timeouts are OSError
            entry["error"] = "%s: %s" % (type(e).__name__, e)
        except ValueError as e:
            entry["error"] = "response is not valid JSON: %s" % e
        entry["fetched_at"] = clock().isoformat()
        index.append(entry)
    if not rels:
        index.append({"source": "alpine", "cve": "", "url": "",
                      "fetched_at": clock().isoformat(), "status": "skipped",
                      "file": None, "error": None})
    (out / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    return index


def main(argv) -> int:
    if len(argv) != 2:
        print("usage: python3 fetch_advisories.py <run folder>", file=sys.stderr)
        return 2
    for e in fetch(Path(argv[1])):
        print("source=%s cve=%s status=%s" % (e["source"], e["cve"], e["status"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
