#!/usr/bin/env python3
"""Render the PHP2Shell verified action plan from a run folder.

Usage: python3 render.py <run folder> [--owners owners.csv]

Judges every PHP install (verify.py), ranks the assets (plan.py) and writes into the run
folder: action-plan.json for agents; report.html, report.pdf and report.csv for people, with
the same detail; and auth-followup.txt. No network calls; the PDF comes from local Chrome.
"""
from __future__ import annotations

import argparse
import base64
import csv
import html
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from string import Template

import plan as planner
import verify

ASSETS = Path(__file__).resolve().parent / "assets"
AUTH_URL = planner.AUTH_URL
BUCKETS = ("FIRST", "NEXT", "SOON", "VERIFY")
CSV_COLUMNS = [
    "rank", "bucket", "asset_id", "hostname", "fqdn", "ip", "url", "owner", "owner_source",
    "action", "fix_target", "reason", "verdict", "verdict_label", "rule", "version", "package",
    "path", "port", "source_plugin", "internet_facing", "serves_web", "possible_compromise",
    "stale", "output_truncated", "credential_state", "unpatched_scan", "aes", "acr",
    "apa_level", "last_seen", "evidence_type", "evidence_source", "evidence_reference",
    "evidence_url", "evidence_observed", "evidence_expected", "evidence_fetched_at",
    "evidence_more", "next_step", "key", "interim_mitigations", "plugins_should_stop",
    "compromise_note"]
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

# Swatches follow Tenable's severity palette (critical, high, medium); the rest are
# cyberagents-exchange-website tokens (accent, text-secondary, MCP blue, bg-tertiary).
CRITICAL, HIGH, MEDIUM, ACCENT = "#91243E", "#DD4B50", "#F18C43", "#E7FF00"
GREY, BLUE, MUTED = "#969696", "#4EA5FF", "#44494B"
VERDICT_COLORS = {"eol": CRITICAL, "no-vendor-fix": CRITICAL, "no-stream-fix": HIGH,
                  "backport-only": HIGH, "vulnerable": MEDIUM, "conflict": ACCENT,
                  "unverified-credentials": GREY, "unverified-no-data": GREY,
                  "likely-patched": GREY, "patched": BLUE, "not-affected": MUTED}
BUCKET_COLORS = {"FIRST": CRITICAL, "NEXT": HIGH, "SOON": MEDIUM, "VERIFY": ACCENT}
BUCKET_LABELS = {"FIRST": "Fix FIRST", "NEXT": "Fix NEXT", "SOON": "Fix SOON",
                 "VERIFY": "Verify first"}
CREDENTIAL_LABELS = {"credentialed": "Credentialed", "not-credentialed": "Not credentialed",
                     "failed": "Credentials failed", "not-applicable": "Not applicable"}
SOURCE_LABELS = {"tenable-hexa": "Tenable Hexa AI MCP", "tenable-faq": "Tenable Research FAQ",
                 "osv": "OSV", "redhat": "Red Hat", "alpine": "Alpine secdb"}
EVIDENCE_LABELS = {"tenable-plugin": "Tenable plugin", "vendor-feed": "Vendor feed",
                   "upstream-version": "Upstream release", "credential": "Credentials",
                   "absence": "No matching plugin"}
YES = {True: "yes", False: "no"}
RULE_4A = "This is a PHP minor-version upgrade: test applications before switching streams."
TRUNCATED = ("The plugin output the skill read lists the first PHP installs only; "
             "more may exist on this host.")
PLAN_COLUMNS = ("Rank", "Bucket", "Asset", "Owner", "Action", "Fix target", "Reason", "Flags",
                "Credentials", "ACR / AES / Attack path")
VERIFY_COLUMNS = ("Asset", "Owner", "Reason", "Next step", "Credentials",
                  "ACR / AES / Attack path")


# --- text helpers ---

def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def link(url, text=None) -> str:
    """An anchor for http(s) URLs only; anything else is shown as text."""
    label = esc(text if text is not None else url)
    if str(url or "").lower().startswith(("https://", "http://")):
        return '<a href="%s">%s</a>' % (esc(url), label)
    return label


def dash(value) -> str:
    text = esc(value)
    return text if text else '<span class="muted">–</span>'


def _num(value) -> str:
    if value is None:
        return "–"
    return str(value) if isinstance(value, int) else "%g" % value


def _cloud_only(e: dict) -> bool:
    """True when every Tenable plugin finding behind the item came from Cloud."""
    src = [x["source"] for i in e.get("php_installs") or [] for x in i.get("evidence") or []
           if x.get("type") == "tenable-plugin"]
    return bool(src) and all(s == "Tenable Cloud" for s in src)


def action_text(e: dict) -> str:
    action, target = e.get("action"), e.get("fix_target") or ""
    if action == "upgrade-stream":
        return "Upgrade to a supported stream (%s); isolate if internet-facing" % (
            target or "a fixed stream")
    if action == "isolate-or-upgrade":
        return ("Take it offline until upgraded" if e["flags"]["internet_facing"]
                else "Isolate or upgrade")
    if action == "vendor-update":
        if target and _cloud_only(e):
            return ("Install the vendor update or rebuild the image from a patched base (%s)"
                    % target)
        return "Install the vendor update (%s)" % target if target else "Install the vendor update"
    if action == "patch":
        return "Upgrade PHP to %s" % (target or "a fixed release")
    return ""


def _owner(e: dict) -> str:
    source = e["owner_source"]
    if source == "unassigned":
        return '<span class="muted">No named owner</span>'
    label = "owner file" if source == "owner-file" else "Tenable tag " + source[4:]
    return '%s<span class="sub">%s</span>' % (esc(e["owner"]), esc(label))


def _asset(e: dict) -> str:
    name = e["hostname"] or e["url"] or e["key"]
    subs = [x for x in (e["fqdn"] if e["fqdn"] != name else "", e["ip"],
                        e["url"] if e["url"] != name else "") if x]
    return '<b class="host">%s</b>%s' % (esc(name), "".join(
        '<span class="sub">%s</span>' % esc(x) for x in subs))


def _scores(e: dict) -> str:
    c = e["context"]
    path = '<span class="sub">%s attack path</span>' % esc(c["apa_level"]) if c["apa_level"] else ""
    return "ACR %s · AES %s%s" % (_num(c["acr"]), _num(c["aes"]), path)


def _chip(text, color=GREY) -> str:
    return '<span class="chip" style="--c:%s">%s</span>' % (color, esc(text))


def _flags(e: dict) -> str:
    f = e["flags"]
    chips = [_chip("internet-facing", CRITICAL) if f["internet_facing"] else "",
             _chip("serves web", MEDIUM) if f["serves_web"] else _chip("command line only"),
             _chip("possible compromise", CRITICAL) if f["possible_compromise"] else "",
             _chip("stale") if f["stale"] else "",
             _chip("output truncated", ACCENT) if f["output_truncated"] else ""]
    return "".join(chips)


def _swatch(text, color) -> str:
    return '<span class="status" style="--c:%s"><span class="swatch"></span>%s</span>' % (
        color, esc(text))


# --- detail view ---

def _notes(e: dict) -> str:
    notes = []
    if e["compromise_note"]:
        notes.append(("alert", esc(e["compromise_note"])))
    if any(i["rule"].startswith("4a") for i in e["php_installs"]):
        notes.append(("", RULE_4A))
    if e["flags"]["output_truncated"]:
        notes.append(("", TRUNCATED))
    if e["flags"]["stale"]:
        notes.append(("", "Last seen %s, more than 30 days ago: confirm the host still exists."
                      % esc(e["context"]["last_seen"])))
    return "".join('<p class="note %s">%s</p>' % n for n in notes)


def _facts(e: dict) -> str:
    f, c = e["flags"], e["context"]
    facts = [("Key", e["key"]), ("Asset ID", e["asset_id"]), ("Hostname", e["hostname"]),
             ("FQDN", e["fqdn"]), ("IP", e["ip"]), ("URL", e["url"]),
             ("Owner", e["owner"]), ("Owner source", e["owner_source"]),
             ("Bucket", BUCKET_LABELS[e["bucket"]]), ("Rank", e["rank"]),
             ("Action", e["action"]), ("Fix target", e["fix_target"]), ("Reason", e["reason"]),
             ("Next step", e.get("next_step")),
             ("Credentials", CREDENTIAL_LABELS[f["credential_state"]]),
             ("Scan for Unpatched Vulnerabilities", YES.get(f["unpatched_scan"], "unknown")),
             ("Internet-facing", YES.get(f["internet_facing"], "unknown")),
             ("Serves web requests", YES.get(f["serves_web"], "unknown")),
             ("Possible compromise", YES.get(f["possible_compromise"], "unknown")),
             ("Stale", YES.get(f["stale"], "unknown")),
             ("Output truncated", YES.get(f["output_truncated"], "unknown")),
             ("ACR", _num(c["acr"])), ("AES", _num(c["aes"])),
             ("Attack path", c["apa_level"] or "–"), ("Last seen", c["last_seen"])]
    return '<dl class="facts">%s</dl>' % "".join(
        "<div><dt>%s</dt><dd>%s</dd></div>" % (esc(k), dash(v)) for k, v in facts
        if not (k == "Next step" and v is None))


def _evidence(ev: list) -> str:
    rows = "".join(
        '<tr><td data-label="Type">%s</td><td data-label="Source">%s</td>'
        '<td data-label="Reference">%s</td><td data-label="Observed">%s</td>'
        '<td data-label="Expected">%s</td><td data-label="Fetched">%s</td></tr>'
        % (esc(EVIDENCE_LABELS.get(x["type"], x["type"])), esc(x["source"]),
           link(x["url"], x["reference_id"]) if x["url"] else dash(x["reference_id"]),
           dash(x["observed"]), dash(x["expected"]), dash(x["fetched_at"])) for x in ev)
    return ('<table class="cards evidence"><thead><tr><th>Type</th><th>Source</th>'
            '<th>Reference</th><th>Observed</th><th>Expected</th><th>Fetched</th></tr></thead>'
            "<tbody>%s</tbody></table>" % rows) if ev else '<p class="muted">No evidence.</p>'


def _install(i: dict) -> str:
    parts = [("PHP", i["version"]), ("Package", i["package"]), ("Path", i["path"]),
             ("Port", i["port"]), ("Plugin", i["source_plugin"]), ("Rule", i["rule"])]
    meta = "".join('<span><em>%s</em> %s</span>' % (k, dash(v)) for k, v in parts)
    return ('<div class="install"><p class="install-head">%s<code>%s</code></p>'
            '<p class="install-meta">%s</p>%s</div>'
            % (_swatch(i["verdict_label"], VERDICT_COLORS.get(i["verdict"], GREY)),
               esc(i["verdict"]), meta, _evidence(i["evidence"])))


def _verification(e: dict) -> str:
    ids = e["verification"]["plugins_should_stop"]
    urls = {x["reference_id"]: x["url"] for i in e["php_installs"] for x in i["evidence"]
            if x["type"] == "tenable-plugin"}
    text = "Rescan after the %s" % ("next step" if e["bucket"] == "VERIFY" else "fix")
    if ids:
        return "%s. These plugins should stop firing: %s." % (text, ", ".join(
            link(urls.get(p, ""), p) for p in ids))
    return "%s, then confirm the new PHP version in the inventory plugin output." % text


def detail(e: dict) -> str:
    mitigations = "".join("<li>%s</li>" % esc(m) for m in e["interim_mitigations"])
    action = action_text(e)
    return ('<div class="detail-body">%s%s%s<h4 class="caption">PHP installs</h4>%s'
            '<div class="detail-cols"><div><h4 class="caption">Interim mitigations</h4>'
            "<ul>%s</ul></div><div><h4 class=\"caption\">Verification</h4><p>%s</p></div></div>"
            "</div>" % (_notes(e), '<p class="note action">%s</p>' % esc(action) if action else "",
                        _facts(e), "".join(_install(i) for i in e["php_installs"]),
                        mitigations or '<li class="muted">None listed.</li>', _verification(e)))


def _rows(entries: list, cells, columns: tuple, empty: str) -> str:
    if not entries:
        return '<tr><td class="empty" colspan="%d">%s</td></tr>' % (len(columns), empty)
    out = []
    for e in entries:
        tds = "".join('<td data-label="%s"%s>%s</td>' % (esc(label), cls, value)
                      for label, (cls, value) in zip(columns, cells(e)))
        out.append('<tr class="row" tabindex="0" aria-expanded="false">%s</tr>'
                   '<tr class="detail"><td colspan="%d">%s</td></tr>'
                   % (tds, len(columns), detail(e)))
    return "".join(out)


def plan_details(plan: dict) -> str:
    """Print-only section: the ranked table prints rows only, then every item's detail."""
    if not plan["items"]:
        return ""
    return ('<section class="block print-detail"><h2>Action plan detail</h2>%s</section>' % "".join(
        '<article class="print-item"><h3 class="detail-head">%d · %s · %s</h3>%s</article>'
        % (e["rank"], BUCKET_LABELS[e["bucket"]], esc(e["hostname"] or e["url"] or e["key"]),
           detail(e)) for e in plan["items"]))


def _plan_cells(e: dict) -> list:
    return [(' class="rank"', '<span class="toggle" aria-hidden="true"></span>%d' % e["rank"]),
            (' class="nowrap"', _swatch(BUCKET_LABELS[e["bucket"]], BUCKET_COLORS[e["bucket"]])),
            (' class="asset"', _asset(e)), ("", _owner(e)),
            (' class="action"', esc(action_text(e))),
            (' class="wrap"', dash(e["fix_target"])), (' class="reason"', esc(e["reason"])),
            ("", _flags(e)), ("", esc(CREDENTIAL_LABELS[e["flags"]["credential_state"]])),
            (' class="nowrap"', _scores(e))]


def _verify_cells(e: dict) -> list:
    return [(' class="asset"', '<span class="toggle" aria-hidden="true"></span>' + _asset(e)),
            ("", _owner(e)), ("", esc(e["reason"])), ("", esc(e["next_step"])),
            ("", esc(CREDENTIAL_LABELS[e["flags"]["credential_state"]])),
            (' class="nowrap"', _scores(e))]


# --- summary sections ---

def _counts(plan: dict) -> dict:
    states = plan["coverage"]["by_credential_state"]
    return {"assets": sum(states.values()),
            "installs": sum(len(e["php_installs"]) for e in plan["items"] + plan["verify_first"]),
            "uncredentialed": states["not-credentialed"] + states["failed"],
            "credential_scope": sum(v for k, v in states.items() if k != "not-applicable"),
            **{b: sum(e["bucket"] == b for e in plan["items"] + plan["verify_first"])
               for b in BUCKETS}}


def banner(plan: dict) -> str:
    n = _counts(plan)
    lines = []
    if n["assets"] == 0:
        lines.append("No PHP installs were found in this run.")
    bad, k, u = n["uncredentialed"], len(plan["items"]), plan["coverage"]["unassigned_actionable"]
    if bad and n["credential_scope"]:
        lines.append("%d of %d PHP hosts %s scanned with working credentials, so %s backport "
                     "status can't be verified. Configure credentialed scans and rescan."
                     % (bad, n["credential_scope"], "wasn't" if bad == 1 else "weren't",
                        "its" if bad == 1 else "their"))
    off = sum((e.get("flags") or {}).get("unpatched_scan") is False for e in plan["items"] + plan["verify_first"])
    if off:
        lines.append("Scan for Unpatched Vulnerabilities was off for %d PHP %s. Turn it on in the "
                     "scan policy so Tenable can report packages with no vendor fix."
                     % (off, "host" if off == 1 else "hosts"))
    lines.append("%d %s action." % (k, "host needs" if k == 1 else "hosts need"))
    lines.append("%d %s no named owner." % (u, "has" if u == 1 else "have"))
    return "".join("<p>%s</p>" % line for line in lines)


def context(plan: dict) -> str:
    v = plan["vulnerability"]
    cvss = " · CVSS %s" % esc(v["cvss"]) if "cvss" in v else ""
    fixed = "".join("<li>PHP %s: <b>%s</b></li>" % (esc(k), esc(r)) for k, r in v["fixed"].items())
    mitigations = "".join("<li>%s</li>" % esc(m) for m in v["interim_mitigations"])
    return ('<p class="eyebrow caption">Vulnerability context</p>'
            "<h2>%s%s · exploitation seen since %s</h2>"
            '<div class="context-cols"><div><h3 class="caption">Fixed releases</h3>'
            '<ul class="fixed">%s</ul>'
            '</div><div><h3 class="caption">Interim mitigations</h3><ul>%s</ul></div></div>'
            '<p class="faq">Details and indicators: %s</p>'
            % (esc(" and ".join(v["cves"])), cvss, esc(v["exploitation_since"]), fixed,
               mitigations, link(v["faq_url"], "Tenable Research FAQ")))


def tiles(plan: dict) -> str:
    n, verdicts = _counts(plan), plan["coverage"]["by_verdict"]
    tiles_ = [(BUCKET_LABELS[b], n[b], BUCKET_COLORS[b]) for b in BUCKETS] + [
        ("Patched (verified)", verdicts["patched"], BLUE),
        ("Likely patched", verdicts["likely-patched"], GREY),
        ("Not affected", verdicts["not-affected"], MUTED)]
    return "".join('<div class="tile clip-corner" style="--c:%s"><b>%d</b>'
                   '<span class="caption">%s</span></div>' % (c, count, esc(label))
                   for label, count, c in tiles_)


def owner_rows(plan: dict) -> str:
    groups: dict = {}
    for e in plan["items"] + plan["verify_first"]:
        g = groups.setdefault((e["owner"], e["owner_source"]), dict.fromkeys(BUCKETS, 0))
        g[e["bucket"]] += 1
    if not groups:
        return '<tr><td class="empty" colspan="6">No hosts need action or verification.</td></tr>'
    order = sorted(groups.items(), key=lambda kv: (
        [-kv[1][b] for b in BUCKETS[:3]], -sum(kv[1].values()), kv[0][0].lower()))
    return "".join(
        '<tr><td data-label="Owner">%s</td>%s<td data-label="Total">%d</td></tr>'
        % (_owner({"owner": o, "owner_source": s}), "".join(
            '<td data-label="%s">%d</td>' % (BUCKET_LABELS[b], c[b]) for b in BUCKETS),
           sum(c.values())) for (o, s), c in order)


def auth_section(plan: dict) -> str:
    entries = plan["items"] + plan["verify_first"]
    groups: dict = {}
    for e in entries:
        if e["flags"]["credential_state"] != "failed":
            continue
        ids = {int(p) for i in e["php_installs"] for x in i["evidence"] if x["type"] == "credential"
               for p in x["reference_id"].split(",") if p.strip().isdigit()}
        for pid in sorted(ids & verify.FAILURE_IDS) or [0]:
            groups.setdefault(pid, []).append(e)
    out = ['<p>Hosts whose credentials failed: the Auth Failure Analyzer skill works out why. '
           "Get it from its CyberAgents Exchange listing: %s</p>" % link(AUTH_URL)]
    if not groups:
        out.append('<p class="muted">No hosts with failed credentials.</p>')
    for pid in sorted(groups):
        hosts = groups[pid]
        target = hosts[0]["asset_id"] or hosts[0]["hostname"] or hosts[0]["ip"]
        out.append('<div class="auth-group"><h3>%s · %d host%s</h3>'
                   "<p>Example: <code>analyze auth failures on %s</code></p>"
                   '<ul class="hosts">%s</ul></div>' % (
                       "Plugin %d" % pid if pid else "Failure plugin not recorded", len(hosts),
                       "" if len(hosts) == 1 else "s", esc(target), "".join(
                           "<li>%s</li>" % esc(" · ".join(x for x in (
                               h["asset_id"], h["hostname"], h["ip"]) if x)) for h in hosts)))
    missing = [e for e in entries if e["flags"]["credential_state"] == "not-credentialed"]
    if missing:
        out.append("<p>%d %s scanned with credentials (%s). Configure credentialed scans and "
                   "rescan.</p>" % (len(missing), "host wasn't" if len(missing) == 1 else
                                    "hosts weren't", esc(", ".join(e["hostname"] or e["key"]
                                                                   for e in missing))))
    return "".join(out)


def sources_rows(plan: dict) -> str:
    colors = {"ok": BLUE, "failed": CRITICAL, "skipped": GREY}
    return "".join(
        '<tr><td data-label="Source">%s</td><td data-label="CVE" class="nowrap">%s</td>'
        '<td data-label="URL" class="wrap">%s</td><td data-label="Fetched" class="nowrap">%s</td>'
        '<td data-label="Status">%s%s</td></tr>'
        % (esc(SOURCE_LABELS.get(s["source"], s["source"])), dash(s["cve"]),
           link(s["url"]) if s["url"] else dash(""), dash(s["fetched_at"]),
           _swatch(s["status"], colors.get(s["status"], GREY)),
           '<span class="sub">%s</span>' % esc(s["error"]) if s["error"] else "")
        for s in plan["sources"])


# --- writers ---

def csv_cell(value) -> str:
    """CSV text for one value; a leading = + - @ (or tab/CR) gets a ' so no sheet runs it."""
    text = ("" if value is None else ("true" if value else "false") if isinstance(value, bool)
            else str(value))
    return "'" + text if text.startswith(FORMULA_START) else text


def csv_rows(plan: dict):
    for e in plan["items"] + plan["verify_first"]:
        base = {k: e.get(k) for k in CSV_COLUMNS if k in e}
        base.update(e["flags"], **e["context"])
        base["interim_mitigations"] = " | ".join(e["interim_mitigations"])
        base["plugins_should_stop"] = " ".join(e["verification"]["plugins_should_stop"])
        for i in e["php_installs"]:
            row = dict(base, **{k: v for k, v in i.items() if k != "evidence"})
            ev = i["evidence"]
            if ev:
                row.update({"evidence_" + ("reference" if k == "reference_id" else k): v
                            for k, v in ev[0].items()})
                row["evidence_more"] = " | ".join(
                    "%s %s %s→%s" % (x["source"], x["reference_id"], x["observed"],
                                     x["expected"]) for x in ev[1:])
            yield [csv_cell(row.get(c)) for c in CSV_COLUMNS]


def write_csv(plan: dict, path) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(CSV_COLUMNS)
        w.writerows(csv_rows(plan))


def write_html(plan: dict, path) -> None:
    n = _counts(plan)
    faq = plan["vulnerability"]["faq_url"]
    lockup = (ASSETS / "tenable-lockup.svg").read_text(encoding="utf-8")
    generated = datetime.fromisoformat(plan["generated_at"]).astimezone(timezone.utc)
    doc = Template((ASSETS / "report.html").read_text(encoding="utf-8")).substitute(
        font=b64(ASSETS / "WorkSans-latin.woff2"),
        lockup_white=base64.b64encode(lockup.encode()).decode(),
        lockup_dark=base64.b64encode(lockup.replace("fill: #fff", "fill: #1E2426").encode()).decode(),
        iris=b64(ASSETS / "tenable-iris.png"),
        generated=esc(generated.strftime("%Y-%m-%d %H:%M UTC")),
        cves=esc(" · ".join(plan["vulnerability"]["cves"])),
        asset_count=n["assets"], install_count=n["installs"],
        skill_version=esc(plan["skill_version"]),
        blog=esc(faq if faq.lower().startswith(("https://", "http://")) else verify.FAQ_URL),
        banner=banner(plan), context=context(plan), tiles=tiles(plan),
        owner_rows=owner_rows(plan),
        plan_rows=_rows(plan["items"], _plan_cells, PLAN_COLUMNS,
                        "No PHP installs were found in this run." if not n["assets"]
                        else "No confirmed-vulnerable hosts in this run."),
        plan_details=plan_details(plan),
        verify_rows=_rows(plan["verify_first"], _verify_cells, VERIFY_COLUMNS,
                          "No hosts need verification."),
        auth_section=auth_section(plan), sources_rows=sources_rows(plan))
    Path(path).write_text(doc, encoding="utf-8")


def b64(path):
    return base64.b64encode(path.read_bytes()).decode()


def find_chrome():
    mac = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    if mac.exists():
        return str(mac)
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "msedge"):
        if shutil.which(name):
            return shutil.which(name)
    return None


def write_pdf(html_path, pdf_path):
    if pdf_path.exists():  # never leave a PDF from an earlier render beside a newer plan
        pdf_path.unlink()
    chrome = find_chrome()
    if not chrome:  # warnings go to stderr: stdout is the machine-read summary
        print("WARN: no Chrome/Chromium found; PDF skipped. Print report.html to PDF manually.",
              file=sys.stderr)
        return False
    profile = tempfile.mkdtemp(prefix=".chrome-", dir=pdf_path.parent)
    try:
        subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                        f"--user-data-dir={profile}", f"--print-to-pdf={pdf_path}",
                        html_path.resolve().as_uri()],
                       check=True, capture_output=True, timeout=120)
    except subprocess.SubprocessError as exc:
        print("WARN: Chrome could not print the PDF (%s). Print report.html to PDF manually."
              % exc.__class__.__name__, file=sys.stderr)
        return False
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    return pdf_path.exists()


def render(run_dir, owners_path=None, pdf=True, now=None) -> tuple:
    """Judge, plan and write every output into run_dir; returns (plan, written paths)."""
    out = Path(run_dir)
    owners = planner.load_owners(Path(owners_path) if owners_path else None)
    run = verify.load_run(out)
    results = verify.judge(run)
    plan = planner.build_plan(results, run, owners, now or datetime.now(timezone.utc))
    files = [out / "action-plan.json", out / "report.csv", out / "report.html",
             out / "auth-followup.txt"]
    files[0].write_text(json.dumps(plan, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_csv(plan, files[1])
    write_html(plan, files[2])
    files[3].write_text(planner.auth_followup(results), encoding="utf-8")
    if pdf and write_pdf(files[2], out / "report.pdf"):
        files.append(out / "report.pdf")
    return plan, files


def remembered_owners(run_dir):
    """The owner file SKILL.md step 5 saved in config.json beside the run folders, or None.

    A remembered file that is gone, or a config.json that cannot be read, is an error:
    rendering on without it would silently drop every owner-file assignment.
    """
    config = Path(run_dir).resolve().parent / "config.json"
    try:
        path = json.loads(config.read_text(encoding="utf-8")).get("owner_file")
    except FileNotFoundError:
        return None
    except (OSError, ValueError, AttributeError) as exc:
        raise ValueError("cannot read %s (%s); fix it or pass --owners" % (config, exc)) from None
    if not path:
        return None
    if not Path(path).expanduser().is_file():
        raise ValueError("owner file %s saved in %s not found; pass --owners with its new path"
                         % (path, config))
    return str(Path(path).expanduser())


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Render the PHP2Shell verified action plan.")
    parser.add_argument("run_dir", help="run folder holding findings.json and assets.json")
    parser.add_argument("--owners", help="owner CSV (asset_id, hostname, fqdn or ip, and owner); "
                        "defaults to owner_file in config.json beside the run folder")
    args = parser.parse_args(argv)
    try:
        plan, files = render(args.run_dir, args.owners or remembered_owners(args.run_dir))
    except (ValueError, OSError) as exc:
        print("render.py: %s" % exc, file=sys.stderr)
        return 1
    n = _counts(plan)
    print("items=%d verify_first=%d assets=%d" % (len(plan["items"]), len(plan["verify_first"]),
                                                  n["assets"]))
    for b in BUCKETS:
        print("  %s: %d" % (b, n[b]))
    for s in plan["sources"]:
        if s["status"] == "failed":
            print("feed_failed=%s %s" % (s["source"], s["cve"] or s["url"]))
    for f in files:
        print(f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
