from __future__ import annotations

import csv
import html
import io
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import render
from tests.schema_check import validate
from tests.test_verify import SHOP, run_dir

ROOT = Path(__file__).parent.parent
OWNERS = Path(__file__).parent / "fixtures" / "owners.csv"
SCHEMA = json.loads((ROOT / "schemas" / "action-plan.schema.json").read_text())
AUTH_URL = "https://exchange.tenable.com/skills/auth-failure-analyzer/"
OUTPUTS = ("action-plan.json", "report.html", "report.csv", "auth-followup.txt")
BANNER = ("2 of 10 PHP hosts weren't scanned with working credentials, so their backport "
          "status can't be verified. Configure credentialed scans and rescan.")
RULE_4A = "This is a PHP minor-version upgrade: test applications before switching streams."
TRUNCATED = ("The plugin output the skill read lists the first PHP installs only; "
             "more may exist on this host.")

# Where every leaf field of an action-plan entry lands in report.csv. verification.rescan is
# always true, so it has no column; that is the one exemption.
LEAF_COLUMNS = {
    "item": {"key": "key", "asset_id": "asset_id", "hostname": "hostname", "fqdn": "fqdn",
             "ip": "ip", "url": "url", "owner": "owner", "owner_source": "owner_source",
             "bucket": "bucket", "rank": "rank", "reason": "reason",
             "compromise_note": "compromise_note", "action": "action",
             "fix_target": "fix_target", "interim_mitigations": "interim_mitigations",
             "next_step": "next_step"},
    "install": {"version": "version", "package": "package", "path": "path", "port": "port",
                "source_plugin": "source_plugin", "verdict": "verdict",
                "verdict_label": "verdict_label", "rule": "rule"},
    "evidence": {"type": "evidence_type", "source": "evidence_source",
                 "reference_id": "evidence_reference", "url": "evidence_url",
                 "observed": "evidence_observed", "expected": "evidence_expected",
                 "fetched_at": "evidence_fetched_at"},
    "flags": {k: k for k in ("internet_facing", "serves_web", "possible_compromise", "stale",
                             "output_truncated", "credential_state", "unpatched_scan")},
    "verification": {"plugins_should_stop": "plugins_should_stop"},
    "context": {k: k for k in ("aes", "acr", "apa_level", "last_seen")},
}
EXEMPT = {("verification", "rescan")}
NESTED = {"php_installs", "flags", "verification", "context"}


def entries(plan):
    return plan["items"] + plan["verify_first"]


def read_csv(path: Path) -> list:
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def cell(value) -> str:
    """The CSV text for a plan value (before the formula guard)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


class Fixture(unittest.TestCase):
    """The shared fixture rendered once through the CLI, PDF included when Chrome exists."""

    @classmethod
    def setUpClass(cls):
        cls.dir = run_dir()
        cls.proc = subprocess.run(
            [sys.executable, str(ROOT / "render.py"), str(cls.dir), "--owners", str(OWNERS)],
            capture_output=True, text=True, timeout=300)
        cls.plan = json.loads((cls.dir / "action-plan.json").read_text(encoding="utf-8"))
        cls.html = (cls.dir / "report.html").read_text(encoding="utf-8")
        cls.rows = read_csv(cls.dir / "report.csv")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir.parent)

    def test_outputs_exist(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stderr)
        for name in OUTPUTS:
            self.assertTrue((self.dir / name).is_file(), name)
        if render.find_chrome() is None:
            self.skipTest("no Chrome: PDF not checked")
        self.assertTrue((self.dir / "report.pdf").is_file())

    def test_cli_output(self):
        lines = self.proc.stdout.splitlines()
        self.assertEqual(lines[:6], ["items=7 verify_first=4 assets=12", "  FIRST: 2",
                                     "  NEXT: 5", "  SOON: 0", "  VERIFY: 4",
                                     "feed_failed=osv CVE-2026-109618"])
        printed = {Path(x).name for x in lines[6:]}
        self.assertTrue(set(OUTPUTS) <= printed, lines)

    def test_plan_is_valid(self):
        self.assertEqual(validate(self.plan, SCHEMA), [])
        self.assertEqual([i["rank"] for i in self.plan["items"]], list(range(1, 8)))

    def test_auth_followup(self):
        text = (self.dir / "auth-followup.txt").read_text(encoding="utf-8")
        self.assertIn(AUTH_URL, text)
        self.assertIn("analyze auth failures on a-authfail", text)

    def test_csv_matches_plan(self):
        installs = sum(len(e["php_installs"]) for e in entries(self.plan))
        self.assertEqual(len(self.rows), installs)
        header = list(self.rows[0])
        self.assertEqual(header[:40], ["rank", "bucket", "asset_id", "hostname", "fqdn", "ip",
                                       "url", "owner", "owner_source", "action", "fix_target",
                                       "reason", "verdict", "verdict_label", "rule", "version",
                                       "package", "path", "port", "source_plugin",
                                       "internet_facing", "serves_web", "possible_compromise",
                                       "stale", "output_truncated", "credential_state",
                                       "unpatched_scan", "aes", "acr", "apa_level", "last_seen",
                                       "evidence_type", "evidence_source", "evidence_reference",
                                       "evidence_url", "evidence_observed", "evidence_expected",
                                       "evidence_fetched_at", "evidence_more", "next_step"])
        self.assertEqual(header[40:], ["key", "interim_mitigations", "plugins_should_stop",
                                       "compromise_note"])
        for cols in LEAF_COLUMNS.values():
            self.assertTrue(set(cols.values()) <= set(header), cols)

        def check_leaves(kind, obj):
            for name in obj:
                if name in NESTED and kind == "item" or (kind, name) in EXEMPT:
                    continue
                self.assertIn(name, LEAF_COLUMNS[kind], "%s.%s has no CSV column" % (kind, name))

        rows = iter(self.rows)
        for e in entries(self.plan):
            check_leaves("item", e)
            for kind in ("flags", "verification", "context"):
                check_leaves(kind, e[kind])
            for inst in e["php_installs"]:
                check_leaves("install", {k: v for k, v in inst.items() if k != "evidence"})
                for ev in inst["evidence"]:
                    check_leaves("evidence", ev)
                row = next(rows)
                self.assertEqual(row["key"], e["key"])
                for name, col in LEAF_COLUMNS["item"].items():
                    want = e.get(name)
                    if name == "interim_mitigations":
                        want = " | ".join(want)
                    self.assertEqual(row[col], cell(want), (e["key"], col))
                for kind in ("flags", "context"):
                    for name, col in LEAF_COLUMNS[kind].items():
                        self.assertEqual(row[col], cell(e[kind][name]), (e["key"], col))
                self.assertEqual(row["plugins_should_stop"],
                                 " ".join(e["verification"]["plugins_should_stop"]))
                for name, col in LEAF_COLUMNS["install"].items():
                    self.assertEqual(row[col], cell(inst[name]), (e["key"], col))
                first, rest = inst["evidence"][0], inst["evidence"][1:]
                for name, col in LEAF_COLUMNS["evidence"].items():
                    self.assertEqual(row[col], cell(first[name]), (e["key"], col))
                self.assertEqual(row["evidence_more"], " | ".join(
                    "%s %s %s→%s" % (x["source"], x["reference_id"], x["observed"], x["expected"])
                    for x in rest))
        self.assertIsNone(next(rows, None))
        for row in self.rows:
            self.assertEqual(row["rank"] == "", row["bucket"] == "VERIFY", row["key"])

    def test_html_has_every_item_and_detail(self):
        doc = self.html
        for e in entries(self.plan):
            self.assertIn(html.escape(e["hostname"], quote=True), doc)
            if e["fix_target"]:
                self.assertIn(html.escape(e["fix_target"], quote=True), doc)
            for inst in e["php_installs"]:
                self.assertIn(html.escape(inst["evidence"][0]["reference_id"], quote=True), doc)
        for e in self.plan["verify_first"]:
            self.assertIn(html.escape(e["next_step"], quote=True), doc)
        self.assertEqual(doc.count('<tr class="row"'), len(entries(self.plan)))
        self.assertEqual(doc.count('<tr class="detail"'), len(entries(self.plan)))
        for text in (AUTH_URL, BANNER, "7 hosts need action.", "2 have no named owner.",
                     RULE_4A, TRUNCATED, "Take it offline until upgraded",
                     "Upgrade to a supported stream (php:8.2 stream); isolate if internet-facing",
                     "Upgrade PHP to 8.3.36", "Assume compromise; check for exploitation since "
                     "2026-10-17.", "HTTP 429", "analyze auth failures on a-authfail"):
            self.assertIn(text, doc)
        for label in ("Fix FIRST", "Fix NEXT", "Fix SOON", "Verify first", "Patched (verified)",
                      "Likely patched", "Not affected"):
            self.assertIn(label, doc)
        self.assertIn("api.osv.dev/v1/vulns/DEBIAN-CVE-2026-109618", doc)
        print_css = doc[doc.index("@media print"):doc.index("</style>")]
        self.assertRegex(print_css, r"\.block\.plan\s*\{\s*break-before:\s*page")
        # Print: the ranked table carries rows only; the details follow in their own section.
        self.assertRegex(print_css, r"\.block\.plan tr\.detail[^{]*\{\s*display:\s*none")
        # Ranked rows must not chain with break-after: avoid, or Chrome pushes the whole
        # table past the page holding its heading.
        self.assertRegex(print_css, r"\.block\.plan tr\.row\s*\{\s*break-after:\s*auto")
        self.assertRegex(print_css, r"\.print-detail\s*\{\s*display:\s*block")
        self.assertRegex(print_css, r"\n\s*tr\.detail\s*\{\s*display:\s*table-row")  # Verify first
        section = doc[doc.index('<section class="block print-detail"'):]
        section = section[:section.index("</section>")]
        heads = re.findall(r'<h3 class="detail-head">(\d+) ', section)
        self.assertEqual(heads, [str(i["rank"]) for i in self.plan["items"]])
        for e in self.plan["items"]:
            self.assertIn(html.escape(e["key"], quote=True), section)
        self.assertIn(RULE_4A, section)
        self.assertIn(TRUNCATED, section)
        self.assertLess(doc.index('<section class="block plan"'), section and
                        doc.index('<section class="block print-detail"'))
        self.assertLess(doc.index('<section class="block print-detail"'),
                        doc.index('<section class="block verify"'))

    def test_html_is_self_contained(self):
        for m in re.finditer(r'(?:src|href)="([^"]*)"', self.html):
            url = m.group(1)
            if m.group(0).startswith("src"):
                self.assertTrue(url.startswith("data:"), url)
        self.assertNotIn("@import", self.html)
        self.assertNotIn("<link", self.html)


class OwnerFileError(unittest.TestCase):
    def test_bad_owner_file_exits_nonzero(self):
        d = run_dir()
        try:
            bad = d.parent / "owners.csv"
            bad.write_text("hostname,team\nweb01,Web\n", encoding="utf-8")
            proc = subprocess.run([sys.executable, str(ROOT / "render.py"), str(d),
                                   "--owners", str(bad)], capture_output=True, text=True,
                                  timeout=60)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("no 'owner' column", proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)
        finally:
            shutil.rmtree(d.parent)


class RememberedOwnerFile(unittest.TestCase):
    """SKILL.md step 5 remembers the owner file in config.json beside the run folders."""

    def main(self, *args, config=None):
        d = run_dir()
        self.addCleanup(shutil.rmtree, d.parent)
        if config is not None:
            (d.parent / "config.json").write_text(json.dumps(config), encoding="utf-8")
        with mock.patch.object(render, "find_chrome", return_value=None), \
                mock.patch("sys.stdout", new_callable=io.StringIO), \
                mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            code = render.main([str(d), *args])
        if not (d / "action-plan.json").exists():
            return code, None, err.getvalue()
        plan = json.loads((d / "action-plan.json").read_text(encoding="utf-8"))
        return code, plan["coverage"]["by_owner_source"].get("owner-file", 0), err.getvalue()

    def test_bare_run_uses_remembered_owner_file(self):
        _, explicit, _ = self.main("--owners", str(OWNERS))
        code, remembered, _ = self.main(config={"owner_file": str(OWNERS),
                                                "owner_tag_category": None})
        self.assertEqual(code, 0)
        self.assertGreater(explicit, 0)
        self.assertEqual(remembered, explicit)

    def test_owners_flag_wins_over_config(self):
        code, n, _ = self.main("--owners", str(OWNERS),
                               config={"owner_file": "/nonexistent/owners.csv"})
        self.assertEqual(code, 0)
        self.assertGreater(n, 0)

    def test_missing_remembered_file_fails(self):
        code, _, err = self.main(config={"owner_file": "/nonexistent/owners.csv"})
        self.assertEqual(code, 1)
        self.assertIn("owner file /nonexistent/owners.csv", err)
        self.assertIn("--owners", err)

    def test_unreadable_config_fails(self):
        d = run_dir()
        self.addCleanup(shutil.rmtree, d.parent)
        (d.parent / "config.json").write_text("{not json", encoding="utf-8")
        with mock.patch("sys.stdout", new_callable=io.StringIO), \
                mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            code = render.main([str(d)])
        self.assertEqual(code, 1)
        self.assertIn("config.json", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())
        self.assertFalse((d / "action-plan.json").exists())

    def test_null_owner_file_is_silent(self):
        code, n, err = self.main(config={"owner_file": None, "owner_tag_category": None})
        self.assertEqual((code, n), (0, 0))
        self.assertNotIn("owner file", err)


class InProcess(unittest.TestCase):
    def render(self, edit=None, owners=OWNERS):
        d = run_dir(edit)
        self.addCleanup(shutil.rmtree, d.parent)
        plan, files = render.render(d, owners, pdf=False)
        return d, plan, files

    def test_escaping(self):
        def edit(files):
            files["assets.json"]["a-rhel9"]["name"] = "<script>x</script>"
            for row in files["findings.json"]:
                if row["asset_id"] == "a-rhel9":
                    row["asset"] = "<script>x</script>"
                    if row["plugin_id"] == "370210":
                        row["plugin_name"] = '=HYPERLINK("x")'
            files["advisories/index.json"][2]["url"] = "javascript:alert(1)"
        d, plan, _ = self.render(edit)
        doc = (d / "report.html").read_text(encoding="utf-8")
        self.assertIn("&lt;script&gt;x&lt;/script&gt;", doc)
        self.assertNotIn("<script>x", doc)
        self.assertIn("=HYPERLINK(&quot;x&quot;)", doc)
        self.assertNotIn('href="javascript:', doc)
        cells = [c for row in read_csv(d / "report.csv") for c in row.values()]
        self.assertIn("'=HYPERLINK(\"x\")", cells)
        self.assertFalse([c for c in cells if c[:1] in ("=", "+", "-", "@")])

    def test_cli_without_chrome_keeps_stdout_contract(self):
        d = run_dir()
        self.addCleanup(shutil.rmtree, d.parent)
        with mock.patch.object(render, "find_chrome", return_value=None), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
                mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            code = render.main([str(d), "--owners", str(OWNERS)])
        self.assertEqual(code, 0)
        lines = out.getvalue().splitlines()
        self.assertEqual(lines[0], "items=7 verify_first=4 assets=12")
        self.assertNotIn("WARN", out.getvalue())
        self.assertIn("WARN: no Chrome/Chromium found; PDF skipped", err.getvalue())
        self.assertNotIn(str(d / "report.pdf"), lines)
        self.assertFalse((d / "report.pdf").exists())

    def test_banner_singular(self):
        plan = {"coverage": {"by_credential_state": {"credentialed": 4, "not-credentialed": 1,
                                                     "failed": 0, "not-applicable": 2},
                             "unassigned_actionable": 1},
                "items": [{"bucket": "FIRST", "php_installs": [{}]}], "verify_first": []}
        text = render.banner(plan)
        for sentence in ("1 of 5 PHP hosts wasn't scanned with working credentials, so its "
                         "backport status can't be verified. Configure credentialed scans and "
                         "rescan.", "1 host needs action.", "1 has no named owner."):
            self.assertIn(sentence, text)
        plan["coverage"]["by_credential_state"]["failed"] = 1
        plan["coverage"]["unassigned_actionable"] = 0
        plan["items"].append({"bucket": "NEXT", "php_installs": [{}]})
        text = render.banner(plan)
        for sentence in ("2 of 6 PHP hosts weren't scanned with working credentials, so their "
                         "backport status can't be verified.", "2 hosts need action.",
                         "0 have no named owner."):
            self.assertIn(sentence, text)

    def test_unpatched_scan_note(self):
        note = "Scan for Unpatched Vulnerabilities was off for %d PHP %s. Turn it on in the " \
               "scan policy so Tenable can report packages with no vendor fix."

        def banner(**flags):
            def edit(files):
                for a in files["assets.json"].values():
                    a["unpatched_scan"] = None
                for k, v in flags.items():
                    files["assets.json"][k]["unpatched_scan"] = v
            d, plan, _ = self.render(edit)
            return render.banner(plan), (d / "report.html").read_text(encoding="utf-8")

        text, doc = banner(**{"a-rhel9": False})
        self.assertIn(note % (1, "host"), text)
        self.assertIn(note % (1, "host"), doc)
        self.assertNotIn("(s)", text)
        text, _ = banner(**{"a-rhel9": False, "a-ol8": False})
        self.assertIn(note % (2, "hosts"), text)
        text, _ = banner(**{"a-rhel9": False, "a-nocreds": False})  # verify_first counts too
        self.assertIn(note % (2, "hosts"), text)
        for flags in ({}, {"a-rhel9": None, "a-ol8": True}):
            text, doc = banner(**flags)
            self.assertNotIn("Scan for Unpatched Vulnerabilities was off", text)
            self.assertNotIn("Scan for Unpatched Vulnerabilities was off", doc)

    def test_vendor_update_copy_for_cloud_only_items(self):
        _, plan, _ = self.render()
        by = {e["asset_id"]: e for e in entries(plan)}
        self.assertEqual(
            render.action_text(by["a-image"]),
            "Install the vendor update or rebuild the image from a patched base (%s)"
            % by["a-image"]["fix_target"])
        self.assertTrue(by["a-image"]["fix_target"].startswith("CVE-"))
        text = render.action_text(by["a-rhel9"])
        self.assertEqual(text, "Install the vendor update (%s)" % by["a-rhel9"]["fix_target"])

    def test_formula_guard(self):
        for text in ("=1+1", "+1", "-1", "@SUM(A1)"):
            self.assertEqual(render.csv_cell(text), "'" + text)
        for value, want in (("a=b", "a=b"), ("", ""), (None, ""), (True, "true"), (7, "7")):
            self.assertEqual(render.csv_cell(value), want)

    def test_empty_run(self):
        def edit(files):
            files["findings.json"] = []
            files["assets.json"] = {}
        d, plan, _ = self.render(edit)
        self.assertEqual(plan["items"], [])
        self.assertEqual(plan["verify_first"], [])
        doc = (d / "report.html").read_text(encoding="utf-8")
        self.assertIn("No PHP installs were found in this run.", doc)
        self.assertNotIn("weren't scanned with working credentials", doc)
        self.assertEqual(read_csv(d / "report.csv"), [])
        for name in OUTPUTS:
            self.assertTrue((d / name).is_file(), name)

    def test_render_offline(self):
        def refuse(*args, **kwargs):
            raise OSError("network access attempted")
        with mock.patch.object(socket, "socket", refuse), \
                mock.patch.object(socket, "create_connection", refuse):
            d, plan, files = self.render()
        self.assertEqual(len(plan["items"]), 7)
        self.assertTrue((d / "report.html").is_file())
        self.assertNotIn(d / "report.pdf", files)

    def test_pdf_failure_warns_and_continues(self):
        d = run_dir()
        self.addCleanup(shutil.rmtree, d.parent)
        (d / "report.pdf").write_text("stale", encoding="utf-8")
        fail = subprocess.CalledProcessError(1, ["chrome"])
        with mock.patch.object(render, "find_chrome", return_value="/bin/chrome"), \
                mock.patch.object(render.subprocess, "run", side_effect=fail), \
                mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            plan, files = render.render(d, OWNERS)
        self.assertIn("WARN: Chrome could not print the PDF", err.getvalue())
        self.assertFalse((d / "report.pdf").exists())
        self.assertNotIn(d / "report.pdf", files)
        self.assertTrue((d / "report.html").is_file())

    def test_no_owner_file(self):
        _, plan, _ = self.render(owners=None)
        self.assertEqual(plan["coverage"]["by_owner_source"].get("owner-file", 0), 0)
        self.assertIn(SHOP, [e["key"] for e in plan["items"]])


if __name__ == "__main__":
    unittest.main()
