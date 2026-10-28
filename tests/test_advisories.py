import ast
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from advisories import Advisories, FixRecord
from inventory import Distro, stream_of

FIXTURES = Path(__file__).parent / "fixtures" / "advisories"
CVE = "CVE-2026-109618"
RHEL9 = Distro("rhel", "9", None)
RHEL8 = Distro("rhel", "8", None)
JAMMY = Distro("ubuntu", "22.04", "Ubuntu:22.04:LTS")
ALPINE = Distro("alpine", "3.22", "Alpine:v3.22")
ALMA8 = Distro("alma", "8", "AlmaLinux:8")
ALMA9 = Distro("alma", "9", "AlmaLinux:9")


def run_dir(edit_index=None) -> Path:
    """A temp run folder holding the fixture feeds under advisories/."""
    tmp = Path(tempfile.mkdtemp())
    shutil.copytree(FIXTURES, tmp / "advisories")
    if edit_index:
        path = tmp / "advisories" / "index.json"
        index = json.loads(path.read_text())
        edit_index(index)
        path.write_text(json.dumps(index))
    return tmp


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = run_dir()
        self.adv = Advisories.load(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir)


class RedHat(Base):
    def test_redhat_same_channel(self):
        recs = self.adv.lookup(RHEL9, "php-cli-8.0.30-3.el9_6.x86_64", "base", CVE)
        self.assertEqual(recs, [FixRecord(
            "redhat", CVE, "RHSA-2026:88720",
            "https://access.redhat.com/errata/RHSA-2026:88720",
            "2026-10-27T15:26:16+00:00", "fixed", "8.0.30-3.el9_6.2", "php-cli")])

    def test_redhat_other_channel_flagged(self):
        recs = self.adv.lookup(RHEL9, "php-cli-8.0.30-5.el9_7.x86_64", "base", CVE)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].status, "fixed")
        self.assertEqual(recs[0].fixed_version, "8.0.30-3.el9_6.2")  # lowest for RHEL 9
        self.assertTrue(recs[0].advisory_id.endswith("(other channel)"))
        self.assertEqual(recs[0].advisory_id, "RHSA-2026:88720 (other channel)")

    def test_redhat_module_stream_absent(self):
        pkg = "php-cli-8.0.30-1.module+el8.10.0+20000+abcdef12.x86_64"
        self.assertEqual(self.adv.lookup(RHEL8, pkg, "8.0", CVE), [])

    def test_redhat_module_stream_match(self):
        pkg = "php-cli-8.2.30-1.module+el8.10.0+22000+0badc0de.x86_64"
        recs = self.adv.lookup(RHEL8, pkg, "8.2", CVE)
        self.assertEqual([(r.fixed_version, r.advisory_id, r.status) for r in recs],
                         [("8.2.35-1.module+el8.10.0+25110+f67151d2", "RHSA-2026:87073", "fixed")])

    def test_redhat_e4s_channel_by_dist_tag(self):
        # E4S CPEs ("rhel_e4s:8.8") carry a digit in the product name.
        pkg = "php-cli-7.4.30-1.module+el8.%s.0+21000+0badc0de.x86_64"
        old = self.adv.lookup(RHEL8, pkg % "8", "7.4", CVE)
        new = self.adv.lookup(RHEL8, pkg % "10", "7.4", CVE)
        self.assertEqual([(r.fixed_version, r.advisory_id) for r in old],
                         [("7.4.33-1.module+el8.8.0+25148+55cf9df9.2", "RHSA-2026:88532")])
        self.assertEqual([(r.fixed_version, r.advisory_id) for r in new],
                         [("7.4.33-8.module+el8.10.0+25117+30337cca", "RHSA-2026:87080")])

    def test_redhat_never_collapses_component_names(self):
        # php-fpm has no entry of its own: fall back to the exact "php" source
        # component, never to php-pecl-apcu (5.1.23) which shares the prefix.
        pkg = "php-fpm-8.2.30-1.module+el8.10.0+22000+0badc0de.x86_64"
        recs = self.adv.lookup(RHEL8, pkg, "8.2", CVE)
        self.assertEqual([(r.package, r.fixed_version) for r in recs],
                         [("php", "8.2.35-1.module+el8.10.0+25110+f67151d2")])

    def test_redhat_not_affected_rhel7(self):
        recs = self.adv.lookup(Distro("rhel", "7", None),
                               "php-cli-5.4.16-48.el7.x86_64", "base", CVE)
        self.assertEqual([(r.status, r.fixed_version) for r in recs], [("not-affected", "")])

    def test_redhat_out_of_support_and_no_fix(self):
        rhel6 = self.adv.lookup(Distro("rhel", "6", None),
                                "php-cli-5.3.3-50.el6_10.x86_64", "base", CVE)
        self.assertEqual([r.status for r in rhel6], ["out-of-support"])
        pkg = "php-cli-8.4.10-1.module+el9.7.0+23000+0ddba11e.x86_64"
        rhel9 = self.adv.lookup(RHEL9, pkg, "8.4", CVE)
        self.assertEqual([r.status for r in rhel9], ["affected-no-fix"])

    def test_redhat_other_cve_absent(self):
        self.assertEqual(self.adv.lookup(
            RHEL9, "php-cli-8.0.30-3.el9_6.x86_64", "base", "CVE-2026-109619"), [])

    def test_redhat_not_used_for_other_vendors(self):
        pkg = "php-cli-8.0.30-3.el9_6.x86_64"
        for family in ("oracle", "centos", "amazon", "fedora"):
            self.assertEqual(self.adv.lookup(Distro(family, "9", None), pkg, "base", CVE), [])


class Osv(Base):
    def test_osv_ubuntu(self):
        recs = self.adv.lookup(JAMMY, "php8.1-cli 8.1.2-1ubuntu2.20", "base", CVE)
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual((r.source, r.status, r.fixed_version, r.advisory_id, r.package),
                         ("osv", "fixed", "8.1.2-1ubuntu2.28", "USN-8948-1", "php8.1"))
        self.assertEqual(r.url, "https://ubuntu.com/security/notices/USN-8948-1")

    def test_osv_exact_ecosystem_only(self):
        pkg = "php8.1-cli 8.1.2-1ubuntu2.20"
        pro = Distro("ubuntu", "22.04", "Ubuntu:Pro:22.04:LTS")
        self.assertEqual(self.adv.lookup(pro, pkg, "base", CVE), [])
        self.assertEqual(self.adv.lookup(Distro("ubuntu", "22.10", None), pkg, "base", CVE), [])

    def test_osv_alma_module_cve_in_related(self):
        pkg = "php-cli-8.2.30-1.module_el8.10.0+4000+aaaa1111.x86_64"
        recs = self.adv.lookup(ALMA8, pkg, stream_of(pkg), "CVE-2026-109619")
        self.assertEqual([(r.advisory_id, r.fixed_version, r.package) for r in recs],
                         [("ALSA-2026:87073", "8.2.35-1.module_el8.10.0+4323+fc907035", "php-cli")])
        self.assertEqual(self.adv.lookup(ALMA8, pkg, "7.4", "CVE-2026-109619"), [])
        self.assertEqual(self.adv.lookup(ALMA8, pkg, "base", "CVE-2026-109619"), [])

    def test_osv_alma9_module_install_never_gets_base_fix(self):
        # ALSA-2026:88720 fixes only the base php; a php:8.2 module install must
        # not borrow it (8.2.30 > 8.0.30 would read as Patched).
        module = "php-cli-8.2.30-1.module_el9.6.0+100+abcd1234.x86_64"
        self.assertEqual(stream_of(module), "8.2")
        self.assertEqual(self.adv.lookup(ALMA9, module, stream_of(module), CVE), [])
        self.assertEqual(self.adv.lookup(ALMA9, module, "base", CVE), [])  # stream contradicts package
        base = "php-cli-8.0.30-1.el9_6.x86_64"
        recs = self.adv.lookup(ALMA9, base, stream_of(base), CVE)
        self.assertEqual([(r.advisory_id, r.fixed_version, r.status) for r in recs],
                         [("ALSA-2026:88720", "8.0.30-3.el9_6", "fixed")])

    def test_stream_argument_must_match_package(self):
        pkg = "php-cli-8.0.30-3.el9_6.x86_64"
        self.assertEqual(self.adv.lookup(RHEL9, pkg, "8.0", CVE), [])

    def test_osv_not_used_for_rhel(self):
        pkg = "php-cli-8.2.30-1.module+el8.10.0+22000+0badc0de.x86_64"
        recs = self.adv.lookup(RHEL8, pkg, "8.2", "CVE-2026-109619")
        self.assertEqual(recs, [])  # only the Alma record carries -109619


class Alpine(Base):
    def test_alpine_cve_match_ignores_ghsa(self):
        recs = self.adv.lookup(ALPINE, "php83-fpm-8.3.30-r0", "base", "CVE-2026-109619")
        self.assertEqual([(r.source, r.status, r.fixed_version, r.package) for r in recs],
                         [("alpine", "fixed", "8.3.36-r0", "php83")])
        self.assertEqual(self.adv.lookup(ALPINE, "php83-fpm-8.3.30-r0", "base",
                                         "GHSA-0000-0000-0000"), [])

    def test_alpine_release_must_match(self):
        other = Distro("alpine", "3.21", "Alpine:v3.21")
        self.assertEqual(self.adv.lookup(other, "php83-8.3.30-r0", "base", CVE), [])


class Sources(unittest.TestCase):
    def test_failed_source_listed(self):
        def fail_redhat(index):
            for e in index:
                if e["source"] == "redhat":
                    e["status"], e["error"] = "failed", "HTTP 429"
        d = run_dir(fail_redhat)  # the raw file stays on disk
        try:
            adv = Advisories.load(d)
            failed = adv.failed_sources()
            self.assertEqual(sorted((f["source"], f["error"]) for f in failed),
                             [("osv", "HTTP 429"), ("redhat", "HTTP 429")])
            self.assertEqual(adv.lookup(RHEL9, "php-cli-8.0.30-3.el9_6.x86_64", "base", CVE), [])
            self.assertEqual(len(adv.lookup(JAMMY, "php8.1-cli 8.1.2-1ubuntu2.20", "base", CVE)), 1)
        finally:
            shutil.rmtree(d)

    def test_sources_lists_every_entry(self):
        d = run_dir()
        try:
            srcs = Advisories.load(d).sources()
        finally:
            shutil.rmtree(d)
        self.assertEqual(len(srcs), 6)
        self.assertEqual(set(srcs[0]), {"source", "cve", "url", "fetched_at", "status", "error"})

    def test_unreadable_raw_file_counts_as_failed(self):
        d = run_dir()
        try:
            (d / "advisories" / "alpine-v3.22.json").write_text("{not json")
            adv = Advisories.load(d)
            self.assertIn("alpine", [f["source"] for f in adv.failed_sources()])
            self.assertEqual(adv.lookup(ALPINE, "php83-8.3.30-r0", "base", CVE), [])
        finally:
            shutil.rmtree(d)

    def test_no_index_is_empty(self):
        d = Path(tempfile.mkdtemp())
        try:
            adv = Advisories.load(d)
        finally:
            shutil.rmtree(d)
        self.assertEqual((adv.sources(), adv.failed_sources()), ([], []))
        self.assertEqual(adv.lookup(RHEL9, "php-cli-8.0.30-3.el9_6.x86_64", "base", CVE), [])


class Encoding(unittest.TestCase):
    def test_every_text_read_and_write_names_utf8(self):
        """Every read_text, write_text and text-mode open in the scripts names an encoding."""
        root = Path(__file__).parent.parent
        missing = []
        for path in sorted(root.glob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, "attr", getattr(node.func, "id", ""))
                mode = next((a.value for a in node.args[1:2] if isinstance(a, ast.Constant)), "r")
                if name in ("read_text", "write_text") or (name == "open" and "b" not in mode):
                    if not any(k.arg == "encoding" for k in node.keywords):
                        missing.append("%s:%d %s" % (path.name, node.lineno, name))
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
