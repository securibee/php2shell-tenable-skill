import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify import (ACTIONABLE, VERDICTS, VERIFY_FIRST, Evidence, credential_state, judge,
                    load_run)

FIXTURE = Path(__file__).parent / "fixtures" / "run"
SHOP = "https://shop.example.com"


def run_dir(edit=None) -> Path:
    """A temp copy of the fixture run folder; edit(files) may change any JSON file in it."""
    tmp = Path(tempfile.mkdtemp())
    shutil.copytree(FIXTURE, tmp / "run")
    d = tmp / "run"
    if edit:
        names = ["findings.json", "assets.json", "plugins.json", "faq.json",
                 "advisories/index.json"]
        files = {n: json.loads((d / n).read_text()) for n in names}
        edit(files)
        for n, data in files.items():
            if data is None:  # None deletes the file
                (d / n).unlink()
            else:
                (d / n).write_text(json.dumps(data))
    return d


def results(edit=None) -> dict:
    d = run_dir(edit)
    try:
        return {r.key: r for r in judge(load_run(d))}
    finally:
        shutil.rmtree(d.parent)


def refs(verdict, kind):
    return [e.reference_id for e in verdict.evidence if e.type == kind]


def first_ev(verdict, kind) -> Evidence:
    return next(e for e in verdict.evidence if e.type == kind)


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = results()

    def verdicts(self, key):
        return [v for _, v in self.r[key].installs]

    def only(self, key):
        vs = self.verdicts(key)
        self.assertEqual(len(vs), 1, key)
        return vs[0]


class CredentialState(unittest.TestCase):
    def test_credential_state(self):
        vm = ["Nessus Scan"]
        self.assertEqual(credential_state({"sensors": vm, "auth_plugins": [141118]}),
                         "credentialed")
        self.assertEqual(credential_state({"sensors": ["Nessus Agent"], "auth_plugins": []}),
                         "credentialed")
        # 97993 replaced the deprecated 12634; older scan data can still carry 12634.
        for pid in (97993, 12634):
            self.assertEqual(credential_state({"sensors": vm, "auth_plugins": [pid]}),
                             "credentialed", pid)
        self.assertEqual(credential_state({"sensors": vm, "auth_plugins": [141118, 104410]}),
                         "failed")
        self.assertEqual(credential_state({"sensors": vm, "auth_plugins": [110723]}),
                         "not-credentialed")
        self.assertEqual(credential_state({"sensors": vm, "auth_plugins": []}),
                         "not-credentialed")
        self.assertEqual(credential_state({"sensors": ["WAS"], "auth_plugins": []}, SHOP),
                         "not-applicable")
        self.assertEqual(credential_state({"sensors": ["Cloud"], "auth_plugins": []}),
                         "not-applicable")

    def test_verdict_sets(self):
        self.assertEqual(VERDICTS["no-stream-fix"], "Vulnerable – no fix for this stream")
        self.assertEqual(ACTIONABLE, {"vulnerable", "no-vendor-fix", "no-stream-fix",
                                      "backport-only", "eol"})
        self.assertEqual(VERIFY_FIRST, {"conflict", "likely-patched",
                                        "unverified-credentials", "unverified-no-data"})


class Table(Fixture):
    def test_every_key(self):
        self.assertEqual(sorted(self.r), sorted([
            "a-rhel9", "a-ol8", "a-ubuntu-ok", "a-ubuntu-conflict", "a-deb-clean",
            "a-nocreds", "a-authfail", "a-win", "a-eol", SHOP, "a-image", "a-trunc"]))
        self.assertEqual([r.key for r in judge(load_run(FIXTURE))], sorted(self.r))

    def test_a_rhel9(self):
        r = self.r["a-rhel9"]
        self.assertEqual([i.path for i, _ in r.installs], ["/usr/bin/php", "/usr/bin/php-cgi"])
        self.assertEqual(r.credential_state, "credentialed")
        for v in self.verdicts("a-rhel9"):
            self.assertEqual((v.code, v.label, v.rule, v.action),
                             ("vulnerable", "Vulnerable", "1+3", "vendor-update"))
            self.assertIn("RHSA-2026:87151", v.fix_target)
            self.assertIn("php-cli-8.0.30-3.el9_6.2", v.fix_target)
            self.assertEqual(v.evidence[0].type, "tenable-plugin")
            self.assertEqual(v.evidence[0].reference_id, "370210")
            feed = first_ev(v, "vendor-feed")
            self.assertEqual((feed.source, feed.reference_id, feed.observed, feed.expected),
                             ("redhat", "RHSA-2026:88720 (CVE-2026-109618)", "8.0.30-3.el9_6",
                              "8.0.30-3.el9_6.2"))
            self.assertEqual(refs(v, "vendor-feed"), ["RHSA-2026:88720 (CVE-2026-109618)"])
            self.assertEqual(feed.url, "https://access.redhat.com/errata/RHSA-2026:88720")
            self.assertEqual(feed.fetched_at, "2026-10-27T15:26:16+00:00")

    def test_a_ol8(self):
        v = self.only("a-ol8")
        self.assertEqual((v.code, v.rule, v.action, v.fix_target),
                         ("no-stream-fix", "4a", "upgrade-stream", "php:8.2 stream"))
        self.assertEqual(v.evidence[0].type, "absence")
        self.assertEqual((v.evidence[0].observed, v.evidence[0].expected),
                         ("php:8.0", "php:7.4, php:8.2"))

    def test_a_ubuntu_ok(self):
        v = self.only("a-ubuntu-ok")
        self.assertEqual((v.code, v.label, v.rule, v.action), ("patched", "Patched", "3", ""))
        feeds = [e for e in v.evidence if e.type == "vendor-feed"]
        self.assertEqual(len(feeds), 2)  # one per run CVE
        for e in feeds:
            self.assertEqual((e.source, e.reference_id, e.observed, e.expected),
                             ("osv", "USN-8948-1 (%s)" % e.reference_id.split("(")[1][:-1],
                              "8.1.2-1ubuntu2.28", "8.1.2-1ubuntu2.28"))
        self.assertEqual(sorted(e.reference_id for e in feeds),
                         ["USN-8948-1 (CVE-2026-109618)", "USN-8948-1 (CVE-2026-109619)"])
        self.assertEqual(refs(v, "tenable-plugin"), [])

    def test_a_ubuntu_conflict(self):
        v = self.only("a-ubuntu-conflict")
        self.assertEqual((v.code, v.label, v.rule, v.action),
                         ("conflict", "Conflict – verify", "1+3", ""))
        self.assertEqual(refs(v, "tenable-plugin"), ["370517"])
        self.assertEqual(first_ev(v, "vendor-feed").expected, "8.1.2-1ubuntu2.28")

    def test_a_deb_clean(self):
        v = self.only("a-deb-clean")
        self.assertEqual((v.code, v.rule, v.action), ("likely-patched", "6", ""))
        self.assertEqual(v.label, "Likely patched – Tenable distro check clean")
        self.assertEqual(v.evidence[0].type, "absence")
        self.assertIn("2026-10-22", v.evidence[0].expected)
        self.assertIn("2026-10-25", v.evidence[0].observed)
        self.assertEqual(refs(v, "credential"), ["141118"])

    def test_a_nocreds(self):
        r = self.r["a-nocreds"]
        v = self.only("a-nocreds")
        self.assertEqual(r.credential_state, "not-credentialed")
        self.assertIsNone(r.installs[0][0].managed_by_os)
        self.assertEqual((v.code, v.rule, v.action), ("unverified-credentials", "7", ""))
        self.assertEqual(v.evidence[0].type, "credential")
        self.assertEqual(v.evidence[0].observed, "not-credentialed")
        self.assertEqual(refs(v, "tenable-plugin"), ["369483"])

    def test_a_authfail(self):
        r = self.r["a-authfail"]
        v = self.only("a-authfail")
        self.assertEqual(r.credential_state, "failed")
        self.assertEqual((v.code, v.rule), ("unverified-credentials", "7"))
        self.assertEqual((v.evidence[0].reference_id, v.evidence[0].observed),
                         ("104410", "failed"))

    def test_a_win(self):
        v = self.only("a-win")
        self.assertEqual((v.code, v.rule, v.action, v.fix_target),
                         ("vulnerable", "5", "patch", "8.3.36"))
        up = v.evidence[0]
        self.assertEqual((up.type, up.observed, up.expected), ("upstream-version", "8.3.30", "8.3.36"))
        self.assertEqual(refs(v, "tenable-plugin"), ["369483"])

    def test_a_eol(self):
        v = self.only("a-eol")
        self.assertEqual((v.code, v.label, v.rule, v.action),
                         ("eol", "Vulnerable – EOL", "5", "isolate-or-upgrade"))
        self.assertEqual(v.evidence[0].observed, "7.2.34")
        self.assertEqual(self.r["a-eol"].asset["ips"], ["203.0.113.10"])

    def test_shop_unjoined_was(self):
        r = self.r[SHOP]
        v = self.only(SHOP)
        self.assertEqual((r.credential_state, r.sources, r.urls),
                         ("not-applicable", {"WAS"}, [SHOP]))
        self.assertEqual((v.code, v.rule, v.action, v.fix_target),
                         ("vulnerable", "5", "patch", "8.3.36"))
        self.assertEqual(refs(v, "tenable-plugin"), ["115721"])
        self.assertEqual((v.evidence[0].observed, v.evidence[0].expected), ("8.3.30", "8.3.36"))

    def test_a_image(self):
        r = self.r["a-image"]
        v = self.only("a-image")
        self.assertEqual((r.credential_state, r.sources), ("not-applicable", {"Cloud"}))
        self.assertEqual(r.installs[0][0].path, "")
        self.assertEqual(r.installs[0][0].version, "8.3.30")
        self.assertEqual((v.code, v.rule, v.action), ("vulnerable", "1", "vendor-update"))
        self.assertEqual(v.evidence[0].reference_id, "CVE-2026-109618")
        self.assertEqual(v.fix_target, "CVE-2026-109618")

    def test_cloud_rule1_names_every_cve_in_the_finding(self):
        def edit(files):
            for row in files["findings.json"]:
                if row["asset_id"] == "a-image":
                    row["cves"] = ["CVE-2026-109618", "CVE-2026-109619"]
        v = results(edit)["a-image"].installs[0][1]
        self.assertEqual((v.code, v.action, v.fix_target),
                         ("vulnerable", "vendor-update", "CVE-2026-109618, CVE-2026-109619"))

    def test_a_trunc(self):
        r = self.r["a-trunc"]
        self.assertTrue(r.output_truncated)
        self.assertEqual(len(r.installs), 2)
        self.assertEqual({(v.code, v.rule) for _, v in r.installs}, {("vulnerable", "3")})
        self.assertEqual([k for k, x in self.r.items() if x.output_truncated], ["a-trunc"])


class FeedFailure(unittest.TestCase):
    def test_feed_failed_never_patched(self):
        for cves in (["CVE-2026-109618"], ["CVE-2026-109619"],
                     ["CVE-2026-109618", "CVE-2026-109619"]):
            def fail(files):
                for e in files["advisories/index.json"]:
                    if e["source"] == "osv" and e["cve"] in cves and "UBUNTU" in e["url"]:
                        e.update(status="failed", file=None, error="HTTP 429")
            with self.subTest(failed=cves):
                v = results(fail)["a-ubuntu-ok"].installs[0][1]
                self.assertEqual((v.code, v.rule), ("unverified-no-data", "8"))
                self.assertEqual(v.evidence[0].type, "absence")
                self.assertIn("fetch failed", v.evidence[0].observed)

    def test_no_feed_record_never_patched(self):
        def drop(files):
            files["advisories/index.json"] = [
                e for e in files["advisories/index.json"] if "UBUNTU" not in e["url"]]
        v = results(drop)["a-ubuntu-ok"].installs[0][1]
        self.assertEqual(v.code, "unverified-no-data")


class AuthOutput(unittest.TestCase):
    def test_auth_output_never_kept(self):
        def stray(files):
            files["assets.json"]["a-authfail"]["auth_output"] = "User: 'svc-scan'\nPort: 22"
        rs = results(stray)
        for r in rs.values():
            self.assertNotIn("svc-scan", repr(r.asset))
            for _, v in r.installs:
                for e in v.evidence:
                    for field in e:
                        self.assertNotIn("svc-scan", field)


class Variants(unittest.TestCase):
    def test_was_join_patched_host_is_conflict(self):
        def join(files):
            row = next(r for r in files["findings.json"] if r["source"] == "WAS")
            row.update(url="https://app02.example.internal", fqdn="", ip="")
        rs = results(join)
        self.assertNotIn(SHOP, rs)
        r = rs["a-ubuntu-ok"]
        self.assertEqual(r.sources, {"VM", "WAS"})
        self.assertEqual(r.urls, ["https://app02.example.internal"])
        codes = [(v.code, v.rule) for _, v in r.installs]
        self.assertEqual(codes, [("patched", "3"), ("conflict", "5+3")])
        self.assertIn("115721", refs(r.installs[1][1], "tenable-plugin"))
        self.assertIn("vendor-feed", [e.type for e in r.installs[1][1].evidence])

    def test_was_join_by_ip_stays_vulnerable(self):
        def join(files):
            row = next(r for r in files["findings.json"] if r["source"] == "WAS")
            row.update(ip="10.0.1.10")
        r = results(join)["a-rhel9"]
        self.assertEqual([(v.code, v.rule) for _, v in r.installs][-1], ("vulnerable", "5"))
        self.assertEqual(r.credential_state, "credentialed")

    def test_was_ambiguous_join_stays_own_result(self):
        def join(files):
            row = next(r for r in files["findings.json"] if r["source"] == "WAS")
            row.update(ip="10.0.1.10")
            files["assets.json"]["a-trunc"]["ips"] = ["10.0.1.10"]
        rs = results(join)
        self.assertIn(SHOP, rs)
        self.assertNotIn("WAS", rs["a-rhel9"].sources)

    def test_rule4_vendor_affected_no_fix(self):
        pkg = "php-cli-8.4.5-1.module+el9.6.0+20000+abcdef12.x86_64"

        def edit(files):
            for r in files["findings.json"]:
                if r["asset_id"] == "a-trunc":
                    r["plugin_output"] = (
                        "Nessus detected 1 install of PHP:\n\n  Path : /usr/bin/php\n"
                        "  Version : 8.4.5\n  Associated Package : %s\n"
                        "  Managed by OS : True\n" % pkg)
        v = results(edit)["a-trunc"].installs[0][1]
        self.assertEqual((v.code, v.rule, v.action),
                         ("no-vendor-fix", "4", "isolate-or-upgrade"))
        self.assertEqual(first_ev(v, "vendor-feed").expected, "affected-no-fix")

    def test_rule4_out_of_support_without_newer_stream(self):
        def edit(files):
            files["assets.json"]["a-trunc"]["os"] = "Red Hat Enterprise Linux 6.10"
            for r in files["findings.json"]:
                if r["asset_id"] == "a-trunc":
                    r["plugin_output"] = (
                        "Nessus detected 1 install of PHP:\n\n  Path : /usr/bin/php\n"
                        "  Version : 5.4.16\n  Associated Package : php-cli-5.4.16-48.el6.x86_64\n"
                        "  Managed by OS : True\n")
        v = results(edit)["a-trunc"].installs[0][1]
        self.assertEqual((v.code, v.rule), ("no-vendor-fix", "4"))
        self.assertEqual(first_ev(v, "vendor-feed").expected, "out-of-support")

    def test_369483_on_distro_install_is_no_data(self):
        def edit(files):
            files["findings.json"].append({
                "asset_id": "a-deb-clean", "asset": "deb01", "ip": "10.0.1.14", "fqdn": "",
                "url": "", "source": "VM", "plugin_id": "369483", "plugin_name": "PHP < 8.2.35",
                "cves": [], "role": "vulnerable", "php_version": "8.2.7", "port": "",
                "last_seen": "2026-10-25"})
            files["plugins.json"] = [p for p in files["plugins.json"]
                                     if not p["name"].startswith("Debian")]
        v = results(edit)["a-deb-clean"].installs[0][1]
        self.assertEqual((v.code, v.rule), ("unverified-no-data", "8"))
        self.assertEqual(refs(v, "tenable-plugin"), ["369483"])

    def test_rule6_needs_plugin_published_before_last_seen(self):
        def edit(files):
            files["assets.json"]["a-deb-clean"]["last_seen"] = "2026-10-21"
        v = results(edit)["a-deb-clean"].installs[0][1]
        self.assertEqual(v.code, "unverified-no-data")


class ReviewFixes(unittest.TestCase):
    def test_plugins_json_absent_keeps_rule_1(self):
        def drop(files):
            files["plugins.json"] = None
        rs = results(drop)
        v = rs["a-ubuntu-conflict"].installs[0][1]
        self.assertEqual((v.code, v.rule), ("conflict", "1+3"))
        for _, v in rs["a-rhel9"].installs:
            self.assertEqual((v.code, v.rule, v.action), ("vulnerable", "1+3", "vendor-update"))
        self.assertEqual(rs["a-win"].installs[0][1].rule, "5")  # 369483 stays version-only

    def test_fired_plugin_missing_from_catalog(self):
        def drop(files):
            files["plugins.json"] = [p for p in files["plugins.json"] if p["plugin_id"] != 370517]
        v = results(drop)["a-ubuntu-conflict"].installs[0][1]
        self.assertEqual((v.code, v.rule), ("conflict", "1+3"))

    def test_uncatalogued_plugin_names(self):
        def add(files):
            row = dict(next(r for r in files["findings.json"] if r["asset_id"] == "a-trunc"))
            row.pop("plugin_output")
            row.update(role="vulnerable", plugin_id=pid, plugin_name=name)
            files["findings.json"].append(row)
        for pid, name, rule in [
                ("372182", "F5 Networks BIG-IP : PHP vulnerabilities (K000163821)", "1+3"),
                ("379999", "Some future PHP check", "1+3"),
                ("370006", "Linux Distros Unpatched Vulnerability : CVE-2026-109618", "2+3"),
                ("115720", "PHP 8.4.x < 8.4.27", "3")]:
            with self.subTest(name=name):
                vs = [v for _, v in results(add)["a-trunc"].installs]
                self.assertEqual({v.rule for v in vs}, {rule})

    def test_distro_plugin_with_only_non_os_installs(self):
        out = ("Nessus detected 1 install of PHP:\n\n  Path : /opt/php/bin/php\n"
               "  Version : 8.3.36\n  Associated Package : None\n  Managed by OS : False\n")
        for pid, name, code, rule in [
                ("370210", "RHEL 9 : php (RHSA-2026:87151)", "vulnerable", "1"),
                ("370006", "Linux Distros Unpatched Vulnerability : CVE-2026-109618",
                 "no-vendor-fix", "2")]:
            def edit(files):
                for r in files["findings.json"]:
                    if r["asset_id"] == "a-rhel9" and r["role"] == "inventory":
                        r["plugin_output"] = out
                    elif r["asset_id"] == "a-rhel9":
                        r.update(plugin_id=pid, plugin_name=name, php_version="8.3.36")
            with self.subTest(plugin=pid):
                (opt, v5), (own, v) = results(edit)["a-rhel9"].installs
                self.assertEqual((opt.path, v5.code, v5.rule), ("/opt/php/bin/php", "patched", "5"))
                self.assertEqual(refs(v5, "tenable-plugin"), [])
                self.assertEqual((own.path, own.version, own.managed_by_os), ("", "8.3.36", None))
                self.assertEqual((v.code, v.rule), (code, rule))
                self.assertEqual(refs(v, "tenable-plugin"), [pid])

    def test_rule6_needs_stream_on_module_families(self):
        def edit(files):
            for r in files["findings.json"]:
                if r["asset_id"] == "a-trunc":
                    r["plugin_output"] = (
                        "Nessus detected 1 install of PHP:\n\n  Path : /usr/bin/php\n"
                        "  Version : 8.2.13\n  Associated Package : None\n"
                        "  Managed by OS : True\n")
        v = results(edit)["a-trunc"].installs[0][1]
        self.assertEqual((v.code, v.rule), ("unverified-no-data", "8"))
        self.assertIn("module stream unknown", v.evidence[0].observed)


ONE_CVE = ["CVE-2026-109618"]  # the only CVE the Alma 9, Ubuntu 24.04 and RHEL feeds carry


def one_install(files, key, os, path, version, package, managed="True", cves=None):
    """Give an asset one PHP install, an OS and optionally a narrower run CVE list."""
    files["assets.json"][key]["os"] = os
    lines = ["Nessus detected 1 install of PHP:", "", "  Path : " + path,
             "  Version : " + version, "  Associated Package : " + package]
    if managed is not None:
        lines.append("  Managed by OS : " + managed)
    for r in files["findings.json"]:
        if r["asset_id"] == key and r["role"] == "inventory":
            r.update(php_version=version, plugin_output="\n".join(lines) + "\n")
    if cves:
        files["faq.json"]["cves"] = cves


def fire_369483(files, key, version):
    r = next(r for r in files["findings.json"] if r["asset_id"] == key)
    files["findings.json"].append(dict(
        r, plugin_id="369483", role="vulnerable", php_version=version, cves=ONE_CVE,
        plugin_name="PHP < 8.2.35 / 8.3.x < 8.3.36 / 8.4.x < 8.4.27 / 8.5.x < 8.5.12 "
                    "Multiple Vulnerabilities"))
    files["findings.json"][-1].pop("plugin_output", None)


def verdict_of(edit, key):
    vs = [v for _, v in results(edit)[key].installs]
    assert len(vs) == 1, vs
    return vs[0]


class ThirdPartyRepos(unittest.TestCase):
    """R42: rule 3 settles Patched only on the vendor's own upstream line."""

    def test_sury_on_ubuntu_2204_is_backport_only(self):
        pkg = "php8.1-cli 8.1.31-1+ubuntu22.04.1+deb.sury.org+1"
        for fired in (False, True):
            def edit(files):
                one_install(files, "a-ubuntu-ok", "Linux Kernel 5.15 on Ubuntu 22.04",
                            "/usr/bin/php8.1", "8.1.31", pkg)
                if fired:
                    fire_369483(files, "a-ubuntu-ok", "8.1.31")
            with self.subTest(fired_369483=fired):
                v = verdict_of(edit, "a-ubuntu-ok")
                self.assertNotEqual(v.code, "patched")
                self.assertEqual((v.code, v.rule, v.action),
                                 ("backport-only", "5", "isolate-or-upgrade"))
                self.assertEqual(v.evidence[0].type, "upstream-version")

    def test_sury_on_ubuntu_2404_is_vulnerable(self):
        def edit(files):
            one_install(files, "a-ubuntu-ok", "Linux Kernel 6.8 on Ubuntu 24.04",
                        "/usr/bin/php8.3", "8.3.30",
                        "php8.3-cli 8.3.30-1+ubuntu24.04.1+deb.sury.org+1", cves=ONE_CVE)
        v = verdict_of(edit, "a-ubuntu-ok")
        self.assertEqual((v.code, v.rule, v.action, v.fix_target),
                         ("vulnerable", "5", "patch", "8.3.36"))

    def test_remi_on_alma9_is_vulnerable(self):
        def edit(files):
            one_install(files, "a-trunc", "AlmaLinux 9.6", "/usr/bin/php", "8.3.30",
                        "php-cli-8.3.30-1.el9.remi.x86_64", cves=ONE_CVE)
        v = verdict_of(edit, "a-trunc")
        self.assertNotEqual(v.code, "patched")
        self.assertEqual((v.code, v.rule, v.action, v.fix_target),
                         ("vulnerable", "5", "patch", "8.3.36"))
        self.assertIn("vendor-feed", [e.type for e in v.evidence])  # the ALSA record is kept

    def test_same_upstream_vendor_update_stays_patched(self):
        def edit(files):
            one_install(files, "a-trunc", "Red Hat Enterprise Linux 9.6", "/usr/bin/php",
                        "8.0.30", "php-cli-8.0.30-3.el9_6.2.x86_64", cves=ONE_CVE)
        v = verdict_of(edit, "a-trunc")
        self.assertEqual((v.code, v.rule), ("patched", "3"))

    def test_same_upstream_alpine_stays_patched(self):
        def edit(files):
            one_install(files, "a-trunc", "Alpine Linux 3.22.1", "/usr/bin/php83", "8.3.36",
                        "php83-8.3.36-r0")
        v = verdict_of(edit, "a-trunc")
        self.assertEqual((v.code, v.rule), ("patched", "3"))

    def test_below_the_fix_stays_vulnerable(self):
        def edit(files):
            one_install(files, "a-trunc", "AlmaLinux 9.6", "/usr/bin/php", "8.0.27",
                        "php-cli-8.0.27-1.el9.x86_64", cves=ONE_CVE)
        v = verdict_of(edit, "a-trunc")
        self.assertEqual((v.code, v.rule, v.action), ("vulnerable", "3", "vendor-update"))
        self.assertIn("php-cli-8.0.30-3.el9_6", v.fix_target)


class NoFeedFamilies(unittest.TestCase):
    """R43: rule 6 also covers a known package on a family with no feed the skill reads."""

    def test_oracle_known_package_is_likely_patched(self):
        def edit(files):
            one_install(files, "a-ol8", "Oracle Linux 8.10", "/usr/bin/php", "8.2.35",
                        "php-cli-8.2.35-1.module+el8.10.0+90000+abcdef12.x86_64")
        v = verdict_of(edit, "a-ol8")
        self.assertEqual((v.code, v.rule), ("likely-patched", "6"))
        self.assertEqual(v.evidence[0].type, "absence")
        self.assertIn("2026-10-22", v.evidence[0].expected)

    def test_amazon_known_package_is_likely_patched(self):
        def edit(files):
            one_install(files, "a-ol8", "Amazon Linux 2023", "/usr/bin/php", "8.3.36",
                        "php8.3-cli-8.3.36-1.amzn2023.0.1.x86_64")
            files["plugins.json"].append({
                "plugin_id": 370900, "name": "Amazon Linux 2023 : php8.3 (ALAS2023-2026-1001)",
                "family": "Amazon Linux Local Security Checks", "scan_type": "local",
                "sensor": "nessus", "published": "2026-10-23"})
        v = verdict_of(edit, "a-ol8")
        self.assertEqual((v.code, v.rule), ("likely-patched", "6"))

    def test_no_feed_family_still_needs_credentials(self):
        def edit(files):
            one_install(files, "a-ol8", "Oracle Linux 8.10", "/usr/bin/php", "8.2.35",
                        "php-cli-8.2.35-1.module+el8.10.0+90000+abcdef12.x86_64")
            files["assets.json"]["a-ol8"]["auth_plugins"] = []
        self.assertEqual(verdict_of(edit, "a-ol8").code, "unverified-credentials")

    def test_feed_family_with_known_package_keeps_rule_8(self):
        def fail(files):
            for e in files["advisories/index.json"]:
                if "UBUNTU" in e["url"]:
                    e.update(status="failed", file=None, error="HTTP 429")
        v = verdict_of(fail, "a-ubuntu-ok")
        self.assertEqual((v.code, v.rule), ("unverified-no-data", "8"))


class NeverPatchedGuards(unittest.TestCase):
    """Invariant 1: no Patched without positive, same-channel evidence."""

    def test_other_channel_fix_at_or_below_install_is_never_patched(self):
        def edit(files):
            one_install(files, "a-trunc", "Red Hat Enterprise Linux 9.7", "/usr/bin/php",
                        "8.0.30", "php-cli-8.0.30-5.el9_7.x86_64", cves=ONE_CVE)
        v = verdict_of(edit, "a-trunc")
        self.assertNotEqual(v.code, "patched")
        self.assertEqual(v.code, "unverified-no-data")
        self.assertIn("RHSA-2026:88720 (other channel) (CVE-2026-109618)",
                      refs(v, "vendor-feed"))

    def test_not_credentialed_with_patched_feed_is_never_patched(self):
        for auth in ([], [110723], [141118, 104410]):
            def edit(files):
                files["assets.json"]["a-ubuntu-ok"]["auth_plugins"] = auth
            with self.subTest(auth=auth):
                v = verdict_of(edit, "a-ubuntu-ok")
                self.assertEqual((v.code, v.rule), ("unverified-credentials", "7"))

    def test_managed_by_os_unknown_with_patched_feed_is_never_patched(self):
        def edit(files):
            one_install(files, "a-ubuntu-ok", "Linux Kernel 5.15 on Ubuntu 22.04",
                        "/usr/bin/php8.1", "8.1.2", "php8.1-cli 8.1.2-1ubuntu2.28", managed=None)
        v = verdict_of(edit, "a-ubuntu-ok")
        self.assertEqual((v.code, v.rule), ("unverified-no-data", "8"))
        self.assertIn("Managed by OS unknown", v.evidence[0].observed)


class ApkSuffix(unittest.TestCase):
    def test_unknown_apk_suffix_does_not_crash_and_is_not_patched(self):
        def edit(files):
            one_install(files, "a-trunc", "Alpine Linux 3.22.1", "/usr/bin/php83", "8.3.36",
                        "php83-8.3.36_foo1-r0")
        v = verdict_of(edit, "a-trunc")
        self.assertNotEqual(v.code, "patched")
        self.assertEqual((v.code, v.rule), ("unverified-no-data", "8"))


class LoadRun(unittest.TestCase):
    def test_empty_run(self):
        d = Path(tempfile.mkdtemp())
        try:
            (d / "findings.json").write_text("[]")
            (d / "assets.json").write_text("{}")
            run = load_run(d)
            self.assertEqual((run.catalog, run.faq), ([], {}))
            self.assertEqual(judge(run), [])
        finally:
            shutil.rmtree(d)

    def test_findings_required(self):
        d = Path(tempfile.mkdtemp())
        try:
            (d / "assets.json").write_text("{}")
            with self.assertRaises(FileNotFoundError):
                load_run(d)
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
