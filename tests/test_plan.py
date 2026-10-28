import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from plan import (SKILL_VERSION, Owners, auth_followup, build_plan, bucket, internet_facing,
                  load_owners, next_step, owner_for, serves_web)
from tests.schema_check import validate
from tests.test_verify import SHOP, run_dir
from verify import ACTIONABLE, VERDICTS, VERIFY_FIRST, judge, load_run

ROOT = Path(__file__).parent.parent
OWNERS = Path(__file__).parent / "fixtures" / "owners.csv"
SCHEMA = json.loads((ROOT / "schemas" / "action-plan.schema.json").read_text())
NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)
AUTH_URL = "https://exchange.tenable.com/skills/auth-failure-analyzer/"


def write_csv(text: str, encoding="utf-8") -> Path:
    d = Path(tempfile.mkdtemp())
    p = d / "owners.csv"
    p.write_bytes(text.encode(encoding))
    return p


def built(edit=None, owners=None, now=NOW):
    d = run_dir(edit)
    try:
        run = load_run(d)
        results = judge(run)
        return build_plan(results, run, load_owners(owners), now), {r.key: r for r in results}
    finally:
        shutil.rmtree(d.parent)


def by_key(plan, section="items"):
    return {(i["asset_id"] or i["url"]): i for i in plan[section]}


def set_asset(files, key, **fields):
    files["assets.json"][key].update(fields)


class Buckets(unittest.TestCase):
    def test_buckets(self):
        def edit(files):  # a command-line-only host that serves no web requests
            set_asset(files, "a-ol8", http_service=False)
        plan, _ = built(edit)
        items, verify = by_key(plan), by_key(plan, "verify_first")
        self.assertEqual(items["a-eol"]["bucket"], "FIRST")
        self.assertEqual(items[SHOP]["bucket"], "FIRST")
        self.assertEqual(items["a-rhel9"]["bucket"], "NEXT")
        self.assertEqual(items["a-ol8"]["bucket"], "SOON")
        for k in ("a-nocreds", "a-ubuntu-conflict", "a-deb-clean"):
            self.assertEqual(verify[k]["bucket"], "VERIFY", k)
            self.assertNotIn(k, items)
        for k in ("a-ubuntu-ok",):
            self.assertNotIn(k, items)
            self.assertNotIn(k, verify)

    def test_bucket_function(self):
        _, res = built()
        self.assertEqual(bucket(res["a-eol"]), "FIRST")
        self.assertEqual(bucket(res["a-rhel9"]), "NEXT")
        self.assertEqual(bucket(res["a-ubuntu-ok"]), "VERIFY")

    def test_internet_and_web(self):
        _, res = built()
        self.assertTrue(internet_facing(res["a-eol"]))      # documentation range stands in for public
        self.assertTrue(internet_facing(res[SHOP]))
        self.assertFalse(internet_facing(res["a-rhel9"]))
        self.assertFalse(internet_facing(res["a-image"]))   # no IP
        self.assertTrue(serves_web(res["a-rhel9"]))         # php-cgi
        self.assertTrue(serves_web(res["a-image"]))         # unknown: assume it does
        _, res = built(lambda f: set_asset(f, "a-ol8", http_service=False))
        self.assertFalse(serves_web(res["a-ol8"]))
        self.assertFalse(internet_facing(res["a-ol8"]))

    def test_unparseable_ip_is_not_internet_facing(self):
        _, res = built(lambda f: set_asset(f, "a-rhel9", ips=["not-an-ip"]))
        self.assertFalse(internet_facing(res["a-rhel9"]))

    def test_internet_first_beats_acr(self):
        def edit(files):
            set_asset(files, "a-eol", acr=2, apa_level=None, aes=10)
            set_asset(files, "a-rhel9", acr=10, apa_level="critical", aes=999)
        plan, _ = built(edit)
        items = by_key(plan)
        self.assertLess(items["a-eol"]["rank"], items["a-rhel9"]["rank"])

    def test_within_bucket_order(self):
        def edit(files):
            for k in ("a-rhel9", "a-trunc", "a-win", "a-image", "a-ol8"):
                set_asset(files, k, apa_level=None, acr=5, aes=100)
            set_asset(files, "a-rhel9", apa_level="high", acr=1)
            set_asset(files, "a-trunc", apa_level="critical", acr=1)
            set_asset(files, "a-win", acr=9, aes=1)
            set_asset(files, "a-ol8", acr=8, aes=500)
            set_asset(files, "a-image", acr=8, aes=600)
        plan, _ = built(edit)
        nxt = [i["asset_id"] for i in plan["items"] if i["bucket"] == "NEXT"]
        self.assertEqual(nxt, ["a-trunc", "a-rhel9", "a-win", "a-image", "a-ol8"])

    def test_ranks_run_across_buckets(self):
        plan, _ = built()
        self.assertEqual([i["rank"] for i in plan["items"]], list(range(1, len(plan["items"]) + 1)))
        order = [i["bucket"] for i in plan["items"]]
        self.assertEqual(order, sorted(order, key=["FIRST", "NEXT", "SOON"].index))
        for v in plan["verify_first"]:
            self.assertIsNone(v["rank"])


class Owner(unittest.TestCase):
    def test_owner_precedence(self):
        csv = write_csv("asset_id,owner\na-ol8,Platform Ops\n")
        plan, _ = built(owners=csv)
        items = by_key(plan)
        self.assertEqual((items["a-ol8"]["owner"], items["a-ol8"]["owner_source"]),
                         ("Platform Ops", "owner-file"))
        plan, _ = built()
        items = by_key(plan)
        self.assertEqual((items["a-ol8"]["owner"], items["a-ol8"]["owner_source"]),
                         ("platform-team", "tag:Owner"))
        self.assertEqual((items["a-trunc"]["owner"], items["a-trunc"]["owner_source"]),
                         ("", "unassigned"))

    def test_identifier_preference(self):
        csv = write_csv("hostname,asset_id,owner\nweb01,,By Name\n,a-rhel9,By Id\n")
        owners = load_owners(csv)
        asset = {"name": "web01", "ips": ["10.0.1.10"], "fqdns": []}
        self.assertEqual(owners.match(asset, "a-rhel9"), "By Id")
        self.assertEqual(owners.match(asset, "other"), "By Name")
        self.assertIsNone(owners.match({"name": "x", "ips": [], "fqdns": []}, "y"))

    def test_owner_csv_excel_quirks(self):
        csv = write_csv(" Hostname ,OWNER\r\nweb01,Web Platform\r\nWEB01,Someone Else\r\n"
                        "db01,\r\ndb01,DBA Team\r\nweb02,\r\n", "utf-8-sig")
        owners = load_owners(csv)
        asset = lambda n: {"name": n, "ips": [], "fqdns": []}
        self.assertEqual(owners.match(asset("web01"), "k1"), "Web Platform")
        self.assertEqual(owners.match(asset("Web01"), "k1"), "Web Platform")
        self.assertEqual(owners.match(asset("db01"), "k2"), "DBA Team")   # blank ignored
        self.assertIsNone(owners.match(asset("web02"), "k3"))
        self.assertEqual(owners.duplicates, 1)

    def test_owner_csv_ip_and_fqdn(self):
        csv = write_csv("fqdn,ip,owner\nA.example.com,,Team A\n,192.0.2.5,Team B\n")
        owners = load_owners(csv)
        self.assertEqual(owners.match({"name": "", "ips": [], "fqdns": ["a.EXAMPLE.com"]}, "k"),
                         "Team A")
        self.assertEqual(owners.match({"name": "", "ips": ["192.0.2.5"], "fqdns": []}, "k"),
                         "Team B")

    def test_owner_csv_not_utf8(self):
        csv = write_csv("hostname,owner\nweb01,Jos\u00e9 Garc\u00eda\n", "cp1252")
        with self.assertRaises(ValueError) as cm:
            load_owners(csv)
        self.assertIn("owner file is not UTF-8; save it as CSV UTF-8", str(cm.exception))
        self.assertNotIsInstance(cm.exception, UnicodeDecodeError)

    def test_owner_csv_missing_header(self):
        with self.assertRaises(ValueError) as cm:
            load_owners(write_csv("hostname,team\nweb01,x\n"))
        self.assertIn("owner", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            load_owners(write_csv("owner,team\nx,y\n"))
        self.assertIn("asset_id", str(cm.exception))

    def test_no_owner_file(self):
        owners = load_owners(None)
        self.assertIsInstance(owners, Owners)
        self.assertIsNone(owners.match({"name": "web01", "ips": [], "fqdns": []}, "k"))
        self.assertEqual(owners.duplicates, 0)

    def test_fixture_owners_leave_an_actionable_asset_unassigned(self):
        plan, _ = built(owners=OWNERS)
        self.assertGreater(plan["coverage"]["unassigned_actionable"], 0)
        items = by_key(plan)
        self.assertEqual(items["a-rhel9"]["owner"], "Web Platform")
        self.assertEqual(items[SHOP]["owner"], "Payments")
        self.assertEqual(items["a-eol"]["owner_source"], "owner-file")


class Identity(unittest.TestCase):
    def test_identity(self):
        def edit(files):
            set_asset(files, "a-trunc", name="web01")
        plan, _ = built(edit)
        named = [i for i in plan["items"] if i["hostname"] == "web01"]
        self.assertEqual({i["asset_id"] for i in named}, {"a-rhel9", "a-trunc"})
        shop = by_key(plan)[SHOP]
        self.assertEqual(shop["asset_id"], "")
        self.assertEqual(shop["url"], SHOP)

    def test_owner_file_does_not_merge_ids(self):
        csv = write_csv("asset_id,owner\na-rhel9,One\n")
        plan, _ = built(owners=csv)
        items = by_key(plan)
        self.assertEqual(items["a-trunc"]["owner_source"], "unassigned")


class Flags(unittest.TestCase):
    def test_stale_flag(self):
        old, edge = "2026-09-26", "2026-09-27"      # 31 and 30 days before 2026-10-27
        plan, _ = built(lambda f: (set_asset(f, "a-rhel9", last_seen=old),
                                   set_asset(f, "a-win", last_seen=edge)))
        items = by_key(plan)
        self.assertTrue(items["a-rhel9"]["flags"]["stale"])
        self.assertFalse(items["a-win"]["flags"]["stale"])

    def test_possible_compromise(self):
        plan, _ = built()
        items = by_key(plan)
        self.assertTrue(items["a-eol"]["flags"]["possible_compromise"])
        self.assertIn("2026-10-17", items["a-eol"]["compromise_note"])
        self.assertTrue(items["a-eol"]["compromise_note"].startswith("Assume compromise"))
        self.assertFalse(items["a-rhel9"]["flags"]["possible_compromise"])
        self.assertEqual(items["a-rhel9"]["compromise_note"], "")


class Content(unittest.TestCase):
    def test_reason_and_action(self):
        plan, _ = built()
        items = by_key(plan)
        self.assertEqual(items[SHOP]["reason"], "internet-facing (WAS)")
        self.assertEqual(items["a-eol"]["reason"],
                         "internet-facing (public IP), critical attack path, ACR 9")
        self.assertEqual(items["a-rhel9"]["reason"], "internal, high attack path, ACR 8")
        self.assertEqual(items["a-eol"]["action"], "isolate-or-upgrade")
        self.assertEqual(items["a-eol"]["fix_target"], "8.2.35")

    def test_worst_install_sets_action(self):
        def edit(files):  # a second, EOL install on a-rhel9
            for r in files["findings.json"]:
                if r["asset_id"] == "a-rhel9" and r["role"] == "inventory":
                    r["plugin_output"] += ("\n  Path : /opt/php72/bin/php\n  Version : 7.2.34\n"
                                           "  Managed by OS : False\n")
        plan, _ = built(edit)
        item = by_key(plan)["a-rhel9"]
        self.assertEqual(len(item["php_installs"]), 3)
        self.assertEqual(item["action"], "isolate-or-upgrade")
        self.assertEqual({i["verdict"] for i in item["php_installs"]}, {"vulnerable", "eol"})

    def test_mitigations_and_vulnerability(self):
        plan, _ = built()
        vuln = plan["vulnerability"]
        self.assertEqual(vuln["interim_mitigations"],
                         ["Block requests with suspicious query strings at the web "
                          "application firewall"])
        self.assertEqual(by_key(plan)["a-eol"]["interim_mitigations"], vuln["interim_mitigations"])
        self.assertEqual(vuln["exploitation_since"], "2026-10-17")
        self.assertNotIn("cvss", vuln)

        def edit(files):
            files["faq.json"] = None
        plan, _ = built(edit)
        vuln = plan["vulnerability"]
        self.assertEqual(vuln["fixed"]["8.4"], "8.4.27")
        self.assertEqual(len(vuln["interim_mitigations"]), 4)
        self.assertIn("memory_limit=-1", vuln["interim_mitigations"][0])
        self.assertIn("fatal_error_backtraces=0", vuln["interim_mitigations"][2])
        self.assertIn("Restart", vuln["interim_mitigations"][3])
        self.assertEqual(vuln["exploitation_since"], "2026-10-17")

    def test_cvss_only_when_faq_gives_one(self):
        def edit(files):
            files["faq.json"]["cvss"] = 9.2
        plan, _ = built(edit)
        self.assertEqual(plan["vulnerability"]["cvss"], 9.2)

    def test_verification_plugins(self):
        plan, _ = built()
        self.assertEqual(by_key(plan)["a-eol"]["verification"],
                         {"rescan": True, "plugins_should_stop": ["369483"]})
        self.assertEqual(by_key(plan)[SHOP]["verification"]["plugins_should_stop"], ["115721"])

    def test_port_and_source_plugin(self):
        plan, _ = built()
        inst = by_key(plan)["a-eol"]["php_installs"][0]
        self.assertEqual((inst["port"], inst["source_plugin"], inst["path"]),
                         ("443", "369483", "/opt/php72/bin/php"))

    def test_coverage_and_sources(self):
        plan, _ = built(owners=OWNERS)
        cov = plan["coverage"]
        self.assertEqual(sum(cov["by_credential_state"].values()), 12)
        self.assertEqual(sum(cov["by_verdict"].values()), 12)
        self.assertEqual(sum(cov["by_owner_source"].values()), 12)
        self.assertEqual(cov["by_owner_source"]["owner-file"], 4)
        self.assertEqual(cov["by_owner_source"]["tag:Owner"], 1)
        self.assertEqual(cov["by_verdict"]["patched"], 1)
        self.assertEqual(cov["output_truncated_assets"], ["a-trunc"])
        names = [s["source"] for s in plan["sources"]]
        self.assertEqual(names[0], "tenable-hexa")
        self.assertIn("tenable-faq", names)
        self.assertIn("osv", names)

    def test_failed_feed_is_listed(self):
        def edit(files):
            files["advisories/index.json"][0].update(status="failed", error="HTTP 429")
        plan, _ = built(edit)
        failed = [s for s in plan["sources"] if s["status"] == "failed"]
        self.assertTrue(any(s["error"] == "HTTP 429" for s in failed))


class Soon(unittest.TestCase):
    """R44: SOON for a host whose PHP is all command-line, output complete, no 10107, no WAS."""

    def test_cli_only_host_with_unknown_http_is_soon(self):
        plan, res = built(lambda f: set_asset(f, "a-ol8", http_service=None))
        self.assertFalse(serves_web(res["a-ol8"]))
        item = by_key(plan)["a-ol8"]
        self.assertEqual((item["bucket"], item["flags"]["serves_web"]), ("SOON", False))
        self.assertIn("no sign PHP serves web requests", item["reason"])

    def test_truncated_output_is_next(self):
        def edit(files):
            set_asset(files, "a-ol8", http_service=None)
            for r in files["findings.json"]:
                if r["asset_id"] == "a-ol8" and r["role"] == "inventory":
                    r["plugin_output"] = r["plugin_output"].replace(
                        "1 install", "2 installs") + "\n  Path : /usr/sb ... (truncated)"
        plan, res = built(edit)
        self.assertTrue(res["a-ol8"].output_truncated)
        self.assertTrue(serves_web(res["a-ol8"]))
        self.assertEqual(by_key(plan)["a-ol8"]["bucket"], "NEXT")

    def test_http_service_seen_is_next(self):
        plan, res = built(lambda f: set_asset(f, "a-ol8", http_service=True))
        self.assertTrue(serves_web(res["a-ol8"]))
        self.assertEqual(by_key(plan)["a-ol8"]["bucket"], "NEXT")

    def test_web_install_with_unknown_http_is_next(self):
        plan, res = built(lambda f: set_asset(f, "a-rhel9", http_service=None))  # php-cgi
        self.assertEqual(by_key(plan)["a-rhel9"]["bucket"], "NEXT")


class Verify(unittest.TestCase):
    def test_next_step_feed_failed_with_known_package(self):
        def fail(files):
            for e in files["advisories/index.json"]:
                if "UBUNTU" in e["url"]:
                    e.update(status="failed", file=None, error="HTTP 429")
        plan, res = built(fail)
        entry = by_key(plan, "verify_first")["a-ubuntu-ok"]
        self.assertEqual(entry["php_installs"][0]["verdict"], "unverified-no-data")
        self.assertEqual(entry["next_step"],
                         "Re-run fetch_advisories.py, then re-render with render.py")

    def test_next_step_unpatched_scan_hint(self):
        def edit(files):  # a-ol8 without credentials is unverified
            set_asset(files, "a-ol8", auth_plugins=[], unpatched_scan=False)
        plan, res = built(edit)
        entry = by_key(plan, "verify_first")["a-ol8"]
        self.assertEqual(entry["next_step"], "Configure credentialed scans and rescan"
                         "; turn on Scan for Unpatched Vulnerabilities")

    def test_next_step_messages(self):
        plan, res = built()
        v = by_key(plan, "verify_first")
        self.assertEqual(v["a-authfail"]["next_step"],
                         "Run Auth Failure Analyzer: analyze auth failures on a-authfail")
        self.assertEqual(v["a-nocreds"]["next_step"], "Configure credentialed scans and rescan")
        self.assertEqual(v["a-ubuntu-conflict"]["next_step"], "Resolve conflicting evidence")
        self.assertEqual(v["a-deb-clean"]["next_step"],
                         "Rescan with credentials after the next plugin update to confirm")
        self.assertEqual(next_step(res["a-authfail"]),
                         "Run Auth Failure Analyzer: analyze auth failures on a-authfail")

    def test_verify_first_shape(self):
        plan, _ = built()
        for v in plan["verify_first"]:
            self.assertEqual((v["bucket"], v["rank"], v["action"], v["fix_target"]),
                             ("VERIFY", None, None, None))
            self.assertTrue(v["reason"])
            self.assertTrue(v["php_installs"])

    def test_auth_followup(self):
        _, res = built()
        text = auth_followup(list(res.values()))
        lines = text.splitlines()
        self.assertEqual(lines[0], AUTH_URL)
        self.assertIn("analyze auth failures on a-authfail", text)
        self.assertIn("a-authfail\tapp04\t10.0.1.16\t104410", lines)
        self.assertNotIn("a-nocreds", text)
        self.assertNotIn("141118", text)


class Robustness(unittest.TestCase):
    def test_idless_failed_host_never_gets_a_synthetic_asset_id(self):
        def edit(files):
            for r in files["findings.json"]:
                if r["asset_id"] == "a-authfail":
                    r["asset_id"] = ""
            files["assets.json"]["app04|10.0.1.16"] = files["assets.json"].pop("a-authfail")
        plan, res = built(edit)
        entry = next(v for v in plan["verify_first"] if v["key"] == "app04|10.0.1.16")
        self.assertEqual(entry["asset_id"], "")
        self.assertEqual(entry["next_step"],
                         "Run Auth Failure Analyzer: analyze auth failures on app04")
        text = auth_followup(list(res.values()))
        self.assertIn("analyze auth failures on app04", text)
        self.assertIn("\tapp04\t10.0.1.16\t104410", text)
        self.assertNotIn("|", text)
        self.assertEqual(validate(plan, SCHEMA), [])
        self.assertEqual(by_key(plan)["a-rhel9"]["key"], "a-rhel9")

    def test_out_of_contract_scores_still_build_a_valid_plan(self):
        def edit(files):
            set_asset(files, "a-rhel9", acr="N/A", aes="N/A", apa_level="medium")
            set_asset(files, "a-trunc", acr=7, aes=700, apa_level="HIGH")
            set_asset(files, "a-win", acr=None, aes=None, apa_level=None)
            set_asset(files, "a-ol8", acr=5, aes=5, apa_level=None)
            set_asset(files, "a-image", acr=5, aes=9, apa_level=None)
        plan, _ = built(edit)
        self.assertEqual(validate(plan, SCHEMA), [])
        items = by_key(plan)
        ctx = items["a-rhel9"]["context"]
        self.assertEqual((ctx["acr"], ctx["aes"], ctx["apa_level"]), (None, None, None))
        self.assertEqual(items["a-trunc"]["context"]["apa_level"], "high")
        nxt = [i["asset_id"] for i in plan["items"] if i["bucket"] == "NEXT"]
        self.assertEqual(nxt, ["a-trunc", "a-image", "a-ol8", "a-rhel9", "a-win"])
        self.assertEqual(items["a-rhel9"]["reason"], "internal")


class ReasonWhere(unittest.TestCase):
    def test_no_ip_says_no_public_ip_recorded(self):
        plan, _ = built()
        items = by_key(plan)
        self.assertEqual(items["a-image"]["flags"]["internet_facing"], False)
        self.assertTrue(items["a-image"]["reason"].startswith("no public IP recorded"))
        self.assertNotIn("internal", items["a-image"]["reason"])
        self.assertEqual(items["a-image"]["bucket"], "NEXT")

    def test_private_ip_stays_internal(self):
        plan, _ = built()
        self.assertTrue(by_key(plan)["a-rhel9"]["reason"].startswith("internal"))

    def test_no_ip_and_no_web_sign(self):
        def edit(files):
            set_asset(files, "a-image", http_service=False)
        plan, _ = built(edit)
        reason = by_key(plan)["a-image"]["reason"]
        self.assertTrue(reason.startswith("no public IP recorded"), reason)


class Schema(unittest.TestCase):
    def test_plan_schema(self):
        plan, _ = built(owners=OWNERS)
        self.assertEqual(validate(plan, SCHEMA), [])
        self.assertEqual(plan["schema_version"], "1.0")
        self.assertEqual(plan["skill_version"], SKILL_VERSION)
        self.assertEqual(SKILL_VERSION, "2.0.0")
        self.assertEqual(plan["generated_at"], "2026-10-27T12:00:00+00:00")
        self.assertTrue(plan["items"])
        for item in plan["items"]:
            self.assertNotEqual(item["bucket"], "VERIFY")
            self.assertNotIn("next_step", item)
            codes = {i["verdict"] for i in item["php_installs"]}
            self.assertTrue(codes & ACTIONABLE)
            self.assertLessEqual(codes, set(VERDICTS))
        for entry in plan["verify_first"]:
            self.assertTrue(entry["next_step"])
            self.assertTrue({i["verdict"] for i in entry["php_installs"]} & VERIFY_FIRST)
            self.assertFalse({i["verdict"] for i in entry["php_installs"]} & ACTIONABLE)
        json.dumps(plan)

    def test_schema_rejects_bad_plan(self):
        plan, _ = built()
        bad = json.loads(json.dumps(plan))
        bad["items"][0]["bucket"] = "LATER"
        bad["items"][0]["extra"] = 1
        del bad["items"][0]["owner"]
        bad["items"][0]["rank"] = "1"
        errors = validate(bad, SCHEMA)
        text = "\n".join(errors)
        for needle in ("bucket", "extra", "owner", "rank"):
            self.assertIn(needle, text)
        self.assertNotEqual(validate({"schema_version": 1}, SCHEMA), [])

    def test_validator_subset(self):
        schema = {"type": "object", "required": ["a"], "additionalProperties": False,
                  "properties": {"a": {"type": ["integer", "null"]},
                                 "b": {"type": "string", "pattern": "^x"},
                                 "c": {"$ref": "#/$defs/c"}},
                  "$defs": {"c": {"type": "array", "items": {"enum": [1, 2]}}}}
        self.assertEqual(validate({"a": None, "b": "xy", "c": [1, 2]}, schema), [])
        self.assertTrue(validate({"a": True}, schema))        # bool is not an integer
        self.assertTrue(validate({"a": 1, "b": "y"}, schema))
        self.assertTrue(validate({"a": 1, "c": [3]}, schema))
        self.assertTrue(validate({"a": 1, "z": 0}, schema))
        self.assertTrue(validate({}, schema))


if __name__ == "__main__":
    unittest.main()
