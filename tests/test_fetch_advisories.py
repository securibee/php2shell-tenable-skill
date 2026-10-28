import http.client
import io
import json
import tempfile
import unittest
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

import fetch_advisories as fa

CVES = ["CVE-2026-109618", "CVE-2026-109619"]


class FakeOpener:
    """Canned bytes per URL; an Exception value is raised. Unlisted URLs 404."""

    def __init__(self, responses=None, default=b"{}"):
        self.responses = responses or {}
        self.default = default
        self.calls = []
        self.headers = []

    def __call__(self, req, timeout=None):
        url = req.full_url
        self.calls.append(url)
        self.headers.append(req.get_header("User-agent"))
        self.timeout = timeout
        r = self.responses.get(url, self.default)
        if isinstance(r, list):  # sequence of results, one per call
            r = r.pop(0) if len(r) > 1 else r[0]
        if isinstance(r, Exception):
            raise r
        return _Resp(r)


class _Resp:
    def __init__(self, body):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(url, code):
    return urllib.error.HTTPError(url, code, "x", {}, io.BytesIO(b""))


class FetchTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.run_dir = Path(self._tmp.name)
        self.sleeps = []

    def write(self, name, obj):
        (self.run_dir / name).write_text(json.dumps(obj))

    def fetch(self, opener, **kw):
        return fa.fetch(self.run_dir, opener=opener, sleep=self.sleeps.append, **kw)

    def test_ok_writes_index_and_raw(self):
        idx = self.fetch(FakeOpener(default=b"{}"))
        rh = [e for e in idx if e["source"] == "redhat" and e["cve"] == CVES[0]][0]
        self.assertEqual(rh["status"], "ok")
        self.assertEqual(rh["file"], "redhat-cve-2026-109618.json")
        self.assertTrue((self.run_dir / "advisories" / rh["file"]).exists())
        self.assertIsNone(rh["error"])
        t = datetime.fromisoformat(rh["fetched_at"])
        self.assertEqual(t.utcoffset().total_seconds(), 0)
        on_disk = json.loads((self.run_dir / "advisories" / "index.json").read_text())
        self.assertEqual(on_disk, idx)
        for e in idx:
            self.assertEqual(set(e), {"source", "cve", "url", "fetched_at",
                                      "status", "file", "error"})

    def test_http_429_is_failed(self):
        url = "https://api.osv.dev/v1/vulns/UBUNTU-" + CVES[0]
        op = FakeOpener({url: http_error(url, 429)})
        idx = self.fetch(op)
        e = [x for x in idx if x["url"] == url][0]
        self.assertEqual(e["status"], "failed")
        self.assertIn("429", e["error"])
        self.assertIsNone(e["file"])
        self.assertFalse((self.run_dir / "advisories" / "osv-UBUNTU-CVE-2026-109618.json").exists())
        self.assertEqual(op.calls.count(url), 2)  # one retry
        self.assertEqual(self.sleeps, [5])
        self.assertTrue(any(x["status"] == "ok" for x in idx))

    def test_retry_then_ok(self):
        url = "https://api.osv.dev/v1/vulns/DEBIAN-" + CVES[0]
        op = FakeOpener({url: [http_error(url, 503), b"{}"]})
        idx = self.fetch(op)
        self.assertEqual([x for x in idx if x["url"] == url][0]["status"], "ok")

    def test_404_not_retried(self):
        url = "https://api.osv.dev/v1/vulns/DEBIAN-" + CVES[0]
        op = FakeOpener({url: http_error(url, 404)})
        idx = self.fetch(op)
        self.assertEqual([x for x in idx if x["url"] == url][0]["status"], "failed")
        self.assertEqual(op.calls.count(url), 1)
        self.assertEqual(self.sleeps, [])

    def test_incomplete_read_is_failed(self):
        url = "https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-109618.json"
        bad = _Resp(b"")
        def boom():
            raise http.client.IncompleteRead(b"{", 100)
        bad.read = boom
        op = FakeOpener()
        orig = op.__call__.__func__
        op.responses[url] = b"{}"
        class Op(FakeOpener):
            def __call__(inner, req, timeout=None):
                if req.full_url == url:
                    inner.calls.append(url)
                    return bad
                return orig(inner, req, timeout)
        op = Op()
        idx = self.fetch(op)
        e = [x for x in idx if x["url"] == url][0]
        self.assertEqual(e["status"], "failed")
        self.assertIn("IncompleteRead", e["error"])
        self.assertIsNone(e["file"])
        self.assertTrue(any(x["status"] == "ok" for x in idx))
        self.assertTrue((self.run_dir / "advisories" / "index.json").exists())

    def test_timeout_is_failed(self):
        url = "https://api.osv.dev/v1/vulns/DEBIAN-" + CVES[1]
        idx = self.fetch(FakeOpener({url: TimeoutError("timed out")}))
        e = [x for x in idx if x["url"] == url][0]
        self.assertEqual(e["status"], "failed")
        self.assertTrue(e["error"])

    def test_bad_json_is_failed(self):
        idx = self.fetch(FakeOpener(default=b"<html>"))
        self.assertTrue(idx)
        for e in idx:
            if e["status"] != "skipped":
                self.assertEqual(e["status"], "failed")
                self.assertIsNone(e["file"])
        adv = self.run_dir / "advisories"
        self.assertEqual([p.name for p in adv.iterdir()], ["index.json"])

    def test_alpine_skipped_without_alpine_assets(self):
        self.write("assets.json", {"a1": {"os": "Ubuntu 22.04"}})
        idx = self.fetch(FakeOpener())
        al = [e for e in idx if e["source"] == "alpine"]
        self.assertEqual(len(al), 1)
        self.assertEqual(al[0]["status"], "skipped")
        self.assertEqual(al[0]["url"], "")
        self.assertIsNone(al[0]["file"])

    def test_alpine_release_fetched(self):
        self.write("assets.json", {"a1": {"os": "Linux Kernel 6 on Alpine Linux 3.22"},
                                   "a2": {"os": "Alpine Linux v3.22.1"}})
        op = FakeOpener()
        idx = self.fetch(op)
        al = [e for e in idx if e["source"] == "alpine"]
        self.assertEqual(len(al), 1)
        self.assertEqual(al[0]["url"], "https://secdb.alpinelinux.org/v3.22/community.json")
        self.assertEqual(al[0]["file"], "alpine-v3.22.json")
        self.assertEqual(al[0]["cve"], "")
        self.assertEqual(al[0]["status"], "ok")

    def test_advisory_ids_from_plugin_names(self):
        names = ["AlmaLinux 8 : php:8.2 (ALSA-2026:87073)",
                 "AlmaLinux 8 : php:8.2 (ALSA-2026:87073)",
                 "Rocky Linux 9 : php (RLSA-2026:87151)",
                 "SUSE SLES15 Security Update : php8 (SUSE-SU-2026:4844-1)",
                 "AlmaLinux 8 : ALSA-2026:A011php:7.2 (ALSA-2026:A011)",
                 "AlmaLinux 9.6 [TuxCare] Security Update: php (ALMALINUX9.6:CLSA-2026:1792602059)"]
        self.write("plugins.json", [{"plugin_id": str(i), "name": n}
                                    for i, n in enumerate(names)])
        op = FakeOpener()
        idx = self.fetch(op)
        osv = [u for u in op.calls if u.startswith("https://api.osv.dev/")]
        self.assertEqual(sorted(osv), sorted(
            ["https://api.osv.dev/v1/vulns/ALSA-2026:87073",
             "https://api.osv.dev/v1/vulns/RLSA-2026:87151",
             "https://api.osv.dev/v1/vulns/SUSE-SU-2026:4844-1",
             "https://api.osv.dev/v1/vulns/ALSA-2026:A011"]
            + ["https://api.osv.dev/v1/vulns/%s-%s" % (p, c)
               for p in ("UBUNTU", "DEBIAN") for c in CVES]))
        e = [x for x in idx if x["url"].endswith("ALSA-2026:87073")][0]
        self.assertEqual(e["cve"], "")
        self.assertEqual(e["file"], "osv-ALSA-2026_87073.json")

    def test_cves_from_faq(self):
        self.write("faq.json", {"cves": ["CVE-2027-1"]})
        op = FakeOpener()
        self.fetch(op)
        self.assertIn("https://security.access.redhat.com/data/csaf/v2/vex/2027/cve-2027-1.json",
                      op.calls)
        self.assertFalse(any("109618" in u for u in op.calls))

    def test_user_agent_timeout_and_now(self):
        op = FakeOpener()
        fixed = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)
        idx = self.fetch(op, now=lambda: fixed)
        self.assertEqual(set(op.headers), {"php2shell-tenable-skill/2.0.0"})
        self.assertEqual(op.timeout, 60)
        self.assertEqual(idx[0]["fetched_at"], "2026-10-27T12:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
