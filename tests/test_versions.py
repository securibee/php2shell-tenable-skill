import unittest

from versions import (Nevra, compare_apk, compare_dpkg, compare_rpm,
                      dist_tag, parse_nevra, upstream_version)


def sign(n):
    return (n > 0) - (n < 0)


class VersionTests(unittest.TestCase):
    def check(self, fn, table):
        for a, b, want in table:
            with self.subTest(a=a, b=b):
                self.assertEqual(sign(fn(a, b)), want)

    def test_dpkg(self):
        self.check(compare_dpkg, [
            ("1.0", "1.0", 0),
            ("1.0~rc1", "1.0", -1),
            ("1:1.0", "2.0", 1),
            ("8.1.2-1ubuntu2.20", "8.1.2-1ubuntu2.28", -1),
            ("7.4.3-4ubuntu2.29+esm5", "7.4.3-4ubuntu2.29", 1),
            ("8.2.35-1~deb12u1", "8.2.35-1", -1),
            ("1.0a", "1.0+", -1),
        ])

    def test_rpm(self):
        self.check(compare_rpm, [
            ("8.0.30-3.el9_6", "8.0.30-3.el9_6.2", -1),
            ("8.0.30-8.el9_8.1", "8.0.30-3.el9_6.2", 1),
            ("0:8.3.36-1.el10_2", "8.3.36-1.el10_2", 0),
            ("1.0~rc1-1", "1.0-1", -1),
            ("1.0^1-1", "1.0-1", 1),
            ("1.10-1", "1.9-1", 1),
            ("1.0a-1", "1.0-1", 1),
        ])

    def test_apk(self):
        self.check(compare_apk, [
            ("8.3.36-r0", "8.3.35-r2", 1),
            ("8.4.27-r0", "8.4.27-r1", -1),
            ("1.0_rc1-r0", "1.0-r0", -1),
            ("1.0_p1-r0", "1.0-r0", 1),
        ])

    def test_apk_unknown_suffix_is_value_error(self):
        for a, b in [("8.3.36_foo1-r0", "8.3.36-r0"), ("8.3.36-r0", "8.3.36_zz-r1")]:
            with self.subTest(a=a, b=b), self.assertRaises(ValueError):
                compare_apk(a, b)

    def test_upstream_version(self):
        for fmt, v, want in [
                ("rpm", "8.0.30-3.el9_6.2", "8.0.30"),
                ("rpm", "1:8.3.30-1.el9.remi", "8.3.30"),
                ("dpkg", "8.1.31-1+ubuntu22.04.1+deb.sury.org+1", "8.1.31"),
                ("dpkg", "1:8.2.35-1~deb12u1", "8.2.35"),
                ("dpkg", "8.2.35", "8.2.35"),
                ("apk", "8.3.36-r0", "8.3.36"),
                ("apk", "8.3.36_rc1-r2", "8.3.36_rc1")]:
            with self.subTest(fmt=fmt, v=v):
                self.assertEqual(upstream_version(fmt, v), want)
        with self.assertRaises(ValueError):
            upstream_version("apk", "8.3.36_foo1-r0")

    def test_parse_nevra(self):
        self.assertEqual(parse_nevra("php-cli-8.0.30-3.el9_6.x86_64"),
                         Nevra("php-cli", 0, "8.0.30", "3.el9_6", "x86_64"))
        self.assertEqual(parse_nevra("php-0:8.3.36-1.el10_2.aarch64").epoch, 0)

    def test_dist_tag(self):
        self.assertEqual(dist_tag("3.el9_6"), "el9_6")
        self.assertEqual(dist_tag("3.el9_6.2"), "el9_6")
        self.assertEqual(dist_tag("1.module+el8.8.0+21196+6feda386"),
                         "module+el8.8.0")


if __name__ == "__main__":
    unittest.main()
