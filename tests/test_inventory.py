import unittest

from inventory import (Distro, Install, classify, coverage, coverage_published,
                       distro_for, parse_installs, stream_of)

MODULE_PKG = "php-cli-8.0.30-1.module+el8.8.0+21196+6feda386.x86_64"


def block(path, version, package, managed="True"):
    lines = [f"  Path : {path}", f"  Version : {version}",
             f"  Associated Package : {package}",
             "  INI file : /etc/php.ini", "  INI source : PHP -i command"]
    if managed is not None:
        lines.append(f"  Managed by OS : {managed}")
    return "\n".join(lines) + "\n"


HEAD = "Nessus detected {} installs of PHP:\n\n"
PKG = "php-cli-8.0.30-3.el9_6.x86_64"


class ParseInstalls(unittest.TestCase):
    def test_parse_two_installs(self):
        out = (HEAD.format(2) + block("/usr/bin/php", "8.0.30", PKG) + "\n"
               + block("/usr/bin/php-cgi", "8.0.30", PKG))
        installs, truncated = parse_installs(out)
        self.assertEqual(installs, [
            Install("/usr/bin/php", "8.0.30", PKG, True),
            Install("/usr/bin/php-cgi", "8.0.30", PKG, True)])
        self.assertFalse(truncated)

    def test_parse_truncated(self):
        out = (HEAD.format(3) + block("/usr/bin/php", "8.0.30", PKG) + "\n"
               + block("/usr/bin/php-cgi", "8.0.30", PKG) + "\n"
               + "  Path : /opt/php/bin/php\n  Version : 8.3.1\n  Assoc\n"
               + "    ... (truncated)")
        installs, truncated = parse_installs(out)
        self.assertEqual([i.path for i in installs],
                         ["/usr/bin/php", "/usr/bin/php-cgi"])
        self.assertTrue(truncated)

    def test_parse_truncated_keeps_block_with_complete_fields(self):
        # Shape seen live: the cut falls after Associated Package, inside INI source.
        out = (HEAD.format(3) + block("/usr/bin/php", "8.0.30", MODULE_PKG) + "\n"
               + f"  Path : /usr/bin/php-cgi\n  Version : 8.0.30\n"
               + f"  Associated Package : {MODULE_PKG}\n  INI file : /etc/php.ini\n"
               + "  INI source : PHP binary\n    ... (truncated)\n")
        installs, truncated = parse_installs(out)
        # Managed by OS was cut off; the same package on a whole block supplies it.
        self.assertEqual(installs, [
            Install("/usr/bin/php", "8.0.30", MODULE_PKG, True),
            Install("/usr/bin/php-cgi", "8.0.30", MODULE_PKG, True)])
        self.assertTrue(truncated)

    def test_parse_truncated_block_without_matching_package_stays_unknown(self):
        out = (HEAD.format(2) + block("/usr/bin/php", "8.0.30", PKG) + "\n"
               + f"  Path : /opt/php/bin/php\n  Version : 8.3.1\n"
               + f"  Associated Package : {MODULE_PKG}\n  INI file : /etc/php.ini\n"
               + "  INI source : PHP binary\n    ... (truncated)\n")
        installs, _ = parse_installs(out)
        self.assertIsNone(installs[1].managed_by_os)

    def test_parse_truncated_drops_field_on_cut_line(self):
        # The line just before the marker may be cut mid-value ("8.3.1" of "8.3.12").
        out = (HEAD.format(2) + block("/usr/bin/php", "8.0.30", PKG) + "\n"
               + f"  Path : /opt/php/bin/php\n  Associated Package : None\n"
               + "  Version : 8.3.1\n    ... (truncated)")
        installs, _ = parse_installs(out)
        self.assertEqual([i.path for i in installs], ["/usr/bin/php"])

    def test_parse_truncated_inline_marker_keeps_previous_line(self):
        # When the marker shares the cut line, every line before it is whole.
        out = (HEAD.format(2) + block("/usr/bin/php", "8.0.30", PKG)
               + "\n  Path : /usr/sb ... (truncated)")
        installs, _ = parse_installs(out)
        self.assertEqual(installs, [Install("/usr/bin/php", "8.0.30", PKG, True)])

    def test_parse_not_os_managed(self):
        out = (HEAD.format(2) + block("/opt/a/php", "8.3.1", "None", "False")
               + "\n" + block("/opt/b/php", "8.3.1", "None", None))
        installs, _ = parse_installs(out)
        self.assertIs(installs[0].managed_by_os, False)
        self.assertIsNone(installs[1].managed_by_os)

    def test_empty(self):
        self.assertEqual(parse_installs(""), ([], False))


class DistroFor(unittest.TestCase):
    def test_distro_for(self):
        cases = [
            (("Oracle Linux 8.10", MODULE_PKG), Distro("oracle", "8", None)),
            (("Linux Kernel 5.15 on Ubuntu 22.04", "php8.1-cli 8.1.2-1ubuntu2.20"),
             Distro("ubuntu", "22.04", "Ubuntu:22.04:LTS")),
            (("Ubuntu 20.04", "php7.4-cli 7.4.3-4ubuntu2.29+esm1"),
             Distro("ubuntu", "20.04", "Ubuntu:Pro:20.04:LTS")),
            (("", "php-cli-8.3.36-1.el10_2.x86_64"), Distro("rhel", "10", None)),
            (("Debian GNU/Linux 12", "php8.2-cli 8.2.7-1~deb12u1"),
             Distro("debian", "12", "Debian:12")),
            (("AlmaLinux 8.10", MODULE_PKG), Distro("alma", "8", "AlmaLinux:8")),
            (("Rocky Linux 9.6", PKG), Distro("rocky", "9", "Rocky Linux:9")),
            (("Red Hat Enterprise Linux 9.4", PKG), Distro("rhel", "9", None)),
            (("Amazon Linux 2023", "php8.3-cli-8.3.2-1.amzn2023.x86_64"),
             Distro("amazon", "2023", None)),
            (("Amazon Linux 2", "php-cli-8.2.1-1.amzn2.x86_64"),
             Distro("amazon", "2", None)),
            (("Fedora Linux 41", "php-cli-8.3.2-1.fc41.x86_64"),
             Distro("fedora", "41", None)),
            (("Alpine Linux 3.22.1", "php83 8.3.2-r0"),
             Distro("alpine", "3.22", "Alpine:v3.22")),
            (("SUSE Linux Enterprise Server 15 SP6", "php8-cli-8.2.1-1.1.x86_64"),
             Distro("suse", "15", "SUSE:Linux Enterprise Server 15 SP6")),
            (("SUSE Linux Enterprise Server 15", "php8-cli-8.2.1-1.1.x86_64"),
             Distro("suse", "15", None)),
            (("Gentoo Linux", "dev-lang/php-8.3.1"), None),
            (("", "php8.1-cli 8.1.2-1ubuntu2.20"), None),
            (("", ""), None),
        ]
        for args, want in cases:
            with self.subTest(args=args):
                self.assertEqual(distro_for(*args), want)


class StreamOf(unittest.TestCase):
    def test_stream_of(self):
        self.assertEqual(stream_of("php-cli-8.3.36-1.el9_6.x86_64"), "base")
        self.assertEqual(stream_of(MODULE_PKG), "8.0")
        self.assertEqual(stream_of("php8.1-cli 8.1.2-1ubuntu2.20"), "base")
        self.assertEqual(stream_of(""), "base")

    def test_stream_of_alma_module(self):
        # AlmaLinux writes module releases with "_" where RHEL and Rocky use "+".
        self.assertEqual(stream_of("php-cli-8.2.30-1.module_el9.6.0+100+abcd1234.x86_64"), "8.2")
        self.assertEqual(stream_of("php-cli-8.2.35-1.module_el8.10.0+4323+fc907035.x86_64"), "8.2")


def P(pid, name, family, scan_type="local", published="2026-10-22"):
    return {"plugin_id": pid, "name": name, "family": family,
            "scan_type": scan_type, "published": published}


class Classify(unittest.TestCase):
    def test_classify(self):
        cases = [
            (P(370210, "RHEL 9 : php (RHSA-2026:87151)", "Red Hat Local Security Checks"), "vendor"),
            (P(372182, "F5 Networks BIG-IP : PHP vulnerabilities (K000163821)", "F5 Networks Local Security Checks"), "vendor"),
            (P(1, "Some Product", "Misc.", "local"), "vendor"),
            (P(370006, "Linux Distros Unpatched Vulnerability : CVE-2026-109618", "Misc.", "combined"), "unpatched"),
            (P(372053, "Amazon Linux Unpatched Vulnerability : CVE-2026-109619", "Misc.", "combined"), "unpatched"),
            (P(369483, "PHP < 8.2.35 / 8.3.x < 8.3.36 Multiple Vulnerabilities", "CGI abuses", "combined"), "version"),
            (P(115719, "PHP 8.x.x < 8.5.12", "Component Vulnerability", "version_based"), "version"),
            (P("216936", "PHP Installed (Linux)", "General", "local"), "inventory"),
            (P(48243, "PHP Version Detection", "Web Servers", "remote"), "inventory"),
            (P(5, "Whatever", "General", "remote"), "other"),
        ]
        for plugin, want in cases:
            with self.subTest(plugin=plugin["plugin_id"]):
                self.assertEqual(classify(plugin), want)


LSC = " Local Security Checks"


class Coverage(unittest.TestCase):
    def test_coverage(self):
        cat = [
            P(1, "Oracle Linux 8 : php:7.4 (ELSA-2026-87080)", "Oracle Linux" + LSC),
            P(2, "Oracle Linux 8 : php:8.2 (ELSA-2026-87073)", "Oracle Linux" + LSC),
            P(3, "RHEL 9 : php (RHSA-2026:87151)", "Red Hat" + LSC),
            P(4, "Ubuntu 22.04 LTS / 24.04 LTS / 26.04 LTS / 26.10 : PHP vulnerabilities (USN-8948-1)",
              "Ubuntu" + LSC),
            P(5, "Linux Distros Unpatched Vulnerability : CVE-2026-109618", "Misc.", "combined"),
        ]
        cov = coverage(cat)
        self.assertEqual(cov[("oracle", "8")], {"7.4", "8.2"})
        self.assertNotIn("8.0", cov[("oracle", "8")])
        self.assertEqual(cov[("rhel", "9")], {"base"})
        for rel in ("22.04", "24.04", "26.04", "26.10"):
            self.assertEqual(cov[("ubuntu", rel)], {"base"})
        self.assertEqual(len(cov), 6)

    def test_coverage_keys_real_names(self):
        cases = [
            ("Debian dsa-6574 : libapache2-mod-php8.4 - security update", "Debian" + LSC, ("debian", "*"), "base"),
            ("Alpine: php82: security update to 8.2.35-r0", "Alpine Linux" + LSC, ("alpine", "*"), "base"),
            ("RockyLinux 9 : php:8.2 (RLSA-2026:87072)", "Rocky Linux" + LSC, ("rocky", "9"), "8.2"),
            ("Rocky Linux 9.6 [CIQ] Security Update: php / php-cli Multiple Vulnerabilities (ciqsa-2026_1715)",
             "Rocky Linux" + LSC, ("rocky", "9"), "base"),
            ("Rocky Linux 9.6 [TuxCare] Security Update: php (ALMALINUX9.6:CLSA-2026:1)",
             "Rocky Linux" + LSC, ("rocky", "9"), "base"),
            ("AlmaLinux 8 : ALSA-2026:A011php:7.2 (ALSA-2026:A011)", "Alma Linux" + LSC, ("alma", "8"), "7.2"),
            ("SUSE SLES15: apache2-mod_php8 / php8 (SUSE-SU-2026:4852-1)", "SuSE" + LSC, ("suse", "15"), "base"),
            ("Amazon Linux 2023 : php8.3, php8.3-cli (ALAS2023-2026-3302)", "Amazon Linux" + LSC, ("amazon", "2023"), "base"),
            ("Amazon Linux 2 : php (ALASPHP8.2-2026-015)", "Amazon Linux" + LSC, ("amazon", "2"), "base"),
            ("CentOS Linux 7.9 [CIQ] Security Update: php (ciqsa-2026_1)", "CentOS" + LSC, ("centos", "7"), "base"),
            ("Fedora 43 : php (2026-d5f8446449)", "Fedora" + LSC, ("fedora", "43"), "base"),
        ]
        for name, family, key, stream in cases:
            with self.subTest(name=name[:40]):
                cov = coverage([P(1, name, family)])
                self.assertEqual(cov, {key: {stream}})

    def test_coverage_skips_unknown_and_non_vendor(self):
        cat = [P(1, "TencentOS 3 : php (TSSA-1)", "Tencent" + LSC),
               P(2, "PHP < 8.3.36", "CGI abuses", "combined"),
               P(3, "Linux Distros Unpatched Vulnerability : CVE-1", "Misc.", "combined")]
        self.assertEqual(coverage(cat), {})

    def test_coverage_published_earliest(self):
        cat = [P(1, "Oracle Linux 8 : php:7.4 (E1)", "Oracle Linux" + LSC, published="2026-10-23"),
               P(2, "Oracle Linux 8 : php:7.4 (E2)", "Oracle Linux" + LSC, published="2026-10-21"),
               P(3, "RHEL 9 : php (R)", "Red Hat" + LSC, published="2026-10-22")]
        self.assertEqual(coverage_published(cat), {
            ("oracle", "8", "7.4"): "2026-10-21", ("rhel", "9", "base"): "2026-10-22"})


if __name__ == "__main__":
    unittest.main()
