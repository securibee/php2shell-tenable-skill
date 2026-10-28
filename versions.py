"""Package version comparison for dpkg, RPM and apk, plus NEVRA parsing."""
from __future__ import annotations

import re
from typing import NamedTuple


def _cmp(a, b) -> int:
    return (a > b) - (a < b)


class Nevra(NamedTuple):
    name: str
    epoch: int
    version: str
    release: str
    arch: str


# dpkg (Debian Policy 5.6.12)

def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if not c or c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_part(a: str, b: str) -> int:
    while a or b:
        # non-digit run, compared char by char (end of run counts as 0)
        while (a and not a[0].isdigit()) or (b and not b[0].isdigit()):
            d = _cmp(_dpkg_order(a[:1]), _dpkg_order(b[:1]))
            if d:
                return d
            a, b = a[1:], b[1:]
        na = re.match(r"\d*", a).group()
        nb = re.match(r"\d*", b).group()
        d = _cmp(int(na or 0), int(nb or 0))
        if d:
            return d
        a, b = a[len(na):], b[len(nb):]
    return 0


def _dpkg_split(v: str):
    epoch, _, rest = v.rpartition(":")
    upstream, sep, revision = rest.rpartition("-")
    if not sep:
        upstream, revision = rest, ""
    return int(epoch or 0), upstream, revision


def compare_dpkg(a: str, b: str) -> int:
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    return _cmp(ea, eb) or _dpkg_part(ua, ub) or _dpkg_part(ra, rb)


# RPM (rpmvercmp)

def _rpm_part(a: str, b: str) -> int:
    if a == b:
        return 0
    while a or b:
        a = re.sub(r"^[^A-Za-z0-9~^]+", "", a)
        b = re.sub(r"^[^A-Za-z0-9~^]+", "", b)
        if a.startswith("~") or b.startswith("~"):
            if not a.startswith("~"):
                return 1
            if not b.startswith("~"):
                return -1
            a, b = a[1:], b[1:]
            continue
        if a.startswith("^") or b.startswith("^"):
            if not a:
                return -1
            if not b:
                return 1
            if not a.startswith("^"):
                return 1
            if not b.startswith("^"):
                return -1
            a, b = a[1:], b[1:]
            continue
        if not a or not b:
            break
        pat = r"\d+" if a[0].isdigit() else r"[A-Za-z]+"
        sa = re.match(pat, a).group()
        mb = re.match(pat, b)
        if not mb:
            return 1 if a[0].isdigit() else -1  # numeric beats alpha
        sb = mb.group()
        if sa.isdigit():
            d = _cmp(int(sa), int(sb))
        else:
            d = _cmp(sa, sb)
        if d:
            return d
        a, b = a[len(sa):], b[len(sb):]
    return _cmp(bool(a), bool(b))


def _rpm_split(v: str):
    epoch, sep, rest = v.partition(":")
    if not sep:
        epoch, rest = "0", v
    ver, sep, rel = rest.rpartition("-")
    if not sep:
        ver, rel = rest, ""
    return int(epoch or 0), ver, rel


def compare_rpm(a: str, b: str) -> int:
    ea, va, ra = _rpm_split(a)
    eb, vb, rb = _rpm_split(b)
    return _cmp(ea, eb) or _rpm_part(va, vb) or _rpm_part(ra, rb)


# apk

_APK_SUFFIX = {"alpha": 0, "beta": 1, "pre": 2, "rc": 3, "": 4,
               "cvs": 5, "svn": 6, "git": 7, "hg": 8, "p": 9}
_APK_RE = re.compile(
    r"^(?P<nums>\d+(?:\.\d+)*)(?P<letter>[a-z]?)(?P<sfx>(?:_[a-z]+\d*)*)"
    r"(?:-r(?P<rev>\d+))?$")


def _apk_parse(v: str):
    m = _APK_RE.match(v)
    if not m:
        raise ValueError(f"unparseable apk version: {v!r}")
    nums = [int(n) for n in m["nums"].split(".")]
    sfx = []
    for s, n in re.findall(r"_([a-z]+)(\d*)", m["sfx"]):
        if s not in _APK_SUFFIX:
            raise ValueError(f"unknown apk version suffix _{s} in {v!r}")
        sfx.append((_APK_SUFFIX[s], int(n or 0)))
    return nums, m["letter"], sfx, int(m["rev"] or 0)


def compare_apk(a: str, b: str) -> int:
    na, la, sa, ra = _apk_parse(a)
    nb, lb, sb, rb = _apk_parse(b)
    n = max(len(na), len(nb))
    d = _cmp(na + [0] * (n - len(na)), nb + [0] * (n - len(nb)))
    if d or la != lb:
        return d or _cmp(la, lb)
    n = max(len(sa), len(sb))
    pad = (_APK_SUFFIX[""], 0)
    return (_cmp(sa + [pad] * (n - len(sa)), sb + [pad] * (n - len(sb)))
            or _cmp(ra, rb))


# upstream part

def upstream_version(fmt: str, v: str) -> str:
    """The upstream part of a package version: RPM version (no epoch or release), dpkg
    upstream (no epoch or revision), apk version before -rN. ValueError if unparseable."""
    if fmt == "rpm":
        return _rpm_split(v)[1]
    if fmt == "dpkg":
        return _dpkg_split(v)[1]
    if fmt == "apk":
        _apk_parse(v)
        return re.sub(r"-r\d+$", "", v)
    raise ValueError(f"unknown package format: {fmt!r}")


# NEVRA and distro tags

def parse_nevra(s: str) -> Nevra:
    rest, _, arch = s.rpartition(".")
    rest, _, release = rest.rpartition("-")
    name, _, ver = rest.rpartition("-")
    epoch, sep, version = ver.partition(":")
    if not sep:
        epoch, version = "0", ver
    return Nevra(name, int(epoch), version, release, arch)


def dist_tag(release: str) -> str:
    m = (re.search(r"module\+el\d+(?:\.\d+)*(?=\+|$)", release)
         or re.search(r"el\d+(?:_\d+)?", release))
    return m.group() if m else ""
