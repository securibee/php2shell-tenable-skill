"""PHP inventory parsing, distro and stream detection, plugin classification."""
from __future__ import annotations

import re
from typing import NamedTuple, Optional

from versions import dist_tag, parse_nevra

INVENTORY_IDS = {"48243", "58987", "200476", "216936"}
UNPATCHED_PREFIXES = ("Linux Distros Unpatched Vulnerability",
                      "Amazon Linux Unpatched Vulnerability")
TRUNCATED = "... (truncated)"


class Install(NamedTuple):
    path: str
    version: str
    package: str
    managed_by_os: Optional[bool]


class Distro(NamedTuple):
    family: str
    major: str
    ecosystem: Optional[str]


# --- plugin 216936 output ---

_FIELD = re.compile(r"^\s*(Path|Version|Associated Package|Managed by OS)\s*:\s*(.*?)\s*$")


def parse_installs(output: str) -> tuple[list[Install], bool]:
    """Installs with a whole Path, Version and package, and whether output was cut short."""
    truncated = TRUNCATED in output
    lines = output.splitlines()
    if truncated:
        cut = next(i for i, l in enumerate(lines) if TRUNCATED in l)
        inline = lines[cut].split(TRUNCATED)[0].strip()  # text before the marker is the cut line
        lines = [l for l in lines[:cut] if l.strip()]
        if not inline:
            lines = lines[:-1]  # otherwise the line before the marker is cut
    blocks: list[dict] = []
    for line in lines:
        m = _FIELD.match(line)
        if not m:
            continue
        key, val = m.groups()
        if key == "Path":
            blocks.append({})
        if blocks:
            blocks[-1][key] = val
    if truncated and blocks and not {"Path", "Version", "Associated Package"} <= set(blocks[-1]):
        blocks.pop()  # the cut fell inside a field that judging needs
    if truncated and blocks and "Managed by OS" not in blocks[-1]:
        # Managed by OS belongs to the package; a whole block with the same package has it.
        same = [b for b in blocks[:-1] if "Managed by OS" in b
                and b["Associated Package"] == blocks[-1]["Associated Package"]]
        if same:
            blocks[-1]["Managed by OS"] = same[0]["Managed by OS"]
    installs = []
    for b in blocks:
        pkg = b.get("Associated Package", "")
        managed = b.get("Managed by OS")
        installs.append(Install(
            b["Path"], b.get("Version", ""),
            "" if pkg.lower() == "none" else pkg,
            None if managed is None else managed.lower() == "true"))
    return installs, truncated


# --- distro and stream ---

_NEVRA = re.compile(r"^\S+-[^-\s]+-[^-\s]+\.[A-Za-z0-9_]+$")

_OS = [  # (family, regex capturing the release); first match wins
    ("rocky", r"rocky\s*linux\s*(\d+)"),
    ("alma", r"alma\s*linux\s*(\d+)"),
    ("oracle", r"oracle\s+linux\D*(\d+)"),
    ("centos", r"centos\D*(\d+)"),
    ("amazon", r"amazon\s+linux\D*?(\d+)"),
    ("fedora", r"fedora\D*(\d+)"),
    ("ubuntu", r"ubuntu\s*(\d+\.\d+)"),
    ("debian", r"debian\D*(\d+)"),
    ("alpine", r"alpine\D*(\d+\.\d+)"),
    ("suse", r"(?:suse|sles)\D*(\d+)"),
    ("rhel", r"(?:red\s*hat|rhel)\D*(\d+)"),
]


def _ecosystem(family: str, major: str, os: str, package: str) -> Optional[str]:
    if family == "ubuntu":
        year, _, month = major.partition(".")
        if month != "04" or int(year) % 2:
            return None
        pro = "+esm" in package
        return "Ubuntu:%s%s:LTS" % ("Pro:" if pro else "", major)
    if family == "debian":
        return "Debian:" + major
    if family == "alma":
        return "AlmaLinux:" + major
    if family == "rocky":
        return "Rocky Linux:" + major
    if family == "alpine":
        return "Alpine:v" + major
    if family == "suse":
        m = re.search(r"(Linux Enterprise\s+\w+\s+\d+)\s+SP(\d+)", os, re.I)
        return "SUSE:%s SP%s" % (m.group(1), m.group(2)) if m else None
    return None


def distro_for(os: str, package: str) -> Optional[Distro]:
    """Distro from the asset OS string; falls back to an RPM el dist tag."""
    low = (os or "").lower()
    if low.strip():
        for family, rx in _OS:
            m = re.search(rx, low)
            if m:
                major = m.group(1)
                return Distro(family, major, _ecosystem(family, major, os, package))
        return None
    if _NEVRA.match(package or ""):
        m = re.match(r"el(\d+)", dist_tag(parse_nevra(package).release))
        if m:
            return Distro("rhel", m.group(1), None)
    return None


def stream_of(package: str) -> str:
    """PHP module stream ("8.0") or "base" for a non-module package."""
    m = re.search(r"php:(\d+\.\d+)", package or "")
    if m:
        return m.group(1)
    if _NEVRA.match(package or ""):
        n = parse_nevra(package)
        if re.search(r"module[+_]el", n.release):  # Alma writes "module_el8"
            v = re.match(r"(\d+\.\d+)", n.version)
            if v:
                return v.group(1)
    return "base"


# --- plugin catalog ---

def classify(plugin: dict) -> str:
    name = plugin.get("name") or ""
    scan = plugin.get("scan_type") or ""
    if str(plugin.get("plugin_id")) in INVENTORY_IDS:
        return "inventory"
    if name.startswith(UNPATCHED_PREFIXES):
        return "unpatched"
    if scan == "local" or (plugin.get("family") or "").endswith("Local Security Checks"):
        return "vendor"
    if scan in ("version_based", "combined"):
        return "version"
    return "other"


_FAMILIES = [("red hat", "rhel"), ("oracle linux", "oracle"), ("alma", "alma"),
             ("rocky", "rocky"), ("centos", "centos"), ("ubuntu", "ubuntu"),
             ("debian", "debian"), ("suse", "suse"), ("alpine", "alpine"),
             ("amazon linux", "amazon"), ("fedora", "fedora")]


def _entries(catalog: list[dict]):
    """Yield (family, major, stream, published) for each vendor plugin."""
    for p in catalog:
        if classify(p) != "vendor":
            continue
        fam = (p.get("family") or "").lower()
        family = next((f for pre, f in _FAMILIES if fam.startswith(pre)), None)
        if not family:
            continue
        name = p.get("name") or ""
        if family in ("debian", "alpine"):
            majors = ["*"]  # names carry no release
        elif family == "ubuntu":
            majors = re.findall(r"\d+\.\d+", name.split(" : ")[0])
        else:
            m = re.match(r"\D*?(\d+)", name)  # distro from family, release from prefix
            majors = [m.group(1)] if m else []
        s = re.search(r"php:(\d+\.\d+)", name)
        for major in majors:
            yield family, major, s.group(1) if s else "base", p.get("published") or ""


def coverage(catalog: list[dict]) -> dict[tuple[str, str], set[str]]:
    """(family, major) -> streams the vendor has fixed."""
    out: dict[tuple[str, str], set[str]] = {}
    for family, major, stream, _ in _entries(catalog):
        out.setdefault((family, major), set()).add(stream)
    return out


def coverage_published(catalog: list[dict]) -> dict[tuple[str, str, str], str]:
    """(family, major, stream) -> earliest published date (YYYY-MM-DD)."""
    out: dict[tuple[str, str, str], str] = {}
    for family, major, stream, pub in _entries(catalog):
        key = (family, major, stream)
        if pub and (key not in out or pub < out[key]):
            out[key] = pub
    return out
