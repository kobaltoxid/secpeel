"""Identify native components that carry no package metadata.

Checkers are our own data (no third-party signature sets are copied). Each needs a presence string
and a version pattern; a library that is present but whose version cannot be read is reported with
an unknown version instead of being guessed. When the same library is installed from a distribution
package in the same artifact, the distribution metadata wins, because upstream version strings do
not show backported fixes.
"""
import json
import re
import struct
import zlib

from .identify import MAX_READ, _read

BINARY_TYPES = {"elf", "pe", "macho", "macho-fat"}

# name, CPE vendor:product, presence regex, version regex (group 1), version confidence,
# report-without-version, distribution source package names.
# Libraries that always embed their version string are not reported without one: a name alone
# usually means the file links to the library rather than bundling it.
CHECKERS = [
    ("openssl", "openssl:openssl", rb"OpenSSL", rb"OpenSSL (\d+\.\d+\.\d+[a-z]?) +\d{1,2} \w{3} \d{4}", "high", False, {"openssl", "openssl3"}),
    ("zlib", "zlib:zlib", rb"Jean-loup Gailly", rb"(?:in|de)flate (\d+\.\d+(?:\.\d+){0,2}) Copyright", "high", False, {"zlib"}),
    ("curl", "haxx:libcurl", rb"libcurl", rb"libcurl/(\d+\.\d+\.\d+)", "high", False, {"curl"}),
    ("libpng", "libpng:libpng", rb"libpng", rb"libpng version (\d+\.\d+\.\d+)", "high", False, {"libpng1.6", "libpng"}),
    ("expat", "libexpat_project:libexpat", rb"expat", rb"expat_(\d+\.\d+\.\d+)", "high", False, {"expat"}),
    ("busybox", "busybox:busybox", rb"BusyBox", rb"BusyBox v(\d+\.\d+\.\d+)", "high", False, {"busybox"}),
    ("bzip2", "bzip:bzip2", rb"bzip2/libbzip2", rb"(1\.0\.\d+), \d{1,2}-\w{3}-\d{4}", "high", False, {"bzip2"}),
    ("libssh2", "libssh2:libssh2", rb"libssh2", rb"SSH-2\.0-libssh2_(\d+\.\d+\.\d+)", "high", False, {"libssh2"}),
    ("openssh", "openbsd:openssh", rb"OpenSSH", rb"OpenSSH_(\d+\.\d+(?:p\d+)?)", "high", False, {"openssh"}),
    # CPython builds its "3.x.y (main, date)" banner at runtime; the binary holds only the PY_VERSION literal.
    ("cpython", "python:python", rb"Py_InitializeFromConfig",
     rb"(?<![\d.])(3\.\d{1,2}\.\d{1,2}(?:[abrc]+\d+)?)\x00", "medium", False, {"python3.11", "python3.12", "python3.13", "python3"}),
    # SQLite always embeds its source ID; the version is a bare NUL-terminated literal, hence medium confidence.
    ("sqlite", "sqlite:sqlite", rb"20\d\d-\d\d-\d\d \d\d:\d\d:\d\d [0-9a-f]{40}",
     rb"(?<![\d.])(3\.\d{1,2}\.\d{1,2})\x00", "medium", True, {"sqlite3"}),
]
COMPILED = [(n, c, re.compile(p), re.compile(v), conf, bare, d) for n, c, p, v, conf, bare, d in CHECKERS]


def cpe(vendor_product, version):
    return "cpe:2.3:a:%s:%s:*:*:*:*:*:*:*" % (vendor_product, version or "*")


def checkers(leaves, result):
    distro_sources = {c["name"] for c in result.components.values() if c.get("distro")}
    distro_ids = {c["name"]: c["id"] for c in result.components.values() if c.get("distro")}
    for leaf in leaves:
        if leaf["type"] not in BINARY_TYPES or leaf["path"] in result.identified:
            continue
        data = _read(leaf, MAX_READ)
        for name, vendor_product, presence, pattern, confidence, report_bare, sources in COMPILED:
            if not presence.search(data):
                continue
            hits = [(m.group(1).decode(), m.start()) for m in pattern.finditer(data)]
            if not hits and not report_bare:
                continue  # a reference to the library, not a bundled copy
            covered = sources & distro_sources
            if covered:
                # Distribution metadata accounts for this file and knows about backports.
                result.identified.setdefault(leaf["path"], distro_ids[sorted(covered)[0]])
                continue
            if hits:
                versions = sorted({v for v, _ in hits})
                if len(versions) == 1:
                    version, offset = versions[0], hits[0][1]
                    result.add("native", name, version, None, leaf["path"], "version-string:" + name,
                               "version %s at offset %d" % (version, offset), confidence=confidence)
                else:
                    # Several versions in one file (bundled copies or tests): report each, flag the ambiguity.
                    for version in versions:
                        result.add("native", name, version, None, leaf["path"], "version-string:" + name,
                                   "one of several versions found in this file: %s" % ", ".join(versions), confidence="low")
            else:
                result.add("native", name, None, None, leaf["path"], "presence-string:" + name,
                           "library markers found but no version string", confidence="low")
            for cid in [c for c in result.components if c.startswith("native:%s@" % name)]:
                result.components[cid]["cpe"] = cpe(vendor_product, result.components[cid]["version"])


# --- PE version resources ------------------------------------------------------------------------

def _utf16_value(data, key):
    marker = key.encode("utf-16-le") + b"\x00\x00"
    pos = data.find(marker)
    if pos < 0:
        return None
    pos += len(marker)
    pos += (-pos) % 4  # values are 32-bit aligned
    end = pos
    while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
        end += 2
    value = data[pos:end].decode("utf-16-le", "replace").strip()
    return value or None


def pe_version(leaves, result):
    for leaf in leaves:
        if leaf["type"] != "pe" or leaf["path"] in result.identified:
            continue
        data = _read(leaf, MAX_READ)
        if b"V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O" not in data:
            continue
        product = _utf16_value(data, "ProductName")
        version = _utf16_value(data, "ProductVersion") or _utf16_value(data, "FileVersion")
        company = _utf16_value(data, "CompanyName")
        if product and version:
            result.add("native", product, version.split()[0], None, leaf["path"], "pe-version-resource",
                       "%s %s%s" % (product, version, (" by " + company) if company else ""), confidence="medium")


# --- Rust cargo-auditable ---------------------------------------------------------------------

def elf_section(data, wanted):
    """Return the bytes of a named section in a little-endian ELF file, or None."""
    if data[:4] != b"\x7fELF" or data[5] != 1:
        return None
    is64 = data[4] == 2
    try:
        if is64:
            shoff, = struct.unpack_from("<Q", data, 0x28)
            shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        else:
            shoff, = struct.unpack_from("<I", data, 0x20)
            shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)

        def section(i):
            base = shoff + i * shentsize
            if is64:
                name, _type, _flags, _addr, offset, size = struct.unpack_from("<IIQQQQ", data, base)
            else:
                name, _type, _flags, _addr, offset, size = struct.unpack_from("<IIIIII", data, base)
            return name, offset, size

        _, str_off, str_size = section(shstrndx)
        names = data[str_off: str_off + str_size]
        for i in range(shnum):
            name_off, offset, size = section(i)
            name = names[name_off: names.index(b"\x00", name_off)]
            if name == wanted:
                return data[offset: offset + size]
    except (struct.error, ValueError, IndexError):
        return None
    return None


def cargo_auditable(leaves, result):
    for leaf in leaves:
        if leaf["type"] != "elf":
            continue
        data = _read(leaf, MAX_READ)
        if b".dep-v0" not in data:
            continue
        section = elf_section(data, b".dep-v0")
        if section is None:
            result.notes[leaf["path"]] = "cargo-auditable marker found but the .dep-v0 section could not be read"
            continue
        try:
            packages = json.loads(zlib.decompress(section)).get("packages", [])
        except (zlib.error, ValueError):
            result.notes[leaf["path"]] = "cargo-auditable data could not be decoded"
            continue
        for pkg in packages:
            if pkg.get("source") == "crates.io" and pkg.get("name") and pkg.get("version"):
                result.add("crates.io", pkg["name"], pkg["version"], "pkg:cargo/%s@%s" % (pkg["name"], pkg["version"]),
                           leaf["path"], "cargo-auditable", "%s %s" % (pkg["name"], pkg["version"]))


def identify_native(leaves, result):
    cargo_auditable(leaves, result)
    pe_version(leaves, result)
    checkers(leaves, result)
