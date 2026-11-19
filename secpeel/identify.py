"""Identify components from metadata embedded in unpacked files.

Each identifier looks at the leaves the unpacker produced and returns components with evidence.
Files a component accounts for (for example the classes inside a Maven JAR) are reported as covered,
so the coverage ledger only lists files nobody could explain.
"""
import email.parser
import json
import re
import urllib.parse

from .inventory import component_id

GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"
MAX_READ = 64 << 20  # never read more than this from one file


class Result:
    def __init__(self):
        self.components = {}          # id -> component
        self.identified = {}          # virtual path -> component id that explains it
        self.notes = {}               # virtual path -> reason a recognised file could not be used

    def add(self, ecosystem, name, version, purl, location, identifier, detail=None, confidence="exact",
            distro=None, covers=()):
        cid = component_id(ecosystem, name, version)
        comp = self.components.get(cid)
        if comp is None:
            comp = self.components[cid] = {
                "id": cid, "name": name, "ecosystem": ecosystem, "version": version, "purl": purl,
                "distro": distro, "scope": "runtime", "direct": None, "root": False, "depends_on": [], "evidence": [],
            }
        if not any(e["location"] == location and e["identifier"] == identifier for e in comp["evidence"]):
            comp["evidence"].append({"identifier": identifier, "location": location, "detail": detail, "confidence": confidence})
        self.identified[location] = cid
        for path in covers:
            self.identified.setdefault(path, cid)
        return cid


def _read(leaf, limit=MAX_READ):
    with open(leaf["real"], "rb") as fh:
        return fh.read(limit)


def _container(virtual):
    return virtual.rsplit("!/", 1)[0] if "!/" in virtual else ""


def _inner(virtual):
    return virtual.rsplit("!/", 1)[-1]


# --- Java -----------------------------------------------------------------------------------------

POM_PROPERTIES = re.compile(r"(?:^|/)META-INF/maven/([^/]+)/([^/]+)/pom\.properties$")


def maven(leaves, result):
    by_container = {}
    for leaf in leaves:
        by_container.setdefault(_container(leaf["path"]), []).append(leaf)
    for container, members in by_container.items():
        poms = [m for m in members if POM_PROPERTIES.search(_inner(m["path"]))]
        for pom in poms:
            props = _properties(_read(pom, 1 << 20).decode("utf-8", "replace"))
            group, artifact = POM_PROPERTIES.search(_inner(pom["path"])).groups()
            group, artifact = props.get("groupId", group), props.get("artifactId", artifact)
            version = props.get("version")
            if not version:
                result.notes[pom["path"]] = "pom.properties has no version"
                continue
            # A JAR usually holds one artifact; its classes are covered by it.
            covers = [m["path"] for m in members] if len(poms) == 1 else []
            result.add("Maven", "%s:%s" % (group, artifact), version,
                       "pkg:maven/%s/%s@%s" % (group, artifact, urllib.parse.quote(version)),
                       pom["path"], "maven-pom-properties", "%s:%s:%s" % (group, artifact, version), covers=covers)
        if poms:
            continue
        manifest = next((m for m in members if _inner(m["path"]).endswith("META-INF/MANIFEST.MF")), None)
        if manifest is None:
            continue
        attrs = _manifest(_read(manifest, 1 << 20).decode("utf-8", "replace"))
        name = attrs.get("Bundle-SymbolicName", "").split(";")[0].strip() or attrs.get("Implementation-Title") \
            or attrs.get("Automatic-Module-Name")
        version = attrs.get("Bundle-Version") or attrs.get("Implementation-Version")
        if name and version:
            # Without groupId and artifactId the component cannot be matched in OSV; it is reported, not guessed.
            result.add("jar-manifest", name, version, None, manifest["path"], "jar-manifest",
                       "name and version from MANIFEST.MF; no Maven coordinates", confidence="low",
                       covers=[m["path"] for m in members])


def _properties(text):
    props = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "!")) and "=" in line:
            key, _, value = line.partition("=")
            props[key.strip()] = value.strip()
    return props


def _manifest(text):
    attrs, key = {}, None
    for line in text.splitlines():
        if line.startswith(" ") and key:
            attrs[key] += line[1:]
        elif ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            attrs[key] = value.strip()
    return attrs


# --- npm, Python, .NET -----------------------------------------------------------------------------

def npm(leaves, result):
    for leaf in leaves:
        if _inner(leaf["path"]).rsplit("/", 1)[-1] != "package.json" or leaf["type"] != "text":
            continue
        try:
            data = json.loads(_read(leaf, 1 << 20))
        except ValueError:
            continue
        name, version = data.get("name"), data.get("version")
        if isinstance(name, str) and isinstance(version, str) and name and version:
            result.add("npm", name, version, "pkg:npm/%s@%s" % (urllib.parse.quote(name, safe="/"), version),
                       leaf["path"], "npm-package-json", "%s@%s" % (name, version))


def python(leaves, result):
    for leaf in leaves:
        inner = _inner(leaf["path"])
        if not re.search(r"\.(dist-info/METADATA|egg-info/PKG-INFO)$|(?:^|/)PKG-INFO$", inner):
            continue
        meta = email.parser.HeaderParser().parsestr(_read(leaf, 1 << 20).decode("utf-8", "replace"))
        name, version = meta.get("Name"), meta.get("Version")
        if name and version:
            normalized = re.sub(r"[-_.]+", "-", name).lower()
            result.add("PyPI", normalized, version, "pkg:pypi/%s@%s" % (normalized, version), leaf["path"],
                       "python-metadata", "%s %s" % (name, version))


def dotnet(leaves, result):
    for leaf in leaves:
        if not _inner(leaf["path"]).endswith(".deps.json"):
            continue
        try:
            data = json.loads(_read(leaf, 8 << 20))
        except ValueError:
            continue
        for key, lib in (data.get("libraries") or {}).items():
            if lib.get("type") != "package" or "/" not in key:
                continue
            name, version = key.split("/", 1)
            result.add("NuGet", name, version, "pkg:nuget/%s@%s" % (name, version), leaf["path"], "dotnet-deps-json", key)
        result.identified.setdefault(leaf["path"], None)


# --- operating-system packages ------------------------------------------------------------------

def os_releases(leaves):
    """Map container prefix -> {"name", "release"} from etc/os-release or etc/alpine-release."""
    found = {}
    for leaf in leaves:
        inner = _inner(leaf["path"])
        if inner.endswith(("etc/os-release", "usr/lib/os-release")):
            fields = dict(line.split("=", 1) for line in _read(leaf, 65536).decode("utf-8", "replace").splitlines() if "=" in line)
            name = fields.get("ID", "").strip('"')
            release = fields.get("VERSION_ID", "").strip('"')
            if name:
                found[(_container(leaf["path"]), leaf["path"][: -len(inner)] + inner[: -len("etc/os-release")])] = \
                    {"name": name, "release": release}
    return found


def _distro_for(path, releases):
    container = _container(path)
    same = [v for (c, _), v in releases.items() if c == container]
    if same:
        return same[0]
    distinct = {(v["name"], v["release"]) for v in releases.values()}
    if len(distinct) == 1:  # for example os-release in an earlier image layer
        return next(iter(releases.values()))
    return None


def _distro_ecosystem(distro):
    if not distro:
        return None
    name, release = distro["name"], distro["release"]
    if name == "debian":
        return "Debian", release.split(".")[0]
    if name == "ubuntu":
        return "Ubuntu", release
    if name == "alpine":
        return "Alpine", "v" + ".".join(release.split(".")[:2])
    return None


def dpkg(leaves, result, releases):
    for leaf in leaves:
        if not _inner(leaf["path"]).endswith("var/lib/dpkg/status"):
            continue
        distro = _distro_for(leaf["path"], releases)
        eco = _distro_ecosystem(distro)
        if eco is None or eco[0] not in ("Debian", "Ubuntu"):
            result.notes[leaf["path"]] = "dpkg database found but the distribution release is unknown"
            continue
        for stanza in _read(leaf).decode("utf-8", "replace").split("\n\n"):
            fields = _manifest(stanza)
            if "install ok installed" not in fields.get("Status", ""):
                continue
            binary, version = fields.get("Package"), fields.get("Version")
            source = fields.get("Source", binary or "")
            m = re.match(r"(\S+)\s*\(([^)]+)\)", source)
            source, source_version = (m.group(1), m.group(2)) if m else (source.strip(), version)
            if binary and source_version:
                # Debian advisories in OSV are keyed by source package.
                result.add(eco[0], source, source_version, "pkg:deb/%s/%s@%s?distro=%s-%s" % (
                    distro["name"], source, urllib.parse.quote(source_version), distro["name"], eco[1]),
                    leaf["path"], "dpkg-status", "binary package %s %s" % (binary, version),
                    distro={"name": distro["name"], "release": eco[1]})


def apk(leaves, result, releases):
    for leaf in leaves:
        if not _inner(leaf["path"]).endswith("lib/apk/db/installed"):
            continue
        eco = _distro_ecosystem(_distro_for(leaf["path"], releases))
        if eco is None or eco[0] != "Alpine":
            result.notes[leaf["path"]] = "apk database found but the Alpine release is unknown"
            continue
        for stanza in _read(leaf).decode("utf-8", "replace").split("\n\n"):
            fields = dict(line.split(":", 1) for line in stanza.splitlines() if len(line) > 2 and line[1] == ":")
            name, version, origin = fields.get("P"), fields.get("V"), fields.get("o")
            if name and version:
                source = origin or name
                result.add("Alpine", source, version, "pkg:apk/alpine/%s@%s?distro=alpine-%s" % (source, version, eco[1][1:]),
                           leaf["path"], "apk-installed", "binary package %s %s" % (name, version),
                           distro={"name": "alpine", "release": eco[1]})


def rpmdb(leaves, result):
    for leaf in leaves:
        if re.search(r"var/lib/rpm/(rpmdb\.sqlite|Packages|Packages\.db)$", _inner(leaf["path"])):
            result.notes[leaf["path"]] = "RPM database parsing is not implemented yet"


# --- Go ---------------------------------------------------------------------------------------------

def _uvarint(data, pos):
    value, shift = 0, 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos
        shift += 7


def go_buildinfo(data):
    """Return (go_version, modinfo) from a Go 1.18+ binary, or None."""
    pos = data.find(GO_BUILDINFO_MAGIC)
    if pos < 0 or len(data) < pos + 32:
        return None
    flags = data[pos + 15]
    if not flags & 0x2:
        return None  # pre-1.18 pointer format
    cursor = pos + 32
    strings = []
    for _ in range(2):
        length, cursor = _uvarint(data, cursor)
        strings.append(data[cursor: cursor + length])
        cursor += length
    version, modinfo = strings
    # modinfo is wrapped in 16-byte binary sentinels; strip them before decoding (as Go's debug/buildinfo does).
    if len(modinfo) >= 33 and modinfo[-17:-16] == b"\n":
        modinfo = modinfo[16:-16]
    return version.decode("utf-8", "replace"), modinfo.decode("utf-8", "replace")


def go(leaves, result):
    for leaf in leaves:
        if leaf["type"] not in ("elf", "pe", "macho"):
            continue
        data = _read(leaf)
        if GO_BUILDINFO_MAGIC not in data:
            continue
        info = go_buildinfo(data)
        if info is None:
            result.notes[leaf["path"]] = "Go binary built before Go 1.18; build info format not supported"
            continue
        version, modinfo = info
        if version.startswith("go"):
            result.add("Go", "stdlib", version[2:], "pkg:golang/stdlib@%s" % version[2:], leaf["path"], "go-buildinfo",
                       "built with %s" % version)
        for line in modinfo.splitlines():
            parts = line.split("\t")
            if parts[0] in ("mod", "dep") and len(parts) >= 3 and parts[2] not in ("(devel)", ""):
                module, mod_version = parts[1], parts[2]
                result.add("Go", module, mod_version.lstrip("v"), "pkg:golang/%s@%s" % (module, mod_version),
                           leaf["path"], "go-buildinfo", "%s %s %s" % (parts[0], module, mod_version))
            elif parts[0] == "mod" and len(parts) >= 2:
                # Built from a source checkout: the module is known, its release version is not.
                result.add("Go", parts[1], None, "pkg:golang/%s" % parts[1], leaf["path"], "go-buildinfo",
                           "main module built as (devel); release version unknown", confidence="low")
            elif parts[0] == "=>" and len(parts) >= 3:
                result.notes.setdefault(leaf["path"], "module replacements present; the replaced versions were recorded")


def identify(leaves):
    result = Result()
    releases = os_releases(leaves)
    for step in (maven, npm, python, dotnet, go):
        step(leaves, result)
    dpkg(leaves, result, releases)
    apk(leaves, result, releases)
    rpmdb(leaves, result)
    # Native checkers run last so distribution packages found above take precedence.
    from .native import identify_native
    identify_native(leaves, result)
    return result


# Kept for tests that build Go buildinfo blobs.
def encode_uvarint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def make_go_buildinfo(version, modinfo):
    header = GO_BUILDINFO_MAGIC + bytes([8, 0x2]) + b"\x00" * 16
    blob = b"\x30\x77\xaf\x0c\x92\x74\x08\x02\x41\xe1\xc1\x07\xe6\xd6\x18\xe6" + modinfo.rstrip("\n").encode() + b"\n" \
        + b"\xf9\x32\x43\x31\x86\x18\x20\x72\x00\x82\x42\x10\x41\x16\xd8\xf2"
    return header + encode_uvarint(len(version)) + version.encode() + encode_uvarint(len(blob)) + blob
