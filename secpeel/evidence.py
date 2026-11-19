"""Code-level evidence for findings in a compiled artifact, without running it.

For each advisory and affected component this checks whether the classes or functions the advisory
names are present in the component, and which other code in the artifact references them. Java
class references come from constant pools; native imports come from symbol tables. Decompiling is
optional (CFR, when CFR_JAR points to its jar and Java is installed) and limited to referencing classes.
"""
import os
import re
import shutil
import struct
import subprocess

from .identify import MAX_READ, _container, _read

CAMEL = re.compile(r"\b[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+\b")
C_FUNCTION = re.compile(r"\b(?:[A-Z][A-Z0-9]{1,}_[A-Za-z0-9_]+|[a-z][a-z0-9]*_[a-z0-9_]{3,})\b")
BACKTICK = re.compile(r"`([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\(?\)?`")
# Words that look like identifiers in advisory prose but name products or formats.
NOISE = {"GitHub", "JavaScript", "TypeScript", "OpenSSL", "PoC", "NodeJS", "MacOS", "WebSocket", "PostgreSQL", "MySQL",
         "SQLite", "LibreSSL", "BoringSSL", "OpenSSH", "README", "DoS", "ReDoS"}


def named_tokens(text):
    tokens = set(CAMEL.findall(text or "")) | set(C_FUNCTION.findall(text or ""))
    tokens |= {t.split(".")[-1] for t in BACKTICK.findall(text or "")}
    return sorted(t for t in tokens if t not in NOISE and len(t) >= 5)


# --- native symbols -------------------------------------------------------------------------------

def elf_symbols(data):
    """(defined, undefined) symbol names from .symtab and .dynsym of a little-endian ELF file."""
    defined, undefined = set(), set()
    if data[:4] != b"\x7fELF" or data[5] != 1:
        return defined, undefined
    is64 = data[4] == 2
    try:
        if is64:
            shoff, = struct.unpack_from("<Q", data, 0x28)
            shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
        else:
            shoff, = struct.unpack_from("<I", data, 0x20)
            shentsize, shnum = struct.unpack_from("<HH", data, 0x2E)
        sections = []
        for i in range(shnum):
            base = shoff + i * shentsize
            if is64:
                _n, sh_type, _f, _a, offset, size, link, _info, _al, entsize = struct.unpack_from("<IIQQQQIIQQ", data, base)
            else:
                _n, sh_type, _f, _a, offset, size, link, _info, _al, entsize = struct.unpack_from("<IIIIIIIIII", data, base)
            sections.append((sh_type, offset, size, link, entsize))
        for sh_type, offset, size, link, entsize in sections:
            if sh_type not in (2, 11) or not entsize:  # SHT_SYMTAB, SHT_DYNSYM
                continue
            _t, str_off, str_size, _l, _e = sections[link]
            strings = data[str_off: str_off + str_size]
            for pos in range(offset, offset + size, entsize):
                if is64:
                    name_off, _info, _other, shndx = struct.unpack_from("<IBBH", data, pos)
                else:
                    name_off, = struct.unpack_from("<I", data, pos)
                    shndx, = struct.unpack_from("<H", data, pos + 14)
                if not name_off:
                    continue
                name = strings[name_off: strings.index(b"\x00", name_off)].decode("utf-8", "replace")
                (undefined if shndx == 0 else defined).add(name)
    except (struct.error, ValueError, IndexError):
        pass
    return defined, undefined


def nm_symbols(path, which=shutil.which, runner=subprocess.run):
    """(defined, undefined) for Mach-O and other formats through the system nm, when available."""
    exe = which("nm")
    if not exe:
        return None
    sets = []
    for flags in (["-gU"], ["-u"]):
        proc = runner([exe] + flags + [str(path)], capture_output=True, text=True, timeout=120)
        names = set()
        for line in (proc.stdout or "").splitlines():
            name = line.split()[-1] if line.split() else ""
            names.add(name[1:] if name.startswith("_") else name)
        sets.append(names - {""})
    return sets[0], sets[1]


def symbols(leaf):
    data = _read(leaf, MAX_READ)
    if leaf["type"] == "elf":
        return elf_symbols(data)
    if leaf["type"] in ("macho", "macho-fat"):
        return nm_symbols(leaf["real"]) or (set(), set())
    return set(), set()


# --- evidence -----------------------------------------------------------------------------------

def decompile(leaf, token, java=None, cfr=None, runner=subprocess.run):
    """Lines mentioning `token` in one decompiled class, or None when CFR is not available."""
    java = java or shutil.which("java")
    cfr = cfr or os.environ.get("CFR_JAR")
    if not java or not cfr or not os.path.isfile(cfr):
        return None
    proc = runner([java, "-jar", cfr, str(leaf["real"])], capture_output=True, text=True, timeout=300)
    return [line.strip() for line in (proc.stdout or "").splitlines() if token in line][:5]


def _split_go_symbol(symbol):
    """golang.org/x/crypto/ssh.NewServerConn -> (golang.org/x/crypto/ssh, NewServerConn); a bare path -> (path, None)."""
    slash = symbol.rfind("/")
    dot = symbol.find(".", slash + 1)
    return (symbol, None) if dot < 0 else (symbol[:dot], symbol[dot + 1:])


def go_evidence(own, comp, symbols, tokens):
    """Go links only functions the program can call, so a symbol in the binary's function table was linked in."""
    module = "" if comp["name"] == "stdlib" else comp["name"]
    wanted = [s for s in symbols if not module or s.startswith(module)]
    precise = bool(wanted)
    if not wanted and module:
        wanted = ["%s.%s" % (module, t) for t in tokens if t[0].isupper() and "_" not in t]  # exported Go names
    present, facts = [], []
    for leaf in own:
        data = _read(leaf, MAX_READ)
        for symbol in wanted:
            package, name = _split_go_symbol(symbol)
            if name is None:
                pattern = re.escape(package).encode() + rb"\.[A-Za-z_(]"
            elif "." in name:
                receiver, method = name.split(".", 1)
                pattern = (re.escape(package) + r"\.(?:\(\*?%s\)|%s)\.%s(?![\w])" % (re.escape(receiver), re.escape(receiver),
                                                                                    re.escape(method))).encode()
            else:
                pattern = (re.escape(package) + r"\.%s(?![\w.])" % re.escape(name)).encode()
            if re.search(pattern, data):
                present.append(symbol)
                facts.append("Function %s is linked into %s; Go links only code the program can call." % (symbol, leaf["path"]))
    verdict = None
    if precise and own and not present:
        verdict = "not-reachable"
        facts.append("None of the vulnerable symbols OSV lists (%s) is linked into %s, so the Go linker found no call path "
                     "to them." % (", ".join(wanted[:5]), ", ".join(l["path"] for l in own[:3])))
    elif own and wanted and not present:
        facts.append("No function named in the advisory (%s) is in the binary's function table." % ", ".join(wanted[:5]))
    return present, facts, verdict


def _rust_mangled(path):
    """Legacy Rust mangling of a::b::c is 1a1b1c (each segment prefixed with its length)."""
    return "".join("%d%s" % (len(part), part) for part in path.split("::") if part).encode()


def rust_evidence(own, comp, symbols, tokens):
    crate = comp["name"].replace("-", "_")
    wanted = [s for s in symbols if s.split("::")[0] in (crate, comp["name"])] or \
        ["%s::%s" % (crate, t) for t in tokens if "_" in t or t[0].isupper()]
    present, facts = [], []
    marker = ("/%s-%s/src/" % (comp["name"], comp.get("version") or "")).encode()
    for leaf in own:
        data = _read(leaf, MAX_READ)
        for symbol in wanted:
            if _rust_mangled(symbol) in data:
                present.append(symbol)
                facts.append("Function %s has a symbol in %s." % (symbol, leaf["path"]))
        if marker in data:
            facts.append("Source paths of %s %s are embedded in %s, so the crate's code is linked in." % (
                comp["name"], comp.get("version"), leaf["path"]))
    if own and wanted and not present:
        facts.append("No symbol for %s was found; release builds are often stripped, so this is inconclusive." % ", ".join(wanted[:5]))
    return present, facts, None


def python_evidence(by_path, leaves, comp, locations, tokens):
    """Find the package's files from RECORD, look for the named definitions, and list other code that imports it."""
    present, facts, files, modules = [], [], [], set()
    for metadata in locations:
        dist_info = metadata.rsplit("/", 1)[0]
        site = dist_info.rsplit("/", 1)[0]
        record = by_path.get(dist_info + "/RECORD")
        if record is None:
            continue
        for row in _read(record, 1 << 22).decode("utf-8", "replace").splitlines():
            rel = row.split(",", 1)[0]
            if rel.endswith((".py", ".pyc")) and not rel.startswith(("..", "/")) and ".dist-info/" not in rel:
                modules.add(rel.split("/")[0].split(".")[0])
                if site + "/" + rel in by_path:
                    files.append(by_path[site + "/" + rel])
    if not files:
        return present, ["No RECORD file lists the package's modules, so its code was not searched."], None
    for token in tokens:
        definition = re.compile(r"^\s*(?:async\s+)?(?:def|class)\s+%s\b" % re.escape(token))
        for leaf in files:
            if leaf["path"].endswith(".pyc"):
                if token.encode() in _read(leaf, 1 << 22):
                    present.append(token)
                    facts.append("%s appears in compiled module %s." % (token, leaf["path"]))
                continue
            for number, line in enumerate(_read(leaf, 1 << 22).decode("utf-8", "replace").splitlines(), 1):
                if definition.match(line):
                    present.append(token)
                    facts.append("%s is defined at %s:%d." % (token, leaf["path"], number))
                    break
    own_paths = {l["path"] for l in files}
    importer = re.compile(r"^\s*(?:import|from)\s+(%s)\b" % "|".join(re.escape(m) for m in sorted(modules))) if modules else None
    users = []
    for leaf in leaves:
        if importer and leaf["path"].endswith(".py") and leaf["path"] not in own_paths:
            text = _read(leaf, 1 << 20).decode("utf-8", "replace")
            if any(importer.match(line) for line in text.splitlines()):
                users.append(leaf["path"])
    if present:
        facts.append("Imported by %d other Python file(s) in the artifact%s." % (
            len(users), (": " + ", ".join(users[:5])) if users else ""))
    return present, facts, None


def collect(leaves, components, matches):
    """Evidence per (advisory, component). `components` maps component id -> inventory component."""
    classes = [l for l in leaves if l["type"] == "java-class"]
    binaries = [l for l in leaves if l["type"] in ("elf", "macho", "macho-fat")]
    symbol_cache = {}
    by_path = {l["path"]: l for l in leaves}

    def syms(leaf):
        if leaf["path"] not in symbol_cache:
            symbol_cache[leaf["path"]] = symbols(leaf)
        return symbol_cache[leaf["path"]]

    results = []
    for adv in matches.get("advisories", []):
        tokens = named_tokens("%s\n%s" % (adv.get("summary", ""), adv.get("details", "")))
        for aff in adv.get("affected", []):
            comp = components.get(aff["component_id"])
            if comp is None:
                continue
            locations = [e["location"] for e in comp.get("evidence", [])]
            facts, present, verdict = [], [], None
            if comp["ecosystem"] in ("Maven", "jar-manifest"):
                jars = {_container(loc) for loc in locations}
                own = [c for c in classes if _container(c["path"]) in jars]
                by_simple = {c["path"].rsplit("/", 1)[-1][:-len(".class")]: c for c in own}
                for token in tokens:
                    cls = by_simple.get(token)
                    if cls is None:
                        continue
                    present.append(token)
                    internal = cls["path"].split("!/")[-1][:-len(".class")].encode()
                    refs = [c for c in classes if c not in own and internal in _read(c, 1 << 22)]
                    facts.append("Class %s is present at %s." % (token, cls["path"]))
                    facts.append("Referenced by %d class(es) outside the component%s." % (
                        len(refs), (": " + ", ".join(r["path"].split("!/")[-1] for r in refs[:5])) if refs else ""))
                    for ref in refs[:2]:
                        lines = decompile(ref, token)
                        if lines:
                            facts.append("Decompiled %s mentions %s: %s" % (ref["path"].split("!/")[-1], token, " | ".join(lines)))
            elif comp["ecosystem"] == "native":
                own = [b for b in binaries if b["path"] in locations]
                for leaf in own:
                    defined, _ = syms(leaf)
                    for token in tokens:
                        if token in defined:
                            present.append(token)
                            importers = [b["path"] for b in binaries if b not in own and token in syms(b)[1]]
                            facts.append("Function %s is defined in %s." % (token, leaf["path"]))
                            facts.append("Imported by %d other binar%s in the artifact%s." % (
                                len(importers), "y" if len(importers) == 1 else "ies",
                                (": " + ", ".join(importers[:5])) if importers else ""))
                if own and tokens and not present:
                    stripped = all(not syms(leaf)[0] for leaf in own)
                    facts.append("None of the names in the advisory (%s) is a defined symbol%s." % (
                        ", ".join(tokens[:6]), "; the library has no symbol table, so this is inconclusive" if stripped else ""))
            elif comp["ecosystem"] == "Go":
                own = [b for b in leaves if b["path"] in locations and b["type"] in ("elf", "macho", "macho-fat", "pe")]
                present, more, verdict = go_evidence(own, comp, aff.get("symbols") or [], tokens)
                facts += more
            elif comp["ecosystem"] == "crates.io":
                own = [b for b in leaves if b["path"] in locations and b["type"] in ("elf", "macho", "macho-fat", "pe")]
                present, more, verdict = rust_evidence(own, comp, aff.get("symbols") or [], tokens)
                facts += more
            elif comp["ecosystem"] == "PyPI":
                present, more, verdict = python_evidence(by_path, leaves, comp, locations, tokens)
                facts += more
            if not tokens and not aff.get("symbols"):
                facts.append("The advisory names no class or function to look for.")
            elif not present and comp["ecosystem"] in ("Maven", "jar-manifest"):
                facts.append("No class named in the advisory (%s) is in the component." % ", ".join(tokens[:6]))
            results.append({
                "advisory_id": adv["id"], "component_id": comp["id"], "named": tokens[:12], "present": sorted(set(present)),
                "facts": facts, "proposed_reachability": verdict or ("conditional" if present else "unknown"),
            })
    return {"schema": "secpeel-evidence", "schema_version": "1.0", "results": results}
