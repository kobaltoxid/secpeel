"""Write results in secdepth's component inventory format (schema_version 1.0)."""
import datetime
import hashlib
import shutil

from . import VERSION

SCHEMA = "secdepth-inventory"
SCHEMA_VERSION = "1.0"
INCOMPLETE = {"unidentified", "unpack-failed", "tool-missing"}
OPTIONAL_TOOLS = ("unblob", "7z", "zstd")


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def component_id(ecosystem, name, version):
    return "%s:%s@%s" % (ecosystem, name, version if version else "unknown")


def build(artifact, display_path, unpacker, components=(), identified_paths=(), which=shutil.which):
    """Assemble the inventory: the artifact as root, found components, and the full coverage ledger."""
    digest = sha256(artifact)
    root_id = component_id("artifact", artifact.name, None)
    root = {
        "id": root_id, "name": artifact.name, "ecosystem": "artifact", "version": None, "scope": "runtime",
        "root": True, "direct": None, "depends_on": sorted(c["id"] for c in components),
        "evidence": [{"identifier": "artifact", "location": artifact.name, "detail": "sha256:" + digest, "confidence": "exact"}],
    }
    identified = set(identified_paths)
    entries = list(unpacker.entries)
    for leaf in unpacker.leaves:
        status = "identified" if leaf["path"] in identified else "unidentified"
        entries.append({"path": leaf["path"], "status": status,
                        "reason": None if status == "identified" else "no identifier matched this file",
                        "type": leaf["type"], "size": leaf["size"]})
    entries.sort(key=lambda e: e["path"])
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer": {"name": "secpeel", "version": VERSION},
        "target": {"kind": "artifact", "path": display_path, "ref": None, "sha256": digest},
        "root_component_id": root_id,
        "components": [root] + list(components),
        "coverage": {
            "complete": not any(e["status"] in INCOMPLETE for e in entries),
            "entries": entries,
            "tools": [{"name": t, "available": which(t) is not None, "used": t in unpacker.tools_used} for t in OPTIONAL_TOOLS],
        },
        "resolution": [],
    }


def summary(data):
    counts = {}
    for entry in data["coverage"]["entries"]:
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    return counts
