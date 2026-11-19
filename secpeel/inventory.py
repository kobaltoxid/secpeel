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


def build(artifact, display_path, unpacker, components=(), identified_paths=(), notes=None, which=shutil.which):
    """Assemble the inventory: the artifact as root, found components, and the full coverage ledger."""
    digest = sha256(artifact)
    root_id = component_id("artifact", artifact.name, None)
    root = {
        "id": root_id, "name": artifact.name, "ecosystem": "artifact", "version": None, "scope": "runtime",
        "root": True, "direct": None, "depends_on": sorted(c["id"] for c in components),
        "evidence": [{"identifier": "artifact", "location": artifact.name, "detail": "sha256:" + digest, "confidence": "exact"}],
    }
    identified = set(identified_paths)
    notes = notes or {}
    entries = list(unpacker.entries)
    for leaf in unpacker.leaves:
        status = "identified" if leaf["path"] in identified else "unidentified"
        reason = None if status == "identified" else notes.get(leaf["path"], "no identifier matched this file")
        entries.append({"path": leaf["path"], "status": status, "reason": reason, "type": leaf["type"], "size": leaf["size"]})
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


def to_cyclonedx(data):
    """A CycloneDX 1.5 SBOM view of the inventory, with where each component was found."""
    root = data["components"][0]
    components = []
    for comp in data["components"][1:]:
        entry = {"type": "library", "bom-ref": comp["id"], "name": comp["name"]}
        if comp.get("version"):
            entry["version"] = comp["version"]
        if comp.get("purl"):
            entry["purl"] = comp["purl"]
        if comp.get("cpe"):
            entry["cpe"] = comp["cpe"]
        entry["evidence"] = {"occurrences": [{"location": e["location"]} for e in comp["evidence"]],
                             "identity": {"field": "purl" if comp.get("purl") else "name",
                                          "confidence": {"exact": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}[comp["evidence"][0]["confidence"]],
                                          "methods": [{"technique": "manifest-analysis", "confidence": 1.0,
                                                       "value": comp["evidence"][0]["identifier"]}]}}
        components.append(entry)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {
            "timestamp": data["generated_at"],
            "tools": {"components": [{"type": "application", "name": data["producer"]["name"], "version": data["producer"]["version"]}]},
            "component": {"type": "file", "bom-ref": root["id"], "name": root["name"],
                          "hashes": [{"alg": "SHA-256", "content": data["target"]["sha256"]}]},
        },
        "components": components,
        "dependencies": [{"ref": root["id"], "dependsOn": [c["bom-ref"] for c in components]}],
    }


def summary(data):
    counts = {}
    for entry in data["coverage"]["entries"]:
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    return counts
