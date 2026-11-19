"""Command line: python3 -m secpeel scan ARTIFACT [options]"""
import argparse
import json
import pathlib
import shutil
import sys
import tempfile

from . import VERSION, evidence, identify, inventory, unpack


MANIFEST = "leaves.json"


def write_manifest(workdir, sha256, unpacker):
    """Record the unpacked files so a later step (evidence) can reuse them instead of unpacking again."""
    leaves = [{"path": l["path"], "real": str(pathlib.Path(l["real"]).resolve().relative_to(workdir.resolve())),
               "type": l["type"], "size": l["size"]} for l in unpacker.leaves]
    (workdir / MANIFEST).write_text(json.dumps({"artifact_sha256": sha256, "leaves": leaves}), encoding="utf-8")


def load_manifest(workdir, sha256):
    """Leaves from a kept scan of the same artifact, or (None, reason)."""
    path = workdir / MANIFEST
    if not path.is_file():
        return None, "no %s in %s" % (MANIFEST, workdir)
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("artifact_sha256") != sha256:
        return None, "%s was written for a different artifact" % path
    leaves = [dict(l, real=workdir / l["real"]) for l in data["leaves"]]
    missing = [l for l in leaves if not l["real"].exists()]
    if missing:
        return None, "%d unpacked files are missing from %s" % (len(missing), workdir)
    return leaves, None


def scan(args):
    artifact = pathlib.Path(args.artifact)
    if not artifact.is_file():
        print("not a file: %s" % artifact, file=sys.stderr)
        return 2
    limits = unpack.Limits(max_depth=args.max_depth, max_total_bytes=args.max_bytes, max_files=args.max_files)
    workdir = pathlib.Path(args.workdir) if args.workdir else pathlib.Path(tempfile.mkdtemp(prefix="secpeel-"))
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        unpacker = unpack.Unpacker(workdir, limits).run(artifact)
        found = identify.identify(unpacker.leaves)
        data = inventory.build(artifact, args.artifact, unpacker, sorted(found.components.values(), key=lambda c: c["id"]),
                               found.identified, found.notes)
        if args.keep_workdir or args.workdir:
            write_manifest(workdir, data["target"]["sha256"], unpacker)
    finally:
        if not args.keep_workdir and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    out = pathlib.Path(args.output) if args.output else pathlib.Path("secpeel-output") / (artifact.name + ".inventory.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if args.cyclonedx:
        pathlib.Path(args.cyclonedx).write_text(json.dumps(inventory.to_cyclonedx(data), indent=2) + "\n", encoding="utf-8")
    counts = inventory.summary(data)
    print("%s: %d components; %d files examined; %s; complete=%s" % (
        out, len(data["components"]) - 1, sum(counts.values()), counts, data["coverage"]["complete"]))
    if args.keep_workdir or args.workdir:
        print("unpacked files kept in %s" % workdir)
    return 0


def evidence_cmd(args):
    artifact = pathlib.Path(args.artifact)
    matches = json.loads(pathlib.Path(args.matches).read_text(encoding="utf-8"))
    data = json.loads(pathlib.Path(args.inventory).read_text(encoding="utf-8"))
    components = {c["id"]: c for c in data["components"]}
    leaves, reason = (None, "no --workdir given")
    if args.workdir:
        leaves, reason = load_manifest(pathlib.Path(args.workdir), inventory.sha256(artifact))
    if leaves is not None:
        print("reusing unpacked files from %s" % args.workdir)
        result = evidence.collect(leaves, components, matches)
    else:
        print("unpacking %s again (%s)" % (artifact.name, reason))
        workdir = pathlib.Path(tempfile.mkdtemp(prefix="secpeel-evidence-"))
        try:
            result = evidence.collect(unpack.Unpacker(workdir).run(artifact).leaves, components, matches)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    out = pathlib.Path(args.output) if args.output else pathlib.Path(args.matches).with_name("evidence.json")
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    present = sum(1 for r in result["results"] if r["present"])
    print("%s: %d findings; vulnerable code located for %d" % (out, len(result["results"]), present))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="secpeel", description="Identify components in compiled artifacts.")
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("scan", help="unpack an artifact and write a component inventory")
    p.add_argument("artifact")
    p.add_argument("--output", help="inventory path (default: secpeel-output/<artifact>.inventory.json)")
    p.add_argument("--cyclonedx", help="also write a CycloneDX 1.5 SBOM to this path")
    p.add_argument("--workdir", help="scratch directory for unpacked files (kept)")
    p.add_argument("--keep-workdir", action="store_true", help="keep the temporary scratch directory")
    p.add_argument("--max-depth", type=int, default=12)
    p.add_argument("--max-bytes", type=int, default=4 << 30, help="total bytes to extract (default 4 GiB)")
    p.add_argument("--max-files", type=int, default=200_000)
    e = sub.add_parser("evidence", help="look for the code advisories name in the artifact (after secdepth's match.py)")
    e.add_argument("artifact")
    e.add_argument("--inventory", required=True)
    e.add_argument("--matches", required=True)
    e.add_argument("--output", help="evidence path (default: evidence.json next to the matches)")
    e.add_argument("--workdir", help="reuse the files a scan kept with --workdir (unpacks again if they do not match)")
    args = parser.parse_args(argv)
    return evidence_cmd(args) if args.command == "evidence" else scan(args)
