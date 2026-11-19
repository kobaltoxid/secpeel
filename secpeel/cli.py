"""Command line: python3 -m secpeel scan ARTIFACT [options]"""
import argparse
import json
import pathlib
import shutil
import sys
import tempfile

from . import VERSION, evidence, identify, inventory, unpack


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
    workdir = pathlib.Path(tempfile.mkdtemp(prefix="secpeel-evidence-"))
    try:
        unpacker = unpack.Unpacker(workdir).run(artifact)
        result = evidence.collect(unpacker.leaves, {c["id"]: c for c in data["components"]}, matches)
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
    args = parser.parse_args(argv)
    return evidence_cmd(args) if args.command == "evidence" else scan(args)
