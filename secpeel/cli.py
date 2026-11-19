"""Command line: python3 -m secpeel scan ARTIFACT [options]"""
import argparse
import json
import pathlib
import shutil
import sys
import tempfile

from . import VERSION, inventory, unpack


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
        data = inventory.build(artifact, args.artifact, unpacker)
    finally:
        if not args.keep_workdir and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    out = pathlib.Path(args.output) if args.output else pathlib.Path("secpeel-output") / (artifact.name + ".inventory.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    counts = inventory.summary(data)
    print("%s: %d files examined; %s; complete=%s" % (out, sum(counts.values()), counts, data["coverage"]["complete"]))
    if args.keep_workdir or args.workdir:
        print("unpacked files kept in %s" % workdir)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="secpeel", description="Identify components in compiled artifacts.")
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("scan", help="unpack an artifact and write a component inventory")
    p.add_argument("artifact")
    p.add_argument("--output", help="inventory path (default: secpeel-output/<artifact>.inventory.json)")
    p.add_argument("--workdir", help="scratch directory for unpacked files (kept)")
    p.add_argument("--keep-workdir", action="store_true", help="keep the temporary scratch directory")
    p.add_argument("--max-depth", type=int, default=12)
    p.add_argument("--max-bytes", type=int, default=4 << 30, help="total bytes to extract (default 4 GiB)")
    p.add_argument("--max-files", type=int, default=200_000)
    args = parser.parse_args(argv)
    return scan(args)
