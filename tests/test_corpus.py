"""Identification corpus: one artifact exercising every identifier and failure mode, scored against an
exact expected component list (recall must be 1.0 and nothing unexpected may appear)."""
import json
import pathlib
import sys
import tempfile
import unittest
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from secpeel import cli, identify  # noqa: E402
import fixtures as fx  # noqa: E402
from test_native import elf_with_section, pe_with_version  # noqa: E402

EXPECTED = {
    "Maven:org.apache.logging.log4j:log4j-core@2.14.1",
    "jar-manifest:com.acme.util@3.2.0",
    "npm:lodash@4.17.20",
    "PyPI:jinja2@2.10",
    "NuGet:Newtonsoft.Json@12.0.1",
    "Go:stdlib@1.21.3",
    "Go:golang.org/x/net@0.17.0",
    "Go:example.com/app@unknown",
    "Debian:openssl@3.0.11-1~deb12u2",
    "Alpine:busybox@1.36.1-r2",
    "native:zlib@1.2.11",
    "native:Widget Tool@2.4.1.0",
    "crates.io:tokio@1.28.0",
}
# Allowed ledger statuses; the CAB depends on whether 7z or unblob is installed on the machine.
EXPECTED_LEDGER = {
    "setup.cab": {"tool-missing", "unpack-failed"},
    "broken.gz": {"unpack-failed"},
    "secrets.zip!/key.pem": {"unpack-failed"},
    "rpm/var/lib/rpm/rpmdb.sqlite": {"unidentified"},
}


def corpus():
    go_bin = fx.ELF + b"\x00" * 32 + identify.make_go_buildinfo(
        "go1.21.3", "path\texample.com/app\nmod\texample.com/app\t(devel)\t\ndep\tgolang.org/x/net\tv0.17.0\th1:x=\n")
    debian = fx.tar_bytes({
        "etc/os-release": b'ID=debian\nVERSION_ID="12"\n',
        "var/lib/dpkg/status": b"Package: libssl3\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.11-1~deb12u2\n",
        "usr/lib/libssl.so.3": fx.ELF + b"\x00OpenSSL 3.0.11 19 Sep 2023\x00",   # covered by the dpkg entry
    })
    alpine = fx.tar_bytes({
        "etc/os-release": b'ID=alpine\nVERSION_ID=3.19.1\n',
        "lib/apk/db/installed": b"P:busybox-binsh\nV:1.36.1-r2\no:busybox\n\n",
    })
    rust = elf_with_section(b".dep-v0", zlib.compress(json.dumps(
        {"packages": [{"name": "tokio", "version": "1.28.0", "source": "crates.io"}]}).encode()))
    return fx.tar_bytes({
        "java/log4j-core.jar": fx.zip_bytes({"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties":
                                             b"groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n"}),
        "java/acme.jar": fx.zip_bytes({"META-INF/MANIFEST.MF": b"Bundle-SymbolicName: com.acme.util\nBundle-Version: 3.2.0\n"}),
        "web/node_modules/lodash/package.json": json.dumps({"name": "lodash", "version": "4.17.20"}).encode(),
        "py/Jinja2-2.10.dist-info/METADATA": b"Name: Jinja2\nVersion: 2.10\n",
        "dotnet/app.deps.json": json.dumps({"libraries": {"Newtonsoft.Json/12.0.1": {"type": "package"}}}).encode(),
        "go/app": go_bin,
        "debian.tar": debian,
        "alpine.tar": alpine,
        "native/libz.so.1": fx.ELF + b"\x00 inflate 1.2.11 Copyright 1995-2017 Mark Adler \x00 Jean-loup Gailly\x00",
        "native/links-to-ssl": fx.ELF + b"\x00libssl.so.3\x00OpenSSL_init_ssl\x00",   # must not be reported
        "win/tool.exe": pe_with_version("Widget Tool", "2.4.1.0"),
        "rust/app": rust,
        "setup.cab": b"MSCF" + b"\x00" * 60,
        "broken.gz": fx.gz(b"x" * 1000)[:15],
        "secrets.zip": fx.zip_bytes({"key.pem": b"x"}, encrypted=["key.pem"]),
        "rpm/var/lib/rpm/rpmdb.sqlite": b"SQLite format 3\x00",
    })


class CorpusTests(unittest.TestCase):
    def test_identification_scores(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        artifact, out = pathlib.Path(tmp.name) / "corpus.tar", pathlib.Path(tmp.name) / "inv.json"
        artifact.write_bytes(corpus())
        cli.main(["scan", str(artifact), "--output", str(out)])
        data = json.loads(out.read_text())
        found = {c["id"] for c in data["components"] if not c.get("root")}
        missing, unexpected = EXPECTED - found, found - EXPECTED
        recall = 1 - len(missing) / len(EXPECTED)
        precision = 1 - len(unexpected) / max(len(found), 1)
        self.assertEqual((recall, precision), (1.0, 1.0), "missing %s, unexpected %s" % (sorted(missing), sorted(unexpected)))
        ledger = {e["path"].split("corpus.tar!/", 1)[-1]: e["status"] for e in data["coverage"]["entries"]}
        for path, allowed in EXPECTED_LEDGER.items():
            self.assertIn(ledger.get(path), allowed, path)
        self.assertFalse(data["coverage"]["complete"])


if __name__ == "__main__":
    unittest.main()
