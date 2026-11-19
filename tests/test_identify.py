import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from secpeel import cli, identify, unpack  # noqa: E402
import fixtures as fx  # noqa: E402

DPKG_STATUS = b"""Package: libssl3
Status: install ok installed
Source: openssl (3.0.11-1~deb12u2)
Version: 3.0.11-1~deb12u2

Package: zlib1g
Status: install ok installed
Source: zlib
Version: 1:1.2.13.dfsg-1

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0
"""

GO_MODINFO = "path\texample.com/app\nmod\texample.com/app\t(devel)\t\ndep\tgolang.org/x/net\tv0.17.0\th1:abc=\n"


def image_tar():
    layer1 = fx.tar_bytes({"etc/os-release": b'ID=debian\nVERSION_ID="12"\n', "var/lib/dpkg/status": DPKG_STATUS})
    jar = fx.zip_bytes({"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties":
                        b"groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n",
                        "org/apache/logging/log4j/core/Logger.class": fx.JAVA_CLASS})
    manifest_jar = fx.zip_bytes({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nBundle-SymbolicName: com.acme.util;singleton:=true\n"
                                 b"Bundle-Version: 3.2.0\n", "com/acme/U.class": fx.JAVA_CLASS})
    go_binary = fx.ELF + b"\x00" * 32 + identify.make_go_buildinfo("go1.21.3", GO_MODINFO)
    layer2 = fx.tar_bytes({
        "app/lib/log4j-core-2.14.1.jar": jar,
        "app/lib/acme-util.jar": manifest_jar,
        "app/node_modules/lodash/package.json": json.dumps({"name": "lodash", "version": "4.17.20"}).encode(),
        "usr/lib/python3/dist-packages/Jinja2-2.10.dist-info/METADATA": b"Metadata-Version: 2.1\nName: Jinja2\nVersion: 2.10\n",
        "app/svc.deps.json": json.dumps({"libraries": {"Newtonsoft.Json/12.0.1": {"type": "package"},
                                                       "svc/1.0.0": {"type": "project"}}}).encode(),
        "usr/local/bin/app": go_binary,
        "var/lib/rpm/rpmdb.sqlite": b"SQLite format 3\x00",
    })
    return fx.tar_bytes({"manifest.json": b"[]", "layer1.tar": layer1, "layer2.tar.gz": fx.gz(layer2)})


class IdentifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = pathlib.Path(self.tmp.name)
        self.artifact = self.dir / "image.tar"
        self.artifact.write_bytes(image_tar())
        self.unpacker = unpack.Unpacker(self.dir / "work", which=lambda _n: None).run(self.artifact)
        self.result = identify.identify(self.unpacker.leaves)
        self.ids = set(self.result.components)

    def test_language_packages(self):
        for cid in ("Maven:org.apache.logging.log4j:log4j-core@2.14.1", "npm:lodash@4.17.20", "PyPI:jinja2@2.10",
                    "NuGet:Newtonsoft.Json@12.0.1", "Go:golang.org/x/net@0.17.0", "Go:stdlib@1.21.3"):
            self.assertIn(cid, self.ids)
        self.assertNotIn("NuGet:svc@1.0.0", self.ids)
        app = self.result.components["Go:example.com/app@unknown"]  # (devel) build: kept with an unknown version
        self.assertIsNone(app["version"])
        self.assertEqual(app["evidence"][0]["confidence"], "low")

    def test_os_packages_use_source_names_and_distro(self):
        openssl = self.result.components["Debian:openssl@3.0.11-1~deb12u2"]
        self.assertEqual(openssl["distro"], {"name": "debian", "release": "12"})
        self.assertIn("libssl3", openssl["evidence"][0]["detail"])
        self.assertIn("Debian:zlib@1:1.2.13.dfsg-1", self.ids)
        self.assertFalse(any("removed-pkg" in c for c in self.ids))

    def test_manifest_only_jar_is_reported_not_guessed(self):
        acme = self.result.components["jar-manifest:com.acme.util@3.2.0"]
        self.assertEqual(acme["evidence"][0]["confidence"], "low")

    def test_classes_are_covered_by_their_jar(self):
        cls = next(p for p in self.result.identified if p.endswith("Logger.class"))
        self.assertEqual(self.result.identified[cls], "Maven:org.apache.logging.log4j:log4j-core@2.14.1")

    def test_unparsed_databases_are_noted(self):
        note = next(v for k, v in self.result.notes.items() if k.endswith("rpmdb.sqlite"))
        self.assertIn("not implemented", note)

    def test_go_buildinfo_parser(self):
        version, modinfo = identify.go_buildinfo(identify.make_go_buildinfo("go1.22.0", GO_MODINFO))
        self.assertEqual(version, "go1.22.0")
        self.assertTrue(modinfo.startswith("path\texample.com/app"))

    def test_cli_inventory(self):
        out = self.dir / "inv.json"
        cli.main(["scan", str(self.artifact), "--output", str(out)])
        data = json.loads(out.read_text())
        statuses = {e["path"].rsplit("/", 1)[-1]: (e["status"], e["reason"]) for e in data["coverage"]["entries"]}
        self.assertEqual(statuses["status"][0], "identified")
        self.assertEqual(statuses["rpmdb.sqlite"], ("unidentified", "RPM database parsing is not implemented yet"))
        root = data["components"][0]
        self.assertEqual(len(root["depends_on"]), len(data["components"]) - 1)


if __name__ == "__main__":
    unittest.main()


class CycloneDxTests(unittest.TestCase):
    setUp = IdentifyTests.setUp
    def test_cyclonedx_export(self):
        out, sbom = self.dir / "inv.json", self.dir / "bom.json"
        cli.main(["scan", str(self.artifact), "--output", str(out), "--cyclonedx", str(sbom)])
        bom = json.loads(sbom.read_text())
        self.assertEqual((bom["bomFormat"], bom["specVersion"]), ("CycloneDX", "1.5"))
        log4j = next(c for c in bom["components"] if c["name"] == "org.apache.logging.log4j:log4j-core")
        self.assertEqual(log4j["purl"], "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        self.assertTrue(log4j["evidence"]["occurrences"][0]["location"].endswith("pom.properties"))
        self.assertEqual(len(bom["dependencies"][0]["dependsOn"]), len(bom["components"]))
