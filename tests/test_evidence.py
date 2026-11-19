import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from secpeel import cli, evidence, identify, unpack  # noqa: E402
import fixtures as fx  # noqa: E402

JNDI = "org/apache/logging/log4j/core/lookup/JndiLookup"
POM = b"groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n"
POM_PATH = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"


def elf_with_symbols(defined=(), undefined=()):
    """ELF64 with .dynstr and .dynsym holding the given defined and undefined symbols."""
    names = list(defined) + list(undefined)
    dynstr, offsets = bytearray(b"\x00"), []
    for name in names:
        offsets.append(len(dynstr))
        dynstr += name.encode() + b"\x00"
    dynsym = bytearray(24)
    for i, name in enumerate(names):
        dynsym += struct.pack("<IBBHQQ", offsets[i], 0x12, 0, 1 if i < len(defined) else 0, 0, 0)
    shstrtab = b"\x00.dynstr\x00.dynsym\x00.shstrtab\x00"
    blobs = [bytes(dynstr), bytes(dynsym), shstrtab]
    offset, layout = 64, []
    for blob in blobs:
        layout.append(offset)
        offset += len(blob)
    shoff = offset
    header = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HHIQQQIHHHHHH", 3, 0x3E, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 4, 3)

    def sh(name, sh_type, off, size, link=0, entsize=0):
        return struct.pack("<IIQQQQIIQQ", name, sh_type, 0, 0, off, size, link, 0, 1, entsize)
    sections = (sh(0, 0, 0, 0) + sh(1, 3, layout[0], len(blobs[0])) + sh(9, 11, layout[1], len(blobs[1]), link=1, entsize=24)
                + sh(17, 3, layout[2], len(blobs[2])))
    return header + b"".join(blobs) + sections


class SymbolTests(unittest.TestCase):
    def test_elf_symbols(self):
        defined, undefined = evidence.elf_symbols(elf_with_symbols(["inflate_fast", "inflate"], ["malloc"]))
        self.assertEqual(defined, {"inflate_fast", "inflate"})
        self.assertEqual(undefined, {"malloc"})

    def test_named_tokens(self):
        text = "JNDI lookups in JndiLookup allow RCE on GitHub; see `MessagePatternConverter.format()` and SSL_free_buffers."
        tokens = evidence.named_tokens(text)
        for token in ("JndiLookup", "MessagePatternConverter", "format", "SSL_free_buffers"):
            self.assertIn(token, tokens)
        self.assertNotIn("GitHub", tokens)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = pathlib.Path(self.tmp.name)

    def collect(self, members, advisories):
        artifact = self.dir / "app.tar"
        artifact.write_bytes(fx.tar_bytes(members))
        leaves = unpack.Unpacker(self.dir / "w", which=lambda _n: None).run(artifact).leaves
        found = identify.identify(leaves)
        return {(r["advisory_id"], r["component_id"]): r
                for r in evidence.collect(leaves, found.components, {"advisories": advisories})["results"]}, found

    def test_log4shell_class_present_and_referenced(self):
        log4j = fx.zip_bytes({POM_PATH: POM, JNDI + ".class": fx.JAVA_CLASS})
        app = fx.zip_bytes({"com/acme/Boot.class": fx.JAVA_CLASS + b"\x01" + JNDI.encode()})
        mitigated = fx.zip_bytes({POM_PATH: POM, "org/apache/logging/log4j/core/Logger.class": fx.JAVA_CLASS})
        cid = "Maven:org.apache.logging.log4j:log4j-core@2.14.1"
        adv = {"id": "CVE-2021-44228", "summary": "RCE", "details": "Remove the JndiLookup class from the classpath.",
               "affected": [{"component_id": cid}]}
        rows, _ = self.collect({"lib/log4j-core.jar": log4j, "lib/app.jar": app}, [adv])
        row = rows[("CVE-2021-44228", cid)]
        self.assertEqual((row["present"], row["proposed_reachability"]), (["JndiLookup"], "conditional"))
        self.assertIn("com/acme/Boot.class", " ".join(row["facts"]))

        rows, _ = self.collect({"lib/log4j-core.jar": mitigated}, [adv])
        row = rows[("CVE-2021-44228", cid)]
        self.assertEqual((row["present"], row["proposed_reachability"]), ([], "unknown"))
        self.assertIn("No class named in the advisory (JndiLookup)", " ".join(row["facts"]))

    def test_native_function_defined_and_imported(self):
        zlib_lib = elf_with_symbols(["inflate_fast"]) + b"\x00 deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly \x00"
        app = elf_with_symbols([], ["inflate_fast"])
        cid = "native:zlib@1.2.11"
        adv = {"id": "CVE-2022-37434", "summary": "heap overflow", "details": "A bug in `inflate_fast` via inflateGetHeader.",
               "affected": [{"component_id": cid}]}
        rows, found = self.collect({"usr/lib/libz.so.1": zlib_lib, "usr/bin/app": app}, [adv])
        self.assertIn(cid, found.components)
        row = rows[("CVE-2022-37434", cid)]
        self.assertEqual(row["present"], ["inflate_fast"])
        self.assertIn("app.tar!/usr/bin/app", " ".join(row["facts"]))

    def test_cli_evidence_command(self):
        artifact = self.dir / "lib.tar"
        artifact.write_bytes(fx.tar_bytes({"log4j.jar": fx.zip_bytes({POM_PATH: POM, JNDI + ".class": fx.JAVA_CLASS})}))
        inv, matches, out = self.dir / "inv.json", self.dir / "matches.json", self.dir / "ev.json"
        cli.main(["scan", str(artifact), "--output", str(inv)])
        matches.write_text(json.dumps({"schema": "secdepth-matches", "schema_version": "1.0", "advisories": [{"id": "CVE-X", "summary": "", "details": "JndiLookup",
                                                       "affected": [{"component_id": "Maven:org.apache.logging.log4j:log4j-core@2.14.1"}]}]}))
        self.assertEqual(cli.main(["evidence", str(artifact), "--inventory", str(inv), "--matches", str(matches),
                                   "--output", str(out)]), 0)
        self.assertEqual(json.loads(out.read_text())["results"][0]["present"], ["JndiLookup"])


if __name__ == "__main__":
    unittest.main()


class WorkdirReuseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = pathlib.Path(self.tmp.name)
        self.artifact = self.dir / "lib.tar"
        self.artifact.write_bytes(fx.tar_bytes({"log4j.jar": fx.zip_bytes({POM_PATH: POM, JNDI + ".class": fx.JAVA_CLASS})}))
        self.inv, self.matches, self.work = self.dir / "inv.json", self.dir / "matches.json", self.dir / "unpacked"
        self.matches.write_text(json.dumps({"schema": "secdepth-matches", "schema_version": "1.0", "advisories": [{"id": "CVE-X", "summary": "", "details": "JndiLookup",
                                                           "affected": [{"component_id": "Maven:org.apache.logging.log4j:log4j-core@2.14.1"}]}]}))
        cli.main(["scan", str(self.artifact), "--output", str(self.inv), "--workdir", str(self.work)])

    def evidence(self, unpacker_calls):
        original = unpack.Unpacker.run

        def counting_run(self_, artifact):
            unpacker_calls.append(artifact)
            return original(self_, artifact)
        unpack.Unpacker.run = counting_run
        self.addCleanup(setattr, unpack.Unpacker, "run", original)
        out = self.dir / "ev.json"
        cli.main(["evidence", str(self.artifact), "--inventory", str(self.inv), "--matches", str(self.matches),
                  "--output", str(out), "--workdir", str(self.work)])
        return json.loads(out.read_text())["results"][0]

    def test_reuses_matching_workdir(self):
        self.assertTrue((self.work / "leaves.json").is_file())
        calls = []
        self.assertEqual(self.evidence(calls)["present"], ["JndiLookup"])
        self.assertEqual(calls, [])  # no second unpack

    def test_unpacks_again_for_a_different_artifact(self):
        self.artifact.write_bytes(fx.tar_bytes({"log4j.jar": fx.zip_bytes({POM_PATH: POM, JNDI + ".class": fx.JAVA_CLASS}),
                                                "extra.txt": b"changed"}))
        calls = []
        self.assertEqual(self.evidence(calls)["present"], ["JndiLookup"])
        self.assertEqual(len(calls), 1)

    def test_unpacks_again_when_files_are_gone(self):
        manifest = json.loads((self.work / "leaves.json").read_text())
        (self.work / manifest["leaves"][0]["real"]).unlink()
        calls = []
        self.evidence(calls)
        self.assertEqual(len(calls), 1)


class MatchesContractTests(unittest.TestCase):
    """secdepth writes matches.json; secpeel must accept what it writes today and reject what it cannot read."""
    FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "secdepth-matches-1.0.json"
    INVENTORY = {"schema": "secdepth-inventory", "schema_version": "1.0", "components": [{"id": "x"}]}

    def problems(self, matches, inventory=None):
        return cli.validate_inputs(matches, inventory or dict(self.INVENTORY), "m.json", "inv.json")

    def load(self):
        return json.loads(self.FIXTURE.read_text())

    def test_accepts_the_producer_fixture(self):
        self.assertEqual(self.problems(self.load()), [])

    def test_accepts_extra_optional_fields_and_minor_versions(self):
        data = self.load()
        data["schema_version"] = "1.7"
        data["advisories"][0]["future_field"] = {"x": 1}
        data["new_top_level"] = True
        self.assertEqual(self.problems(data), [])

    def test_accepts_empty_advisories(self):
        data = self.load()
        data["advisories"] = []
        self.assertEqual(self.problems(data), [])

    def test_rejects_unsupported_major_version(self):
        data = self.load()
        data["schema_version"] = "2.0"
        self.assertTrue(any("m.json" in p and "2.0" in p for p in self.problems(data)))
        inventory = dict(self.INVENTORY, schema_version="3.1")
        self.assertTrue(any("inv.json" in p for p in self.problems(self.load(), inventory)))

    def test_rejects_missing_required_fields(self):
        data = self.load()
        del data["advisories"]
        self.assertIn("m.json: advisories must be a list", self.problems(data))
        data = self.load()
        del data["advisories"][0]["affected"][0]["component_id"]
        self.assertTrue(any("advisories[0].affected" in p for p in self.problems(data)))

    def test_cli_rejects_a_bad_file(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        artifact = root / "a.tar"
        artifact.write_bytes(fx.tar_bytes({"x.txt": b"x"}))
        (root / "inv.json").write_text(json.dumps(self.INVENTORY))
        bad = self.load()
        bad["schema_version"] = "2.0"
        (root / "m.json").write_text(json.dumps(bad))
        self.assertEqual(cli.main(["evidence", str(artifact), "--inventory", str(root / "inv.json"),
                                   "--matches", str(root / "m.json")]), 1)
