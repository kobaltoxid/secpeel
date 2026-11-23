import json
import pathlib
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

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


    def test_records_an_artifact_that_is_not_a_container(self):
        binary = self.dir / "app"
        binary.write_bytes(b"\x7fELF plain executable bytes")
        work = self.dir / "binary-work"
        self.assertEqual(cli.main(["scan", str(binary), "--output", str(self.dir / "bin.json"), "--workdir", str(work)]), 0)
        sha256 = json.loads((self.dir / "bin.json").read_text())["target"]["sha256"]
        leaves, reason = cli.load_manifest(work, sha256)
        self.assertIsNone(reason)
        self.assertEqual([l["real"] for l in leaves], [binary.resolve()])


class WorkdirLifecycleTests(unittest.TestCase):
    def test_temporary_workdir_is_removed_when_unpacking_fails(self):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        scratch = root / "scratch"
        artifact = root / "artifact.bin"
        artifact.write_bytes(b"artifact")
        with mock.patch.object(cli.tempfile, "mkdtemp", return_value=str(scratch)):
            with mock.patch.object(unpack.Unpacker, "run", side_effect=RuntimeError("boom")):
                with self.assertRaises(RuntimeError):
                    cli.main(["scan", str(artifact), "--output", str(root / "inventory.json")])
        self.assertFalse(scratch.exists())

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


class EcosystemEvidenceTests(unittest.TestCase):
    def collect(self, members, components, advisories):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        artifact = pathlib.Path(tmp.name) / "app.tar"
        artifact.write_bytes(fx.tar_bytes(members))
        leaves = unpack.Unpacker(pathlib.Path(tmp.name) / "w", which=lambda _n: None).run(artifact).leaves
        rows = evidence.collect(leaves, {c["id"]: c for c in components}, {"advisories": advisories})["results"]
        return {r["advisory_id"]: r for r in rows}

    @staticmethod
    def comp(cid, name, version, ecosystem, location):
        return {"id": cid, "name": name, "version": version, "ecosystem": ecosystem,
                "evidence": [{"location": location}]}

    def test_go_symbols_linked_or_not(self):
        binary = fx.ELF + b"\x00golang.org/x/crypto/ssh.NewServerConn\x00golang.org/x/crypto/ssh.(*connection).serverAuthenticate\x00"
        comp = self.comp("Go:golang.org/x/crypto@0.1.0", "golang.org/x/crypto", "0.1.0", "Go", "app.tar!/bin/svc")
        rows = self.collect({"bin/svc": binary}, [comp], [
            {"id": "GO-1", "summary": "", "details": "", "affected": [{"component_id": comp["id"],
             "symbols": ["golang.org/x/crypto/ssh.NewServerConn", "golang.org/x/crypto/ssh.connection.serverAuthenticate"]}]},
            {"id": "GO-2", "summary": "", "details": "", "affected": [{"component_id": comp["id"],
             "symbols": ["golang.org/x/crypto/acme.Client.Register"]}]}])
        self.assertEqual(rows["GO-1"]["proposed_reachability"], "conditional")
        self.assertEqual(len(rows["GO-1"]["present"]), 2)
        self.assertEqual(rows["GO-2"]["proposed_reachability"], "not-reachable")
        self.assertIn("no call path", " ".join(rows["GO-2"]["facts"]))

    def test_rust_symbol_and_crate_paths(self):
        binary = fx.ELF + b"\x00_ZN5regex5Regex3new17h0123456789abcdefE\x00/root/.cargo/registry/src/regex-1.5.4/src/re.rs\x00"
        comp = self.comp("crates.io:regex@1.5.4", "regex", "1.5.4", "crates.io", "app.tar!/bin/tool")
        rows = self.collect({"bin/tool": binary}, [comp], [
            {"id": "RUSTSEC-1", "summary": "", "details": "", "affected": [{"component_id": comp["id"], "symbols": ["regex::Regex::new"]}]},
            {"id": "RUSTSEC-2", "summary": "", "details": "", "affected": [{"component_id": comp["id"], "symbols": ["regex::RegexSet::new"]}]}])
        self.assertEqual(rows["RUSTSEC-1"]["proposed_reachability"], "conditional")
        self.assertIn("crate's code is linked", " ".join(rows["RUSTSEC-1"]["facts"]))
        self.assertEqual(rows["RUSTSEC-2"]["proposed_reachability"], "unknown")
        self.assertIn("inconclusive", " ".join(rows["RUSTSEC-2"]["facts"]))

    def test_python_definition_and_importers(self):
        site = "usr/lib/python3/site-packages/"
        members = {
            site + "yaml_lib-5.3.dist-info/METADATA": b"Name: yaml-lib\nVersion: 5.3\n",
            site + "yaml_lib-5.3.dist-info/RECORD": b"yaml_lib/__init__.py,,\nyaml_lib/loader.py,,\nyaml_lib-5.3.dist-info/METADATA,,\n",
            site + "yaml_lib/__init__.py": b"from .loader import full_load\n",
            site + "yaml_lib/loader.py": b"import os\n\ndef full_load(stream):\n    return eval(stream)\n",
            "app/main.py": b"import yaml_lib\nprint(yaml_lib.full_load('1'))\n",
        }
        comp = self.comp("PyPI:yaml-lib@5.3", "yaml-lib", "5.3", "PyPI", "app.tar!/" + site + "yaml_lib-5.3.dist-info/METADATA")
        rows = self.collect(members, [comp], [
            {"id": "PYSEC-1", "summary": "Unsafe full_load", "details": "Calling full_load on untrusted input runs code.",
             "affected": [{"component_id": comp["id"]}]},
            {"id": "PYSEC-2", "summary": "Issue in dump_all", "details": "", "affected": [{"component_id": comp["id"]}]}])
        self.assertEqual(rows["PYSEC-1"]["proposed_reachability"], "conditional")
        facts = " ".join(rows["PYSEC-1"]["facts"])
        self.assertIn("yaml_lib/loader.py:3", facts)
        self.assertIn("app.tar!/app/main.py", facts)
        self.assertEqual(rows["PYSEC-2"]["proposed_reachability"], "unknown")
