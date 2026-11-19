import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from secpeel import cli, filetypes, inventory, unpack  # noqa: E402
import fixtures as fx  # noqa: E402

SECDEPTH_INVENTORY = ROOT.parent / "secdepth" / "skills" / "secdepth" / "scripts" / "inventory.py"


def no_tools(_name):
    return None


class Workspace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = pathlib.Path(self.tmp.name)

    def write(self, name, data):
        path = self.dir / name
        path.write_bytes(data)
        return path

    def unpack(self, path, limits=None, which=no_tools):
        work = self.dir / ("work-" + path.name)
        return unpack.Unpacker(work, limits, which=which).run(path)

    def statuses(self, unpacker):
        result = {e["path"]: e["status"] for e in unpacker.entries}
        result.update({leaf["path"]: "leaf:" + leaf["type"] for leaf in unpacker.leaves})
        return result


class FiletypeTests(unittest.TestCase):
    def test_magic_detection(self):
        cases = {
            fx.zip_bytes({"a": b"x"}): "zip", fx.gz(b"x"): "gzip", fx.xz(b"x"): "xz", fx.tar_bytes({"a": b"x"}): "tar",
            fx.ar_bytes({"a": b"x"}): "ar", fx.cpio_newc({"a": b"x"}): "cpio-newc", fx.rpm_bytes(b""): "rpm",
            fx.ELF: "elf", b"MZ\x90\x00": "pe", b"MSCF\x00\x00": "cab", fx.JAVA_CLASS: "java-class",
            fx.FAT_MACHO: "macho-fat", b"plain text\n": "text", b"\x00\x01\x02binary": "data",
        }
        for data, kind in cases.items():
            self.assertEqual(filetypes.detect_bytes(data), kind, data[:12])

    def test_text_with_truncated_multibyte_tail(self):
        sample = ("a" * 4095 + "é").encode()[:4096]
        self.assertEqual(filetypes.detect_bytes(sample), "text")


class UnpackTests(Workspace):
    def test_nested_formats_reach_leaves(self):
        jar = fx.zip_bytes({"META-INF/maven/org.x/lib/pom.properties": b"version=1.0\n", "org/x/A.class": fx.JAVA_CLASS})
        deb = fx.ar_bytes({"debian-binary": b"2.0\n", "control.tar.gz": fx.gz(fx.tar_bytes({"control": b"Package: zlib\n"})),
                           "data.tar.xz": fx.xz(fx.tar_bytes({"usr/lib/libz.so.1": fx.ELF}))})
        outer = fx.gz(fx.tar_bytes({"app/lib.jar": jar, "pkg/zlib.deb": deb, "initrd.cpio": fx.cpio_newc({"bin/busybox": fx.ELF})}))
        u = self.unpack(self.write("bundle.tar.gz", outer))
        s = self.statuses(u)
        self.assertEqual(s["bundle.tar.gz"], "unpacked")
        self.assertEqual(s["bundle.tar.gz!/bundle.tar"], "unpacked")
        self.assertEqual(s["bundle.tar.gz!/bundle.tar!/app/lib.jar!/org/x/A.class"], "leaf:java-class")
        self.assertEqual(s["bundle.tar.gz!/bundle.tar!/pkg/zlib.deb!/data.tar.xz!/data.tar!/usr/lib/libz.so.1"], "leaf:elf")
        self.assertEqual(s["bundle.tar.gz!/bundle.tar!/initrd.cpio!/bin/busybox"], "leaf:elf")
        self.assertIn("bundle.tar.gz!/bundle.tar!/pkg/zlib.deb!/control.tar.gz!/control.tar!/control", s)

    def test_problems_are_recorded_not_dropped(self):
        evil = fx.zip_bytes({"../evil.txt": b"x", "ok.txt": b"fine", "secret.bin": b"x"}, encrypted=["secret.bin"])
        outer = fx.tar_bytes({"evil.zip": evil, "broken.gz": fx.gz(b"payload" * 100)[:20]}, symlinks={"link": "/etc/passwd"})
        u = self.unpack(self.write("t.tar", outer))
        s = self.statuses(u)
        reasons = {e["path"]: e["reason"] for e in u.entries}
        self.assertEqual(s["t.tar!/evil.zip!/../evil.txt"], "unpack-failed")
        self.assertIn("unsafe member path", reasons["t.tar!/evil.zip!/../evil.txt"])
        self.assertEqual(s["t.tar!/evil.zip!/secret.bin"], "unpack-failed")
        self.assertEqual(reasons["t.tar!/evil.zip!/secret.bin"], "encrypted member")
        self.assertEqual(s["t.tar!/evil.zip!/ok.txt"], "leaf:text")
        self.assertEqual(s["t.tar!/link"], "skipped")
        self.assertEqual(s["t.tar!/broken.gz"], "unpack-failed")
        self.assertFalse((self.dir.parent / "evil.txt").exists())

    def test_non_utf8_member_name_does_not_fail_container(self):
        import io
        import tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT, encoding="latin-1") as tf:
            for name in ("umlauts-\xc4\xd6\xdc", "plain.txt"):
                info = tarfile.TarInfo(name)
                info.size = 2
                tf.addfile(info, io.BytesIO(b"ok"))
        u = self.unpack(self.write("names.tar", buf.getvalue()))
        s = self.statuses(u)
        self.assertEqual(s["names.tar"], "unpacked")
        self.assertEqual(s["names.tar!/plain.txt"], "leaf:text")
        self.assertEqual(len(u.leaves), 2)

    def test_rpm_payload(self):
        payload = fx.gz(fx.cpio_newc({"./usr/lib64/libssl.so.3": fx.ELF}, symlinks={"./usr/lib64/libssl.so": "libssl.so.3"}))
        u = self.unpack(self.write("openssl.rpm", fx.rpm_bytes(payload)))
        s = self.statuses(u)
        self.assertEqual(s["openssl.rpm!/payload!/payload.decompressed!/usr/lib64/libssl.so.3"], "leaf:elf")
        self.assertEqual(s["openssl.rpm!/payload!/payload.decompressed!/usr/lib64/libssl.so"], "skipped")

    def test_limits(self):
        big = fx.gz(b"\x00" * 200_000)
        u = self.unpack(self.write("bomb.gz", big), limits=unpack.Limits(max_total_bytes=100_000))
        self.assertEqual(self.statuses(u)["bomb.gz"], "unpack-failed")
        deep = b"x"
        for _ in range(4):
            deep = fx.gz(deep)
        u = self.unpack(self.write("deep.gz", deep), limits=unpack.Limits(max_depth=2))
        self.assertIn("unpack-failed", self.statuses(u).values())

    def test_missing_external_tool(self):
        u = self.unpack(self.write("setup.cab", b"MSCF" + b"\x00" * 60))
        entry = u.entries[0]
        self.assertEqual((entry["status"], entry["type"]), ("tool-missing", "cab"))
        self.assertIn("unblob, 7z", entry["reason"])


class InventoryTests(Workspace):
    def test_cli_writes_valid_inventory(self):
        artifact = self.write("app.zip", fx.zip_bytes({"lib/a.jar": fx.zip_bytes({"A.class": fx.JAVA_CLASS}), "README": b"hi"}))
        out = self.dir / "inv.json"
        self.assertEqual(cli.main(["scan", str(artifact), "--output", str(out)]), 0)
        data = json.loads(out.read_text())
        self.assertEqual(data["target"]["sha256"], inventory.sha256(artifact))
        self.assertFalse(data["coverage"]["complete"])  # leaves are unidentified until identifiers exist
        self.assertEqual(inventory.summary(data), {"unpacked": 2, "unidentified": 2})
        if not SECDEPTH_INVENTORY.exists():
            self.skipTest("secdepth checkout not found next to secpeel")
        spec = importlib.util.spec_from_file_location("secdepth_inventory", SECDEPTH_INVENTORY)
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        self.assertEqual(validator.validate(data), [])


if __name__ == "__main__":
    unittest.main()
