import json
import pathlib
import struct
import sys
import tempfile
import unittest
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from secpeel import identify, native, unpack  # noqa: E402
import fixtures as fx  # noqa: E402


def elf_with_section(name, content):
    """Minimal little-endian ELF64 with a null section, .shstrtab and one named section."""
    shstrtab = b"\x00.shstrtab\x00" + name + b"\x00"
    header_size, shentsize = 64, 64
    data_off = header_size
    strtab_off = data_off + len(content)
    shoff = strtab_off + len(shstrtab)
    header = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0, 0, shoff, 0,
                                                                     header_size, 0, 0, shentsize, 3, 1)
    def sh(name_off, offset, size):
        return struct.pack("<IIQQQQIIQQ", name_off, 1, 0, 0, offset, size, 0, 0, 1, 0)
    sections = sh(0, 0, 0) + sh(1, strtab_off, len(shstrtab)) + sh(11, data_off, len(content))
    return header + content + shstrtab + sections


def pe_with_version(product, version, company="Example Corp"):
    """Version strings with values on absolute 32-bit boundaries, as in real PE resources."""
    out = bytearray(b"MZ" + b"\x00" * 62 + "VS_VERSION_INFO".encode("utf-16-le") + b"\x00" * 6)
    for key, value in (("CompanyName", company), ("ProductName", product), ("ProductVersion", version)):
        out += key.encode("utf-16-le") + b"\x00\x00"
        out += b"\x00" * ((-len(out)) % 4)
        out += value.encode("utf-16-le") + b"\x00\x00"
        out += b"\x00" * ((-len(out)) % 4)
    return bytes(out)


class NativeTests(unittest.TestCase):
    def scan(self, members):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = pathlib.Path(tmp.name) / "a.tar"
        path.write_bytes(fx.tar_bytes(members))
        leaves = unpack.Unpacker(pathlib.Path(tmp.name) / "w", which=lambda _n: None).run(path).leaves
        return identify.identify(leaves)

    def test_version_strings(self):
        result = self.scan({
            "lib/libcrypto.so.3": fx.ELF + b"\x00OpenSSL 3.0.11 19 Sep 2023\x00",
            "lib/libz.so.1": fx.ELF + b"\x00 deflate 1.2.13 Copyright 1995-2022 Jean-loup Gailly and Mark Adler \x00",
            "bin/busybox": fx.ELF + b"\x00BusyBox v1.36.1 (2023-07-01) multi-call binary\x00",
            "lib/libsqlite3.so": fx.ELF + b"\x002023-10-10 12:14:04 4310099cce5a487035fa535dd3002c59ac7f1d1b\x00\x003.43.2\x00",
        })
        ids = set(result.components)
        for cid in ("native:openssl@3.0.11", "native:zlib@1.2.13", "native:busybox@1.36.1", "native:sqlite@3.43.2"):
            self.assertIn(cid, ids)
        self.assertEqual(result.components["native:openssl@3.0.11"]["cpe"], "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*")
        self.assertEqual(result.components["native:sqlite@3.43.2"]["evidence"][0]["confidence"], "medium")

    def test_linking_to_a_library_is_not_bundling_it(self):
        result = self.scan({"bin/app": fx.ELF + b"\x00libssl.so.3\x00OpenSSL_init_ssl\x00"})
        self.assertEqual(result.components, {})

    def test_distribution_package_takes_precedence(self):
        layer = {
            "etc/os-release": b'ID=debian\nVERSION_ID="12"\n',
            "var/lib/dpkg/status": b"Package: libssl3\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.11-1~deb12u2\n",
            "usr/lib/libssl.so.3": fx.ELF + b"\x00OpenSSL 3.0.11 19 Sep 2023\x00",
        }
        result = self.scan(layer)
        self.assertNotIn("native:openssl@3.0.11", result.components)
        libssl = next(p for p in result.identified if p.endswith("libssl.so.3"))
        self.assertEqual(result.identified[libssl], "Debian:openssl@3.0.11-1~deb12u2")

    def test_pe_version_resource(self):
        result = self.scan({"setup.exe": pe_with_version("Widget Tool", "2.4.1.0")})
        widget = result.components["native:Widget Tool@2.4.1.0"]
        self.assertIn("Example Corp", widget["evidence"][0]["detail"])

    def test_cargo_auditable(self):
        deps = {"packages": [{"name": "tokio", "version": "1.28.0", "source": "crates.io"},
                             {"name": "app", "version": "0.1.0", "source": "local"}]}
        binary = elf_with_section(b".dep-v0", zlib.compress(json.dumps(deps).encode()))
        self.assertIsNotNone(native.elf_section(binary, b".dep-v0"))
        result = self.scan({"bin/app": binary})
        self.assertIn("crates.io:tokio@1.28.0", result.components)
        self.assertNotIn("crates.io:app@0.1.0", result.components)


if __name__ == "__main__":
    unittest.main()
