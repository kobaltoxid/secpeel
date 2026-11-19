"""Build small archives for tests; nothing binary is committed to the repository."""
import gzip
import io
import lzma
import struct
import tarfile
import zipfile


def zip_bytes(members, encrypted=()):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    raw = bytearray(buf.getvalue())
    # zipfile cannot write encrypted members; set the "encrypted" flag bit in both headers instead.
    for name in encrypted:
        encoded = name.encode()
        for signature, flag_offset, name_offset in ((b"PK\x03\x04", 6, 30), (b"PK\x01\x02", 8, 46)):
            pos = raw.find(signature)
            while pos != -1:
                if raw[pos + name_offset: pos + name_offset + len(encoded)] == encoded:
                    raw[pos + flag_offset] |= 0x1
                pos = raw.find(signature, pos + 1)
    return bytes(raw)


def tar_bytes(members, symlinks=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for name, target in (symlinks or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
    return buf.getvalue()


def gz(data):
    return gzip.compress(data)


def xz(data):
    return lzma.compress(data)


def ar_bytes(members):
    out = bytearray(b"!<arch>\n")
    for name, data in members.items():
        header = "%-16s%-12d%-6d%-6d%-8s%-10d`\n" % (name + "/", 0, 0, 0, "100644", len(data))
        out += header.encode() + data + (b"\n" if len(data) % 2 else b"")
    return bytes(out)


def cpio_newc(members, symlinks=None):
    out = bytearray()

    def entry(name, data, mode):
        nonlocal out
        encoded = name.encode() + b"\x00"
        fields = [0, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
        out += b"070701" + "".join("%08x" % f for f in fields).encode() + encoded
        out += b"\x00" * ((-len(out)) % 4)
        out += data + b"\x00" * ((-len(data)) % 4)

    for name, data in members.items():
        entry(name, data, 0o100644)
    for name, target in (symlinks or {}).items():
        entry(name, target.encode(), 0o120777)
    entry("TRAILER!!!", b"", 0)
    return bytes(out)


def rpm_bytes(payload):
    """Minimal RPM: lead, empty signature and header structures, then the payload."""
    lead = b"\xed\xab\xee\xdb" + b"\x00" * 92
    empty_header = b"\x8e\xad\xe8\x01" + b"\x00" * 4 + struct.pack(">II", 0, 0)
    return lead + empty_header + empty_header + payload


ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57 + b"libz 1.2.11"
JAVA_CLASS = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 16
FAT_MACHO = b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\x00" * 16
