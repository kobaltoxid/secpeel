"""Detect file types by content (magic bytes), never by file name."""
import struct

HEAD_BYTES = 65536

# Kinds the standard library can unpack, and the external tools that can open the rest.
STDLIB_CONTAINERS = {"zip", "gzip", "bzip2", "xz", "zstd", "tar", "ar", "cpio-newc", "cpio-odc", "rpm"}
EXTERNAL_CONTAINERS = {
    "squashfs": ["unblob", "7z"],
    "iso9660": ["unblob", "7z"],
    "ole": ["unblob", "7z"],          # MSI installers and other compound files
    "cab": ["unblob", "7z"],
    "7z": ["unblob", "7z"],
    "rar": ["unblob", "7z"],
}


def detect(path):
    """Return a short kind string such as 'zip', 'elf' or 'data'."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(HEAD_BYTES)
    except OSError:
        return "unreadable"
    return detect_bytes(head)


def detect_bytes(head):
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh"):
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if head.startswith(b"!<arch>\n"):
        return "ar"
    if head.startswith((b"070701", b"070702")):
        return "cpio-newc"
    if head.startswith(b"070707"):
        return "cpio-odc"
    if head.startswith(b"\xed\xab\xee\xdb"):
        return "rpm"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "tar"
    if head.startswith((b"hsqs", b"sqsh")):
        return "squashfs"
    if len(head) > 0x8006 and head[0x8001:0x8006] == b"CD001":
        return "iso9660"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"MSCF"):
        return "cab"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"MZ"):
        return "pe"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if head.startswith(b"\xca\xfe\xba\xbe") and len(head) >= 8:
        # Fat Mach-O stores a small architecture count here; a Java class stores minor/major version >= 45.
        return "macho-fat" if struct.unpack(">I", head[4:8])[0] < 45 else "java-class"
    if _looks_textual(head):
        return "text"
    return "data"


def _looks_textual(head):
    sample = head[:4096]
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError as exc:
        # The sample may end inside a multi-byte character; only earlier errors mean binary data.
        return exc.start >= len(sample) - 3 and exc.reason == "unexpected end of data"


def is_container(kind):
    return kind in STDLIB_CONTAINERS or kind in EXTERNAL_CONTAINERS
