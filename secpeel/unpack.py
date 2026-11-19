"""Unpack an artifact recursively and record what happened to every file.

Containers are unpacked into a scratch directory. Every file ends up in exactly one place: a
container that was unpacked, a member that was skipped or failed, or a leaf for the identifiers.
Nothing is dropped silently.
"""
import bz2
import collections
import gzip
import lzma
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import zipfile

from . import filetypes

try:
    from compression import zstd  # Python 3.14+
except ImportError:  # pragma: no cover - depends on the interpreter
    zstd = None

CHUNK = 1 << 20
DECOMPRESSED_SUFFIXES = {".gz": "", ".tgz": ".tar", ".bz2": "", ".tbz2": ".tar", ".xz": "", ".txz": ".tar", ".zst": ""}


class UnpackError(Exception):
    """The container could not be unpacked; the message is the reason recorded in the ledger."""


class ToolMissing(Exception):
    """An optional external tool is needed for this container but none is installed."""


class Limits:
    def __init__(self, max_depth=12, max_total_bytes=4 << 30, max_files=200_000):
        self.max_depth = max_depth
        self.max_total_bytes = max_total_bytes
        self.max_files = max_files


class Unpacker:
    def __init__(self, workdir, limits=None, which=shutil.which):
        self.workdir = pathlib.Path(workdir)
        self.limits = limits or Limits()
        self.which = which
        self.total_bytes = 0
        self.file_count = 0
        self.counter = 0
        self.entries = []   # ledger entries for containers and member problems
        self.leaves = []    # files for the identifiers: {"path", "real", "type", "size"}
        self.tools_used = set()

    # --- public -----------------------------------------------------------------------------

    def run(self, artifact):
        artifact = pathlib.Path(artifact)
        # A fresh folder per run, so a reused scratch directory never mixes or collides with earlier runs.
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.workdir = pathlib.Path(tempfile.mkdtemp(prefix="run-", dir=self.workdir))
        queue = collections.deque([(artifact, artifact.name, 0)])
        while queue:
            real, virtual, depth = queue.popleft()
            kind = filetypes.detect(real)
            size = real.stat().st_size if real.exists() else None
            if not filetypes.is_container(kind):
                self.leaves.append({"path": virtual, "real": real, "type": kind, "size": size})
                continue
            if depth >= self.limits.max_depth:
                self._entry(virtual, "unpack-failed", "nesting deeper than %d levels" % self.limits.max_depth, kind, size)
                continue
            self.counter += 1
            out = self.workdir / ("%06d" % self.counter)
            out.mkdir(parents=True)
            try:
                children = self._unpack(kind, real, out, virtual)
            except ToolMissing as exc:
                self._entry(virtual, "tool-missing", str(exc), kind, size)
                continue
            except (UnpackError, OSError, EOFError, ValueError, zipfile.BadZipFile, tarfile.TarError, lzma.LZMAError) as exc:
                self._entry(virtual, "unpack-failed", str(exc) or exc.__class__.__name__, kind, size)
                continue
            self._entry(virtual, "unpacked", "%d members" % len(children), kind, size)
            for child_real, member in children:
                queue.append((child_real, "%s!/%s" % (virtual, member), depth + 1))
        return self

    # --- helpers ------------------------------------------------------------------------------

    def _entry(self, path, status, reason, kind=None, size=None):
        self.entries.append({"path": _clean(path), "status": status, "reason": reason, "type": kind, "size": size})

    def _safe_target(self, out, member):
        parts = [p for p in member.replace("\\", "/").split("/") if p not in ("", ".")]
        if not parts or ".." in parts or member.startswith(("/", "\\")) or ":" in parts[0]:
            raise UnpackError("unsafe member path %r" % member)
        # Archives may hold names that are not valid UTF-8; escape them on disk, keep them in the ledger.
        return out.joinpath(*(p.encode("utf-8", "backslashreplace").decode("utf-8") for p in parts))

    def _reserve(self, size, virtual):
        if self.file_count + 1 > self.limits.max_files:
            raise UnpackError("more than %d files in total" % self.limits.max_files)
        if size is not None and self.total_bytes + size > self.limits.max_total_bytes:
            raise UnpackError("extracting %s would exceed the %d-byte limit" % (virtual, self.limits.max_total_bytes))

    def _copy(self, src, dest, virtual):
        """Stream src into dest while enforcing the total size budget."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        self._reserve(0, virtual)
        written = 0
        with open(dest, "wb") as fh:
            while True:
                block = src.read(CHUNK)
                if not block:
                    break
                written += len(block)
                if self.total_bytes + written > self.limits.max_total_bytes:
                    raise UnpackError("decompressed size exceeds the %d-byte limit" % self.limits.max_total_bytes)
                fh.write(block)
        self.total_bytes += written
        self.file_count += 1
        return dest

    def _member(self, out, virtual, member, opener, size=None, children=None):
        """Extract one member, recording unsafe paths and limit hits against the member itself."""
        try:
            target = self._safe_target(out, member)
            self._reserve(size, virtual)
            with opener() as src:
                children.append((self._copy(src, target, virtual), target.relative_to(out).as_posix()))
        except UnpackError as exc:
            self._entry("%s!/%s" % (virtual, member), "unpack-failed", str(exc))
        except OSError as exc:
            # One unwritable or unreadable member must not fail the whole container.
            self._entry("%s!/%s" % (virtual, member), "unpack-failed", "%s: %s" % (exc.__class__.__name__, exc.strerror or exc))

    # --- formats ------------------------------------------------------------------------------

    def _unpack(self, kind, real, out, virtual):
        handler = getattr(self, "_unpack_" + kind.replace("-", "_"), None)
        if handler is not None:
            return handler(real, out, virtual)
        return self._unpack_external(kind, real, out, virtual)

    def _unpack_zip(self, real, out, virtual):
        children = []
        with zipfile.ZipFile(real) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    self._entry("%s!/%s" % (virtual, info.filename), "skipped", "symbolic link")
                    continue
                if info.flag_bits & 0x1:
                    self._entry("%s!/%s" % (virtual, info.filename), "unpack-failed", "encrypted member")
                    continue
                self._member(out, virtual, info.filename, lambda i=info: zf.open(i), info.file_size, children)
        return children

    def _single_stream(self, real, out, virtual, opener):
        name = pathlib.Path(virtual.rsplit("!/", 1)[-1]).name
        suffix = pathlib.Path(name).suffix.lower()
        stem = name[: -len(suffix)] + DECOMPRESSED_SUFFIXES[suffix] if suffix in DECOMPRESSED_SUFFIXES else name + ".decompressed"
        with opener(real) as src:
            return [(self._copy(src, out / stem, virtual), stem)]

    def _unpack_gzip(self, real, out, virtual):
        return self._single_stream(real, out, virtual, lambda p: gzip.open(p, "rb"))

    def _unpack_bzip2(self, real, out, virtual):
        return self._single_stream(real, out, virtual, lambda p: bz2.open(p, "rb"))

    def _unpack_xz(self, real, out, virtual):
        return self._single_stream(real, out, virtual, lambda p: lzma.open(p, "rb"))

    def _unpack_zstd(self, real, out, virtual):
        if zstd is None:
            if self.which("zstd"):
                return self._unpack_external("zstd", real, out, virtual)
            raise ToolMissing("zstd needs Python 3.14+ or the zstd command")
        return self._single_stream(real, out, virtual, lambda p: zstd.open(p, "rb"))

    def _unpack_tar(self, real, out, virtual):
        children = []
        with tarfile.open(real, "r:") as tf:
            for info in tf:
                if info.isdir():
                    continue
                member = info.name
                if info.issym() or info.islnk():
                    self._entry("%s!/%s" % (virtual, member), "skipped", "link to %s" % info.linkname)
                    continue
                if not info.isfile():
                    self._entry("%s!/%s" % (virtual, member), "skipped", "special file")
                    continue
                self._member(out, virtual, member, lambda i=info: tf.extractfile(i), info.size, children)
        return children

    def _unpack_ar(self, real, out, virtual):
        children, long_names = [], b""
        with open(real, "rb") as fh:
            fh.read(8)
            while True:
                header = fh.read(60)
                if not header:
                    break
                if len(header) < 60 or header[58:60] != b"`\n":
                    raise UnpackError("truncated or malformed ar header")
                name = header[:16].rstrip()
                size = int(header[48:58].strip() or 0)
                data_start = fh.tell()
                if name == b"//":
                    long_names = fh.read(size)
                elif name == b"/" or name == b"/SYM64/":
                    pass  # symbol table
                else:
                    if name.startswith(b"/") and long_names:
                        offset = int(name[1:])
                        name = long_names[offset:long_names.index(b"\n", offset)]
                    member = name.decode("utf-8", "replace").rstrip("/")
                    fh.seek(data_start)
                    self._member(out, virtual, member, lambda: _Limited(fh, size), size, children)
                fh.seek(data_start + size + (size % 2))
        return children

    def _unpack_cpio_newc(self, real, out, virtual):
        return self._cpio(real, out, virtual, newc=True)

    def _unpack_cpio_odc(self, real, out, virtual):
        return self._cpio(real, out, virtual, newc=False)

    def _cpio(self, real, out, virtual, newc):
        children = []
        header_len = 110 if newc else 76
        with open(real, "rb") as fh:
            while True:
                header = fh.read(header_len)
                if len(header) < header_len:
                    raise UnpackError("truncated cpio archive (no trailer)")
                if newc:
                    fields = [int(header[6 + 8 * i: 14 + 8 * i], 16) for i in range(13)]
                    mode, filesize, namesize = fields[1], fields[6], fields[11]
                else:
                    mode, namesize, filesize = int(header[18:24], 8), int(header[59:65], 8), int(header[65:76], 8)
                name = fh.read(namesize).rstrip(b"\x00").decode("utf-8", "replace")
                if newc:
                    fh.seek((-(header_len + namesize)) % 4, os.SEEK_CUR)
                if name == "TRAILER!!!":
                    break
                data_start = fh.tell()
                if stat.S_ISREG(mode):
                    self._member(out, virtual, name, lambda: _Limited(fh, filesize), filesize, children)
                elif stat.S_ISLNK(mode):
                    self._entry("%s!/%s" % (virtual, name), "skipped", "symbolic link")
                elif not stat.S_ISDIR(mode):
                    self._entry("%s!/%s" % (virtual, name), "skipped", "special file")
                fh.seek(data_start + filesize + ((-filesize) % 4 if newc else 0))
        return children

    def _unpack_rpm(self, real, out, virtual):
        """Skip the lead, signature and header; the payload is a compressed cpio archive."""
        with open(real, "rb") as fh:
            fh.seek(96)
            for padded in (True, False):
                magic = fh.read(16)
                if len(magic) < 16 or magic[:3] != b"\x8e\xad\xe8":
                    raise UnpackError("malformed rpm header")
                count, store = struct.unpack(">II", magic[8:16])
                skip = count * 16 + store
                if padded:
                    skip += (-skip) % 8
                fh.seek(skip, os.SEEK_CUR)
            return [(self._copy(fh, out / "payload", virtual), "payload")]

    def _unpack_external(self, kind, real, out, virtual):
        tools = filetypes.EXTERNAL_CONTAINERS.get(kind, []) + (["zstd"] if kind == "zstd" else [])
        for tool in tools:
            exe = self.which(tool)
            if not exe:
                continue
            if tool == "unblob":
                cmd = [exe, "--extract-dir", str(out), str(real)]
            elif tool == "7z":
                cmd = [exe, "x", "-y", "-snl-", "-o" + str(out), str(real)]
            else:
                cmd = [exe, "-d", "-q", "-o", str(out / pathlib.Path(real).stem), str(real)]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            if proc.returncode != 0:
                raise UnpackError("%s failed: %s" % (tool, (proc.stderr.strip().splitlines() or ["exit %d" % proc.returncode])[-1]))
            self.tools_used.add(tool)
            children = []
            for path in sorted(p for p in out.rglob("*") if p.is_file() and not p.is_symlink()):
                size = path.stat().st_size
                self._reserve(size, virtual)
                self.total_bytes += size
                self.file_count += 1
                children.append((path, path.relative_to(out).as_posix()))
            return children
        raise ToolMissing("%s needs one of: %s" % (kind, ", ".join(tools) or "an external extractor"))


def _clean(path):
    """Drop leading './' from each member segment so ledger paths look the same for every format."""
    return "!/".join(re.sub(r"^(\./)+", "", part) for part in path.split("!/"))


class _Limited:
    """Read at most `size` bytes from an open file, as a context manager for _member."""

    def __init__(self, fh, size):
        self.fh, self.remaining = fh, size

    def read(self, n=-1):
        if self.remaining <= 0:
            return b""
        n = self.remaining if n < 0 else min(n, self.remaining)
        data = self.fh.read(n)
        if len(data) < n and not data:
            raise UnpackError("archive ended inside a member")
        self.remaining -= len(data)
        return data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False
