import hashlib
import os
import re
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"MajiroArcV3.000\0"
HEADER = struct.Struct("<16sIII")
INDEX = struct.Struct("<QII")
MAX_NAMES = 64 * 1024 * 1024


class ValidationError(ValueError):
    pass


def safe_name(name):
    if not isinstance(name, str) or not name or len(name) > 1024:
        raise ValidationError("Invalid relative path")
    parts = name.replace("\\", "/").split("/")
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    reserved.update(f"{prefix}{i}" for prefix in ("COM", "LPT") for i in range(1, 10))
    for part in parts:
        if (not part or part in (".", "..") or part.endswith((".", " "))
                or any(ord(c) < 32 or c in '<>:"|?*' for c in part)
                or part.split(".", 1)[0].upper() in reserved
                or re.match(r"^(COM|LPT)[¹²³](?:\.|$)", part, re.I)):
            raise ValidationError(f"Unsafe relative path: {name!r}")
    return "/".join(parts)


def name_key(name):
    return safe_name(name).casefold()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def regular_file(path):
    path = Path(path)
    info = path.lstat()
    if not path.is_file() or path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValidationError(f"Expected an ordinary file: {path}")
    return info


@dataclass(frozen=True)
class Entry:
    name: str
    raw_name: bytes
    key: int
    offset: int
    size: int


class Archive:
    def __init__(self, path):
        self.path = Path(path)
        info = regular_file(self.path)
        self._stamp = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        with self.path.open("rb") as stream:
            header = stream.read(HEADER.size)
            if len(header) != HEADER.size:
                raise ValidationError("Truncated ARC header")
            magic, count, names_offset, data_offset = HEADER.unpack(header)
            if magic != MAGIC:
                raise ValidationError("Only Majiro ARC V3 is supported")
            if count > 1_000_000 or not HEADER.size + count * INDEX.size <= names_offset <= data_offset <= info.st_size:
                raise ValidationError("Invalid ARC index bounds")
            if data_offset - names_offset > MAX_NAMES:
                raise ValidationError("ARC filename table exceeds the supported limit")
            table = stream.read(count * INDEX.size)
            stream.seek(names_offset)
            names = stream.read(data_offset - names_offset)
        cursor = 0
        seen_names, seen_keys, spans, entries = set(), set(), [], []
        for key, offset, size in INDEX.iter_unpack(table):
            end = names.find(b"\0", cursor)
            if end < 0:
                raise ValidationError("Missing ARC filename terminator")
            raw = names[cursor:end]
            cursor = end + 1
            try:
                name = raw.decode("cp932", errors="strict")
            except UnicodeDecodeError as exc:
                raise ValidationError("Invalid CP932 ARC filename") from exc
            normalized = name_key(name)
            if normalized in seen_names or key in seen_keys:
                raise ValidationError("Duplicate ARC filename or hash")
            if offset < data_offset or offset > info.st_size or size > info.st_size - offset:
                raise ValidationError(f"ARC payload outside file: {name!r}")
            if size:
                spans.append((offset, offset + size))
            seen_names.add(normalized)
            seen_keys.add(key)
            entries.append(Entry(name, raw, key, offset, size))
        if any(names[cursor:]):
            raise ValidationError("Unexpected data after ARC filename table")
        spans.sort()
        if any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
            raise ValidationError("Overlapping ARC payloads")
        self.entries = tuple(entries)
        self.by_name = {name_key(entry.name): entry for entry in entries}
        self._check_unchanged()

    def _check_unchanged(self):
        info = regular_file(self.path)
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != self._stamp:
            raise ValidationError("ARC changed after indexing")

    def read(self, name):
        self._check_unchanged()
        entry = self.by_name[name_key(name)]
        with self.path.open("rb") as stream:
            stream.seek(entry.offset)
            data = stream.read(entry.size)
        self._check_unchanged()
        if len(data) != entry.size:
            raise ValidationError("Truncated ARC payload")
        return data

    def rebuild(self, replacements, output):
        output = Path(output)
        if output.exists() or output.is_symlink():
            raise ValidationError("ARC output must be a new file")
        normalized = {}
        for name, payload in replacements.items():
            key = name_key(name)
            if key in normalized or key not in self.by_name or not isinstance(payload, bytes):
                raise ValidationError("Unknown, duplicate or invalid replacement")
            normalized[key] = payload
        names = b"".join(entry.raw_name + b"\0" for entry in self.entries)
        names_offset = HEADER.size + len(self.entries) * INDEX.size
        cursor = data_offset = names_offset + len(names)
        table = []
        for entry in self.entries:
            payload = normalized.get(name_key(entry.name))
            size = entry.size if payload is None else len(payload)
            if cursor + size > 0xFFFFFFFF:
                raise ValidationError("ARC exceeds 32-bit offsets")
            table.append(INDEX.pack(entry.key, cursor, size))
            cursor += size
        self._check_unchanged()
        fd, temporary = tempfile.mkstemp(prefix=".kotoba-arc-", dir=output.parent)
        temporary = Path(temporary)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(HEADER.pack(MAGIC, len(self.entries), names_offset, data_offset))
                stream.write(b"".join(table))
                stream.write(names)
                for entry in self.entries:
                    key = name_key(entry.name)
                    stream.write(normalized[key] if key in normalized else self.read(entry.name))
                stream.flush()
                os.fsync(stream.fileno())
            rebuilt = Archive(temporary)
            for before, after in zip(self.entries, rebuilt.entries):
                expected = normalized.get(name_key(before.name))
                if expected is None:
                    expected = self.read(before.name)
                if (before.raw_name, before.key) != (after.raw_name, after.key) or rebuilt.read(after.name) != expected:
                    raise ValidationError("ARC rebuild verification failed")
            self._check_unchanged()
            os.link(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)
