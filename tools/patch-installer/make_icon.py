"""Extract the icon group from a PE executable into a standalone .ico file.

Usage: python3 make_icon.py <game.exe> <out.ico>
Keeps every size present in the RT_GROUP_ICON so Explorer picks the best one.
"""
import struct
import sys


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def rva_to_off(sections, rva):
    for va, vsz, raw, rsz in sections:
        if va <= rva < va + max(vsz, rsz):
            return raw + (rva - va)
    raise ValueError("RVA %x not in any section" % rva)


def parse_sections(data):
    e_lfanew = u32(data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("not a PE file")
    coff = e_lfanew + 4
    nsec = u16(data, coff + 2)
    optsz = u16(data, coff + 16)
    opt = coff + 20
    magic = u16(data, opt)
    if magic != 0x10B:
        raise ValueError("not PE32")
    res_rva = u32(data, opt + 96 + 8 * 2)
    res_size = u32(data, opt + 96 + 8 * 2 + 4)
    sec = opt + optsz
    sections = []
    for i in range(nsec):
        s = sec + i * 40
        vsz, va, rsz, raw = u32(data, s + 8), u32(data, s + 12), u32(data, s + 16), u32(data, s + 20)
        sections.append((va, vsz, raw, rsz))
    return sections, res_rva, res_size


def walk_dir(data, base, off, path, out):
    """Collect (type, name, lang, entry_offset) leaves of the resource tree."""
    named, ids = u16(data, off + 12), u16(data, off + 14)
    for i in range(named + ids):
        e = off + 16 + i * 8
        name = u32(data, e)
        target = u32(data, e + 4)
        level = len(path)
        if level < 2:
            if name & 0x80000000:
                key = ("named", name & 0x7FFFFFFF)
            else:
                key = ("id", name)
            walk_dir(data, base, base + (target & 0x7FFFFFFF), path + [key], out)
        else:
            off_leaf = base + target
            rva = u32(data, off_leaf)
            size = u32(data, off_leaf + 4)
            out.append((tuple(path), rva, size))


def extract(exe, out_ico):
    data = open(exe, "rb").read()
    sections, res_rva, res_size = parse_sections(data)
    if not res_rva:
        raise ValueError("no resource directory")
    base = rva_to_off(sections, res_rva)
    leaves = []
    walk_dir(data, base, base, [], leaves)

    groups = [l for l in leaves if l[0][0] == ("id", 14)]
    if not groups:
        raise ValueError("no RT_GROUP_ICON")
    # Prefer the smallest group id (Explorer convention).
    path, rva, size = sorted(groups, key=lambda l: l[0][1][1])[0]
    g = data[rva_to_off(sections, rva):rva_to_off(sections, rva) + size]
    count = u16(g, 4)
    icons = {}
    for l in leaves:
        if l[0][0] == ("id", 3):
            icons.setdefault(l[0][1][1], []).append(l)

    entries, blobs = [], []
    offset = 6 + 16 * count
    for i in range(count):
        e = 6 + 14 * i
        w, h, cc, res, planes, bits = struct.unpack_from("<BBBBHH", g, e)
        size_i, icon_id = u32(g, e + 8), u16(g, e + 12)
        cands = icons.get(icon_id)
        if not cands:
            raise ValueError("missing RT_ICON %d" % icon_id)
        lpath, lrva, lsize = cands[0]
        blob = data[rva_to_off(sections, lrva):rva_to_off(sections, lrva) + lsize]
        entries.append(struct.pack("<BBBBHHII", w, h, cc, res, planes, bits, len(blob), offset))
        blobs.append(blob)
        offset += len(blob)

    with open(out_ico, "wb") as f:
        f.write(struct.pack("<HHH", 0, 1, count))
        f.write(b"".join(entries))
        f.write(b"".join(blobs))
    print(out_ico, count, "sizes")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    extract(sys.argv[1], sys.argv[2])
