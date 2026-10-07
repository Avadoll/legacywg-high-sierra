"""Inspect an x86_64 Mach-O without executing it or changing load commands."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import struct


def inspect(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe":
        raise ValueError("Expected little-endian 64-bit thin Mach-O")
    _, cpu, subtype, filetype, count, size, flags, reserved = struct.unpack_from("<8I", data)
    if cpu != 0x01000007 or 32 + size > len(data):
        raise ValueError("Not an x86_64 Mach-O or invalid command table")
    commands = []
    dylibs = []
    versions = []
    symbol_table = None
    offset = 32
    for _ in range(count):
        command, length = struct.unpack_from("<II", data, offset)
        if length < 8 or offset + length > 32 + size:
            raise ValueError("Invalid load command")
        commands.append(hex(command))
        if command in (0xc, 0x18 | 0x80000000, 0x1f | 0x80000000, 0x23 | 0x80000000):
            name_offset = struct.unpack_from("<I", data, offset + 8)[0]
            if name_offset >= length: raise ValueError("Invalid dylib name offset")
            dylibs.append(data[offset+name_offset:offset+length].split(b"\0", 1)[0].decode("utf-8"))
        if command == 0x32:
            platform, minimum, sdk, tools = struct.unpack_from("<4I", data, offset+8)
            versions.append({"command": "LC_BUILD_VERSION", "platform": platform, "minos": version(minimum), "sdk": version(sdk)})
        if command == 0x24:
            minimum, sdk = struct.unpack_from("<II", data, offset+8)
            versions.append({"command": "LC_VERSION_MIN_MACOSX", "minos": version(minimum), "sdk": version(sdk)})
        if command == 0x2:
            symbol_table = struct.unpack_from("<4I", data, offset+8)
        offset += length
    undefined = []
    if symbol_table:
        symbols, symbol_count, strings, string_size = symbol_table
        if symbols + symbol_count*16 > len(data) or strings + string_size > len(data):
            raise ValueError("Invalid symbol table")
        for i in range(symbol_count):
            name, symbol_type, section, description, value = struct.unpack_from("<IBBHQ", data, symbols+i*16)
            if symbol_type & 0x0e == 0 and name and name < string_size:
                undefined.append(data[strings+name:strings+string_size].split(b"\0", 1)[0].decode("utf-8"))
    forbidden = [name for name in dylibs if name.startswith(("/usr/local/", "/opt/homebrew/", "/opt/local/"))]
    if forbidden: raise ValueError("Non-system dynamic dependency detected")
    return {"file": path.name, "arch": "x86_64", "versions": versions, "dylibs": dylibs,
            "undefined_symbols": sorted(undefined), "load_commands": commands,
            "high_sierra_runtime": "NOT_RUN", "note": "Metadata does not prove OS compatibility."}


def version(value: int) -> str:
    return f"{value >> 16}.{(value >> 8) & 255}.{value & 255}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.binary), indent=2))
