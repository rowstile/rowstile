#!/usr/bin/env python3
"""Each platform package (`npm pack` of packaging/npm/out/cli-*), checked as far as Linux can check it. The
Linux ones are started too (packaging/test.sh); the macOS and Windows ones can't be, here or on Linux CI runners,
so their archive is read instead:

  - the Python its package.json names is there, executable, and built for the package's system and CPU (ELF:
    the machine and the C library's loader; Mach-O: the CPU; PE: x64);
  - every library a binary in it loads is in the package, or is one the system has (glibc's, musl's, macOS's
    /usr/lib and /System, Windows' own DLLs): what trim() removes, and a new python-build-standalone release
    needs, shows here;
  - the standard library modules the command imports are there, with those they import unconditionally: as a
    file, a compiled module beside them, or built into the binary (on Windows, in its table of built-in modules;
    elsewhere, with its init function).

    python3 packaging/npm/platforms.py packaging/out/rowstile-cli-*.tgz

Run on the Python the packages bring (packaging/test.sh runs it in python:3.13), which reads their standard
library's syntax. Standard library only.
"""

from __future__ import annotations

import ast
import json
import os
import re
import struct
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))

# (ELF machine, the loader the binary names) for each Linux target
ELF = {
    ("x64", "glibc"): (62, "/lib64/ld-linux-x86-64.so.2"),
    ("arm64", "glibc"): (183, "/lib/ld-linux-aarch64.so.1"),
    ("x64", "musl"): (62, "/lib/ld-musl-x86_64.so.1"),
    ("arm64", "musl"): (183, "/lib/ld-musl-aarch64.so.1"),
}
MACHO_CPU = {"x64": 0x01000007, "arm64": 0x0100000C}
PE_MACHINE = {"x64": 0x8664}
# the libraries each system has: anything else a binary loads must be in the package
SYSTEM = {
    "glibc": {"libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "libutil.so.1", "librt.so.1"}
    | {"ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1"},
    "musl": {"libc.so"},
    "win32": {
        "advapi32.dll",
        "bcrypt.dll",
        "crypt32.dll",
        "iphlpapi.dll",
        "kernel32.dll",
        "msvcrt.dll",
        "ole32.dll",
        "oleaut32.dll",
        "propsys.dll",
        "rpcrt4.dll",
        "user32.dll",
        "version.dll",
        "winmm.dll",
        "ws2_32.dll",
    },
}
# modules only one kind of system has (the command imports them behind a check of the platform)
ONLY = {"win32": {"msvcrt", "winreg", "_winapi", "nt"}, "posix": {"pwd", "grp", "fcntl", "termios", "resource"}}
# compiled modules the command needs that the standard library imports inside a try (which the walk below doesn't
# follow): OpenSSL's hashes (hashlib.pbkdf2_hmac, for SCRAM, has no fallback)
NEEDED = ["_hashlib"]


def elf(data: bytes) -> tuple[int, str | None, list[str]]:
    """(machine, the loader it names, the libraries it needs) of a 64-bit little-endian ELF file."""
    if data[4:6] != b"\x02\x01":
        raise ValueError("not a 64-bit little-endian ELF file")
    machine = struct.unpack_from("<H", data, 18)[0]
    phoff, shoff = struct.unpack_from("<QQ", data, 32)
    phentsize, phnum, shentsize, shnum = struct.unpack_from("<HHHH", data, 54)
    interp = None
    for i in range(phnum):
        p_type, _, p_offset, _, _, p_filesz = struct.unpack_from("<IIQQQQ", data, phoff + i * phentsize)
        if p_type == 3:  # PT_INTERP
            interp = data[p_offset : p_offset + p_filesz].split(b"\0")[0].decode()
    sections = [struct.unpack_from("<IIQQQQII", data, shoff + i * shentsize) for i in range(shnum)]
    needed: list[str] = []
    for _, sh_type, _, _, offset, size, link, _ in sections:
        if sh_type != 6:  # SHT_DYNAMIC
            continue
        strtab = sections[link][4]
        for at in range(offset, offset + size, 16):
            tag, value = struct.unpack_from("<qQ", data, at)
            if tag == 0:
                break
            if tag == 1:  # DT_NEEDED
                needed.append(data[strtab + value :].split(b"\0", 1)[0].decode())
    return machine, interp, needed


def macho(data: bytes) -> tuple[int, list[str]]:
    """(CPU type, the libraries it needs, weak ones aside) of a 64-bit Mach-O file."""
    if struct.unpack_from("<I", data, 0)[0] != 0xFEEDFACF:
        raise ValueError("not a 64-bit Mach-O file")
    cpu, _, _, ncmds = struct.unpack_from("<iiII", data, 4)
    needed: list[str] = []
    at = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, at)
        # LC_LOAD_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB (not LC_LOAD_WEAK_DYLIB: it may be missing)
        if cmd in (0xC, 0x8000001F, 0x80000023):
            name = struct.unpack_from("<I", data, at + 8)[0]
            needed.append(data[at + name : at + size].split(b"\0", 1)[0].decode())
        at += size
    return cpu, needed


def pe(data: bytes) -> tuple[int, list[str]]:
    """(machine, the DLLs it imports) of a PE file (an .exe, .dll or .pyd)."""
    if data[:2] != b"MZ":
        raise ValueError("not a PE file")
    head = struct.unpack_from("<I", data, 0x3C)[0]
    if data[head : head + 4] != b"PE\0\0":
        raise ValueError("not a PE file")
    machine, nsections = struct.unpack_from("<HH", data, head + 4)
    optional_size = struct.unpack_from("<H", data, head + 20)[0]
    optional = head + 24
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise ValueError("not a 64-bit PE file")
    imports = struct.unpack_from("<I", data, optional + 112 + 8)[0]  # data directory 1: the import table
    table = optional + optional_size
    sections = [struct.unpack_from("<IIII", data, table + i * 40 + 8) for i in range(nsections)]

    def offset(rva: int) -> int:
        for vsize, vaddr, rawsize, rawptr in sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                return rawptr + rva - vaddr
        raise ValueError(f"no section holds {rva:#x}")

    needed: list[str] = []
    if imports:
        at = offset(imports)
        while True:
            name = struct.unpack_from("<5I", data, at)[3]
            if not name:
                break
            needed.append(data[offset(name) :].split(b"\0", 1)[0].decode())
            at += 20
    return machine, needed


def inittab(data: bytes, name: str) -> bool:
    """Whether a Windows Python's DLL builds the module in: its table of them (CPython's PC/config.c) holds a
    pointer to the name, then one to the module's init function, in code. The name alone is in every Python
    (sys.stdlib_module_names)."""
    head = struct.unpack_from("<I", data, 0x3C)[0]
    nsections, optional_size = struct.unpack_from("<H", data, head + 6)[0], struct.unpack_from("<H", data, head + 20)[0]
    base = struct.unpack_from("<Q", data, head + 24 + 24)[0]
    sections = [struct.unpack_from("<IIII12xI", data, head + 24 + optional_size + i * 40 + 8) for i in range(nsections)]
    code = [(vaddr, vaddr + vsize) for vsize, vaddr, _, _, flags in sections if flags & 0x20000000]  # executable
    for found in re.finditer(re.escape(b"\0" + name.encode() + b"\0"), data):
        at = found.start() + 1
        rva = next(
            (vaddr + at - rawptr for _, vaddr, size, rawptr, _ in sections if rawptr <= at < rawptr + size), None
        )
        if rva is None:
            continue
        for ref in re.finditer(re.escape(struct.pack("<Q", base + rva)), data):
            init = struct.unpack_from("<Q", data, ref.end())[0] - base
            if any(start <= init < end for start, end in code):
                return True
    return False


def binary(data: bytes) -> str | None:
    """The kind of a file that is a binary (elf, macho, pe), or None."""
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] == b"\xcf\xfa\xed\xfe":
        return "macho"
    if data[:2] == b"MZ":
        return "pe"
    return None


def imports(tree: ast.Module, name: str, package: bool, everywhere: bool) -> tuple[set[str], set[str]]:
    """The absolute names of the modules a module imports: all of them, or only its unconditional ones (at the
    top of the module: not in a function, an if or a try). Then the names `from package import name` takes,
    which may be modules of the package or not."""
    nodes = ast.walk(tree) if everywhere else iter(tree.body)
    sure: set[str] = set()
    maybe: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            sure.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = name.split(".") if package else name.split(".")[:-1]
                parts = parts[: len(parts) - node.level + 1]
                base = ".".join(parts + ([node.module] if node.module else []))
            sure.add(base)
            maybe.update(f"{base}.{a.name}" for a in node.names if a.name != "*")
    return {m for m in sure if m}, maybe


def command_imports() -> set[str]:
    """The standard library modules the command's own modules import, anywhere."""
    out: set[str] = set()
    for folder in ("authzlib", "cli"):
        path = os.path.join(ROOT, "core", folder)
        for f in sorted(os.listdir(path)):
            if f.endswith(".py"):
                with open(os.path.join(path, f), encoding="utf-8") as fh:
                    found, _ = imports(ast.parse(fh.read()), f"{folder}.{f[:-3]}", False, True)
                out.update(m for m in found if m.split(".")[0] in sys.stdlib_module_names)
    with open(os.path.join(HERE, "rowstile", "bin", "rowstile.js"), encoding="utf-8") as fh:
        probe = re.search(r'const probe = "import ([\w, ]+)"', fh.read())
    if not probe:
        raise SystemExit("platforms.py: no probe of compiled modules in rowstile.js")
    return out | {m.strip() for m in probe.group(1).split(",")} | set(NEEDED)


def check(path: str, wanted: set[str]) -> list[str]:
    """What is wrong with one platform package: nothing, or a sentence each."""
    files: dict[str, bytes] = {}
    executable: set[str] = set()
    with tarfile.open(path) as tar:
        for member in tar:  # in the archive's order: a gzip stream is read once
            got = tar.extractfile(member) if member.isfile() else None
            if got is not None:
                files[member.name.removeprefix("package/")] = got.read()
                if member.mode & 0o111:
                    executable.add(member.name.removeprefix("package/"))
    pkg = json.loads(files["package.json"])
    name, system, cpu = pkg["name"], pkg["os"][0], pkg["cpu"][0]
    libc = pkg.get("libc", [None])[0]
    exe = pkg["rowstilePython"]
    if exe not in files:
        return [f"{name}: its Python, {exe}, isn't in the package"]
    problems: list[str] = []
    if system != "win32" and exe not in executable:
        problems.append(f"{name}: {exe} isn't executable")
    try:
        if system == "linux":
            machine, interp, _ = elf(files[exe])
            if (machine, interp) != ELF[(cpu, libc)]:
                problems.append(f"{name}: {exe} is for machine {machine} with {interp}, not {cpu} with {libc}")
        elif system == "darwin":
            if macho(files[exe])[0] != MACHO_CPU[cpu]:
                problems.append(f"{name}: {exe} is for CPU {macho(files[exe])[0]:#x}, not {cpu}")
        elif pe(files[exe])[0] != PE_MACHINE[cpu]:
            problems.append(f"{name}: {exe} is for machine {pe(files[exe])[0]:#x}, not {cpu}")
    except ValueError as e:
        problems.append(f"{name}: {exe}: {e}")

    # every library each binary loads: in the package, or the system's
    here = {os.path.basename(f).lower() for f in files}
    for f, data in sorted(files.items()):
        kind = binary(data)
        if kind is None:
            continue
        try:
            needed = elf(data)[2] if kind == "elf" else macho(data)[1] if kind == "macho" else pe(data)[1]
        except ValueError as e:
            problems.append(f"{name}: {f}: {e}")
            continue
        for lib in needed:
            if system == "darwin" and lib.startswith(("/usr/lib/", "/System/Library/")):
                continue
            low = os.path.basename(lib).lower()
            if low in here or low in SYSTEM.get(libc or system, set()) or low.startswith("api-ms-win-"):
                continue
            problems.append(f"{name}: {f} loads {lib}, which isn't in the package")

    # the standard library modules the command imports, and what they import unconditionally
    lib = "python/Lib" if system == "win32" else next(os.path.dirname(f) for f in files if f.endswith("/os.py"))
    folder = "python/DLLs/" if system == "win32" else f"{lib}/lib-dynload/"
    compiled = {f[len(folder) :].split(".")[0] for f in files if f.startswith(folder) and f.endswith((".so", ".pyd"))}
    main = files[next((f for f in files if re.fullmatch(r"python/python3\d+\.dll", f)), exe)]

    def built_in(module: str) -> bool:
        """Whether the binary builds the module in: on Windows, its table of them; elsewhere, its init function
        (PyInit_<module>, a symbol the binary exports for compiled modules to link against)."""
        if module in ("sys", "builtins", "marshal", "_warnings"):
            return True  # the interpreter's own (Python/, not Modules/), with init functions of other names
        return inittab(main, module) if system == "win32" else f"PyInit_{module}\0".encode() in main

    skip = ONLY["posix" if system == "win32" else "win32"]

    def find(module: str) -> str | None:
        """Where a module is: its source, `compiled`, `built-in`, or None."""
        rel = module.replace(".", "/")
        for f in (f"{lib}/{rel}.py", f"{lib}/{rel}/__init__.py"):
            if f in files:
                return f
        if module in compiled:
            return "compiled"
        return "built-in" if "." not in module and built_in(module) else None

    todo = [(m, True) for m in sorted(wanted)]
    seen: set[str] = set()
    while todo:
        module, sure = todo.pop()
        if module in seen or module.split(".")[0] in skip:
            continue
        seen.add(module)
        where = find(module)
        if where is None:
            if not sure:
                continue  # `from package import name`: a name of the package, not a module
            parent = find(module.rpartition(".")[0]) if "." in module else None
            # os.path: an attribute of a module that isn't a package; collections.abc: a name its package puts
            # in sys.modules
            if (
                parent
                and parent.endswith(".py")
                and (not parent.endswith("__init__.py") or f"sys.modules['{module}']" in files[parent].decode())
            ):
                continue
            problems.append(f"{name}: no module {module} (the command imports it, or a module it imports does)")
            continue
        if "." in module:
            todo.append((module.rpartition(".")[0], True))  # its package, imported first
        if where.endswith(".py"):
            found, maybe = imports(ast.parse(files[where], where), module, where.endswith("__init__.py"), False)
            todo.extend([(m, True) for m in sorted(found)] + [(m, False) for m in sorted(maybe)])
    return problems


def main() -> int:
    paths = sys.argv[1:]
    if not paths:
        print("usage: python3 packaging/npm/platforms.py packaging/out/rowstile-cli-*.tgz", file=sys.stderr)
        return 2
    wanted = command_imports()
    problems = [p for path in paths for p in check(path, wanted)]
    for p in problems:
        print(p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
