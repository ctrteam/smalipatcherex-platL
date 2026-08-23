"""SmaliPatcherEx CLI.

Converts a stock services.jar into a flashable Magisk module:
    jar -> extract dex -> baksmali -> regex patch smali -> smali assemble
    -> repack jar -> magisk zip

Requires Java 17 on PATH and network access the first time (downloads
baksmali/smali fat jars next to this script if missing).
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

from . import __version__
from .patch_definitions import ALL, BY_NAME, list_for_api
from .patch_engine import PatchEngine
from .magisk_builder import build as build_module

BAKSMALI_URL = "https://github.com/baksmali/smali/releases/download/3.0.9/baksmali-3.0.9-fat.jar"
SMALI_URL = "https://github.com/baksmali/smali/releases/download/3.0.9/smali-3.0.9-fat.jar"

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
BAKSMALI_JAR = os.path.join(TOOL_DIR, "baksmali.jar")
SMALI_JAR = os.path.join(TOOL_DIR, "smali.jar")

DEFAULT_OUTPUT = os.path.join(os.path.expanduser("~"), "Desktop", "SmaliPatcherEx_Output")



# helpers

def log(msg: str) -> None:
    print(msg, flush=True)


def run(cmd: str, args: list[str], workdir: str | None) -> tuple[int, str]:
    """Run a subprocess, streaming stderr to our log; return (code, stderr)."""
    proc = subprocess.Popen(
        [cmd, *args],
        cwd=workdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    err_chunks: list[str] = []
    assert proc.stderr is not None
    for line in proc.stderr:
        err_chunks.append(line)
        log("  " + line.rstrip())
    proc.wait()
    return proc.returncode, "".join(err_chunks)


def download(url: str, dest: str, label: str) -> None:
    if os.path.exists(dest):
        log(f"[✓] {label}.jar present")
        return
    log(f"[*] Downloading {label}.jar ...")
    tmp = dest + ".part"
    with urllib.request.urlopen(url, timeout=120) as resp, open(tmp, "wb") as fh:
        shutil.copyfileobj(resp, fh)
    os.replace(tmp, dest)
    size_kb = os.path.getsize(dest) // 1024
    log(f"[✓] {label}.jar ({size_kb} KB)")


def ensure_java() -> None:
    try:
        r = subprocess.run(["java", "-version"], capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("Java not found. Install Java 17+ and make sure 'java' is on PATH.")
    out = (r.stderr or "") + (r.stdout or "")
    if "version" not in out:
        sys.exit(f"Java check failed:\n{out.strip()}")
    first = out.strip().splitlines()[0]
    log(f"[✓] Java: {first}")


def ensure_tools() -> None:
    download(BAKSMALI_URL, BAKSMALI_JAR, "baksmali")
    download(SMALI_URL, SMALI_JAR, "smali")


def extract_dex(jar_path: str, out_dir: str) -> list[str]:
    """Pull every classes*.dex out of a jar; returns extracted file paths."""
    dex_re = re.compile(r"^classes\d*\.dex$")
    found: list[str] = []
    with zipfile.ZipFile(jar_path) as zf:
        for entry in zf.infolist():
            if dex_re.match(os.path.basename(entry.filename)):
                dest = os.path.join(out_dir, os.path.basename(entry.filename))
                with zf.open(entry) as src, open(dest, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                found.append(dest)
                log(f"  extracted: {entry.filename} ({entry.file_size // 1024} KB)")
    return found


def repack_jar(src: str, dex_map: dict[str, str], out_path: str) -> None:
    """Copy ``src`` to ``out_path`` replacing entries named in ``dex_map``."""
    tmp = out_path + ".tmp"
    with zipfile.ZipFile(src) as zin, \
         zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        for entry in zin.infolist():
            replacement = dex_map.get(entry.filename)
            if replacement is not None:
                zout.write(replacement, entry.filename)
                log(f"  replaced: {entry.filename}")
            else:
                with zin.open(entry) as f_in:
                    zout.writestr(entry, f_in.read())
    os.replace(tmp, out_path)
    size_kb = os.path.getsize(out_path) // 1024
    log(f"[✓] Repacked JAR ({size_kb} KB)")



# pipeline

def pipeline(jar_path: str, api: int, patches: list[str],
             output_dir: str, fingerprint: str) -> str:
    """Full decompile → patch → rebuild flow. Returns module zip path."""
    ensure_java()
    ensure_tools()

    work = tempfile.mkdtemp(prefix=f"smpx_")
    try:
        log("═" * 40)
        log(f" SmaliPatcherEx v{__version__} — API {api}")
        log("═" * 40)

        # -- extract 
        log("\n[1/4] Extracting DEX...")
        dex_dir = os.path.join(work, "dex")
        os.makedirs(dex_dir, exist_ok=True)
        dex_files = extract_dex(jar_path, dex_dir)
        if not dex_files:
            sys.exit("No classes.dex found inside services.jar!")

        # -- baksmali 
        log("\n[2/4] Disassembling...")
        roots: list[tuple[str, str, str]] = []  # (dex_name, dex_path, smali_dir)
        for dex in dex_files:
            stem = os.path.splitext(os.path.basename(dex))[0]  # e.g. classes2
            suffix = stem.replace("classes", "") or "1"
            smali_dir = os.path.join(work, f"smali_c{suffix}")
            os.makedirs(smali_dir, exist_ok=True)

            name = os.path.basename(dex)
            log(f"  baksmali ← {name} -> {os.path.basename(smali_dir)}")
            code, err = run(
                "java",
                ["-jar", BAKSMALI_JAR, "disassemble", "--api", str(api),
                 "--output", smali_dir, dex],
                work,
            )
            if code != 0:
                sys.exit(f"baksmali failed for {name}:\n{err}")

            n = sum(len(fs) for _, _, fs in os.walk(smali_dir) if fs)
            log(f"[✓] {name}: {n} smali files")
            roots.append((name, dex, smali_dir))

        # -- patch 
        log("\n[3/4] Patching smali...")
        applied: list[str] = []
        patched_dexes: set[str] = set()

        for dex_name, _dex_path, smali_dir in roots:
            log(f"[*] Scanning {dex_name} ...")
            engine = PatchEngine(smali_dir, api)
            engine.log = log
            results = engine.run_all(patches)
            here = sorted(r.patch.name for r in results.values() if r.applied)
            if here:
                applied.extend(here)
                patched_dexes.add(dex_name)
                log(f"[✓] {dex_name}: applied {', '.join(here)}")
            else:
                log(f"[-] {dex_name}: no matches")

        applied = list(dict.fromkeys(applied))  # dedupe, keep order
        if not applied:
            sys.exit(
                "No patches applied — target classes not found in this "
                "services.jar.\nMake sure the jar matches your device build."
            )

        # -- reassemble 
        log("\n[4/4] Recompiling...")
        rebuilt_dir = os.path.join(work, "rebuilt")
        os.makedirs(rebuilt_dir, exist_ok=True)

        dex_map: dict[str, str] = {}
        for dex_name, dex_path, smali_dir in roots:
            if dex_name in patched_dexes:
                out_dex = os.path.join(rebuilt_dir, dex_name)
                # NOTE: no --api flag on assemble; smali picks min required.
                log(f"  smali -> {dex_name}")
                code, err = run(
                    "java",
                    ["-jar", SMALI_JAR, "assemble", "--output", out_dex,
                     smali_dir],
                    work,
                )
                if code != 0:
                    sys.exit(f"smali recompile failed for {dex_name}:\n{err}")
                size_kb = os.path.getsize(out_dex) // 1024
                log(f"[✓] Recompiled {dex_name} ({size_kb} KB)")
            else:
                out_dex = dex_path
                log(f"[=] Keeping original {dex_name}")
            dex_map[dex_name] = out_dex

        patched_jar = os.path.join(work, "services.jar")
        repack_jar(jar_path, dex_map, patched_jar)

        os.makedirs(output_dir, exist_ok=True)
        out_jar = os.path.join(output_dir, "services.jar")
        shutil.copyfile(patched_jar, out_jar)

        mod_zip = build_module(out_jar, output_dir, fingerprint, applied, log=log)
        return mod_zip
    finally:
        shutil.rmtree(work, ignore_errors=True)


# CLI

def cmd_list(args: argparse.Namespace) -> None:
    print(f"Patches available (API target: {args.api}):\n" if args.api
          else "Patches available:\n")
    for p in ALL:
        if args.api is None:
            mark = " "
        else:
            mark = "*" if p.android_min <= args.api <= p.android_max else "x"
        rng = f"A{p.android_min}-A{p.android_max}"
        print(f" [{mark}] {p.name:<32} {rng:<10} {p.description}")
    if args.api is not None:
        print("\n[*] applies at this API level   [x] out of range")


BANNER = r"""
  ___            _ _ ___      _      _            ___      __   _____ 
 / __|_ __  __ _| (_) _ \__ _| |_ __| |_  ___ _ _| __|_ __ \ \ / /_  )
 \__ \ '  \/ _` | | |  _/ _` |  _/ _| ' \/ -_) '_| _|\ \ /  \ V / / / 
 |___/_|_|_\__,_|_|_|_| \__,_|\__\__|_||_\___|_| |___/_\_\   \_/ /___|

 By mfajarb
                                                                      
"""


def print_banner() -> None:
    print(BANNER.format(version=__version__))
    cmd_list(argparse.Namespace(api=None))
    print()
    print("usage: smpx <command> [options]")
    print("  auto   pull from a connected phone, patch, build module")
    print("  pull   just grab services.jar + device info")
    print("  run    patch a jar you already have")
    print("  list   this patch table (--api N to filter)")
    print("  show   details for specific patches")


def cmd_patches(args: argparse.Namespace) -> int:
    names = [n for n in args.names if n in BY_NAME]
    unknown = [n for n in args.names if n not in BY_NAME]
    if unknown:
        print(f"unknown patches: {', '.join(unknown)}", file=sys.stderr)
        return 2
    for n in names:
        p = BY_NAME[n]
        print(f"{p.name}\n  glob:  {p.file_glob}\n  api:   A{p.android_min}-A{p.android_max}"
              f"\n  desc:  {p.description}\n")
    return 0

# device (adb)

def adb(*args: str, check=True) -> str:
    """Run an adb command and return stripped stdout."""
    r = subprocess.run(["adb", *args], capture_output=True, text=True)
    out = (r.stdout or "").strip()
    if check and r.returncode != 0:
        err = (r.stderr or out or f"adb exit {r.returncode}").strip()
        sys.exit(f"adb {' '.join(args)} failed:\n{err}")
    return out


def require_device() -> None:
    if shutil.which("adb") is None:
        sys.exit("adb not found on PATH. Install platform-tools:\n"
                 "  winget install Google.PlatformTools")
    state = adb("get-state", check=False)
    if state != "device":
        sys.exit(
            "No device connected.\n"
            "Plug the phone in, enable USB debugging, then run "
            "'adb devices' to confirm it shows 'device'."
        )


def pull_from_device(output_dir: str) -> tuple[str, int, str]:
    """Pull services.jar + read API level & fingerprint off the device.

    Returns (jar_path, api_level, fingerprint). The jar is stored inside
    ``output_dir`` so it survives after patching.
    """
    os.makedirs(output_dir, exist_ok=True)
    jar_path = os.path.join(output_dir, "services.jar")

    log("[*] Reading device properties ...")
    sdk = adb("shell", "getprop ro.build.version.sdk")
    fingerprint = adb("shell", "getprop ro.build.fingerprint")
    log(f"[✓] API {sdk} — {fingerprint}")

    log("[*] Pulling services.jar ...")
    adb("pull", "/system/framework/services.jar", jar_path)
    size_kb = os.path.getsize(jar_path) // 1024
    log(f"[✓] Saved: {jar_path} ({size_kb} KB)")

    return jar_path, int(sdk), fingerprint


def cmd_pull(args: argparse.Namespace) -> int:
    require_device()
    jar_path, api, fp = pull_from_device(args.output)
    log("")
    log("[✓] Done. Next step:")
    log(f"  python smpx.py run --jar \"{jar_path}\" --api {api} \\")
    log(f"      --patches auto --fingerprint \"{fp}\"")
    return 0


def cmd_auto(args: argparse.Namespace) -> int:
    """pull + run in one go."""
    require_device()
    jar_path, api, fp = pull_from_device(args.output)

    # explicit CLI flags win over device-detected values
    api = args.api if args.api is not None else api
    fp = args.fingerprint if args.fingerprint else fp

    selected = parse_patch_selection(args.patches, api)
    module = pipeline(jar_path, api, selected, args.output, fp)
    log("")
    log(f"[✓] Module: {module}")
    log("[✓] JAR:     " + os.path.join(args.output, "services.jar"))
    log("Flash via Magisk / KernelSU / APatch → reboot")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.jar):
        print(f"input not found: {args.jar}", file=sys.stderr)
        return 1

    selected = parse_patch_selection(args.patches, args.api)
    if not selected:
        print("no patches selected", file=sys.stderr)
        return 1

    module = pipeline(args.jar, args.api, selected, args.output, args.fingerprint or "")
    log("")
    log(f"[✓] Module: {module}")
    log("[✓] JAR:     " + os.path.join(args.output, "services.jar"))
    log("Flash via Magisk / KernelSU / APatch → reboot")
    return 0


def parse_patch_selection(spec: str, api: int) -> list[str]:
    """Resolve the --patches argument into concrete patch names.

    Accepts 'all', a comma-separated list of names, or 'auto' (= all
    patches whose API range covers ``api``).
    """
    spec = (spec or "").strip().lower()
    if spec in ("all", ""):
        return [p.name for p in ALL]
    if spec == "auto":
        return [p.name for p in list_for_api(api)]
    chosen: list[str] = []
    for raw in spec.split(","):
        name = raw.strip()
        if not name:
            continue
        if name == "all":
            chosen.extend(p.name for p in ALL)
        elif name == "auto":
            chosen.extend(p.name for p in list_for_api(api))
        elif name in BY_NAME:
            chosen.append(name)
        else:
            sys.exit(f"unknown patch: {name!r}\nRun 'smpx list' to see options.")
    return list(dict.fromkeys(chosen))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="smpx",
        description="Patch Android services.jar and build a Magisk module.",
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = ap.add_subparsers(dest="command")

    p_run = sub.add_parser("run", help="patch services.jar and build the module")
    p_run.add_argument("--jar", required=True, help="path to services.jar")
    p_run.add_argument("--api", type=int, default=36, help="Android API level (default 36)")
    p_run.add_argument("--patches", default="all",
                       help="'all' | 'auto' | comma-separated names (default: all)")
    p_run.add_argument("--output", default=DEFAULT_OUTPUT,
                       help="output directory (default: ~/Desktop/SmaliPatcherEx_Output)")
    p_run.add_argument("--fingerprint", default="",
                       help="device fingerprint to embed in the module (optional)")
    p_run.set_defaults(func=cmd_run)

    p_pull = sub.add_parser("pull",
                            help="pull services.jar (+API/fingerprint) from a connected phone")
    p_pull.add_argument("--output", default=DEFAULT_OUTPUT,
                        help="output directory (default: ~/Desktop/SmaliPatcherEx_Output)")
    p_pull.set_defaults(func=cmd_pull)

    p_auto = sub.add_parser("auto",
                            help="one shot: pull from device, patch, build module")
    p_auto.add_argument("--api", type=int, default=None,
                        help="override API level (default: read from device)")
    p_auto.add_argument("--patches", default="auto",
                        help="'all' | 'auto' | comma-separated names (default: auto)")
    p_auto.add_argument("--output", default=DEFAULT_OUTPUT,
                        help="output directory (default: ~/Desktop/SmaliPatcherEx_Output)")
    p_auto.add_argument("--fingerprint", default="",
                        help="override fingerprint (default: read from device)")
    p_auto.set_defaults(func=cmd_auto)

    p_list = sub.add_parser("list", help="list available patches")
    p_list.add_argument("--api", type=int, default=None,
                        help="only show which patches match an API level")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="show details of specific patches")
    p_show.add_argument("names", nargs="+", help="patch names")
    p_show.set_defaults(func=cmd_patches)

    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        print_banner()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
