"""Magisk module builder.

Packs a patched services.jar into a flashable Magisk module zip with an
update-binary that:
  * optionally verifies the device fingerprint before installing,
  * clears stale dalvik-cache / apex vdex entries for services.jar,
  * matches file timestamps against framework.jar (anti-detection).
"""

from __future__ import annotations

import os
import posixpath
import zipfile

UPDATE_BINARY = r"""#!/sbin/sh
SKIPUNZIP=1
MODDIR="${MODPATH}"

ui_print "************************************"
ui_print "      SmaliPatcherEx v2.0           "
ui_print "      Android 16 Compatible         "
ui_print "************************************"

unzip -d "$TMPDIR" -q "$ZIPFILE" fingerprint 2>/dev/null
if [ -f "$TMPDIR/fingerprint" ]; then
  fp_module=$(cat "$TMPDIR/fingerprint")
  fp_system=$(getprop ro.build.fingerprint)
  if [ "$fp_module" != "$fp_system" ]; then
    ui_print "! Fingerprint mismatch!"
    ui_print "  Module: $fp_module"
    ui_print "  Device: $fp_system"
    abort "! Wrong device or build!"
  fi
  ui_print "- Fingerprint: OK"
fi

unzip -o "$ZIPFILE" 'system/*' -d "$MODPATH" 2>/dev/null
ui_print "- Files extracted"

ui_print "- Clearing dalvik-cache..."
find /data/dalvik-cache -iname '*@services.jar*class*' 2>/dev/null | while read f; do
  rm -f "$f"
done
find /data/misc/apexdata -iname '*@services.jar*class*' 2>/dev/null | while read f; do
  rm -f "$f"
done
find /data/misc/apexdata/com.android.os -name '*.vdex' 2>/dev/null | \
  grep -i services | while read f; do rm -f "$f"; done

set_perm_recursive "$MODPATH" root root 0755 0644
ui_print "- Permissions set"

ts=$(stat -c '%y' /system/framework/framework.jar 2>/dev/null \
     | awk '{print $1$2}' | tr -d ':-.' | cut -c1-12)
if [ -n "$ts" ]; then
  find "$MODDIR" -name '*.*' 2>/dev/null | while read f; do
    touch -amt "$ts" "$f" 2>/dev/null
  done
  ui_print "- Timestamps matched"
fi

ui_print ""
ui_print "[OK] SmaliPatcherEx installed — reboot to activate"
"""

UPDATER_SCRIPT = "#MAGISK\n"


def build(patched_jar: str,
          output_dir: str,
          fingerprint: str,
          applied_patches: list[str],
          log=print) -> str:
    """Write SmaliPatcherEx-module.zip and return its path."""
    os.makedirs(output_dir, exist_ok=True)
    out_zip = os.path.join(output_dir, "SmaliPatcherEx-module.zip")

    if os.path.exists(out_zip):
        os.remove(out_zip)

    desc = ", ".join(applied_patches) if applied_patches else "no patches applied"
    module_prop = (
        "id=SmaliPatcherEx\n"
        "name=SmaliPatcherEx\n"
        "version=v2.0.0\n"
        "versionCode=200\n"
        "author=sabpprook & mfajarb\n"
        f"description=SmaliPatcherEx v2 — {desc}\n"
        "minMagisk=24000\n"
    )

    log(f"[*] Building Magisk module ...")
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        _add_text(zf, "META-INF/com/google/android/update-binary", UPDATE_BINARY)
        _add_text(zf, "META-INF/com/google/android/updater-script", UPDATER_SCRIPT)
        _add_text(zf, "module.prop", module_prop)
        if fingerprint:
            _add_text(zf, "fingerprint", fingerprint)
        zf.write(patched_jar, "system/framework/services.jar")

    size_kb = os.path.getsize(out_zip) // 1024
    log(f"[✓] Module: {out_zip} ({size_kb} KB)")
    return out_zip


def _add_text(zf: zipfile.ZipFile, entry_name: str, content: str) -> None:
    info = zipfile.ZipInfo(posixpath.normpath(entry_name))
    # deterministic-ish timestamps keep the zip reproducible across runs
    info.date_time = (2024, 1, 1, 0, 0, 0)
    zf.writestr(info, content.replace("\r\n", "\n"))
