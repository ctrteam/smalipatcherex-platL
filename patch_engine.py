"""Patch engine — finds and replaces smali patterns on disk."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Callable, Iterable

from .patch_definitions import Patch

FLAGS = re.MULTILINE | re.DOTALL


@dataclass
class PatchResult:
    patch: Patch
    applied: bool = False
    files: list[str] = field(default_factory=list)
    reason: str = ""

    def __bool__(self) -> bool:
        """Truthy when the patch actually changed something."""
        return self.applied


class PatchEngine:
    """Walks a smali tree and applies regex patches to matching files."""

    def __init__(self, smali_root: str, api: int):
        self.smali_root = smali_root
        self.api = api
        self.log: Callable[[str], None] | None = None

    # -- public 

    def run_all(self, names: Iterable[str]) -> dict[str, PatchResult]:
        """Apply each named patch; returns name→result."""
        from .patch_definitions import BY_NAME

        results: dict[str, PatchResult] = {}
        for name in names:
            patch = BY_NAME.get(name)
            if patch is None:
                self._log(f"! unknown patch: {name}")
                continue
            self._log(f"applying {name} ...")
            r = self.apply(patch)
            results[name] = r
            if r.applied:
                files = ", ".join(r.files) or "?"
                self._log(f"+ {name}: {files}")
            else:
                self._log(f"- {name}: skipped ({r.reason})")
        return results

    def apply(self, patch: Patch) -> PatchResult:
        """Apply ``patch`` to every file under root matching its glob."""
        result = PatchResult(patch=patch)

        if not (patch.android_min <= self.api <= patch.android_max):
            result.reason = f"api {self.api} out of range ({patch.android_min}-{patch.android_max})"
            return result

        targets = list(self._glob(patch.file_glob))
        if not targets:
            result.reason = f"no file matched {patch.file_glob!r}"
            return result

        matched_any = False
        for path in targets:
            text = self._read(path)
            if text is None:
                continue
            patched, count = self._patch_text(text, patch)
            if patched != text:
                self._write(path, patched)
                label = os.path.basename(path)
                if count > 1:
                    label = f"{label} ({count}x)"
                result.files.append(label)
                result.applied = True
                matched_any = True

        if not matched_any:
            result.reason = "pattern not found in matched files"
        return result

    # -- internals 

    def _patch_text(self, text: str, patch: Patch) -> tuple[str, int]:
        """Return (new_text, match_count) for one patch on one file."""
        if patch.multi:
            matches = list(re.finditer(patch.search, text, FLAGS))
            if not matches:
                return text, 0
            return re.sub(patch.search, patch.replace, text, flags=FLAGS), len(matches)

        # single-match path
        if not re.search(patch.search, text, FLAGS):
            return text, 0
        new = re.sub(patch.search, patch.replace, text, count=1, flags=FLAGS)
        return new, 1 if new != text else 0

    def _glob(self, pattern: str) -> Iterable[str]:
        """Yield .smali files under root whose basename matches ``pattern``."""
        if not pattern or not os.path.isdir(self.smali_root):
            return
        # fnmatch treats `*` as "anything including /", so we match on
        # basename only by splitting off the filename portion.
        name_pat = os.path.basename(pattern.replace("\\", "/"))
        for dirpath, _dirs, files in os.walk(self.smali_root):
            for f in files:
                if f.endswith(".smali") and fnmatch(f, name_pat):
                    yield os.path.join(dirpath, f)

    def _read(self, path: str) -> str | None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError as exc:
            self._log(f"! read error {path}: {exc}")
            return None

    def _write(self, path: str, content: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)

    def _log(self, msg: str) -> None:
        if self.log:
            self.log(msg)
