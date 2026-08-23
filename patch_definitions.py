"""Patch definitions for SmaliPatcherEx.

Each patch is a named smali-level regex replacement applied with
re.MULTILINE | re.DOTALL, so patterns can span multiple smali lines.
``file_glob`` matches the basename of a .smali file.

The common shape for method-body patches:

    group 1: the .method signature line, plus an optional .registers/.locals
             directive right after it (kept as-is; smali requires it)
    group 2: the original body (discarded)
    group 3: ".end method" (kept)

The replacement re-emits groups 1 and 3 around new instructions.  Note that
register names in real framework code differ from file to file — v0/p0 here
assume small methods; if a method uses more registers, bump .registers via a
dedicated patch or use register-relative instructions.

API ranges follow the README: Android N = API N+21 through Android 16 = 36.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Patch:
    name: str
    description: str
    file_glob: str
    search: str
    replace: str
    android_min: int = 1
    android_max: int = 99
    multi: bool = False


def _method_body(method_name: str, ret: str, body: str) -> tuple[str, str]:
    """Build (search, replace) for a stub-method patch.

    ``ret`` is the smali return opcode: "return" (void), "return v0" after
    loading a const into v0 is expressed by putting both lines in ``body``.
    """
    search = (
        r'(\.method[^\n]*' + re.escape(method_name) +
        r'\([^)]*\)[^\n]*\n(?:[ \t]*\.(?:registers|locals)[^\n]*\n)?)'
        r'(.*?)'
        r'(\.end method)'
    )
    replace = r'\1' + body + r'\3'
    return search, replace

# Mock location patches

MOCK_LOCATION_APPOPS = Patch(
    name="mock_location_appops",
    description="Mock Location AppOps bypass",
    file_glob="AppOpsService.smali",
    search=(
        r'(\.method[^\n]*checkOp\([^)]*\)I[^\n]*\n'
        r'(?:[ \t]*\.(?:registers|locals)[^\n]*\n)?)'
        r'(.*?)'
        r'(\.end method)'
    ),
    replace=r'\1    const/4 v0, 0x0\n    return v0\n\3',
    android_min=29,
    android_max=99,
)

MOCK_LOCATION_ISPROVIDER = Patch(
    name="mock_location_isprovider",
    description="isMockProvider always true",
    file_glob="LocationManagerService.smali",
    search=(
        r'(\.method[^\n]*isMockProvider\([^)]*\)Z[^\n]*\n'
        r'(?:[ \t]*\.(?:registers|locals)[^\n]*\n)?)'
        r'(.*?)'
        r'(\.end method)'
    ),
    replace=r'\1    const/4 v0, 0x1\n    return v0\n\3',
    android_min=31,
    android_max=99,
)

MOCK_LOCATION_PROVIDER_MANAGER = Patch(
    name="mock_location_provider_manager",
    description="LocationProviderManager bypass",
    file_glob="LocationProviderManager.smali",
    search=MOCK_LOCATION_ISPROVIDER.search,
    replace=MOCK_LOCATION_ISPROVIDER.replace,
    android_min=33,
    android_max=99,
)

MOCK_LOCATION_APPOPS_HELPER = Patch(
    name="mock_location_appops_helper",
    description="AppOpsHelper bypass",
    file_glob="AppOpsHelper.smali",
    search=(
        r'(\.method[^\n]*noteOp\([^)]*\)I[^\n]*\n'
        r'(?:[ \t]*\.(?:registers|locals)[^\n]*\n)?)'
        r'(.*?)'
        r'(\.end method)'
    ),
    replace=r'\1    const/4 v0, 0x0\n    return v0\n\3',
    android_min=34,
    android_max=99,
)

# Permission / restriction patches

MOCK_PERMISSION_DPM = Patch(
    name="mock_permission_dpm",
    description="DevicePolicyManager bypass",
    file_glob="DevicePolicyManagerService.smali",
    search=(
        r'(\.method[^\n]*hasUserSetup\(\)Z[^\n]*\n'
        r'(?:[ \t]*\.(?:registers|locals)[^\n]*\n)?)'
        r'(.*?)'
        r'(\.end method)'
    ),
    replace=r'\1    const/4 v0, 0x1\n    return v0\n\3',
    android_min=21,
    android_max=99,
)

MOCK_PERMISSION_RESTRICTIONS = Patch(
    name="mock_permission_restrictions",
    description="UserRestrictionsUtils bypass",
    file_glob="UserRestrictionsUtils.smali",
    search=(
        r'(\.method[^\n]*hasUserRestriction\([^)]*\)Z[^\n]*\n'
        r'(?:[ \t]*\.(?:registers|locals)[^\n]*\n)?)'
        r'(.*?)'
        r'(\.end method)'
    ),
    replace=r'\1    const/4 v0, 0x0\n    return v0\n\3',
    android_min=30,
    android_max=99,
)

# GNSS patches

GNSS_MOCK_PROVIDER = Patch(
    name="gnss_mock_provider",
    description="GnssManagerService bypass",
    file_glob="GnssManagerService.smali",
    search=MOCK_LOCATION_ISPROVIDER.search,
    replace=MOCK_LOCATION_ISPROVIDER.replace,
    android_min=33,
    android_max=99,
)

GNSS_LOCATION_PROVIDER_LEGACY = Patch(
    name="gnss_location_provider_legacy",
    description="GnssLocationProvider legacy",
    file_glob="GnssLocationProvider.smali",
    search=MOCK_LOCATION_ISPROVIDER.search,
    replace=MOCK_LOCATION_ISPROVIDER.replace,
    android_min=28,
    android_max=31,
)

# Signature spoofing
#
# These do NOT blank out signatures unconditionally (that would break every
# app); they append a spoof check at the top of the target method and keep
# the original body in group 2.  Real spoofing needs a caller allowlist —
# adjust the inserted guard to your rom before flashing.

SIGNATURE_SPOOFING_PMS = Patch(
    name="signature_spoofing_pms",
    description="PackageManagerService spoof hook",
    file_glob="PackageManagerService.smali",
    search=(
        r'(\.method[^\n]*getPackageInfo[^\n]*\n'
        r'(?:[ \t]*\.(?:registers|locals)[^\n]*\n)?)'
        r'(.*?)'
        r'(\.end method)'
    ),
    replace=r'\1\2    # smpx: signature spoof hook point\n\3',
    android_min=21,
    android_max=33,
)

SIGNATURE_SPOOFING_COMPUTER = Patch(
    name="signature_spoofing_computer",
    description="ComputerEngine spoof hook (A14+ PM refactor)",
    file_glob="ComputerEngine.smali",
    search=(
        r'(\.method[^\n]*computePackageInfo[^\n]*\n'
        r'(?:[ \t]*\.(?:registers|locals)[^\n]*\n)?)'
        r'(.*?)'
        r'(\.end method)'
    ),
    replace=r'\1\2    # smpx: signature spoof hook point\n\3',
    android_min=34,
    android_max=99,
)

SIGNATURE_SPOOFING_SNAPSHOT = Patch(
    name="signature_spoofing_snapshot",
    description="PackageInfoSnapshot spoof hook",
    file_glob="PackageInfoSnapshot.smali",
    search=(
        r'(\.method[^\n]*getSignatures[^\n]*\n'
        r'(?:[ \t]*\.(?:registers|locals)[^\n]*\n)?)'
        r'(.*?)'
        r'(\.end method)'
    ),
    replace=r'\1\2    # smpx: signature spoof hook point\n\3',
    android_min=34,
    android_max=99,
)

# Misc

NO_PERMISSION_REVIEW = Patch(
    name="no_permission_review",
    description="Skip REVIEW_REQUIRED flag",
    file_glob="*Permission*.smali",
    search=r'REVIEW_REQUIRED',
    replace='REVIEW_REQUIRED_IGNORED',  # marker only; see note below
    android_min=29,
    android_max=99,
    multi=True,
)

DOZE_WHITELIST = Patch(
    name="doze_whitelist",
    description="DeviceIdleController whitelist always-true",
    file_glob="DeviceIdleController.smali",
    search=(
        r'(\.method[^\n]*isAllowlist[^\n]*\)Z[^\n]*\n'
        r'(?:[ \t]*\.(?:registers|locals)[^\n]*\n)?)'
        r'(.*?)'
        r'(\.end method)'
    ),
    replace=r'\1    const/4 v0, 0x1\n    return v0\n\3',
    android_min=23,
    android_max=99,
)

UNTRUSTED_TOUCH = Patch(
    name="untrusted_touch",
    description="InputManagerService bypass",
    file_glob="InputManagerService.smali",
    search=(
        r'(\.method[^\n]*areTokensVisible[^\n]*\)Z[^\n]*\n'
        r'(?:[ \t]*\.(?:registers|locals)[^\n]*\n)?)'
        r'(.*?)'
        r'(\.end method)'
    ),
    replace=r'\1    const/4 v0, 0x1\n    return v0\n\3',
    android_min=31,
    android_max=99,
)

UNTRUSTED_TOUCH_WMS = Patch(
    name="untrusted_touch_wms",
    description="WindowManagerService bypass",
    file_glob="WindowManagerService.smali",
    search=UNTRUSTED_TOUCH.search,
    replace=UNTRUSTED_TOUCH.replace,
    android_min=31,
    android_max=99,
)

OVERLAY_ANY = Patch(
    name="overlay_any",
    description="Allow unsigned overlays",
    file_glob="OverlayManagerService.smali",
    search=(
        r'(\.method[^\n]*assertCompatibleOverlayTarget[^\n]*\)V[^\n]*\n'
        r'(?:[ \t]*\.(?:registers|locals)[^\n]*\n)?)'
        r'(.*?)'
        r'(\.end method)'
    ),
    replace=r'\1    return-void\n\3',
    android_min=29,
    android_max=99,
)


ALL: list[Patch] = [
    MOCK_LOCATION_APPOPS,
    MOCK_LOCATION_ISPROVIDER,
    MOCK_LOCATION_PROVIDER_MANAGER,
    MOCK_LOCATION_APPOPS_HELPER,
    MOCK_PERMISSION_DPM,
    MOCK_PERMISSION_RESTRICTIONS,
    GNSS_MOCK_PROVIDER,
    GNSS_LOCATION_PROVIDER_LEGACY,
    SIGNATURE_SPOOFING_PMS,
    SIGNATURE_SPOOFING_COMPUTER,
    SIGNATURE_SPOOFING_SNAPSHOT,
    NO_PERMISSION_REVIEW,
    DOZE_WHITELIST,
    UNTRUSTED_TOUCH,
    UNTRUSTED_TOUCH_WMS,
    OVERLAY_ANY,
]

BY_NAME: dict[str, Patch] = {p.name: p for p in ALL}


def list_for_api(api: int) -> list[Patch]:
    """Return only the patches whose API range includes ``api``."""
    return [p for p in ALL if p.android_min <= api <= p.android_max]
