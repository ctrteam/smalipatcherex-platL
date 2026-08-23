# SmaliPatcherEx CLI (Python)

Patch Android `services.jar` and pack the result into a Magisk module —
entirely from the command line.

    services.jar -> extract dex -> baksmali -> patch smali -> smali assemble
                 -> repack jar -> Magisk module zip

## Requirements

- Python 3.10+ (stdlib only, no pip installs)
- Java 17+ on PATH
- adb on PATH (only for `pull` / `auto`) — `winget install Google.PlatformTools`
- Internet on first run (downloads baksmali/smali 3.0.9 fat jars into `smpx/`)

## Usage

The one-liner, with the phone plugged in (USB debugging enabled):

```sh
python smpx.py auto
```

That reads API level + fingerprint off the device, pulls services.jar,
applies every patch that matches your API, and writes to
`~/Desktop/SmaliPatcherEx_Output/`:

- `services.jar` — patched jar (the unpatched original from `pull` gets overwritten)
- `SmaliPatcherEx-module.zip` — flash via Magisk / KernelSU / APatch

### Step by step

```sh
# 1. pull from a connected phone (no root needed)
python smpx.py pull

# 2. patch the pulled jar with the exact values it printed
python smpx.py run --jar "C:\...\SmaliPatcherEx_Output\services.jar" \
    --api 36 --patches auto --fingerprint "google/.../release-keys"

# or patch an arbitrary jar without a phone:
python smpx.py run --jar services.jar --api 36 --patches mock_location_appops
```

`--patches` accepts:

- `all` — every defined patch
- `auto` — only patches whose API range covers `--api`
- comma-separated names, e.g. `mock_location_appops,doze_whitelist`

```sh
python smpx.py list --api 36     # what applies at this API level
python smpx.py show signature_spoofing_pms   # details for one patch
```

## Layout

```
smpx/
  cli.py               argparse entry, download + jar/dex plumbing, adb helpers
  patch_definitions.py the named smali regex patches
  patch_engine.py      glob + regex apply over a smali tree
  magisk_builder.py    module.prop / update-binary / zip writer
  baksmali.jar         fetched automatically if missing
  smali.jar
smpx.py              launcher: python smpx.py ...
```

## Patches included

| Patch | Description | Android |
|-------|-------------|---------|
| mock_location_appops | Mock Location AppOps bypass | A10–A16 |
| mock_location_isprovider | isMockProvider always true | A12–A16 |
| mock_location_provider_manager | LocationProviderManager bypass | A13–A16 |
| mock_location_appops_helper | AppOpsHelper bypass | A14–A16 |
| mock_permission_dpm | DevicePolicyManager bypass | A5–A16 |
| mock_permission_restrictions | UserRestrictionsUtils bypass | A11–A16 |
| gnss_mock_provider | GnssManagerService bypass | A13–A16 |
| gnss_location_provider_legacy | GnssLocationProvider legacy | A9–A12 |
| signature_spoofing_pms | PackageManagerService | A5–A13 |
| signature_spoofing_computer | ComputerEngine (A14+ PM refactor) | A14–A16 |
| signature_spoofing_snapshot | Snapshot class | A14–A16 |
| no_permission_review | Skip REVIEW_REQUIRED flag | A10–A16 |
| doze_whitelist | DeviceIdleController whitelist | A6–A16 |
| untrusted_touch | InputManagerService bypass | A12–A16 |
| untrusted_touch_wms | WindowManagerService bypass | A12–A16 |
| overlay_any | Allow unsigned overlays | A10–A16 |
