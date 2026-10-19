# HomehubUnlocker

An [LSPosed](https://github.com/LSPosed/LSPosed) module for the BITKEY homehub
Android app (`app.jp.co.bitkey.homehub`) that reveals the passcode and NFC card
registration menus hidden by server-issued contract flags.

## Background

In organization-managed (rental) properties, homehub devices are often shared
out with a **contract** issued by the property manager. A contract is a small
server-issued record on each `AuthDevice`:

```dart
class _AuthDeviceContractPart {
  final String relatedKeyType;   // "owner" / "subowner" / …
  final bool canDeviceSetting;   // on-device settings menu
  final bool canNfcSetting;      // IC card registration menu
  final bool canPasscodeSetting; // passcode registration menu
  final DateTime? validFrom, validTo;
}
```

`AuthDevice.contracts` holds the list for the signed-in user;
`_currentlyValidContracts()` filters it by the current time. The settings rows
(パスコード認証 / 交通系ICカード認証) are shown when the corresponding getter returns
true. For a tenant with a *subowner* contract the server sends
`canNfcSetting: false, canPasscodeSetting: false`, so the rows vanish — even
though the registration endpoints and the device firmware accept the
operations regardless (the flags gate the UI only; verified on 3.35.3, see
CONTRIBUTING.md).

The flags are evaluated in the Dart AOT image (`libapp.so`) of the Flutter
app, so no Java-level hook can reach them. This module patches the machine
code instead.

## How it works

Reconstructed to Dart, the two getters look like this:

```dart
// AuthDevice (auth_device.dart) — 0x74f7dc
bool get canNfcSetting {
  if (contracts.isEmpty) return true;                    // fail-open
  return _currentlyValidContracts()
      .any((c) => c.canNfcSetting);                      // ← false for subowner
}

// 0x754358
bool get canPasscodeSetting {
  if (contracts.isEmpty) {
    switch (deviceType) { /* per-model default: true/false */ }
  }
  // shared tail, reached for non-empty contracts:
  if (contracts.isEmpty) return true;                    // fail-open
  return _currentlyValidContracts()
      .any((c) => c.canPasscodeSetting) || deviceDefault;
}
```

The key design fact: **when the app has no contract information at all, both
getters return `true`** — the UI is only hidden once contract data exists that
denies the permission. The compiler lays that "no data" case out as the
fall-through of the list-length check:

```asm
ldr  … GDT length call on this->contracts
cbnz w0, <evaluate contracts>     ; list non-empty → compute the real result
add  x0, NULL, #0x20              ; r0 = true  (the app's own empty-list path)
```

The module replaces that single `cbnz` with a `NOP`, so control always falls
through into the app's own `true` — no injected constants, no extra branch,
and the result flows out through the app's normal return path. Two details
matter when choosing *which* `cbnz` to NOP:

- `canNfcSetting` has a single length check; its fall-through is directly
  `true` → patch it (`0x74f824`).
- `canPasscodeSetting` checks the length **twice**: the first check's
  fall-through enters the device-type switch (which may return false), while
  the *second* check's fall-through is directly `true` → patch the second one
  (`0x754474`). Every non-empty-contract execution passes through it.

With the built-in offset table exactly two instructions are patched (homehub
3.35.3, arm64; both words are `0x35000060`, i.e. `cbnz w0, #+0xc`):

| getter              | function vaddr | guard cbnz vaddr |
|---------------------|----------------|------------------|
| `canNfcSetting`     | `0x74f7dc`     | `0x74f824`       |
| `canPasscodeSetting`| `0x754358`     | `0x754474`       |

The structural scanner used for unknown versions matches this whole getter
shape, so on 3.35.3 it finds a third site of the same family
(`canDeviceSetting`, `0xc4afcc`) and force-trues it too — harmless, since that
is also the app's own empty-list behaviour and the flag is usually true
anyway.

Because homehub ships with `extractNativeLibs="false"`, `libapp.so` is never
unpacked: the module finds it inside `split_config.arm64_v8a.apk` by parsing
`/proc/self/maps`, the APK zip central directory, and the ELF program headers,
then patches the two words through a layered write strategy:

1. `/proc/self/mem` (`pwrite`) — works on most ROMs;
2. if the kernel/SELinux denies opening it (hardened OEM ROMs): a private
   anonymous `PROT_READ|PROT_WRITE|PROT_EXEC` overlay mapped with
   `Os.mmap(MAP_FIXED)` over the two target pages, contents restored and the
   patch applied through `sun.misc.Unsafe` — anonymous RWX mappings only need
   `process:execmem` (the permission every app holds for the JIT), which
   sidesteps the `execmod` check that blocks making APK-backed code pages
   writable;
3. `mprotect` + `Unsafe` as a last resort.

The patch is applied right before Dart `main()` executes (hook on
`DartExecutor.executeDartEntrypoint`, with a maps-polling watchdog as
fallback), so the modified words have never been executed and no cache flush
is needed.

Offsets are resolved in this order:

1. `/data/local/tmp/homehub_unlocker.json` (see below),
2. a built-in table for known app versions,
3. a structural signature scan over the executable segment that recognizes the
   getter shape (frame setup → `this->contracts` load → decompress →
   dispatch-table `length` call → guard branch → `true`). The scan tolerates
   register re-allocation and immediate drift, so it usually keeps working
   after minor app updates.

Nothing is sent anywhere and no server-side state is modified by the module
itself; it only stops the local UI from hiding features your contract
disallows.

## Configuration (optional)

Create `/data/local/tmp/homehub_unlocker.json` (make it world-readable:
`adb push homehub_unlocker.json /data/local/tmp/ && adb shell su -c "chmod 644 /data/local/tmp/homehub_unlocker.json"`)
to pin offsets for an app version or to disable the signature scan:

```json
{
  "autoScan": true,
  "apps": {
    "app.jp.co.bitkey.homehub": {
      "offsets": {
        "3.35.3": ["0x74f824", "0x754474"],
        "*": []
      }
    }
  }
}
```

- `offsets` keys are `versionName` values, `*` matches any version.
- If an empty list resolves, nothing is patched unless `autoScan` is enabled.
- Run `adb logcat -s LSPosed-Bridge` (or filter `HomehubUnlocker`): after an
  app update the signature scan logs the vaddrs it patched, which you can copy
  into the config to pin them.

### Finding offsets for a new version manually

1. Pull the new `split_config.arm64_v8a.apk`, extract `lib/arm64-v8a/libapp.so`.
2. Run [blutter](https://github.com/worawit/blutter) on it and open
   `asm/.../auth_device.dart`.
3. In `AuthDevice::canNfcSetting`, the guard is the `cbnz w0` after the
   `GDT[... + ...]()` length call whose fall-through is `add x0, NULL, #0x20 ; true`.
4. In `AuthDevice::canPasscodeSetting`, use the *second* such `cbnz` (the first
   one selects a device-type fallback).
5. Put both vaddrs into the config file under the new `versionName`.

## Build

```
nix develop -c ./build.sh
```

(Any Android SDK with aapt2 / d8 / zipalign / apksigner and a JDK 17 works
too; the script only needs `ANDROID_HOME` set.)

## Install

```
adb install -r HomehubUnlocker.apk
```

Enable the module in LSPosed with scope **BITKEY homehub**
(`app.jp.co.bitkey.homehub`), then force-stop the app and open it again.
Verify with `adb logcat -s LSPosed-Bridge | grep HomehubUnlocker`.

## One-shot alternative (Frida)

If you just need it once (or want to test offsets for a new version), the same
patch as a standalone script — no module install, root shell with
frida-server is enough:

```
frida -U -f app.jp.co.bitkey.homehub -l frida/homehub-unlock.js
# or attach to the already-running app:
frida -U app.jp.co.bitkey.homehub -l frida/homehub-unlock.js
```

It NOPs the same two guard branches via `Memory.patchCode` (which handles
page protection and instruction-cache maintenance itself), then you reopen the
device settings page. Offsets live in the `OFFSETS` table at the top of the
script; see [CONTRIBUTING.md](CONTRIBUTING.md) for how to find new ones with
blutter and for the reverse-engineering notes behind this project.

## Disclaimer

For properties, devices and accounts you legitimately administer (e.g. your
own rental contract). The module changes local UI gating only; operations that
the server actually enforces are unaffected. Use responsibly and within the
terms of your contract.
