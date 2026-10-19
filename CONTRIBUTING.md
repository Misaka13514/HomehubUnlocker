# Contributing

All repo content (code, comments, docs) stays in English. Communication in
issues/PRs can be any language.

## Layout

```
src/net/apeiria/homehubunlocker/   module code (no UI, hooks only)
  MainHook.java      entry point: anchors, watchdog, patch application
  DartImage.java     locates libapp.so in the process, memory access
  PatchPlan.java     offset resolution: config file -> builtin table -> scan
frida/homehub-unlock.js            one-shot Frida variant of the same patch
stubs/               compile-only Xposed API stubs
build.sh             Gradle-free build (aapt2/javac/d8/apksigner)
```

## Adding offsets for a new app version

1. Pull the new split and extract the image:

   ```
   adb shell pm path app.jp.co.bitkey.homehub        # note the split_config.arm64_v8a.apk
   adb pull <split-apk-path>
   unzip split_config.arm64_v8a.apk 'lib/arm64-v8a/libapp.so'
   ```

2. Run [blutter](https://github.com/worawit/blutter) on it
   (`docker run --rm -v <dir>:/bw ghcr.io/worawit/blutter -o /bw/out /bw/libapp.so`).
   Full analysis crashes on some macOS hosts; the Linux/Docker path works.

3. Open `asm/<image>/auth_device.dart` (class `AuthDevice`):
   - `canNfcSetting`: the guard is the `cbnz w0` after the dynamic-dispatch
     `length` call whose fall-through is `add x0, NULL, #0x20 ; true`.
   - `canPasscodeSetting`: use the **second** such `cbnz`; the first one
     selects a device-type fallback path instead.
   Both look like `cbnz w0, <compute-real-result>` followed within a few
   instructions by `add xR, x22, #0x20`.

4. Add the two vaddrs to `BUILTIN_OFFSETS` in `PatchPlan.java` (and/or to the
   config JSON on the device, `{"apps": {"app.jp.co.bitkey.homehub":
   {"offsets": {"<versionName>": ["0x…", "0x…"]}}}}`) — then check logcat:

   ```
   adb logcat -s LSPosed-Bridge | grep HomehubUnlocker
   ```

   You want `patched 2/2 site(s)` and the two rows (passcode / IC card
   settings) on the device settings page, with no crash.

The structural scanner (`PatchPlan.scan`) usually finds the sites on its own
after minor updates; the builtin/config entries only make the result
deterministic.

## Notes from reverse-engineering 3.35.3

These are the load-bearing details behind the code; they held for
Dart 3.12 AOT (snapshot hash 41be3daa…) on arm64 and are what the signature
scanner is built on.

### The permission getters in detail

`AuthDevice` (package `homehub_flutter/2_domains/devices/auth_device/model/
auth_device.dart`) carries `contracts`, a `GrowableList` of contract parts at
field offset `0x3c` (untagged; the prologue loads it with
`ldur wR, [x1, #0x3b]` tagged, then decompresses). Two getters matter:

**`canNfcSetting` @ `0x74f7dc`** — a single length check:

```asm
0x74f820: blr  lr                  ; GDT length call on this->contracts
0x74f824: cbnz w0, #0x74f830       ; 0x35000060 — non-empty → evaluate contracts
0x74f828: add  x0, x22, #0x20      ; r0 = true (empty-list fail-open)
0x74f82c: b    <epilogue>
0x74f830: … _currentlyValidContracts().any((c) => c.canNfcSetting) …
```

**`canPasscodeSetting` @ `0x754358`** — two length checks plus a device-type
switch:

```asm
0x75439c: blr  lr                  ; length call #1
0x7543a0: cbnz w0, #0x754448       ; 0x35000540 — non-empty → shared tail
          ; fall-through: switch on deviceType (binary-search lowering over
          ; cases 3/4/6/0xf/0x12/0x2e…): some cases → 0x75444c, others → false
0x75444c: ldur x0, [fp, #-8]       ; reload contracts
          ; length call #2 (same GDT slot)
0x754474: cbnz w0, #0x754480       ; 0x35000060 — non-empty → any() path
0x754478: add  x0, x22, #0x20      ; r0 = true
0x754480: … _currentlyValidContracts().any((c) => c.canPasscodeSetting)
             || <field-based device default> …
```

The double length check looks redundant but is just how the two source paths
(never-had-contracts vs has-contracts) converge on one tail. Both NOP sites
are therefore exactly the instructions where "has contract data" is decided,
and their fall-through is the app's own "no contract data ⇒ allow" constant.

Semantics summary:

| situation | canNfcSetting | canPasscodeSetting |
|---|---|---|
| no contracts fetched | true | device-type default |
| contracts fetched, none valid now | false (`any` over empty) | device default |
| valid subowner contract (`can*=false`) | false | false |
| after patch | true | true |

Callers test the returned compressed bool with `tbnz w0, #4` (true encodes as
`null+0x20`, false as `null+0x30`, so bit 4 separates them).

**Runtime validation path** (how this was first proven, before any code
patching): a Frida script walked `AuthDevice.contracts` (length at untagged
`+0xc`, `_data` ref at `+0x10`, backing `_List` elements at `+0x10`) and
flipped the `canNfcSetting`/`canPasscodeSetting` fields (untagged `+0x18`/
`+0x1c`) to true — the rows appeared. The one-shot script shipped in
`frida/` now uses the simpler NOP patch instead.

**Enforcement empirics**: the contract flags gate the UI only. With the rows
revealed, a sub-owner session completed full passcode and IC-card
registration against the normal endpoints (`/users/passcode-key-sources`,
`/users/nfc-cards`, `…/treasure-data-sources/deliver`) and the device
accepted the BLE writes — no server-side rejection. Do not generalize this to
other endpoints (factory reset, for one, needs a server-issued
`ownershipSignature` regardless of UI state).

### libapp.so loading layout

`extractNativeLibs="false"`, so the linker maps the image straight out of the
split APK (zip entry `lib/arm64-v8a/libapp.so`, stored uncompressed). To
translate a Dart snapshot vaddr to a runtime address: parse
`/proc/self/maps` for APK-backed pages → walk the zip end-of-central-directory
and central directory to get the entry's local header and data offset → parse
the ELF program headers → `vaddr -> file offset -> maps page -> runtime addr`.
All PT_LOADs in this image satisfy `p_offset == p_vaddr`. The executable
segment is vaddr `0x720000`, size `0xa9fdf0`.

### Dart AOT arm64 ABI cheat sheet (as emitted for this build)

| role | register |
|---|---|
| Dart virtual SP | `x15` |
| thread (THR) | `x26` |
| heap base (compressed pointers) | `x28` |
| compressed null sentinel | `x22` |

- Compressed booleans: `null + 0x20` = true, `null + 0x30` = false. The
  fail-open constant the getters load is `add xR, x22, #0x20`.
- Pointer decompression: `add xR, xR, x28, lsl #32` (ADD shifted-register with
  shift amount 32; the hw shift enum field is `00` for LSL).
- `b.ls` (stack-overflow check) has cond field `1001` (LS), i.e. low byte of
  the word `0x…09`.
- Dynamic-dispatch (`GDT`) call tail is exactly:
  `F2A00031` (movk x17,#1,lsl#16), `8B11001E` (add lr,x0,x17),
  `F87E7ABE` (ldr lr,[x21,lr,lsl#3]), `D63F03C0` (blr lr), then `cbnz w0,…`
  — the quartet is what the scanner keys on.

### Writing to the code pages on hardened ROMs

The patch needs to flip one instruction word in an APK-backed `r-x` mapping.
What worked and what didn't on a ColorOS/Android 16 device with KernelSU+SuSFS:

1. `/proc/self/mem` (`Os.open` + `pread/pwrite`): **EACCES** on open, with no
   AVC denial in dmesg — a kernel-level restriction (SuSFS-style), not
   classic SELinux policy. Works on most other ROMs, so it stays as the first
   choice.
2. Making the APK-backed page writable via `mprotect` is doubly unavailable:
   the public SDK has no `Os.mprotect`, and reflecting
   `libcore.io.Libcore`/`.Linux` yields no usable signature. Even when
   available it would need the `execmod` allow, which app domains don't get.
3. **What works**: `Os.mmap(MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS,
   PROT_READ|PROT_WRITE|PROT_EXEC)` over the page(s) holding the patch site,
   restore the page contents read from the original mapping, then apply the
   patch through `sun.misc.Unsafe.putInt`. Anonymous RWX needs only
   `process:execmem` — the permission every app domain holds for the JIT — so
   no file-based check applies.

Patching before Dart `main()` runs (the `executeDartEntrypoint` hook) also
sidesteps instruction-cache staleness; the watchdog fallback patches early
enough in practice that it has not mattered.

### LSPosed operational notes

- `assets/xposed_init` (class name of the entry point) is mandatory, and
  `aapt2 link` needs `-A assets` for it to land in the APK. Missing either =
  module silently never loads.
- On the Vector fork (zygisk_vector on KernelSU), `modules_config.db` keeps a
  stale `modules.apk_path` when a module APK is reinstalled (the manager then
  shows "enabled, but framework cannot find a loadable APK"). Fix:
  `/data/adb/lspd/cli db backup <f>` → `sqlite3` `UPDATE modules SET
  apk_path=…` → `cli db restore <f>`. Re-check after every reinstall since
  `/data/app/…` paths rotate.
- Module logs surface as `VectorLegacyBridge` tagged lines in plain logcat;
  the framework's own log (`cli log cat`) was unreliable for this.

## Testing checklist

- cold start the app, expect `[HomehubUnlocker] patched 2/2 site(s)` once
- device settings page shows the passcode and IC card rows
- app survives navigation / no `FATAL` in logcat
- config file overrides still work (`/data/local/tmp/homehub_unlocker.json`)
- force-stop + relaunch (idempotency: `already patched` path)
