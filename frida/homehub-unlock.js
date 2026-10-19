/**
 * One-shot Frida unlock for the BITKEY homehub app (no LSPosed module needed).
 *
 *   frida -U -f app.jp.co.bitkey.homehub -l homehub-unlock.js
 *   frida -U app.jp.co.bitkey.homehub -l homehub-unlock.js   (attach to running app)
 *
 * Reveals the same hidden rows as the module (passcode / IC card settings) by
 * NOP-ing the guard cbnz of the AuthDevice permission getters inside libapp.so,
 * so they fall through to the app's own fail-open `true` path.
 *
 * Frida's Memory.patchCode takes care of mprotect and instruction-cache
 * maintenance, so this also works on an already-running app — just reopen the
 * device settings page afterwards.
 *
 * Offsets are libapp.so vaddrs (see CONTRIBUTING.md for how to find new ones
 * with blutter). Patched sites on 3.35.3:
 *   0x74f824  AuthDevice.canNfcSetting      guard cbnz
 *   0x754474  AuthDevice.canPasscodeSetting guard cbnz (second length check)
 */

// vaddr offsets per app versionName; "*" matches any version.
const OFFSETS = {
  '3.35.3': [0x74f824, 0x754474],
  '*': [0x74f824, 0x754474],
};

const NOP_ARM64 = [0x1f, 0x20, 0x03, 0xd5]; // 0xD503201F

function appVersion() {
  let version = null;
  Java.perform(() => {
    try {
      const ActivityThread = Java.use('android.app.ActivityThread');
      const ctx = ActivityThread.currentApplication().getApplicationContext();
      version = ctx.getPackageManager()
        .getPackageInfo('app.jp.co.bitkey.homehub', 0).versionName.value;
    } catch (e) {
      console.log('[!] could not read app version: ' + e);
    }
  });
  return version;
}

function patchSites(base, offsets) {
  let applied = 0;
  for (const off of offsets) {
    const addr = base.add(off);
    const before = Memory.readByteArray(addr, 4);
    const word = new DataView(before).getUint32(0, true);
    const top = (word >>> 24) & 0xff;
    if (word === 0xd503201f) {
      console.log('[+] 0x' + off.toString(16) + ' already patched');
      applied++;
      continue;
    }
    // cbz/cbnz w/x (0x34/0x35/0xb4/0xb5) — sanity check like the module
    if (top !== 0x34 && top !== 0x35 && top !== 0xb4 && top !== 0xb5) {
      console.log('[!] 0x' + off.toString(16) + ' skipped: word 0x'
        + word.toString(16) + ' is not a guard branch (wrong app version?)');
      continue;
    }
    Memory.patchCode(addr, 4, (writer) => {
      writer.putNop();
    });
    const after = new DataView(Memory.readByteArray(addr, 4)).getUint32(0, true);
    if (after === 0xd503201f) {
      console.log('[+] 0x' + off.toString(16) + ' patched (was 0x'
        + word.toString(16) + ')');
      applied++;
    } else {
      console.log('[!] 0x' + off.toString(16) + ' verify failed: 0x'
        + after.toString(16));
    }
  }
  return applied;
}

function tryPatch() {
  const base = Module.findBaseAddress('libapp.so');
  if (base === null) {
    return false; // libapp.so not mapped yet (spawn mode, engine still loading)
  }
  console.log('[*] libapp.so base ' + base);
  const version = appVersion() || '?';
  const offsets = OFFSETS[version] || OFFSETS['*'];
  console.log('[*] app version ' + version + ', offsets '
    + offsets.map((o) => '0x' + o.toString(16)).join(', '));
  const applied = patchSites(base, offsets);
  console.log((applied === offsets.length ? '[✓]' : '[!]')
    + ' patched ' + applied + '/' + offsets.length
    + ' site(s) — open the device settings page in the app');
  return applied > 0;
}

if (!tryPatch()) {
  // In spawn mode the engine has not mapped libapp.so yet; retry briefly.
  const timer = setInterval(() => {
    if (tryPatch()) {
      clearInterval(timer);
    }
  }, 500);
}
