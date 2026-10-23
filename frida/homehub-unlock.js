/**
 * One-shot Frida unlock for the BITKEY homehub app (no LSPosed module needed).
 *
 *   frida -U -f app.jp.co.bitkey.homehub -l homehub-unlock.js
 *   frida -U -n homehub -l homehub-unlock.js          (attach to running app)
 *   frida -U -n homehub -l homehub-unlock.js -q       (one-shot; patches persist
 *                                                      in the process after exit)
 *
 * Reveals the same hidden rows as the module (passcode / IC card settings) by
 * NOP-ing the guard cbnz of the AuthDevice permission getters inside libapp.so,
 * so they fall through to the app's own fail-open `true` path, plus the
 * DeviceDetailView guard that hides the 出入り履歴 (device log) tab.
 *
 * Frida's Memory.patchCode takes care of mprotect and instruction-cache
 * maintenance, so this also works on an already-running app — just reopen the
 * device settings / lock detail page afterwards.
 *
 * Offsets are libapp.so vaddrs (see CONTRIBUTING.md for how to find new ones
 * with blutter). Patched sites on 3.35.3:
 *   0x74f824  AuthDevice.canNfcSetting      guard cbnz
 *   0x754474  AuthDevice.canPasscodeSetting guard cbnz (second length check)
 *   0xc82a9c  DeviceDetailView.build guard tbnz after showLogTab() —
 *             NOP forces the 出入り履歴 tab to appear (the server does not
 *             enforce the log authority; the tab VM just GETs
 *             /homehubDevice/v1/devices/{id}/logs).
 *
 * Frida 17 note: the find* family (Process.findModuleByName,
 * Module.findBaseAddress) and the Memory.readXxx/writeXxx free functions were
 * removed. This script uses Process.getModuleByName / ptr.readByteArray and
 * falls back gracefully where possible.
 */

// vaddr offsets per app versionName; "*" matches any version.
const OFFSETS = {
  '3.35.3': [0x74f824, 0x754474, 0xc82a9c],
  '*': [0x74f824, 0x754474, 0xc82a9c],
};

const NOP_ARM64 = [0x1f, 0x20, 0x03, 0xd5]; // 0xD503201F

/** Locate libapp.so across frida versions; null when not mapped yet. */
function findLibApp() {
  if (typeof Process.getModuleByName === 'function') {
    try {
      return Process.getModuleByName('libapp.so');
    } catch (e) {
      return null; // not mapped yet (spawn mode, engine still loading)
    }
  }
  if (typeof Process.findModuleByName === 'function') {
    return Process.findModuleByName('libapp.so');
  }
  const mods = Process.enumerateModules();
  for (let i = 0; i < mods.length; i++) {
    if (mods[i].name === 'libapp.so') {
      return mods[i];
    }
  }
  return null;
}

function readWord(addr) {
  return new DataView(addr.readByteArray(4)).getUint32(0, true);
}

/** Write one NOP at addr, handling page protection + icache. */
function writeNop(addr) {
  if (typeof Memory.patchCode === 'function') {
    Memory.patchCode(addr, 4, (code) => {
      // `code` is a NativePointer to the temporarily writable region,
      // NOT an Arm64Writer — construct one explicitly.
      const writer = new Arm64Writer(code, { pc: addr });
      try {
        writer.putNop();
        writer.flush();
      } finally {
        writer.dispose();
      }
    });
    return;
  }
  // Fallback for builds without Memory.patchCode.
  Memory.protect(addr, 4, 'rwx');
  addr.writeByteArray(NOP_ARM64);
  Memory.protect(addr, 4, 'r-x');
}

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
    const word = readWord(addr);
    const top = (word >>> 24) & 0xff;
    if (word === 0xd503201f) {
      console.log('[+] 0x' + off.toString(16) + ' already patched');
      applied++;
      continue;
    }
    // cbz/cbnz/tbz/tbnz w/x (0x34-0x37 / 0xb4-0xb7) — sanity check like the module
    if (top < 0x34 || top > 0x37 && top < 0xb4 || top > 0xb7) {
      console.log('[!] 0x' + off.toString(16) + ' skipped: word 0x'
        + word.toString(16) + ' is not a guard branch (wrong app version?)');
      continue;
    }
    writeNop(addr);
    const after = readWord(addr);
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
  const mod = findLibApp();
  if (mod === null) {
    return false; // libapp.so not mapped yet (spawn mode, engine still loading)
  }
  const base = mod.base;
  console.log('[*] libapp.so base ' + base);
  const version = appVersion() || '?';
  const offsets = OFFSETS[version] || OFFSETS['*'];
  console.log('[*] app version ' + version + ', offsets '
    + offsets.map((o) => '0x' + o.toString(16)).join(', '));
  const applied = patchSites(base, offsets);
  console.log((applied === offsets.length ? '[✓]' : '[!]')
    + ' patched ' + applied + '/' + offsets.length
    + ' site(s) — reopen the lock detail page in the app');
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
