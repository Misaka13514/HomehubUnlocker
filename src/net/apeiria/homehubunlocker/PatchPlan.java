package net.apeiria.homehubunlocker;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONObject;

/**
 * Decides which instruction words to patch.
 *
 * The registration menus are hidden because the AuthDevice permission getters
 * (canNfcSetting / canPasscodeSetting) walk the server-issued contracts and
 * return false for sub-owner contracts. Both getters contain a guard branch
 *
 *     cbnz w0, <compute-result>     ; taken when contracts is non-empty
 *     add  x0, NULL, #0x20          ; r0 = true (the app's own fail-open path)
 *
 * Turning that cbnz into a NOP makes the getter return true through the app's
 * own code, with no injected constants. (The app treats "no contract data" as
 * allow: that is the fall-through being taken — the disassembly-level story is
 * in CONTRIBUTING.md, "The permission getters in detail".) This class produces
 * the vaddrs of the guard branches to NOP:
 *
 *   1. explicit offsets from the config file (preferred, see README),
 *   2. a built-in table for known app versions,
 *   3. a structural signature scan over the executable segment (best effort,
 *      survives register re-allocation and immediate drift between builds).
 */
final class PatchPlan {

    static final String TARGET_PACKAGE = "app.jp.co.bitkey.homehub";
    private static final String CONFIG_PATH = "/data/local/tmp/homehub_unlocker.json";

    /**
     * Guard-branch vaddrs per app versionName. Offsets refer to the libapp.so
     * of homehub 3.35.3 (arm64):
     *   canNfcSetting      @ 0x74f7dc, guard cbnz @ +0x48
     *   canPasscodeSetting @ 0x754358, guard cbnz @ +0x11c (the second length
     *   check; the first one selects a device-type fallback instead)
     */
    private static final String BUILTIN_VERSION = "3.35.3";
    private static final long[] BUILTIN_OFFSETS = {0x74f824L, 0x754474L};

    private PatchPlan() {}

    static long[] resolve(DartImage img, String versionName, StringBuilder log) throws IOException {
        JSONObject cfg = loadConfig(log);

        // 1. config file: "apps" -> package -> "offsets" -> versionName (or "*")
        long[] fromCfg = offsetsFromConfig(cfg, versionName, log);
        if (fromCfg != null) {
            log.append("using config offsets: ").append(hex(fromCfg)).append('\n');
            return fromCfg;
        }

        // 2. built-in table
        if (BUILTIN_VERSION.equals(versionName)) {
            log.append("using built-in offsets for ").append(versionName)
                    .append(": ").append(hex(BUILTIN_OFFSETS)).append('\n');
            return BUILTIN_OFFSETS;
        }

        // 3. signature scan
        boolean autoScan = true;
        if (cfg != null) {
            autoScan = cfg.optBoolean("autoScan", true);
        }
        if (!autoScan) {
            log.append("autoScan disabled and no offsets configured; nothing to do\n");
            return new long[0];
        }
        long[] found = scan(img, log);
        log.append("autoScan patched sites: ").append(hex(found)).append('\n');
        return found;
    }

    private static JSONObject loadConfig(StringBuilder log) {
        try {
            File f = new File(CONFIG_PATH);
            if (!f.canRead()) {
                return null;
            }
            byte[] data = new byte[(int) f.length()];
            try (java.io.FileInputStream in = new java.io.FileInputStream(f)) {
                int off = 0;
                while (off < data.length) {
                    int n = in.read(data, off, data.length - off);
                    if (n < 0) {
                        break;
                    }
                    off += n;
                }
            }
            log.append("config loaded from ").append(CONFIG_PATH).append('\n');
            return new JSONObject(new String(data, "UTF-8"));
        } catch (Exception e) {
            log.append("config not used: ").append(e).append('\n');
            return null;
        }
    }

    private static long[] offsetsFromConfig(JSONObject cfg, String versionName, StringBuilder log) {
        if (cfg == null) {
            return null;
        }
        JSONObject apps = cfg.optJSONObject("apps");
        if (apps == null) {
            return null;
        }
        JSONObject app = apps.optJSONObject(TARGET_PACKAGE);
        if (app == null) {
            return null;
        }
        JSONObject offsets = app.optJSONObject("offsets");
        if (offsets == null) {
            return null;
        }
        String[] keys = versionName != null
                ? new String[] {versionName, "*"}
                : new String[] {"*"};
        for (String key : keys) {
            List<Long> vals = new ArrayList<>();
            org.json.JSONArray arr = offsets.optJSONArray(key);
            if (arr == null) {
                continue;
            }
            for (int i = 0; i < arr.length(); i++) {
                String s = arr.optString(i, null);
                if (s == null) {
                    continue;
                }
                try {
                    vals.add(Long.decode(s.trim()));
                } catch (NumberFormatException e) {
                    log.append("bad offset entry '").append(s).append("'\n");
                }
            }
            if (!vals.isEmpty()) {
                long[] out = new long[vals.size()];
                for (int i = 0; i < out.length; i++) {
                    out[i] = vals.get(i);
                }
                return out;
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Structural signature scan
    // ------------------------------------------------------------------

    /**
     * Matches the shape of an AuthDevice permission getter:
     *
     *   stp fp, lr, [sp, #-0x10]!
     *   mov fp, sp
     *   sub sp, sp, #imm
     *   stur x1, [fp, #-imm]          ; SetupParameters(this)
     *   ldr x16, [THR, #imm]          ; stack limit
     *   cmp sp, x16
     *   b.ls <stack overflow>
     *   ldur wR, [x1, #imm]           ; this->contracts
     *   add xR, xR, HEAP, lsl #32     ; DecompressPointer
     *   ... GDT length call tail ...
     *   movk x17, #1, lsl #16
     *   add lr, x0, x17
     *   ldr lr, [x21, lr, lsl #3]
     *   blr lr
     *   cbnz w0, <compute>            ; <- NOP this, when followed by
     *   add xR, NULL, #0x20           ;    "r0 = true"
     *
     * Register numbers and immediates are matched loosely; the fixed
     * instructions (frame setup, dispatch-table tail, true constant) are
     * matched exactly. A getter whose first guard leads to a reload of
     * `this` (device-type fallback, e.g. canPasscodeSetting) is handled by
     * patching its second length guard instead.
     */
    static long[] scan(DartImage img, StringBuilder log) throws IOException {
        long[] seg = img.execSegment();
        if (seg == null) {
            log.append("no executable segment found\n");
            return new long[0];
        }
        long segVaddr = seg[0];
        long segLen = seg[1];
        log.append("scanning exec segment vaddr=0x").append(Long.toHexString(segVaddr))
                .append(" len=0x").append(Long.toHexString(segLen)).append('\n');

        List<Long> patches = new ArrayList<>();
        long chunkWords = 16384; // 64 KiB per read, plus a 64-word overlap
        long totalWords = segLen / 4;
        for (long base = 0; base < totalWords; base += chunkWords) {
            int words = (int) Math.min(chunkWords + 64, totalWords - base);
            byte[] data;
            try {
                data = img.read(img.addr(segVaddr + base * 4), words * 4);
            } catch (IOException e) {
                continue;
            }
            int[] w = new int[words];
            ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(w);
            for (int i = 0; i + 60 < words; i++) {
                if (!prologueMatches(w, i)) {
                    continue;
                }
                long funcVaddr = segVaddr + (base + i) * 4;
                long patch = findGuard(w, i);
                if (patch >= 0) {
                    long patchVaddr = funcVaddr + patch;
                    if (!patches.contains(patchVaddr)) {
                        patches.add(patchVaddr);
                        log.append("signature match: patch @ 0x")
                                .append(Long.toHexString(patchVaddr)).append('\n');
                    }
                }
            }
        }
        long[] out = new long[patches.size()];
        for (int i = 0; i < out.length; i++) {
            out[i] = patches.get(i);
        }
        return out;
    }

    private static boolean prologueMatches(int[] w, int i) {
        if (w[i] != 0xA9BF79FD           // stp fp, lr, [sp, #-0x10]!
                || w[i + 1] != 0xAA0F03FD // mov fp, sp
                || (w[i + 2] >>> 24) != 0xD1
                || bits(w[i + 2], 9, 5) != 15 || bits(w[i + 2], 4, 0) != 15) { // sub x15(DartSP), x15, #imm
            return false;
        }
        if ((w[i + 3] >>> 24) != 0xF8    // stur x1, [fp, #imm9]
                || bits(w[i + 3], 9, 5) != 29 || bits(w[i + 3], 4, 0) != 1) {
            return false;
        }
        if ((w[i + 4] >>> 24) != 0xF9    // ldr x16, [x26(THR), #imm]
                || bits(w[i + 4], 9, 5) != 26 || bits(w[i + 4], 4, 0) != 16) {
            return false;
        }
        if ((w[i + 5] >>> 24) != 0xEB    // cmp x15(DartSP), x16 (subs zr)
                || bits(w[i + 5], 9, 5) != 15 || bits(w[i + 5], 20, 16) != 16
                || bits(w[i + 5], 4, 0) != 31) {
            return false;
        }
        if ((w[i + 6] >>> 24) != 0x54 || (w[i + 6] & 0xf) != 0x9) { // b.ls (cond 9)
            return false;
        }
        if ((w[i + 7] >>> 24) != 0xB8    // ldur wR, [x1, #imm9]  this->contracts
                || bits(w[i + 7], 9, 5) != 1 || bits(w[i + 7], 4, 0) == 31) {
            return false;
        }
        int imm9 = signExtend(bits(w[i + 7], 20, 12), 9);
        if (imm9 < 0x20 || imm9 > 0x60) {
            return false;
        }
        return (w[i + 8] >>> 24) == 0x8B // add xR, xR, x28(HEAP), lsl #32 (shift 0 = LSL)
                && bits(w[i + 8], 23, 22) == 0
                && bits(w[i + 8], 20, 16) == 28
                && bits(w[i + 8], 15, 10) == 32
                && bits(w[i + 8], 9, 5) == bits(w[i + 8], 4, 0);
    }

    /**
     * Returns the byte offset (from the function start) of the guard cbnz to
     * NOP, or -1 if this function does not match the getter shape.
     */
    private static long findGuard(int[] w, int i) {
        int first = findGdtTail(w, i + 9, i + 56);
        if (first < 0) {
            return -1;
        }
        int guard1 = first + 4; // the cbnz after the GDT call
        for (int k = guard1 + 1; k <= guard1 + 5; k++) {
            if (isLoadTrue(w[k])) {
                return (guard1 - i) * 4L; // true follows directly: NOP guard1
            }
        }
        for (int k = guard1 + 1; k <= guard1 + 4; k++) {
            if (isFpLoad(w[k])) {
                // second length guard later in the function
                int second = findGdtTail(w, guard1 + 1, guard1 + 72);
                if (second >= 0) {
                    int guard2 = second + 4;
                    for (int k2 = guard2 + 1; k2 <= guard2 + 5; k2++) {
                        if (isLoadTrue(w[k2])) {
                            return (guard2 - i) * 4L;
                        }
                    }
                }
                return -1;
            }
        }
        return -1;
    }

    /** Index of "movk x17,#1,lsl16; add lr,x0,x17; ldr lr,[x21,lr,lsr...]; blr lr" tail. */
    private static int findGdtTail(int[] w, int from, int to) {
        for (int j = from; j <= to - 4; j++) {
            if (w[j] == 0xF2A00031          // movk x17, #1, lsl #16
                    && w[j + 1] == 0x8B11001E // add lr, x0, x17
                    && w[j + 2] == 0xF87E7ABE // ldr lr, [x21, lr, lsl #3]
                    && w[j + 3] == 0xD63F03C0 // blr lr
                    && (w[j + 4] >>> 24) == 0x35) { // cbnz w0, ...
                return j;
            }
        }
        return -1;
    }

    /** add xR, x22(NULL), #0x20  =>  r = true */
    private static boolean isLoadTrue(int word) {
        return (word >>> 24) == 0x91
                && bits(word, 21, 10) == 0x20
                && bits(word, 9, 5) == 22;
    }

    /** ldur/stur xR, [fp, #imm]  (reload of a stack slot) */
    private static boolean isFpLoad(int word) {
        return (word >>> 24) == 0xF8 && bits(word, 9, 5) == 29;
    }

    static int bits(int word, int hi, int lo) {
        return (word >>> lo) & ((1 << (hi - lo + 1)) - 1);
    }

    private static int signExtend(int value, int width) {
        int shift = 32 - width;
        return (value << shift) >> shift;
    }

    private static String hex(long[] vals) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < vals.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append("0x").append(Long.toHexString(vals[i]));
        }
        return sb.append(']').toString();
    }
}
