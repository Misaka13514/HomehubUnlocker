package net.apeiria.homehubunlocker;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import java.lang.reflect.Method;

/**
 * LSPosed module for app.jp.co.bitkey.homehub.
 *
 * The home management company can issue "sub-owner" contracts that clear the
 * canNfcSetting / canPasscodeSetting flags, which hides the passcode and NFC
 * card registration menus in the app even though the device itself accepts
 * them. This module NOPs the guard branch of those permission getters inside
 * the Dart AOT image (libapp.so) so they return true via the app's own
 * fail-open path, revealing the hidden menus.
 */
public final class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "HomehubUnlocker";

    private final Patcher patcher = new Patcher();

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!PatchPlan.TARGET_PACKAGE.equals(lpparam.packageName)) {
            return;
        }
        // Only the main process hosts the Flutter engine.
        if (!lpparam.packageName.equals(lpparam.processName)) {
            return;
        }
        log("loaded in " + lpparam.processName);

        // Preferred anchor: patch right before Dart main() executes. At this
        // point libapp.so is mapped but its code has never run, so there are
        // no stale icache lines for the patched words.
        try {
            Class<?> exec = Class.forName(
                    "io.flutter.embedding.engine.dart.DartExecutor", false, lpparam.classLoader);
            XC_MethodHook anchor = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    patcher.run("dart-entrypoint");
                }
            };
            int hooked = 0;
            for (Method m : exec.getDeclaredMethods()) {
                if (!"executeDartEntrypoint".equals(m.getName())) {
                    continue;
                }
                Class<?>[] pt = m.getParameterTypes();
                Object[] args = new Object[pt.length + 1];
                System.arraycopy(pt, 0, args, 0, pt.length);
                args[pt.length] = anchor;
                try {
                    XposedHelpers.findAndHookMethod(exec, "executeDartEntrypoint", args);
                    hooked++;
                } catch (Throwable ignored) {
                }
            }
            log("hooked executeDartEntrypoint overloads: " + hooked);
        } catch (Throwable t) {
            log("entrypoint hook unavailable: " + t);
        }

        // Watchdog: patch as soon as libapp.so shows up in the maps, in case
        // the entrypoint hook could not be installed.
        Thread watchdog = new Thread(new Runnable() {
            @Override
            public void run() {
                for (int i = 0; i < 120 && !patcher.isDone(); i++) {
                    try {
                        patcher.run("watchdog");
                    } catch (Throwable ignored) {
                    }
                    if (patcher.isDone()) {
                        return;
                    }
                    try {
                        Thread.sleep(250);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
            }
        }, "HomehubUnlocker-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    /** Applies the patch exactly once per process. */
    private static final class Patcher {

        private boolean done;

        synchronized boolean isDone() {
            return done;
        }

        synchronized void run(String trigger) {
            if (done) {
                return;
            }
            DartImage img = null;
            try {
                img = DartImage.locate();
                if (img == null) {
                    return; // libapp.so not mapped yet
                }
                String version = appVersionName();
                log("libapp.so located via " + trigger + "; app version " + version
                        + "; memory access: " + img.accessMode());

                StringBuilder sb = new StringBuilder();
                long[] sites = PatchPlan.resolve(img, version, sb);
                for (String line : sb.toString().split("\n")) {
                    if (!line.isEmpty()) {
                        log("  " + line);
                    }
                }

                int applied = 0;
                for (long vaddr : sites) {
                    long addr = img.addr(vaddr);
                    int word = img.readWord(addr);
                    if (word == 0xD503201F) {
                        log("0x" + Long.toHexString(vaddr) + " already patched");
                        applied++;
                        continue;
                    }
                    int top = (word >>> 24) & 0xff;
                    // cbz/cbnz/tbz/tbnz, 32/64 bit — sanity-check that the
                    // configured offset really points at a guard branch.
                    if (top != 0x34 && top != 0x35 && top != 0xB4 && top != 0xB5) {
                        log("0x" + Long.toHexString(vaddr) + " skipped: word 0x"
                                + Integer.toHexString(word) + " is not a guard branch");
                        continue;
                    }
                    img.writeWord(addr, 0xD503201F);
                    int verify = img.readWord(addr);
                    if (verify == 0xD503201F) {
                        log("0x" + Long.toHexString(vaddr) + " patched (was 0x"
                                + Integer.toHexString(word) + ")");
                        applied++;
                    } else {
                        log("0x" + Long.toHexString(vaddr) + " verify FAILED (read back 0x"
                                + Integer.toHexString(verify) + ")");
                    }
                }
                log("patched " + applied + "/" + sites.length + " site(s)");
                done = applied > 0 || sites.length == 0;
            } catch (Throwable t) {
                String msg = String.valueOf(t);
                if (!msg.equals(lastError)) {
                    lastError = msg;
                    log("patch failed via " + trigger + ": " + t);
                    XposedBridge.log(t);
                }
            } finally {
                if (img != null) {
                    img.close();
                }
            }
        }

        private String lastError;
    }

    private static String appVersionName() {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object app = XposedHelpers.callStaticMethod(at, "currentApplication");
            if (app == null) {
                return null;
            }
            Object pm = XposedHelpers.callMethod(app, "getPackageManager");
            Object info = XposedHelpers.callMethod(pm, "getPackageInfo",
                    PatchPlan.TARGET_PACKAGE, 0);
            return (String) XposedHelpers.getObjectField(info, "versionName");
        } catch (Throwable t) {
            return null;
        }
    }

    private static void log(String msg) {
        XposedBridge.log("[" + TAG + "] " + msg);
    }
}
