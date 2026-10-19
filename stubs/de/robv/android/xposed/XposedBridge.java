package de.robv.android.xposed;

/** Compile-only stub. Real implementation is provided by the Xposed framework at runtime. */
public final class XposedBridge {
  private XposedBridge() {}

  public static void log(String text) {
    throw new IllegalStateException("stub");
  }

  public static void log(Throwable t) {
    throw new IllegalStateException("stub");
  }
}
