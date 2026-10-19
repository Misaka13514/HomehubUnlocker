package de.robv.android.xposed;

/** Compile-only stub. Real implementation is provided by the Xposed framework at runtime. */
public final class XposedHelpers {
  private XposedHelpers() {}

  public static XC_MethodHook.Unhook findAndHookMethod(
      Class<?> clazz, String methodName, Object... parameterTypesAndCallback) {
    throw new IllegalStateException("stub");
  }

  public static XC_MethodHook.Unhook findAndHookMethod(
      String className,
      ClassLoader classLoader,
      String methodName,
      Object... parameterTypesAndCallback) {
    throw new IllegalStateException("stub");
  }

  public static Object callMethod(Object obj, String methodName, Object... args) {
    throw new IllegalStateException("stub");
  }

  public static Object callStaticMethod(Class<?> clazz, String methodName, Object... args) {
    throw new IllegalStateException("stub");
  }

  public static Object getObjectField(Object obj, String fieldName) {
    throw new IllegalStateException("stub");
  }
}
