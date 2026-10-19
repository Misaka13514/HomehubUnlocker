package de.robv.android.xposed;

import java.lang.reflect.Member;

/** Compile-only stub. Real implementation is provided by the Xposed framework at runtime. */
public abstract class XC_MethodHook {

  /** Compile-only stub. */
  public static class Unhook {
    public Member getHookedMethod() {
      throw new IllegalStateException("stub");
    }

    public void unhook() {
      throw new IllegalStateException("stub");
    }
  }

  /** Compile-only stub. */
  public static class MethodHookParam {
    public Member method;
    public Object thisObject;
    public Object[] args;
    private Object result = null;
    private Throwable throwable = null;

    public Object getResult() {
      return result;
    }

    public void setResult(Object result) {
      this.result = result;
      this.throwable = null;
    }

    public Throwable getThrowable() {
      return throwable;
    }

    public void setThrowable(Throwable throwable) {
      this.throwable = throwable;
      this.result = null;
    }

    public boolean hasThrowable() {
      return throwable != null;
    }
  }

  protected void beforeHookedMethod(MethodHookParam param) throws Throwable {}

  protected void afterHookedMethod(MethodHookParam param) throws Throwable {}
}
