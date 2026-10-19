package net.apeiria.homehubunlocker;

import android.system.Os;
import android.system.OsConstants;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Locates the Dart AOT image (libapp.so) inside the current process and provides
 * read/write access to it through /proc/self/mem.
 *
 * The app ships with {@code android:extractNativeLibs="false"}, so libapp.so is
 * never unpacked to disk: the dynamic linker maps it straight out of the split
 * APK (split_config.arm64_v8a.apk). To translate Dart snapshot vaddrs into
 * runtime addresses we therefore:
 *
 *   1. read /proc/self/maps and collect the file-backed mappings of every APK,
 *   2. parse the APK zip central directory to find the libapp.so entry and the
 *      file offset of its ELF header (D),
 *   3. parse the ELF program headers of libapp.so,
 *   4. map vaddr -> file offset (D + p_offset + (v - p_vaddr)) -> the maps
 *      entry covering that file page -> runtime address.
 *
 * A directly extracted libapp.so (offset == 0 mapping) is also supported for
 * builds that change the extraction behaviour.
 */
final class DartImage {

    private static final String TAG = "HomehubUnlocker";
    private static final String LIB_NAME = "libapp.so";
    private static final String LIB_ZIP_ENTRY = "lib/arm64-v8a/libapp.so";

    /** One file-backed mapping from /proc/self/maps. */
    private static class MapLine {
        final long start;
        final long end;
        final long fileOffset;
        final String path;

        MapLine(long start, long end, long fileOffset, String path) {
            this.start = start;
            this.end = end;
            this.fileOffset = fileOffset;
            this.path = path;
        }

        long length() {
            return end - start;
        }
    }

    /** One PT_LOAD segment of libapp.so. */
    private static class Segment {
        final long flags;
        final long offset;
        final long vaddr;
        final long filesz;

        Segment(long flags, long offset, long vaddr, long filesz) {
            this.flags = flags;
            this.offset = offset;
            this.vaddr = vaddr;
            this.filesz = filesz;
        }
    }

    private final List<MapLine> maps;
    private final String sourcePath; // apk or .so path hosting the image
    private final long elfFileOffset; // file offset of the ELF header inside sourcePath
    private final List<Segment> segments;
    private final FileDescriptor mem;

    private DartImage(List<MapLine> maps, String sourcePath, long elfFileOffset,
            List<Segment> segments, FileDescriptor mem) {
        this.maps = maps;
        this.sourcePath = sourcePath;
        this.elfFileOffset = elfFileOffset;
        this.segments = segments;
        this.mem = mem;
    }

    static DartImage locate() throws IOException {
        List<MapLine> maps = readMaps();

        // Case 1: libapp.so mapped as a plain file (extractNativeLibs="true").
        for (MapLine line : maps) {
            if (line.path != null && line.path.endsWith("/" + LIB_NAME) && line.fileOffset == 0) {
                FileDescriptor mem = openMem();
                DartImage img = new DartImage(maps, line.path, 0, null, mem);
                if (img.checkElfHeader(img.addr(0))) {
                    return img;
                }
                closeQuietly(mem);
            }
        }

        // Case 2: libapp.so mapped from inside an APK.
        List<String> apkPaths = new ArrayList<>();
        for (MapLine line : maps) {
            if (line.path != null && line.path.endsWith(".apk") && !apkPaths.contains(line.path)) {
                apkPaths.add(line.path);
            }
        }
        for (String apk : apkPaths) {
            long elfOff = findZipEntryOffset(apk, LIB_ZIP_ENTRY);
            if (elfOff < 0) {
                continue;
            }
            List<Segment> segments = readSegments(apk, elfOff);
            if (segments == null || segments.isEmpty()) {
                continue;
            }
            FileDescriptor mem = openMem();
            DartImage img = new DartImage(maps, apk, elfOff, segments, mem);
            if (img.checkElfHeader(img.addr(0))) {
                return img;
            }
            closeQuietly(mem);
        }
        return null;
    }

    private static List<MapLine> readMaps() throws IOException {
        RandomAccessFile raf = new RandomAccessFile("/proc/self/maps", "r");
        List<MapLine> out = new ArrayList<>();
        String line;
        while ((line = raf.readLine()) != null) {
            int space = line.indexOf(' ');
            if (space < 0) {
                continue;
            }
            String[] range = line.substring(0, space).split("-");
            if (range.length != 2) {
                continue;
            }
            // fields: perms offset dev inode pathname (pathname may contain
            // spaces, so split with a limit and keep the remainder intact)
            String[] rest = line.substring(space + 1).trim().split("\\s+", 5);
            if (rest.length < 5 || rest[0].length() != 4) {
                continue; // anonymous or special mapping
            }
            String path = rest[4];
            if (path.startsWith("[") || path.isEmpty()) {
                continue;
            }
            out.add(new MapLine(Long.parseUnsignedLong(range[0], 16),
                    Long.parseUnsignedLong(range[1], 16),
                    Long.parseUnsignedLong(rest[1], 16), path));
        }
        raf.close();
        return out;
    }

    /**
     * Returns the file offset of the stored (uncompressed) data of {@code name}
     * inside the zip at {@code apk}, or -1.
     */
    private static long findZipEntryOffset(String apk, String name) throws IOException {
        RandomAccessFile raf = new RandomAccessFile(apk, "r");
        try {
            long fileLen = raf.length();
            int tail = (int) Math.min(fileLen, 65557 + 22);
            byte[] buf = new byte[tail];
            raf.seek(fileLen - tail);
            raf.readFully(buf);
            int eocd = -1;
            for (int i = buf.length - 22; i >= 0; i--) {
                if (buf[i] == 0x50 && buf[i + 1] == 0x4b && buf[i + 2] == 0x05
                        && buf[i + 3] == 0x06) {
                    eocd = i;
                    break;
                }
            }
            if (eocd < 0) {
                return -1;
            }
            long cdOffset = u32(buf, eocd + 16);
            int cdCount = u16(buf, eocd + 10);
            raf.seek(cdOffset);
            byte[] cd = new byte[(int) Math.min(fileLen - cdOffset, 1 << 20)];
            int cdRead = raf.read(cd);
            int pos = 0;
            for (int i = 0; i < cdCount && pos + 46 <= cdRead; i++) {
                if (u32(cd, pos) != 0x02014b50) {
                    break;
                }
                int nameLen = u16(cd, pos + 28);
                int extraLen = u16(cd, pos + 30);
                int commentLen = u16(cd, pos + 32);
                long localHeader = u32(cd, pos + 42);
                String entry = new String(cd, pos + 46, nameLen, "UTF-8");
                if (entry.equals(name)) {
                    byte[] lfh = new byte[30];
                    raf.seek(localHeader);
                    raf.readFully(lfh);
                    if (u32(lfh, 0) != 0x04034b50) {
                        return -1;
                    }
                    return localHeader + 30 + u16(lfh, 26) + u16(lfh, 28);
                }
                pos += 46 + nameLen + extraLen + commentLen;
            }
            return -1;
        } finally {
            raf.close();
        }
    }

    /** Parses PT_LOAD segments of the ELF at {@code elfOff} inside {@code apk}. */
    private static List<Segment> readSegments(String apk, long elfOff) throws IOException {
        RandomAccessFile raf = new RandomAccessFile(apk, "r");
        try {
            byte[] eh = new byte[64];
            raf.seek(elfOff);
            raf.readFully(eh);
            if (u32(eh, 0) != 0x464c457f) {
                return null; // not an ELF
            }
            long phoff = u64(eh, 0x20);
            int phentsize = u16(eh, 0x36);
            int phnum = u16(eh, 0x38);
            List<Segment> out = new ArrayList<>();
            byte[] ph = new byte[phentsize];
            for (int i = 0; i < phnum; i++) {
                raf.seek(elfOff + phoff + (long) i * phentsize);
                raf.readFully(ph);
                if (u32(ph, 0) != 1) {
                    continue; // PT_LOAD only
                }
                out.add(new Segment(u32(ph, 4), u64(ph, 8), u64(ph, 16), u64(ph, 32)));
            }
            return out;
        } finally {
            raf.close();
        }
    }

    private static FileDescriptor openMem() {
        try {
            return Os.open("/proc/self/mem", OsConstants.O_RDWR, 0);
        } catch (Exception e) {
            // SELinux on hardened ROMs denies the app domain opening
            // /proc/self/mem; fall back to sun.misc.Unsafe for access.
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Unsafe fallback memory access (used when /proc/self/mem is denied)
    // ------------------------------------------------------------------

    private static Object unsafe;
    private static java.lang.reflect.Method getIntMethod;
    private static java.lang.reflect.Method putIntMethod;

    private static void initUnsafe() throws IOException {
        if (unsafe != null) {
            return;
        }
        try {
            Class<?> c = Class.forName("sun.misc.Unsafe");
            java.lang.reflect.Field f = c.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            unsafe = f.get(null);
            getIntMethod = c.getMethod("getInt", long.class);
            putIntMethod = c.getMethod("putInt", long.class, int.class);
        } catch (Throwable t) {
            throw new IOException("sun.misc.Unsafe unavailable: " + t);
        }
    }

    private static Method protectMethod;  // mprotect(address, byteCount, protection)
    private static Object protectTarget;  // null for static, else receiver
    private static boolean protectLong;    // address/size params are long
    private static boolean protectResolved;

    /**
     * Resolves an mprotect entry point. android.system.Os does not expose
     * mprotect in the public SDK, but the runtime class may carry it as a
     * hidden method; libcore.io.Libcore.os works as a second chance.
     */
    private static void initProtect() throws IOException {
        if (protectResolved) {
            if (protectMethod == null) {
                throw new IOException("no mprotect entry point: " + protectWhy);
            }
            return;
        }
        protectResolved = true;
        StringBuilder why = new StringBuilder();
        exemptHiddenApis(why);

        try {
            int osMethods = 0;
            StringBuilder seen = new StringBuilder();
            for (Method m : Os.class.getDeclaredMethods()) {
                osMethods++;
                String n = m.getName();
                if (n.contains("prot") || n.contains("map")) {
                    if (seen.length() > 0) {
                        seen.append(',');
                    }
                    seen.append(n);
                }
                if ("mprotect".equals(m.getName())) {
                    Class<?>[] pt = m.getParameterTypes();
                    if (pt.length == 3 && pt[2] == int.class
                            && (pt[0] == long.class || pt[0] == int.class)) {
                        m.setAccessible(true);
                        protectMethod = m;
                        protectTarget = null; // static
                        protectLong = pt[0] == long.class;
                        return;
                    }
                }
            }
            why.append("Os has ").append(osMethods).append(" methods (prot/map: ")
                    .append(seen).append("); ");
        } catch (Throwable t) {
            why.append("Os scan failed: ").append(t).append("; ");
        }

        for (String cn : new String[] {"libcore.io.Libcore", "libcore.io.Linux", "libcore.io.Android"}) {
            try {
                Class<?> c = Class.forName(cn);
                Object impl = c;
                try {
                    java.lang.reflect.Field f = c.getDeclaredField("os");
                    f.setAccessible(true);
                    impl = f.get(null);
                } catch (Throwable ignored) {
                    // Linux/Android are the impl themselves; no "os" field
                }
                for (Method m : impl.getClass().getDeclaredMethods()) {
                    if ("mprotect".equals(m.getName())) {
                        Class<?>[] pt = m.getParameterTypes();
                        if (pt.length == 3 && pt[2] == int.class
                                && (pt[0] == long.class || pt[0] == int.class)) {
                            m.setAccessible(true);
                            protectMethod = m;
                            protectTarget = impl;
                            protectLong = pt[0] == long.class;
                            return;
                        }
                    }
                }
                why.append(cn).append(" found but has no matching mprotect; ");
            } catch (Throwable t) {
                why.append(cn).append(": ").append(t.getClass().getSimpleName()).append("; ");
            }
        }
        protectWhy = why.toString();
        throw new IOException("no mprotect entry point: " + protectWhy);
    }

    private static String protectWhy;

    /** Best-effort removal of hidden-API reflection restrictions. */
    private static void exemptHiddenApis(StringBuilder why) {
        try {
            Method forName = Class.class.getDeclaredMethod("forName", String.class);
            Method getDeclaredMethod = Class.class.getDeclaredMethod(
                    "getDeclaredMethod", String.class, Class[].class);
            Class<?> vmRuntimeClass = (Class<?>) forName.invoke(null, "dalvik.system.VMRuntime");
            Method getRuntime = (Method) getDeclaredMethod.invoke(
                    vmRuntimeClass, new Object[] {"getRuntime", null});
            Method setExemptions = (Method) getDeclaredMethod.invoke(
                    vmRuntimeClass, new Object[] {"setHiddenApiExemptions",
                        new Class[] {String[].class}});
            Object runtime = getRuntime.invoke(null);
            setExemptions.invoke(runtime, new Object[] {new String[] {"L"}});
        } catch (Throwable t) {
            why.append("hidden-api exemption failed: ").append(t.getClass().getSimpleName());
            why.append(" (").append(String.valueOf(t.getMessage())).append("); ");
        }
    }

    // ------------------------------------------------------------------
    // Anonymous RWX overlay via Os.mmap (fallback when mprotect is absent).
    //
    // Making an APK-backed executable page writable trips SELinux execmod,
    // but anonymous RWX mappings only need process:execmem, which every app
    // domain holds for the JIT. We therefore re-map the two pages holding
    // the patch site as a private anonymous RWX overlay, restore their
    // contents and apply the patch inside it.
    // ------------------------------------------------------------------

    private static Method mmapMethod;
    private static Class<?>[] mmapParams;
    private static String mmapSig;

    private static void initMmap(StringBuilder why) throws IOException {
        if (mmapMethod != null) {
            return;
        }
        for (Method m : Os.class.getDeclaredMethods()) {
            if (!"mmap".equals(m.getName())) {
                continue;
            }
            Class<?>[] pt = m.getParameterTypes();
            mmapSig = java.util.Arrays.toString(pt);
            if (pt.length == 6 && pt[0] == long.class && pt[1] == long.class
                    && pt[2] == int.class && pt[3] == int.class
                    && (pt[4] == FileDescriptor.class || pt[4] == int.class)
                    && pt[5] == long.class) {
                m.setAccessible(true);
                mmapMethod = m;
                mmapParams = pt;
                return;
            }
        }
        throw new IOException("Os.mmap not usable, signature " + mmapSig
                + (why.length() > 0 ? " [" + why + "]" : ""));
    }

    private static void overlayWritable(long page, int len) throws IOException {
        initMmap(new StringBuilder());
        try {
            // mmap(address, byteCount, prot, flags, fd, offset) with
            // MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS: fd ignored for anonymous.
            Object fdArg = mmapParams[4] == FileDescriptor.class ? null : Integer.valueOf(-1);
            mmapMethod.invoke(null, page, (long) len,
                    OsConstants.PROT_READ | OsConstants.PROT_WRITE | OsConstants.PROT_EXEC,
                    0x10 | 0x02 | 0x20, fdArg, 0L);
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            throw new IOException("mmap overlay @0x" + Long.toHexString(page) + ": " + cause);
        }
    }

    private static void protect(long addr, int len, int prot) throws IOException {
        initProtect();
        try {
            if (protectLong) {
                protectMethod.invoke(protectTarget, addr, (long) len, prot);
            } else {
                protectMethod.invoke(protectTarget, (int) addr, len, prot);
            }
        } catch (Exception e) {
            throw new IOException("mprotect @0x" + Long.toHexString(addr) + ": " + e);
        }
    }

    private static void unsafeWriteWord(long addr, int word) throws IOException {
        initUnsafe();
        long page = addr & ~0xfffL;
        int len = (int) (((addr + 4 + 0xfffL) & ~0xfffL) - page);

        // Strategy 1: private anonymous RWX overlay (no execmod needed).
        IOException overlayError;
        try {
            byte[] snapshot = unsafeRead(page, len);
            overlayWritable(page, len);
            try {
                for (int i = 0; i + 4 <= snapshot.length; i += 4) {
                    int v = (snapshot[i] & 0xff) | ((snapshot[i + 1] & 0xff) << 8)
                            | ((snapshot[i + 2] & 0xff) << 16) | (snapshot[i + 3] << 24);
                    putIntMethod.invoke(unsafe, page + i, v);
                }
                putIntMethod.invoke(unsafe, addr, word);
                return;
            } catch (Exception e) {
                throw new IOException("putInt @0x" + Long.toHexString(addr) + ": " + e);
            }
        } catch (IOException e) {
            overlayError = e;
        }

        // Strategy 2: mprotect RW -> write -> restore RX (when available).
        protect(page, len, OsConstants.PROT_READ | OsConstants.PROT_WRITE);
        try {
            putIntMethod.invoke(unsafe, addr, word);
        } catch (Exception e) {
            throw new IOException("putInt @0x" + Long.toHexString(addr) + ": " + e
                    + " [overlay failed first: " + overlayError + "]");
        } finally {
            try {
                protect(page, len, OsConstants.PROT_READ | OsConstants.PROT_EXEC);
            } catch (IOException ignored) {
            }
        }
    }

    private int unsafeReadWord(long addr) throws IOException {
        initUnsafe();
        try {
            return (Integer) getIntMethod.invoke(unsafe, addr);
        } catch (Exception e) {
            throw new IOException("getInt @0x" + Long.toHexString(addr) + ": " + e);
        }
    }

    private static byte[] unsafeRead(long addr, int len) throws IOException {
        initUnsafe();
        byte[] out = new byte[len];
        try {
            for (int i = 0; i + 4 <= len; i += 4) {
                int v = (Integer) getIntMethod.invoke(unsafe, addr + i);
                out[i] = (byte) v;
                out[i + 1] = (byte) (v >> 8);
                out[i + 2] = (byte) (v >> 16);
                out[i + 3] = (byte) (v >> 24);
            }
        } catch (Exception e) {
            throw new IOException("bulk getInt @0x" + Long.toHexString(addr) + ": " + e);
        }
        return out;
    }

    /** Runtime address of a Dart snapshot vaddr. */
    long addr(long vaddr) throws IOException {
        if (segments == null) {
            // direct mapping, ELF header at file offset 0
            for (MapLine line : maps) {
                if (line.path.equals(sourcePath)) {
                    return line.start - line.fileOffset + vaddr;
                }
            }
            throw new IOException("libapp.so mapping vanished");
        }
        for (Segment seg : segments) {
            if (vaddr >= seg.vaddr && vaddr < seg.vaddr + seg.filesz) {
                long fileOff = elfFileOffset + seg.offset + (vaddr - seg.vaddr);
                return fileToAddr(fileOff);
            }
        }
        throw new IOException("vaddr 0x" + Long.toHexString(vaddr) + " not inside any PT_LOAD");
    }

    private long fileToAddr(long fileOff) throws IOException {
        long page = fileOff & ~0xfffL;
        for (MapLine line : maps) {
            if (line.path.equals(sourcePath)
                    && page >= line.fileOffset
                    && page < line.fileOffset + line.length()) {
                return line.start + (page - line.fileOffset) + (fileOff & 0xfffL);
            }
        }
        throw new IOException("file offset 0x" + Long.toHexString(fileOff)
                + " of " + sourcePath + " is not mapped");
    }

    /** Executable PT_LOAD segment (vaddr, filesz) for signature scanning. */
    long[] execSegment() {
        for (Segment seg : segments) {
            if ((seg.flags & 0x1) != 0) {
                return new long[] {seg.vaddr, seg.filesz};
            }
        }
        return null;
    }

    private boolean checkElfHeader(long at) {
        try {
            byte[] magic = read(at, 4);
            return magic != null && magic[0] == 0x7f && magic[1] == 0x45
                    && magic[2] == 0x4c && magic[3] == 0x46;
        } catch (Exception e) {
            return false;
        }
    }

    byte[] read(long addr, int len) throws IOException {
        if (mem == null) {
            return unsafeRead(addr, len);
        }
        byte[] out = new byte[len];
        try {
            Os.pread(mem, out, 0, len, addr);
            return out;
        } catch (Exception e) {
            throw new IOException("pread @0x" + Long.toHexString(addr) + " failed: " + e);
        }
    }

    void writeWord(long addr, int word) throws IOException {
        if (mem == null) {
            unsafeWriteWord(addr, word);
            return;
        }
        try {
            Os.pwrite(mem, ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
                    .putInt(word).array(), 0, 4, addr);
        } catch (Exception e) {
            throw new IOException("pwrite @0x" + Long.toHexString(addr) + " failed: " + e);
        }
    }

    int readWord(long addr) throws IOException {
        if (mem == null) {
            return unsafeReadWord(addr);
        }
        ByteBuffer bb = ByteBuffer.wrap(read(addr, 4)).order(ByteOrder.LITTLE_ENDIAN);
        return bb.getInt();
    }

    /** Human-readable name of the active memory-access channel. */
    String accessMode() {
        return mem != null ? "/proc/self/mem" : "sun.misc.Unsafe";
    }

    void close() {
        closeQuietly(mem);
    }

    private static void closeQuietly(FileDescriptor fd) {
        try {
            Os.close(fd);
        } catch (Exception ignored) {
        }
    }

    private static int u16(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8);
    }

    private static long u32(byte[] b, int off) {
        return (u16(b, off) & 0xffffffffL) | (u16(b, off + 2) << 16);
    }

    private static long u64(byte[] b, int off) {
        return u32(b, off) | (u32(b, off + 4) << 32);
    }
}
