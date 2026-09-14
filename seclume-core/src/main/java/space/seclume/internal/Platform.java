package space.seclume.internal;

import java.util.Locale;

/** Which operating system we are running on. */
public final class Platform {

    private static final String OS = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);

    private Platform() {
    }

    public static boolean isWindows() {
        return OS.contains("win");
    }

    public static boolean isMac() {
        return OS.contains("mac");
    }

    public static boolean isLinux() {
        return OS.contains("linux");
    }
}
