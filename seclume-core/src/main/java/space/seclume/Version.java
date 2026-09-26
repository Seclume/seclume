package space.seclume;

/**
 * Which build of seclume is running - from the jar's manifest.
 *
 * <p>For the report a support request starts with, and for an application
 * that logs what it runs on. Code that did not come from a jar - the tests,
 * an IDE's build - has no manifest to read, and says so instead of guessing.
 */
public final class Version {

    private Version() {
    }

    /** The version, {@code 0.10.0} say - or {@code "development"} outside a jar. */
    public static String current() {
        String version = Version.class.getPackage().getImplementationVersion();
        return version == null || version.isBlank() ? "development" : version;
    }
}
