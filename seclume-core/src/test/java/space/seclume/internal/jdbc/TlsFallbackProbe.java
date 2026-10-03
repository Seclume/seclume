package space.seclume.internal.jdbc;

/** For the TLS tests in another package: what TlsFallback would make of a failure. */
public final class TlsFallbackProbe {

    private TlsFallbackProbe() {
    }

    public static boolean wouldFallBack(Throwable failure) {
        return TlsFallback.versionRefused(failure) != null;
    }
}
