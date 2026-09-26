package space.seclume.tck.fuzz;

import java.io.IOException;

import space.seclume.internal.Transport;
import space.seclume.internal.TransportProvider;

/**
 * A server made of bytes somebody wrote down, reachable through the URL.
 *
 * <p>{@link HostileTransport} can be handed to {@code resume()}, which skips
 * the login. That is most of the decoder surface and none of the part that
 * matters most: <b>the login is where the credential is</b>. A password is
 * read from its provider, hashed or wrapped, written into a packet and sent -
 * and if the server goes away in the middle of that, the question is not what
 * the driver decodes but whether the secret is still in memory afterwards.
 *
 * <p>Reaching {@code open()} needs a transport the driver chose for itself,
 * and {@link space.seclume.internal.Transports} already has the seam: a
 * provider on the class path, asked for by name. So a test says
 * {@code transport=scripted} in the URL, leaves the script here, and the
 * driver logs in against it believing it is a socket.
 *
 * <p><b>The script is per thread</b>, because the tests that use this run one
 * case after another on one thread and a static field shared between them
 * would make a failure depend on what ran before it.
 */
public final class ScriptedTransportProvider implements TransportProvider {

    /** The name a URL asks for: {@code transport=scripted}. */
    public static final String NAME = "scripted";

    private static final ThreadLocal<byte[]> SCRIPT = new ThreadLocal<>();
    private static final ThreadLocal<int[]> CHUNKS = new ThreadLocal<>();
    private static final ThreadLocal<HostileTransport> LAST = new ThreadLocal<>();

    /**
     * What the next connection on this thread will be answered with.
     *
     * @param chunks how the bytes arrive, repeating; empty for one block
     */
    public static void nextScript(byte[] script, int... chunks) {
        SCRIPT.set(script);
        CHUNKS.set(chunks);
        LAST.remove();
    }

    /** Forgets the script, so a stray connection fails loudly rather than oddly. */
    public static void clear() {
        SCRIPT.remove();
        CHUNKS.remove();
        LAST.remove();
    }

    /** The transport the last connection got - for a test that asks what was read. */
    public static HostileTransport last() {
        return LAST.get();
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Transport connect(String host, int port, int connectTimeoutMillis)
            throws IOException {
        byte[] script = SCRIPT.get();
        if (script == null) {
            throw new IOException("no script was left for this thread - "
                    + "ScriptedTransportProvider.nextScript was not called");
        }
        int[] chunks = CHUNKS.get();
        HostileTransport transport = chunks == null || chunks.length == 0
                ? HostileTransport.of(script)
                : HostileTransport.of(script, chunks);
        LAST.set(transport);
        return transport;
    }
}
