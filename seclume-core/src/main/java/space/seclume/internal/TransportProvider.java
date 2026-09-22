package space.seclume.internal;

import java.io.IOException;

/**
 * Another way of reaching a server, offered by something that is not this
 * library.
 *
 * <p>The drivers open exactly one kind of connection themselves: a socket.
 * That is the transport every database conversation has always run on and the
 * one this project supports. Anything else - a descriptor opened through
 * syscalls, a connection that can be taken apart and rebuilt, a stack in user
 * space - is somebody else's concern, and this interface is where that
 * somebody attaches.
 *
 * <p><b>Found by name, through {@link java.util.ServiceLoader}.</b> A provider
 * on the class path says what it is called; a URL option or the system
 * property {@code seclume.transport} asks for it by that name. Nothing here
 * knows what any of them do, and no driver has to be changed when one appears.
 *
 * <p>Why a seam rather than an implementation: a transport that can be frozen
 * and thawed is a different product with a different licence, and a library
 * that has to be rebuilt to accept one is a library that decides for its
 * users. This way the decision is a jar on the class path.
 */
public interface TransportProvider {

    /**
     * The name this provider answers to - {@code socket} is taken.
     *
     * <p>Compared case-insensitively, because it arrives from a URL where
     * nobody is careful about case.
     */
    String name();

    /**
     * Whether it can be used on this machine, right now.
     *
     * <p>A provider that needs a kernel feature, a capability or a driver
     * answers honestly here, so that a name ending in {@code -if-available}
     * can fall back to the socket rather than failing a connection.
     */
    default boolean available() {
        return true;
    }

    /** Opens one connection, the way {@code SocketTransport.connect} would. */
    Transport connect(String host, int port, int connectTimeoutMillis) throws IOException;
}
