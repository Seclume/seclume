package space.seclume;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * How a connection proved who it was, and what is carrying it.
 *
 * <p>Two facts every driver here knows about itself and no JDBC method asks
 * for. {@link java.sql.DatabaseMetaData} will tell you the server's version
 * and its keyword list; it has nothing to say about whether the password went
 * over the wire under SCRAM or under a cipher nobody should still be using,
 * and nothing about whether there was a cipher at all.
 *
 * <p><b>Why that is worth an interface.</b> A driver whose reason for
 * existing is what happens to a credential should be able to state what
 * happened to it - and the people who most need the answer are the ones least
 * able to get it: an operator looking at a connection they did not configure,
 * on a server somebody else set up, asking the only question that matters
 * before a migration. "TLS is on" is a setting; this is the connection saying
 * what it actually negotiated.
 *
 * <p>It is also what makes a generated compatibility table able to carry an
 * authentication row and a TLS row without anybody typing one in.
 *
 * <p><b>No secret ever passes through here.</b> The method's name, the
 * protocol version, the cipher suite - never a key, never a fingerprint, never
 * anything a hash of a short secret could be recovered from. See
 * {@code seclume-heapcheck} for why that distinction is taken seriously.
 */
public interface Secured {

    /**
     * What the server demanded and this driver did, by name.
     *
     * <p>For example {@code SCRAM-SHA-256}, {@code caching_sha2_password},
     * {@code O5LOGON (12c verifier)}. The wording is the protocol's, not this
     * library's, because the person reading it is going to search for it.
     */
    String authenticationMethod();

    /**
     * The protocol, the cipher suite and which stack carried it - or
     * {@code null} where the connection is in the clear.
     *
     * <p>Which stack is not decoration: both of them negotiate TLS 1.3 with
     * the same suites against the same server, so "TLSv1.3" alone says nothing
     * about whether the traffic secrets were ever Java objects.
     */
    String tlsDescription();

    /**
     * The certificate the server presented, or {@code null} in the clear.
     *
     * <p>Whether it was checked depends on the connection's settings - this
     * says what was shown, not that it was trusted. {@code seclume-verify
     * --print-pin} prints its pin from here, ready for {@code tlsPin}.
     */
    default java.security.cert.X509Certificate serverCertificate() {
        return null;
    }

    /**
     * The facts of any seclume connection - also through a pool.
     *
     * @throws SQLException if this is not a seclume connection
     */
    static Secured of(Connection connection) throws SQLException {
        if (connection instanceof Secured secured) {
            return secured;
        }
        if (connection.isWrapperFor(Secured.class)) {
            return connection.unwrap(Secured.class);
        }
        throw new SQLException("this is not a seclume connection, so it cannot say how it was "
                + "authenticated: " + connection.getClass().getName());
    }
}
