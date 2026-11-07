package space.seclume.ldap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.internal.TlsLayer;
import space.seclume.internal.Transport;

/**
 * Where the placeholder becomes the password, without a server: only in a
 * simple bind as the user it was made for, on a connection to the server it
 * was made for. Spring Security binds an end user with what they typed over
 * the same socket factory - so a placeholder typed into a login form, by
 * someone who read it in a heap dump or guessed it, must not log them in as
 * the application, and one registration's password must not go to another
 * registered server.
 */
class LdapPlaceholderSlotTest {

    private static final String PASSWORD = "the-service-password";
    private static final String SERVICE = "cn=app,ou=services,dc=example,dc=com";
    private static final String ALICE = "uid=alice,ou=people,dc=example,dc=com";

    @TempDir
    Path dir;

    /** A TLS layer that is a buffer: what was written to it, in order. */
    private static final class Written implements TlsLayer {
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        @Override
        public void write(ByteBuffer plain) {
            byte[] copy = new byte[plain.remaining()];
            plain.get(copy);
            bytes.writeBytes(copy);
        }

        @Override
        public int read(ByteBuffer target) {
            return -1;
        }

        @Override
        public X509Certificate peerCertificate() {
            return null;
        }

        @Override
        public String description() {
            return "written";
        }

        @Override
        public boolean movable() {
            return false;
        }

        @Override
        public void replaceTransport(Transport replacement) {
        }

        @Override
        public void discard() {
        }

        @Override
        public void close() {
        }
    }

    @AfterEach
    void forgetTheServers() {
        SeclumeLdap.BY_AUTHORITY.clear();
    }

    private String secretFile(String content) throws IOException {
        Path file = Files.createTempFile(dir, "ldap", ".pw");
        Files.writeString(file, content);
        return file.toString().replace('\\', '/');
    }

    private SeclumeLdap registered(String authority, String user, String password)
            throws IOException {
        return SeclumeLdap.of("ldaps://" + authority + "/dc=example,dc=com?user=" + user
                + "&provider=file&path=" + secretFile(password));
    }

    private SeclumeLdap registered() throws IOException {
        return registered("ldap.example.com:636", SERVICE, PASSWORD);
    }

    private SeclumeLdap kerberos(String authority) throws IOException {
        return SeclumeLdap.of("ldaps://" + authority + "/dc=example,dc=com?authentication=kerberos",
                () -> {
                    throw new AssertionError("no Kerberos bind was to be started");
                });
    }

    /** What a connection to {@code authority} sends for these writes. */
    private static byte[] sent(String authority, byte[]... messages) throws IOException {
        Written wire = new Written();
        LdapSocket socket = new LdapSocket(SeclumeLdap.BY_AUTHORITY.get(authority), wire);
        OutputStream out = socket.getOutputStream();
        for (byte[] message : messages) {
            out.write(message);
        }
        return wire.bytes.toByteArray();
    }

    // ---- BER, as JNDI writes it -----------------------------------------------------

    private static byte[] tlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int length = content.length;
        if (length < 0x80) {
            out.write(length);
        } else {
            int size = length < 0x100 ? 1 : length < 0x10000 ? 2 : 3;
            out.write(0x80 | size);
            for (int i = size - 1; i >= 0; i--) {
                out.write(length >>> (8 * i));
            }
        }
        out.writeBytes(content);
        return out.toByteArray();
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] bind(int id, String name, String password, byte[]... controls) {
        byte[] op = tlv(0x60, concat(tlv(0x02, new byte[] {3}), tlv(0x04, utf8(name)),
                tlv(0x80, utf8(password))));
        byte[] message = concat(tlv(0x02, new byte[] {(byte) id}), op);
        return tlv(0x30, controls.length == 0 ? message
                : concat(message, tlv(0xA0, concat(controls))));
    }

    private static byte[] search(int id, String filterValue) {
        byte[] op = tlv(0x63, concat(tlv(0x04, utf8("dc=example,dc=com")),
                tlv(0x0A, new byte[] {2}), tlv(0x0A, new byte[] {0}), tlv(0x02, new byte[] {0}),
                tlv(0x02, new byte[] {0}), tlv(0x01, new byte[] {0}),
                tlv(0xA3, concat(tlv(0x04, utf8("description")), tlv(0x04, utf8(filterValue)))),
                tlv(0x30, new byte[0])));
        return tlv(0x30, concat(tlv(0x02, new byte[] {(byte) id}), op));
    }

    // ---- where it is the password ---------------------------------------------------

    @Test
    void theApplicationsOwnBindCarriesThePassword() throws Exception {
        SeclumeLdap ldap = registered();
        assertArrayEquals(bind(1, SERVICE, PASSWORD),
                sent("ldap.example.com:636", bind(1, SERVICE, ldap.password())));
    }

    @Test
    void controlsAfterTheBindAreKept() throws Exception {
        SeclumeLdap ldap = registered();
        byte[] control = tlv(0x30, tlv(0x04, utf8("2.16.840.1.113730.3.4.16")));
        assertArrayEquals(bind(7, SERVICE, PASSWORD, control),
                sent("ldap.example.com:636", bind(7, SERVICE, ldap.password(), control)));
    }

    @Test
    void lengthsGrowIntoTheLongFormWithThePassword() throws Exception {
        String longPassword = "p".repeat(200);
        SeclumeLdap ldap = registered("ldap.example.com:636", SERVICE, longPassword);
        assertArrayEquals(bind(2, SERVICE, longPassword),
                sent("ldap.example.com:636", bind(2, SERVICE, ldap.password())));
    }

    @Test
    void aBindDnOutsideAsciiIsComparedInUtf8() throws Exception {
        String user = "cn=Jürgen Größe,ou=services,dc=example,dc=com";
        SeclumeLdap ldap = registered("ldap.example.com:636", user.replace(" ", "%20"), PASSWORD);
        assertEquals(user, ldap.user());
        assertArrayEquals(bind(3, user, PASSWORD),
                sent("ldap.example.com:636", bind(3, user, ldap.password())));
    }

    @Test
    void writesSplitAnywhereGiveTheSameBytes() throws Exception {
        SeclumeLdap ldap = registered();
        byte[] stream = concat(bind(1, SERVICE, ldap.password()), search(2, "x"));
        byte[] expected = concat(bind(1, SERVICE, PASSWORD), search(2, "x"));
        for (int cut = 0; cut <= stream.length; cut++) {
            byte[] first = java.util.Arrays.copyOfRange(stream, 0, cut);
            byte[] second = java.util.Arrays.copyOfRange(stream, cut, stream.length);
            assertArrayEquals(expected, sent("ldap.example.com:636", first, second),
                    "split at " + cut);
        }
    }

    // ---- where it is not ----------------------------------------------------------

    @Test
    void typedIntoALoginFormForAnotherUserItStaysThePlaceholder() throws Exception {
        SeclumeLdap ldap = registered();
        byte[] login = bind(4, ALICE, ldap.password());
        assertArrayEquals(login, sent("ldap.example.com:636", login));
        // A name that only starts like the service's, or is it with something after.
        for (String near : new String[] {"cn=app", SERVICE + ",o=x", "CN=app,ou=services,"
                + "dc=example,dc=com", "", " " + SERVICE}) {
            byte[] bind = bind(5, near, ldap.password());
            assertArrayEquals(bind, sent("ldap.example.com:636", bind), near);
        }
    }

    @Test
    void anotherServersPlaceholderIsNotThisServersPassword() throws Exception {
        SeclumeLdap first = registered("ldap.example.com:636", SERVICE, PASSWORD);
        SeclumeLdap other = registered("partner.example.org:636", SERVICE, "partner-password");
        byte[] bind = bind(1, SERVICE, first.password());
        assertArrayEquals(bind, sent("partner.example.org:636", bind));
        assertArrayEquals(bind(1, SERVICE, "partner-password"),
                sent("partner.example.org:636", bind(1, SERVICE, other.password())));
        // The same host on another port is another server.
        registered("ldap.example.com:1636", SERVICE, "x");
        assertArrayEquals(bind, sent("ldap.example.com:1636", bind));
    }

    @Test
    void aKerberosPlaceholderForAnotherUserStartsNoKerberosBind() throws Exception {
        SeclumeLdap ldap = kerberos("kdc-ldap.example.com:636");
        byte[] login = bind(1, ALICE, ldap.password());
        assertArrayEquals(login, sent("kdc-ldap.example.com:636", login));
    }

    @Test
    void thePlaceholderAnywhereElseIsLeftAlone() throws Exception {
        SeclumeLdap ldap = registered();
        byte[] search = search(9, ldap.password());
        byte[] asName = bind(10, ldap.password(), "secret");
        assertArrayEquals(concat(search, asName),
                sent("ldap.example.com:636", search, asName));
    }

    @Test
    void anUnknownPlaceholderGoesOutAsTyped() throws Exception {
        registered();
        byte[] typed = bind(1, SERVICE, SeclumeLdap.PLACEHOLDER_PREFIX + "1");
        assertArrayEquals(typed, sent("ldap.example.com:636", typed));
    }

    @Test
    void placeholdersCannotBeGuessedFromOneAnother() throws Exception {
        Set<String> seen = new HashSet<>();
        String previous = null;
        for (int i = 0; i < 50; i++) {
            String placeholder = registered().password();
            assertTrue(placeholder.startsWith(SeclumeLdap.PLACEHOLDER_PREFIX), placeholder);
            String random = placeholder.substring(SeclumeLdap.PLACEHOLDER_PREFIX.length());
            assertEquals(24, random.length(), random);
            assertTrue(random.matches("[A-Za-z0-9_-]+"), random);
            assertFalse(random.matches("[0-9]+"), "a counter: " + random);
            assertTrue(seen.add(random), "repeated: " + random);
            if (previous != null) {
                assertNotEquals(previous, placeholder);
            }
            previous = placeholder;
        }
    }

    @Test
    void aBindWhoseLengthsDoNotAddUpIsRefused() throws Exception {
        SeclumeLdap ldap = registered();
        byte[] good = bind(1, SERVICE, ldap.password());
        // The name's length, said to be longer than the BindRequest.
        int nameLength = 2 + 3 + 2 + 3 + 1;                 // SEQ, id, [APP 0], version, tag
        byte[] longName = good.clone();
        longName[nameLength] = (byte) 0x7F;
        IOException e = assertThrows(IOException.class, () -> sent("ldap.example.com:636",
                longName));
        assertTrue(e.getMessage().contains("do not add up"), e.getMessage());
    }
}
