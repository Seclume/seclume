package space.seclume.ssh;

import java.security.KeyPair;
import java.util.List;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;

import space.seclume.keys.SeclumeKeys;

/**
 * SSH logins with a private key that stays in OpenSSL.
 *
 * <p>Apache MINA SSHD - and Spring Integration's SFTP, which is built on it -
 * logs in with a {@link KeyPair}, and a key read the usual way is a set of
 * {@code BigInteger}s on the heap for as long as the client lives. Here the
 * private half is an {@code OpenSslPrivateKey}: SSHD asks the JCA for a
 * signature, the JCA hands it to seclume's provider, and OpenSSL signs.
 *
 * <pre>
 * SshClient client = SshClient.setUpDefaultClient();
 * client.setKeyIdentityProvider(SeclumeSsh.identity("provider=file&amp;path=/run/secrets/id_ecdsa"));
 * client.start();
 *
 * // Spring Integration SFTP
 * DefaultSftpSessionFactory factory = new DefaultSftpSessionFactory(client, false);
 * </pre>
 *
 * <p>RSA (signing {@code rsa-sha2-256} and {@code rsa-sha2-512}, not the SHA-1
 * {@code ssh-rsa}) and ECDSA on P-256, P-384 and P-521. The key file is PEM or
 * DER - PKCS#8, PKCS#1 or SEC 1; OpenSSH's own format
 * ({@code BEGIN OPENSSH PRIVATE KEY}) is converted once with
 * {@code ssh-keygen -p -m PEM -f key}. Ed25519 is not supported yet.
 *
 * <p>Password logins cannot be done this way: SSH encrypts the password inside
 * SSHD, in Java, before it reaches a socket. A key is the way to log in
 * without a secret on the heap.
 */
public final class SeclumeSsh {

    private SeclumeSsh() {
    }

    /** The key named by {@code keySpec} (the secret provider's options), with its public half. */
    public static KeyPair keyPair(String keySpec) {
        return SeclumeKeys.keyPair(keySpec);
    }

    /** The key as SSHD's identity provider - for a client, or one session. */
    public static KeyIdentityProvider identity(String keySpec) {
        List<KeyPair> keys = List.of(keyPair(keySpec));
        return session -> keys;
    }

    /** Adds the key to one session, before {@code session.auth()}. */
    public static void addIdentity(ClientSession session, String keySpec) {
        session.addPublicKeyIdentity(keyPair(keySpec));
    }

    /** Sets the key on a client, for all its sessions. */
    public static SshClient withIdentity(SshClient client, String keySpec) {
        client.setKeyIdentityProvider(identity(keySpec));
        return client;
    }
}
