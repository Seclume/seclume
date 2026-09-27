package space.seclume.spring;

import java.nio.file.Path;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.keyverifier.KnownHostsServerKeyVerifier;
import org.apache.sshd.client.keyverifier.RejectAllServerKeyVerifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.integration.sftp.session.DefaultSftpSessionFactory;

import space.seclume.ssh.SeclumeSsh;

/**
 * SSH and SFTP logins with a private key that stays in OpenSSL:
 *
 * <pre>
 * seclume.ssh.key=provider=file&amp;path=/run/secrets/id_ecdsa
 * seclume.ssh.known-hosts=/etc/ssh/ssh_known_hosts        (or allow-unknown-hosts=true)
 *
 * seclume.sftp.host=files.example.com                     (optional: a session factory)
 * seclume.sftp.port=22
 * seclume.sftp.user=deploy
 * </pre>
 *
 * <p>An Apache SSHD {@link SshClient} bean, started, whose identity is the key
 * (see {@link SeclumeSsh}), and which checks the server's host key against
 * {@code known-hosts} - an unknown server is refused unless
 * {@code seclume.ssh.allow-unknown-hosts=true}. With {@code seclume.sftp.host}
 * and Spring Integration's SFTP support there, a
 * {@link DefaultSftpSessionFactory} on that client as well.
 */
@AutoConfiguration
@ConditionalOnClass(name = {"space.seclume.ssh.SeclumeSsh", "org.apache.sshd.client.SshClient"})
@ConditionalOnProperty("seclume.ssh.key")
public class SeclumeSshAutoConfiguration {

    @Bean(destroyMethod = "stop")
    @ConditionalOnMissingBean
    public SshClient seclumeSshClient(Environment environment) {
        SshClient client = SeclumeSsh.withIdentity(SshClient.setUpDefaultClient(),
                environment.getRequiredProperty("seclume.ssh.key"));
        String knownHosts = environment.getProperty("seclume.ssh.known-hosts");
        boolean allowUnknown = environment.getProperty("seclume.ssh.allow-unknown-hosts",
                Boolean.class, false);
        if (knownHosts != null) {
            client.setServerKeyVerifier(new KnownHostsServerKeyVerifier(allowUnknown
                    ? AcceptAllServerKeyVerifier.INSTANCE : RejectAllServerKeyVerifier.INSTANCE,
                    Path.of(knownHosts)));
        } else {
            client.setServerKeyVerifier(allowUnknown ? AcceptAllServerKeyVerifier.INSTANCE
                    : RejectAllServerKeyVerifier.INSTANCE);
        }
        client.start();
        return client;
    }

    /** Spring Integration's SFTP, when {@code seclume.sftp.host} names a server. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.integration.sftp.session"
            + ".DefaultSftpSessionFactory")
    @ConditionalOnProperty("seclume.sftp.host")
    static class Sftp {

        @Bean
        @ConditionalOnMissingBean
        DefaultSftpSessionFactory seclumeSftpSessionFactory(SshClient client,
                                                            Environment environment) {
            DefaultSftpSessionFactory factory = new DefaultSftpSessionFactory(client, true);
            factory.setHost(environment.getRequiredProperty("seclume.sftp.host"));
            factory.setPort(environment.getProperty("seclume.sftp.port", Integer.class, 22));
            factory.setUser(environment.getRequiredProperty("seclume.sftp.user"));
            return factory;
        }
    }
}
