package space.seclume.spring;

import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;

import space.seclume.Secured;
import space.seclume.ServerCapacity;
import space.seclume.Version;
import space.seclume.pool.PoolStatistics;
import space.seclume.pool.SeclumePool;

/**
 * {@code /actuator/seclume}: for every data source, how it is secured - the
 * question an audit asks and the application usually cannot answer.
 *
 * <p>Per pool: how the login proved itself, which TLS and which stack carries
 * it, which certificate the server showed and when it expires, how many
 * connections the server allows and has, and the pool's own numbers. What is
 * never here: a password, a host's credentials, a statement. The certificate
 * appears by subject, issuer and expiry - public facts, and the expiry is the
 * one that ends in an outage when nobody looks.
 *
 * <p>Exposed like every endpoint: {@code management.endpoints.web.exposure.include=seclume}.
 */
@Endpoint(id = "seclume")
public final class SeclumeEndpoint {

    private final List<SeclumePool> pools;

    public SeclumeEndpoint(List<SeclumePool> pools) {
        this.pools = List.copyOf(pools);
    }

    @ReadOperation
    public Map<String, Object> report() {
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("version", Version.current());
        Map<String, Object> sources = new LinkedHashMap<>();
        for (SeclumePool pool : pools) {
            PoolStatistics statistics = pool.statistics();
            sources.put(statistics.name(), describe(pool, statistics));
        }
        report.put("dataSources", sources);
        return report;
    }

    private static Map<String, Object> describe(SeclumePool pool, PoolStatistics statistics) {
        Map<String, Object> source = new LinkedHashMap<>();
        Map<String, Object> numbers = new LinkedHashMap<>();
        numbers.put("active", statistics.active());
        numbers.put("idle", statistics.idle());
        numbers.put("total", statistics.total());
        numbers.put("waiting", statistics.waiting());
        source.put("pool", numbers);
        try (Connection connection = pool.getConnection()) {
            Secured secured = Secured.of(connection);
            source.put("authentication", secured.authenticationMethod());
            String tls = secured.tlsDescription();
            source.put("tls", tls == null ? "none - the connection is in the clear" : tls);
            X509Certificate certificate = secured.serverCertificate();
            if (certificate != null) {
                Map<String, Object> shown = new LinkedHashMap<>();
                shown.put("subject", certificate.getSubjectX500Principal().getName());
                shown.put("issuer", certificate.getIssuerX500Principal().getName());
                shown.put("expires", certificate.getNotAfter().toInstant().toString());
                source.put("serverCertificate", shown);
            }
            if (connection.isWrapperFor(ServerCapacity.class)) {
                ServerCapacity.Capacity capacity =
                        connection.unwrap(ServerCapacity.class).capacity();
                Map<String, Object> server = new LinkedHashMap<>();
                server.put("allowed", capacity.allowed() < 0 ? "not visible" : capacity.allowed());
                server.put("inUse", capacity.inUse() < 0 ? "not visible" : capacity.inUse());
                source.put("serverCapacity", server);
            }
        } catch (SQLException | RuntimeException e) {
            source.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return source;
    }
}
