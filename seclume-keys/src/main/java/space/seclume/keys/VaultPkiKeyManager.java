package space.seclume.keys;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretScope;

/**
 * A client (or server) certificate from Vault's PKI engine whose key was never
 * anywhere but in OpenSSL.
 *
 * <p>{@code pki/issue} would be the short way, and Vault would make the key -
 * and send it back in a JSON answer, where every client turns it into a
 * {@code String}. Here the key is generated in OpenSSL (or CNG), a
 * certification request is signed with it there, and {@code pki/sign/<role>}
 * returns only the certificate: the key leaves neither the process nor native
 * memory, and Vault never has it.
 *
 * <p>The certificate is renewed - a new key, a new request - once
 * {@code renew-at} of its lifetime has passed (two thirds by default), and
 * the new pair is used from the next handshake on; generations and their
 * aliases are {@link RotatingKeyManager}'s. A renewal that fails is tried
 * again, sooner the closer the end, and the certificate in hand stays until
 * it expires. The Vault token comes from the same settings and logins as
 * {@code provider=vault}'s ({@link SecretProviders#vaultToken}).
 *
 * <p>The chain is the certificate and its issuing CA, as Vault reports them:
 * what a peer that trusts the root needs from a two-level PKI.
 */
final class VaultPkiKeyManager extends RotatingKeyManager {

    private static final System.Logger LOG =
            System.getLogger(VaultPkiKeyManager.class.getName());
    private static final int ANSWER = SecretFetch.MAX_RESPONSE;
    private static final int PEM = 64 * 1024;
    /** Never sooner than this between two attempts, so that a broken Vault is not hammered. */
    private static final Duration SHORTEST_RETRY = Duration.ofSeconds(10);
    private static final Duration LONGEST_RETRY = Duration.ofMinutes(5);

    private final String host;
    private final int port;
    private final boolean verify;
    private final int timeoutMillis;
    private final String namespace;
    private final String signPath;
    private final String commonName;
    private final String altNames;
    private final String ipSans;
    private final String ttl;
    private final double renewAt;
    private final String name;
    private final SecretProvider token;
    private final Clock clock;
    private final ScheduledExecutorService scheduler;
    private volatile Instant notAfter;
    private volatile Instant nextRenewal;
    private boolean closed;

    VaultPkiKeyManager(Map<String, String> settings, Clock clock) {
        this.clock = clock;
        String address = required(settings, "address");
        URI uri = URI.create(address);
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("the Vault address must be https://, not "
                    + address + ": the token would travel in the clear");
        }
        this.host = uri.getHost();
        this.port = uri.getPort() > 0 ? uri.getPort() : 443;
        this.verify = !"false".equalsIgnoreCase(settings.getOrDefault("verify", "true"));
        this.timeoutMillis = Integer.parseInt(settings.getOrDefault("timeout-millis", "10000"));
        this.namespace = settings.get("namespace");
        String mount = trimSlashes(settings.getOrDefault("pki-mount", "pki"));
        String role = required(settings, "pki-role");
        if (!mount.matches("[A-Za-z0-9_./-]+") || !role.matches("[A-Za-z0-9_.-]+")) {
            throw new IllegalArgumentException("pki-mount and pki-role are path names: "
                    + "letters, digits, '_', '.', '-' (and '/' in a mount)");
        }
        this.signPath = "/v1/" + mount + "/sign/" + role;
        this.commonName = required(settings, "common-name");
        this.altNames = settings.get("alt-names");
        this.ipSans = settings.get("ip-sans");
        this.ttl = settings.get("ttl");
        String given = settings.get("name");
        this.name = given == null || given.isBlank() ? commonName : given.trim();
        this.renewAt = Double.parseDouble(settings.getOrDefault("renew-at", "0.67"));
        if (!(renewAt > 0.1 && renewAt < 0.95)) {
            throw new IllegalArgumentException("renew-at is a fraction of the certificate's "
                    + "lifetime between 0.1 and 0.95, not " + renewAt);
        }
        this.token = SecretProviders.vaultToken(settings);
        try {
            install(issue());
        } catch (IOException | RuntimeException e) {
            token.close();
            throw new IllegalStateException("no certificate from Vault at " + address
                    + signPath + ": " + e.getMessage(), e);
        }
        register();
        this.scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "seclume-vault-pki " + commonName);
            thread.setDaemon(true);
            return thread;
        });
        schedule(Duration.between(clock.instant(), nextRenewal));
    }

    private static String required(Map<String, String> settings, String name) {
        String value = settings.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("a certificate from Vault's PKI needs " + name);
        }
        return value.trim();
    }

    private static String trimSlashes(String path) {
        String trimmed = path.trim();
        while (trimmed.startsWith("/")) {
            trimmed = trimmed.substring(1);
        }
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    /** When the certificate in hand ends. */
    Instant notAfter() {
        return notAfter;
    }

    /** When it is to be replaced. */
    @Override
    Instant nextRenewal() {
        return nextRenewal;
    }

    @Override
    String name() {
        return name;
    }

    @Override
    String kind() {
        return "vault-pki";
    }

    /** Replaces the certificate now - a new key, a new request. */
    synchronized void renewNow() throws IOException {
        try {
            install(issue());
        } catch (IOException | RuntimeException e) {
            failed(e.getMessage());
            throw e;
        }
        succeeded();
        LOG.log(System.Logger.Level.INFO, "a new certificate for " + commonName + " from "
                + signPath + ", valid until " + notAfter + "; used from the next handshake on");
    }

    private void schedule(Duration delay) {
        long millis = Math.max(0, delay.toMillis());
        scheduler.schedule(this::renewOrRetry, millis, TimeUnit.MILLISECONDS);
    }

    private void renewOrRetry() {
        synchronized (this) {
            if (closed) {
                return;
            }
        }
        try {
            renewNow();
            schedule(Duration.between(clock.instant(), nextRenewal));
        } catch (IOException | RuntimeException e) {
            Duration retry = retryAfter(clock.instant(), notAfter);
            LOG.log(System.Logger.Level.WARNING, "the certificate for " + commonName
                    + " could not be renewed (" + e.getMessage() + "); the one in hand ends "
                    + notAfter + ", trying again in " + retry.toSeconds() + "s");
            schedule(retry);
        }
    }

    /**
     * When to try again after a failed renewal: a tenth of what is left, between
     * ten seconds and five minutes - so that the last hour of a certificate
     * sees a dozen attempts and a broken Vault is not asked every second.
     */
    static Duration retryAfter(Instant now, Instant end) {
        Duration left = Duration.between(now, end);
        Duration tenth = left.isNegative() ? Duration.ZERO : left.dividedBy(10);
        if (tenth.compareTo(SHORTEST_RETRY) < 0) {
            return SHORTEST_RETRY;
        }
        return tenth.compareTo(LONGEST_RETRY) > 0 ? LONGEST_RETRY : tenth;
    }

    /** {@code fraction} of the way from {@code from} to {@code to}. */
    static Instant renewalTime(Instant from, Instant to, double fraction) {
        long whole = Duration.between(from, to).toMillis();
        return from.plusMillis((long) (whole * fraction));
    }

    /** A new key, a request signed by it, the certificate Vault signs for it - recorded either way. */
    private SeclumeKeyManager issue() throws IOException {
        space.seclume.jfr.SeclumeEvents.CertificateRenewal event =
                space.seclume.jfr.Observed.beginCertificateRenewal();
        try {
            SeclumeKeyManager issued = issueOnly();
            space.seclume.jfr.Observed.endCertificateRenewal(event, name, signPath, true,
                    notAfter.toEpochMilli(), null);
            return issued;
        } catch (IOException | RuntimeException e) {
            space.seclume.jfr.Observed.endCertificateRenewal(event, name, signPath, false,
                    notAfter == null ? 0 : notAfter.toEpochMilli(), e.getMessage());
            throw e;
        }
    }

    private SeclumeKeyManager issueOnly() throws IOException {
        NativeKey key = NativeKey.generateP256();
        try {
            X509Certificate[] chain = sign(CertificationRequest.pem(key, commonName));
            if (!Arrays.equals(key.publicKey.getEncoded(),
                    chain[0].getPublicKey().getEncoded())) {
                throw new IOException("Vault signed a certificate for another key");
            }
            Instant start = chain[0].getNotBefore().toInstant();
            Instant end = chain[0].getNotAfter().toInstant();
            notAfter = end;
            nextRenewal = renewalTime(start, end, renewAt);
            return new SeclumeKeyManager(chain, OpenSslPrivateKey.of(key));
        } catch (IOException | RuntimeException e) {
            key.destroy();
            throw e;
        }
    }

    private X509Certificate[] sign(String csr) throws IOException {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("csr", csr);
        body.put("common_name", commonName);
        if (altNames != null && !altNames.isBlank()) {
            body.put("alt_names", altNames);
        }
        if (ipSans != null && !ipSans.isBlank()) {
            body.put("ip_sans", ipSans);
        }
        if (ttl != null && !ttl.isBlank()) {
            body.put("ttl", ttl);
        }
        body.put("format", "pem");
        try (Arena arena = Arena.ofConfined();
             SecretScope vaultToken = SecretScope.fromProvider(token)) {
            MemorySegment answer = arena.allocate(ANSWER);
            Map<String, String> headers = namespace == null || namespace.isBlank()
                    ? Map.of("Content-Type", "application/json")
                    : Map.of("Content-Type", "application/json", "X-Vault-Namespace", namespace);
            SecretFetch.Response response = SecretFetch.send(host, port, verify, timeoutMillis,
                    "POST", signPath, headers,
                    List.of(new SecretFetch.SecretHeader("X-Vault-Token", vaultToken.segment(),
                            vaultToken.length())),
                    json(body), answer);
            if (!response.ok()) {
                throw new IOException("Vault answered " + response.status() + " to "
                        + signPath);
            }
            int length = response.bodyLength();
            List<X509Certificate> chain = new ArrayList<>(
                    certificates(text(arena, answer, length, "data", "certificate")));
            if (JsonOff.has(answer, length, "data", "issuing_ca")) {
                for (X509Certificate issuer : certificates(
                        text(arena, answer, length, "data", "issuing_ca"))) {
                    if (!issuer.equals(chain.get(0))) {
                        chain.add(issuer);
                    }
                }
            }
            return chain.toArray(X509Certificate[]::new);
        } catch (JsonOff.NotFound e) {
            throw new IOException("Vault's answer holds no certificate", e);
        }
    }

    /** A string of the answer - a certificate, public - as Java text. */
    private static String text(Arena arena, MemorySegment answer, int length, String... path) {
        MemorySegment out = arena.allocate(PEM);
        int written = JsonOff.string(answer, length, out, path);
        // seclume-allow: a certificate, which is public
        return new String(out.asSlice(0, written).toArray(ValueLayout.JAVA_BYTE),
                StandardCharsets.UTF_8);
    }

    private static List<X509Certificate> certificates(String pem) throws IOException {
        try {
            // seclume-allow: a certificate, which is public
            byte[] bytes = pem.getBytes(StandardCharsets.US_ASCII);
            Collection<? extends Certificate> read = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(bytes));
            if (read.isEmpty()) {
                throw new IOException("Vault's answer holds no certificate");
            }
            return read.stream().map(X509Certificate.class::cast).toList();
        } catch (GeneralSecurityException e) {
            throw new IOException("Vault's certificate could not be read", e);
        }
    }

    /** A flat JSON object of strings; none of them is a secret. */
    static String json(Map<String, String> fields) {
        StringBuilder out = new StringBuilder("{");
        for (Map.Entry<String, String> field : fields.entrySet()) {
            if (out.length() > 1) {
                out.append(',');
            }
            quote(out, field.getKey());
            out.append(':');
            quote(out, field.getValue());
        }
        return out.append('}').toString();
    }

    private static void quote(StringBuilder out, String text) {
        out.append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    /** Stops renewing; the certificates in use stay until the manager is gone. */
    @Override
    public void close() {
        synchronized (this) {
            if (closed) {
                return;
            }
            closed = true;
        }
        unregister();
        scheduler.shutdownNow();
        token.close();
    }
}
