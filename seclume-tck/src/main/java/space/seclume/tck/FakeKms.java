package space.seclume.tck;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Base64; // seclume-allow: a fake service's own made-up keys and signatures
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * A stand-in for a key management service, for tests: an HTTPS server on
 * 127.0.0.1 whose keys - made by {@code openssl}, one file per version in a
 * directory of its own - sign the hashes they are sent, with {@code openssl
 * pkeyutl}. It answers as four services do, each with its own paths and
 * credentials, and keeps every request it got:
 *
 * <ul>
 *   <li>Vault's transit engine - {@code GET /v1/<mount>/keys/<name>},
 *       {@code POST /v1/<mount>/sign/<name>/<hash>} with a {@code prehashed}
 *       input, an {@code X-Vault-Token};
 *   <li>AWS KMS - {@code POST /} with {@code X-Amz-Target}
 *       {@code TrentService.GetPublicKey} or {@code .Sign} ({@code MessageType
 *       DIGEST}), a SigV4 {@code Authorization} for {@code kms} (its form is
 *       checked, not its signature);
 *   <li>Google Cloud KMS - {@code GET /v1/<version>/publicKey},
 *       {@code POST /v1/<version>:asymmetricSign}, a bearer token
 *       ({@link #gcpKeyName});
 *   <li>Azure Key Vault - {@code GET /keys/<name>[/<version>]},
 *       {@code POST /keys/<name>/<version>/sign} answering ECDSA as r and s, a
 *       bearer token.
 * </ul>
 *
 * <p>Its certificate is its own, so a client talks to it with
 * {@code verify=false}. What it cannot show is a real service's behaviour - its
 * policies, quotas, latency; the answers are the shapes the service's API
 * documentation gives.
 */
public final class FakeKms implements AutoCloseable {

    /** What kind of key it holds. */
    public enum KeyType {
        P256("ecdsa-p256", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"),
        P384("ecdsa-p384", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"),
        RSA2048("rsa-2048", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048");

        private final String transitType;
        private final List<String> generate;

        KeyType(String transitType, String... generate) {
            this.transitType = transitType;
            this.generate = List.of(generate);
        }

        boolean rsa() {
            return this == RSA2048;
        }
    }

    private static final Pattern KEYS = Pattern.compile("/v1/(.+)/keys/([^/?]+)");
    private static final Pattern SIGN = Pattern.compile("/v1/(.+)/sign/([^/?]+)/(sha2-[0-9]+)");
    private static final Pattern GCP_PUBLIC = Pattern.compile(
            "/v1/projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/([^/]+)"
                    + "/cryptoKeyVersions/([0-9]+)/publicKey");
    private static final Pattern GCP_SIGN = Pattern.compile(
            "/v1/projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/([^/]+)"
                    + "/cryptoKeyVersions/([0-9]+):asymmetricSign");
    private static final Pattern AZURE_KEY =
            Pattern.compile("/keys/([^/?]+)(?:/([^/?]+))?\\?api-version=[0-9.]+");
    private static final Pattern AZURE_SIGN =
            Pattern.compile("/keys/([^/?]+)/([^/?]+)/sign\\?api-version=[0-9.]+");

    private final Path directory;
    private final KeyType type;
    private final String keyName;
    private final List<Path> versions = new CopyOnWriteArrayList<>();
    private final List<String> requests = new CopyOnWriteArrayList<>();
    private final SSLServerSocket socket;
    private volatile int refusal;
    private volatile boolean stopped;

    /** A fake transit engine with one key, {@code keyName}, of {@code type}, at version 1. */
    public FakeKms(KeyType type, String keyName) throws IOException {
        this.type = type;
        this.keyName = keyName;
        this.directory = Files.createTempDirectory("seclume-fake-kms");
        rotate();
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-days", "2", "-subj", "/CN=fake-kms", "-addext",
                "subjectAltName=IP:127.0.0.1", "-keyout", "server.key", "-out", "server.pem");
        openssl("pkcs12", "-export", "-inkey", "server.key", "-in", "server.pem",
                "-passout", "pass:fake-kms", "-out", "server.p12");
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(directory.resolve("server.p12"))) {
                store.load(in, "fake-kms".toCharArray());
            }
            KeyManagerFactory keys =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(store, "fake-kms".toCharArray());
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(keys.getKeyManagers(), null, null);
            this.socket = (SSLServerSocket) context.getServerSocketFactory()
                    .createServerSocket(0, 16, InetAddress.getLoopbackAddress());
        } catch (java.security.GeneralSecurityException e) {
            throw new IOException("the fake service's TLS could not be set up", e);
        }
        Thread thread = new Thread(this::serve, "fake-kms");
        thread.setDaemon(true);
        thread.start();
    }

    /** {@code https://127.0.0.1:<port>}. */
    public String address() {
        return "https://127.0.0.1:" + socket.getLocalPort();
    }

    /** The current version's key file - PEM, for a test that makes a certificate by hand. */
    public Path keyFile() {
        return versions.get(versions.size() - 1);
    }

    /** How many versions the key has. */
    public int latestVersion() {
        return versions.size();
    }

    /** A new version of the key, which becomes the latest. */
    public void rotate() throws IOException {
        String file = "key-v" + (versions.size() + 1) + ".pem";
        List<String> arguments = new ArrayList<>(List.of("genpkey"));
        arguments.addAll(type.generate);
        arguments.addAll(List.of("-out", file));
        openssl(arguments.toArray(String[]::new));
        versions.add(directory.resolve(file));
    }

    /** The resource name Cloud KMS knows {@code version} of the key by. */
    public String gcpKeyName(int version) {
        return "projects/seclume-test/locations/global/keyRings/test/cryptoKeys/" + keyName
                + "/cryptoKeyVersions/" + version;
    }

    /** Every request so far, as {@code METHOD path} and the body on the next line. */
    public List<String> requests() {
        return requests;
    }

    /** Answers every request from now on with {@code status} - 0 to answer again. */
    public void refuse(int status) {
        this.refusal = status;
    }

    private void serve() {
        while (!stopped) {
            try (SSLSocket accepted = (SSLSocket) socket.accept()) {
                accepted.setSoTimeout(30_000);
                InputStream in = accepted.getInputStream();
                String head = head(in);
                String[] lines = head.split("\r\n");
                String[] requestLine = lines[0].split(" ");
                Map<String, String> headers = new LinkedHashMap<>();
                for (int i = 1; i < lines.length; i++) {
                    int colon = lines[i].indexOf(':');
                    if (colon > 0) {
                        headers.put(lines[i].substring(0, colon).trim().toLowerCase(Locale.ROOT),
                                lines[i].substring(colon + 1).trim());
                    }
                }
                int length = contentLength(headers.get("content-length"));
                // seclume-allow: a fake service's own made-up data, no application secret
                String body = new String(in.readNBytes(length), StandardCharsets.UTF_8);
                requests.add(requestLine[0] + " " + requestLine[1] + "\n" + body);
                String[] answer = answer(requestLine[0], requestLine[1], headers, body);
                // seclume-allow: a fake service's own made-up data, no application secret
                byte[] out = answer[1].getBytes(StandardCharsets.UTF_8);
                OutputStream to = accepted.getOutputStream();
                to.write(("HTTP/1.1 " + answer[0] + " \r\nContent-Type: application/json\r\n"
                        + "Content-Length: " + out.length + "\r\nConnection: close\r\n\r\n")
                        .getBytes(StandardCharsets.US_ASCII)); // seclume-allow: a fake service's header
                to.write(out);
                to.flush();
            } catch (IOException | RuntimeException e) {
                if (stopped) {
                    return;
                }
            }
        }
    }

    private String[] answer(String method, String path, Map<String, String> headers,
            String body) {
        if (refusal != 0) {
            return new String[] {String.valueOf(refusal),
                "{\"errors\":[\"permission denied\"]}"};
        }
        try {
            String target = headers.get("x-amz-target");
            if (method.equals("POST") && path.equals("/") && target != null) {
                return aws(target, headers.get("authorization"), body);
            }
            Matcher gcpPublic = GCP_PUBLIC.matcher(path);
            Matcher gcpSign = GCP_SIGN.matcher(path);
            if (gcpPublic.matches() || gcpSign.matches()) {
                return gcp(method, gcpPublic.matches() ? gcpPublic : gcpSign,
                        gcpSign.matches(), headers.get("authorization"), body);
            }
            Matcher azureKey = AZURE_KEY.matcher(path);
            Matcher azureSign = AZURE_SIGN.matcher(path);
            if (azureSign.matches() || azureKey.matches()) {
                return azure(method, azureSign.matches() ? azureSign : azureKey,
                        azureSign.matches(), headers.get("authorization"), body);
            }
            if (headers.get("x-vault-token") == null || headers.get("x-vault-token").isBlank()) {
                return new String[] {"403", "{\"errors\":[\"missing client token\"]}"};
            }
            Matcher keys = KEYS.matcher(path);
            if (method.equals("GET") && keys.matches()) {
                if (!keys.group(2).equals(keyName)) {
                    return new String[] {"404", "{\"errors\":[]}"};
                }
                StringBuilder versionsJson = new StringBuilder();
                for (int v = 1; v <= versions.size(); v++) {
                    if (v > 1) {
                        versionsJson.append(',');
                    }
                    versionsJson.append('"').append(v).append("\":{\"name\":\"")
                            .append(type.name()).append("\",\"public_key\":\"")
                            .append(json(publicPem(versions.get(v - 1)))).append("\"}");
                }
                return new String[] {"200", "{\"data\":{\"name\":\"" + keyName
                        + "\",\"type\":\"" + type.transitType + "\",\"latest_version\":"
                        + versions.size() + ",\"supports_signing\":true,\"keys\":{"
                        + versionsJson + "}}}"};
            }
            Matcher sign = SIGN.matcher(path);
            if (method.equals("POST") && sign.matches()) {
                if (!sign.group(2).equals(keyName)) {
                    return new String[] {"404", "{\"errors\":[]}"};
                }
                if (!body.contains("\"prehashed\":true")) {
                    return new String[] {"400", "{\"errors\":[\"this fake signs hashes\"]}"};
                }
                int version = Integer.parseInt(field(body, "key_version", "1"));
                if (version < 1 || version > versions.size()) {
                    return new String[] {"400", "{\"errors\":[\"no such key version\"]}"};
                }
                byte[] hash = Base64.getDecoder().decode(field(body, "input", "")); // seclume-allow: a public hash
                String digest = sign.group(3).replace("sha2-", "sha");
                String padding = field(body, "signature_algorithm", "pss");
                byte[] signature = sign(versions.get(version - 1), digest, hash,
                        padding.equals("pss"));
                return new String[] {"200", "{\"data\":{\"signature\":\"vault:v" + version + ":"
                        + Base64.getEncoder().encodeToString(signature) // seclume-allow: a fake signature
                        + "\",\"key_version\":" + version + "}}"};
            }
            return new String[] {"404", "{\"errors\":[]}"};
        } catch (IOException | RuntimeException e) {
            return new String[] {"500", "{\"errors\":[\"" + json(String.valueOf(e.getMessage()))
                    + "\"]}"};
        }
    }

    private String[] aws(String target, String authorization, String body) throws IOException {
        if (authorization == null || !authorization.startsWith("AWS4-HMAC-SHA256 Credential=")
                || !authorization.contains("/kms/aws4_request")) {
            return new String[] {"400", "{\"__type\":\"MissingAuthenticationTokenException\","
                    + "\"message\":\"no SigV4 signature for kms\"}"};
        }
        if (!field(body, "KeyId", "").equals(keyName)) {
            return new String[] {"400", "{\"__type\":\"NotFoundException\",\"message\":"
                    + "\"Key '" + json(field(body, "KeyId", "")) + "' does not exist\"}"};
        }
        Path key = keyFile();
        String spec = switch (type) {
            case P256 -> "ECC_NIST_P256";
            case P384 -> "ECC_NIST_P384";
            case RSA2048 -> "RSA_2048";
        };
        if (target.equals("TrentService.GetPublicKey")) {
            return new String[] {"200", "{\"KeyId\":\"" + keyName + "\",\"KeySpec\":\""
                    + spec + "\",\"KeyUsage\":\"SIGN_VERIFY\",\"PublicKey\":\""
                    + Base64.getEncoder().encodeToString(publicDer(key)) // seclume-allow: a public key
                    + "\"}"};
        }
        if (!target.equals("TrentService.Sign")) {
            return new String[] {"400", "{\"__type\":\"UnknownOperationException\"}"};
        }
        if (!field(body, "MessageType", "RAW").equals("DIGEST")) {
            return new String[] {"400", "{\"__type\":\"ValidationException\",\"message\":"
                    + "\"this fake signs digests\"}"};
        }
        String algorithm = field(body, "SigningAlgorithm", "");
        String digest = "sha" + algorithm.substring(algorithm.lastIndexOf('_') + 1);
        boolean allowed = switch (type) {
            case P256 -> algorithm.equals("ECDSA_SHA_256");
            case P384 -> algorithm.equals("ECDSA_SHA_384");
            case RSA2048 -> algorithm.startsWith("RSASSA_");
        };
        if (!allowed) {
            return new String[] {"400", "{\"__type\":\"InvalidKeyUsageException\","
                    + "\"message\":\"" + algorithm + " is not valid for " + spec + "\"}"};
        }
        byte[] hash = Base64.getDecoder().decode(field(body, "Message", "")); // seclume-allow: a public hash
        byte[] signature = sign(key, digest, hash, algorithm.startsWith("RSASSA_PSS"));
        return new String[] {"200", "{\"KeyId\":\"" + keyName + "\",\"Signature\":\""
                + Base64.getEncoder().encodeToString(signature) // seclume-allow: a fake signature
                + "\",\"SigningAlgorithm\":\"" + algorithm + "\"}"};
    }

    private String gcpAlgorithm() {
        return switch (type) {
            case P256 -> "EC_SIGN_P256_SHA256";
            case P384 -> "EC_SIGN_P384_SHA384";
            case RSA2048 -> "RSA_SIGN_PSS_2048_SHA256";
        };
    }

    private String[] gcp(String method, Matcher name, boolean signing, String authorization,
            String body) throws IOException {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return new String[] {"401", "{\"error\":{\"code\":401,\"message\":"
                    + "\"Request is missing required authentication credential.\"}}"};
        }
        int version = Integer.parseInt(name.group(2));
        if (!name.group(1).equals(keyName) || version < 1 || version > versions.size()) {
            return new String[] {"404", "{\"error\":{\"code\":404,\"message\":"
                    + "\"CryptoKeyVersion not found.\"}}"};
        }
        Path key = versions.get(version - 1);
        if (!signing && method.equals("GET")) {
            return new String[] {"200", "{\"pem\":\"" + json(publicPem(key))
                    + "\",\"algorithm\":\"" + gcpAlgorithm() + "\",\"name\":\""
                    + gcpKeyName(version) + "\"}"};
        }
        String algorithm = gcpAlgorithm();
        String digest = algorithm.substring(algorithm.lastIndexOf('_') + 1)
                .toLowerCase(Locale.ROOT);
        Matcher hash = Pattern.compile("\"" + digest + "\"\\s*:\\s*\"([^\"]*)\"")
                .matcher(body);
        if (!method.equals("POST") || !hash.find()) {
            return new String[] {"400", "{\"error\":{\"code\":400,\"message\":"
                    + "\"Digest type must match the key's algorithm " + algorithm + ".\"}}"};
        }
        byte[] signature = sign(key, digest, Base64.getDecoder().decode(hash.group(1)), // seclume-allow: a public hash
                type.rsa());
        return new String[] {"200", "{\"signature\":\""
                + Base64.getEncoder().encodeToString(signature) // seclume-allow: a fake signature
                + "\",\"name\":\"" + gcpKeyName(version) + "\"}"};
    }

    private String[] azure(String method, Matcher key, boolean signing, String authorization,
            String body) throws IOException {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return new String[] {"401", "{\"error\":{\"code\":\"Unauthorized\","
                    + "\"message\":\"AKV10000: Request is missing a Bearer token.\"}}"};
        }
        String version = key.group(2);
        int index = version == null ? versions.size() : version.startsWith("ver")
                ? Integer.parseInt(version.substring(3)) : 0;
        if (!key.group(1).equals(keyName) || index < 1 || index > versions.size()) {
            return new String[] {"404", "{\"error\":{\"code\":\"KeyNotFound\","
                    + "\"message\":\"A key with (name/id) " + key.group(1) + " was not found "
                    + "in this key vault.\"}}"};
        }
        Path file = versions.get(index - 1);
        if (!signing && method.equals("GET")) {
            java.security.PublicKey publicKey;
            try {
                publicKey = java.security.KeyFactory.getInstance(type.rsa() ? "RSA" : "EC")
                        .generatePublic(new java.security.spec.X509EncodedKeySpec(
                                publicDer(file)));
            } catch (java.security.GeneralSecurityException e) {
                throw new IOException("the fake's own public key could not be read", e);
            }
            StringBuilder jwk = new StringBuilder("{\"kid\":\"" + address() + "/keys/"
                    + keyName + "/ver" + index + "\"");
            if (publicKey instanceof java.security.interfaces.ECPublicKey ec) {
                int size = type == KeyType.P384 ? 48 : 32;
                jwk.append(",\"kty\":\"EC\",\"crv\":\"").append(type == KeyType.P384
                        ? "P-384" : "P-256").append("\",\"x\":\"")
                        .append(url(fixed(ec.getW().getAffineX().toByteArray(), size))) // seclume-allow: a public point
                        .append("\",\"y\":\"")
                        .append(url(fixed(ec.getW().getAffineY().toByteArray(), size))) // seclume-allow: a public point
                        .append('"');
            } else if (publicKey instanceof java.security.interfaces.RSAPublicKey rsa) {
                jwk.append(",\"kty\":\"RSA\",\"n\":\"")
                        .append(url(rsa.getModulus().toByteArray())) // seclume-allow: a public modulus
                        .append("\",\"e\":\"")
                        .append(url(rsa.getPublicExponent().toByteArray())) // seclume-allow: a public exponent
                        .append('"');
            }
            return new String[] {"200", "{\"key\":" + jwk + "}}"};
        }
        String algorithm = field(body, "alg", "");
        String digest = "sha" + algorithm.substring(2);
        boolean allowed = switch (type) {
            case P256 -> algorithm.equals("ES256");
            case P384 -> algorithm.equals("ES384");
            case RSA2048 -> algorithm.startsWith("PS") || algorithm.startsWith("RS");
        };
        if (!allowed) {
            return new String[] {"400", "{\"error\":{\"code\":\"BadParameter\","
                    + "\"message\":\"" + algorithm + " does not fit the key\"}}"};
        }
        byte[] signature = sign(file, digest,
                Base64.getUrlDecoder().decode(field(body, "value", "")), // seclume-allow: a public hash
                algorithm.startsWith("PS"));
        if (!type.rsa()) {
            signature = raw(signature, type == KeyType.P384 ? 48 : 32);
        }
        return new String[] {"200", "{\"kid\":\"" + address() + "/keys/" + keyName + "/ver"
                + index + "\",\"value\":\"" + url(signature) + "\"}"};
    }

    private static String url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); // seclume-allow: public data
    }

    /** A big-endian number in exactly {@code size} bytes. */
    private static byte[] fixed(byte[] number, int size) {
        byte[] out = new byte[size];
        int from = Math.max(0, number.length - size);
        System.arraycopy(number, from, out, size - (number.length - from), number.length - from);
        return out;
    }

    /** A DER ECDSA signature as r and s of {@code size} bytes each, as Key Vault answers. */
    private static byte[] raw(byte[] der, int size) throws IOException {
        int at = 2 + ((der[1] & 0x80) != 0 ? (der[1] & 0x7f) : 0);
        byte[] out = new byte[2 * size];
        for (int part = 0; part < 2; part++) {
            if (der[at] != 0x02) {
                throw new IOException("not a DER ECDSA signature");
            }
            int length = der[at + 1] & 0xff;
            byte[] value = java.util.Arrays.copyOfRange(der, at + 2, at + 2 + length);
            System.arraycopy(fixed(value, size), 0, out, part * size, size);
            at += 2 + length;
        }
        return out;
    }

    private byte[] publicDer(Path key) throws IOException {
        Path out = directory.resolve(key.getFileName() + ".pub.der");
        if (!Files.exists(out)) {
            openssl("pkey", "-in", key.toString(), "-pubout", "-outform", "DER", "-out",
                    out.toString());
        }
        return Files.readAllBytes(out); // seclume-allow: a public key
    }

    /** A JSON field's value, a string or a number, from a flat request body. */
    private static String field(String body, String name, String absent) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*(\"([^\"]*)\"|([0-9]+))")
                .matcher(body);
        if (!m.find()) {
            return absent;
        }
        return m.group(2) != null ? m.group(2) : m.group(3);
    }

    private byte[] sign(Path key, String digest, byte[] hash, boolean pss) throws IOException {
        Path in = Files.createTempFile(directory, "hash", ".bin");
        Path out = directory.resolve(in.getFileName() + ".sig");
        try {
            Files.write(in, hash);
            List<String> arguments = new ArrayList<>(List.of("pkeyutl", "-sign", "-inkey",
                    key.toString(), "-in", in.toString(), "-out", out.toString(), "-pkeyopt",
                    "digest:" + digest));
            if (type.rsa()) {
                arguments.addAll(pss ? List.of("-pkeyopt", "rsa_padding_mode:pss", "-pkeyopt",
                        "rsa_pss_saltlen:digest") : List.of("-pkeyopt", "rsa_padding_mode:pkcs1"));
            }
            openssl(arguments.toArray(String[]::new));
            return Files.readAllBytes(out); // seclume-allow: a fake service's signature, public
        } finally {
            Files.deleteIfExists(in);
            Files.deleteIfExists(out);
        }
    }

    private String publicPem(Path key) throws IOException {
        Path out = directory.resolve(key.getFileName() + ".pub");
        if (!Files.exists(out)) {
            openssl("pkey", "-in", key.toString(), "-pubout", "-out", out.toString());
        }
        return Files.readString(out); // seclume-allow: a public key
    }

    private void openssl(String... arguments) throws IOException {
        List<String> command = new ArrayList<>(List.of("-c", "exec openssl \"$@\"", "openssl"));
        command.addAll(List.of(arguments));
        Process process = Shell.builder(command.toArray(String[]::new))
                .directory(directory.toFile()).redirectErrorStream(true).start();
        try {
            byte[] output = process.getInputStream().readAllBytes(); // seclume-allow: openssl's own messages
            if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
                throw new IOException("openssl " + arguments[0] + " failed: "
                        + new String(output, StandardCharsets.UTF_8)); // seclume-allow: openssl's own messages
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while openssl ran", e);
        }
    }

    private static String head(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) >= 0) {
            head.write(b);
            int n = head.size();
            byte[] seen = head.toByteArray();
            if (n >= 4 && seen[n - 4] == '\r' && seen[n - 3] == '\n' && seen[n - 2] == '\r'
                    && seen[n - 1] == '\n') {
                break;
            }
        }
        return head.toString(StandardCharsets.US_ASCII);
    }

    private static int contentLength(String value) throws IOException {
        if (value == null) {
            return 0;
        }
        try {
            int length = Integer.parseInt(value.trim());
            if (length < 0 || length > 1 << 20) {
                throw new IOException("a Content-Length this fake will not read: " + value);
            }
            return length;
        } catch (NumberFormatException e) {
            throw new IOException("a Content-Length that is no number: " + value, e);
        }
    }

    private static String json(String text) {
        return text.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
                .replace("\r", "");
    }

    @Override
    public void close() throws IOException {
        stopped = true;
        socket.close();
        try (var files = Files.list(directory)) {
            for (Path file : files.toList()) {
                Files.deleteIfExists(file);
            }
        }
        Files.deleteIfExists(directory);
    }
}
