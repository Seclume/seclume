package space.seclume.admission;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedKeyManager;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import space.seclume.keys.SeclumeKeys;

/**
 * The webhook: {@code POST /mutate} takes an {@code AdmissionReview} for a
 * pod and answers with the patch {@link Injection} makes of its annotations;
 * {@code GET /healthz} says it is up.
 *
 * <pre>
 * java -jar seclume-admission.jar --tls-cert /tls/tls.crt --tls-key /tls/tls.key \
 *     --sidecar-image registry.example/seclume-heapcheck:0.14.0
 * </pre>
 *
 * <p>It never refuses a pod: a request it cannot read or a pod it cannot
 * change is let through, with a warning that the API server passes on to
 * whoever applied it. Its TLS key is read into native memory by
 * seclume-keys and never onto the heap; a renewed key and certificate
 * (cert-manager) are taken up from the next handshake on.
 */
public final class AdmissionServer implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger(AdmissionServer.class.getName());
    /** Far beyond any pod; a request larger than this is not read. */
    static final int LARGEST = 4 << 20;

    private final HttpsServer server;
    private final ExecutorService executor;

    private AdmissionServer(HttpsServer server, ExecutorService executor) {
        this.server = server;
        this.executor = executor;
    }

    /** Serves on {@code address} with {@code tls} until closed. */
    public static AdmissionServer start(InetSocketAddress address, SSLContext tls,
            Injection.Settings settings) throws IOException {
        HttpsServer server = HttpsServer.create(address, 64);
        server.setHttpsConfigurator(new HttpsConfigurator(tls));
        server.createContext("/mutate", exchange -> mutate(exchange, settings));
        server.createContext("/healthz", exchange -> answer(exchange, 200, "text/plain", "ok\n"));
        ExecutorService executor = Executors.newFixedThreadPool(8, runnable -> {
            Thread thread = new Thread(runnable, "seclume-admission");
            thread.setDaemon(true);
            return thread;
        });
        server.setExecutor(executor);
        server.start();
        return new AdmissionServer(server, executor);
    }

    /** The port it listens on. */
    public int port() {
        return server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(1);
        executor.shutdownNow();
    }

    private static void mutate(HttpExchange exchange, Injection.Settings settings)
            throws IOException {
        try (exchange) {
            if (!"POST".equals(exchange.getRequestMethod())) {
                answer(exchange, 405, "text/plain", "POST an AdmissionReview\n");
                return;
            }
            String body;
            try (InputStream in = exchange.getRequestBody()) {
                byte[] read = in.readNBytes(LARGEST + 1);
                if (read.length > LARGEST) {
                    answer(exchange, 413, "text/plain", "an AdmissionReview of more than "
                            + LARGEST + " bytes is not read\n");
                    return;
                }
                body = StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(read)).toString();
            } catch (CharacterCodingException e) {
                answer(exchange, 400, "text/plain", "the request is not UTF-8\n");
                return;
            }
            String answer;
            try {
                answer = review(body, settings);
            } catch (IllegalArgumentException e) {
                answer(exchange, 400, "text/plain", e.getMessage() + "\n");
                return;
            }
            answer(exchange, 200, "application/json", answer);
        }
    }

    private static void answer(HttpExchange exchange, int status, String type, String text)
            throws IOException {
        ByteBuffer bytes = StandardCharsets.UTF_8.encode(text);
        exchange.getResponseHeaders().set("Content-Type", type);
        exchange.sendResponseHeaders(status, bytes.remaining());
        try (OutputStream out = exchange.getResponseBody()) {
            Channels.newChannel(out).write(bytes);
        }
    }

    /**
     * The answer to one {@code AdmissionReview}: always allowed, with the
     * patch for a pod that asks for one.
     *
     * @throws IllegalArgumentException when {@code body} is no AdmissionReview
     */
    static String review(String body, Injection.Settings settings) {
        Map<String, Object> review = Json.asObject(Json.parse(body));
        Map<String, Object> request = Json.asObject(review.get("request"));
        String uid = Json.asString(request.get("uid"));
        if (uid == null) {
            throw new IllegalArgumentException("an AdmissionReview without a request uid");
        }
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("uid", uid);
        response.put("allowed", Boolean.TRUE);
        Map<String, Object> pod = Json.asObject(request.get("object"));
        String kind = Json.asString(Json.asObject(request.get("kind")).get("kind"));
        if ("Pod".equals(kind) && !pod.isEmpty()) {
            String who = describe(request, pod);
            try {
                Injection.Result result = Injection.mutate(pod, settings);
                if (!result.patch().isEmpty()) {
                    response.put("patchType", "JSONPatch");
                    // seclume-allow: the patch holds the pod's structure and the webhook's own values, never a value of the pod's
                    response.put("patch", java.util.Base64.getEncoder().encodeToString(
                            utf8(Json.write(result.patch()))));
                    LOG.log(System.Logger.Level.INFO, "seclume: " + who + ": injected "
                            + String.join(", ", result.injected()));
                }
                if (!result.warnings().isEmpty()) {
                    response.put("warnings", new ArrayList<Object>(result.warnings()));
                    for (String warning : result.warnings()) {
                        LOG.log(System.Logger.Level.WARNING, who + ": " + warning);
                    }
                }
            } catch (RuntimeException e) {
                // Never in the pod's way: let it through as it is, and say so.
                String warning = "seclume: the pod was not changed - " + e.getClass()
                        .getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
                response.put("warnings", List.of(warning));
                LOG.log(System.Logger.Level.WARNING, who + ": " + warning);
            }
        }
        Map<String, Object> answer = new LinkedHashMap<>();
        answer.put("apiVersion", review.getOrDefault("apiVersion", "admission.k8s.io/v1"));
        answer.put("kind", "AdmissionReview");
        answer.put("response", response);
        return Json.write(answer);
    }

    /** Exactly the UTF-8 bytes of {@code text} - an encoder's array may be longer. */
    static byte[] utf8(String text) {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(text);
        byte[] bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        return bytes;
    }

    private static String describe(Map<String, Object> request, Map<String, Object> pod) {
        Map<String, Object> metadata = Json.asObject(pod.get("metadata"));
        String name = Json.asString(metadata.get("name"));
        if (name == null) {
            String generated = Json.asString(metadata.get("generateName"));
            name = generated == null ? "(unnamed)" : generated + "*";
        }
        String namespace = Json.asString(request.get("namespace"));
        return "pod " + (namespace == null ? "" : namespace + "/") + name;
    }

    /** The command line; see {@link #usage()}. */
    public static void main(String[] arguments) throws Exception {
        Map<String, String> options = new LinkedHashMap<>();
        List<String> flags = List.of("--native-sidecar");
        for (int i = 0; i < arguments.length; i++) {
            String argument = arguments[i];
            if (flags.contains(argument)) {
                options.put(argument, "true");
            } else if (argument.startsWith("--") && i + 1 < arguments.length
                    && OPTIONS.contains(argument)) {
                options.put(argument, arguments[++i]);
            } else {
                System.err.println("unknown option or missing value: " + argument);
                System.err.println(usage());
                System.exit(2);
            }
        }
        if (!options.containsKey("--tls-cert") || !options.containsKey("--tls-key")
                || !options.containsKey("--sidecar-image")) {
            System.err.println(usage());
            System.exit(2);
        }
        Injection.Settings defaults = Injection.Settings.of(options.get("--sidecar-image"));
        Injection.Settings settings = new Injection.Settings(defaults.sidecarImage(),
                options.getOrDefault("--heapcheck-jar", defaults.heapcheckJar()),
                Duration.ofSeconds(number(options, "--interval-seconds",
                        (int) defaults.interval().toSeconds())),
                options.containsKey("--native-sidecar"),
                options.getOrDefault("--sidecar-memory", defaults.sidecarMemory()),
                options.get("--dump-size-limit"),
                options.getOrDefault("--spiffe-csi-driver", defaults.spiffeCsiDriver()),
                options.get("--spiffe-host-path"),
                options.getOrDefault("--spiffe-mount-path", defaults.spiffeMountPath()),
                options.getOrDefault("--spiffe-socket", defaults.spiffeSocket()));
        X509ExtendedKeyManager keys = SeclumeKeys.keyManager(Path.of(options.get("--tls-cert")),
                "provider=file&path=" + options.get("--tls-key"), Duration.ofMinutes(1));
        SSLContext tls;
        try {
            tls = SSLContext.getInstance("TLSv1.3");    // the API server speaks it
            tls.init(new KeyManager[] {keys}, null, null);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("the webhook's TLS context could not be made", e);
        }
        int port = number(options, "--port", 8443);
        AdmissionServer server = start(new InetSocketAddress(port), tls, settings);
        LOG.log(System.Logger.Level.INFO, "seclume: admission webhook on port " + server.port()
                + ", sidecar image " + settings.sidecarImage());
        Runtime.getRuntime().addShutdownHook(new Thread(server::close));
        Thread.currentThread().join();
    }

    private static int number(Map<String, String> options, String name, int fallback) {
        String value = options.get(name);
        if (value == null) {
            return fallback;
        }
        try {
            int number = Integer.parseInt(value.strip());
            if (number >= 0) {
                return number;
            }
        } catch (NumberFormatException notANumber) {
            // said below
        }
        System.err.println(name + " " + value + ": a whole number, not negative");
        System.exit(2);
        return fallback;
    }

    private static final List<String> OPTIONS = List.of("--port", "--tls-cert", "--tls-key",
            "--sidecar-image", "--heapcheck-jar", "--interval-seconds", "--sidecar-memory",
            "--dump-size-limit", "--spiffe-csi-driver", "--spiffe-host-path",
            "--spiffe-mount-path", "--spiffe-socket");

    static String usage() {
        return """
                usage: java -jar seclume-admission.jar --tls-cert <chain.pem> --tls-key <key.pem>
                                                       --sidecar-image <image> [options]

                  --port              where it listens (8443)
                  --tls-cert          the serving certificate chain, PEM; with --tls-key
                                      looked at every minute and taken up when renewed
                  --sidecar-image     the image of the dump-redacting sidecar: Java 25 and
                                      seclume-heapcheck.jar
                  --heapcheck-jar     where the jar is in that image
                                      (/opt/seclume/seclume-heapcheck.jar)
                  --interval-seconds  how often the sidecar looks at the folder (10)
                  --native-sidecar    the sidecar as a native one (an init container with
                                      restartPolicy Always, Kubernetes 1.29+)
                  --sidecar-memory    the sidecar's memory request and limit (256Mi)
                  --dump-size-limit   the dump folder's sizeLimit (none)
                  --spiffe-csi-driver the Workload API volume's CSI driver (csi.spiffe.io)
                  --spiffe-host-path  a host directory with the socket instead
                  --spiffe-mount-path where it is mounted (/spiffe-workload-api)
                  --spiffe-socket     the socket's file name there (spire-agent.sock)

                pod annotations:
                  seclume.space/redact-dumps: "true"     dumps redacted where they lie
                  seclume.space/secret-volumes: a,b       volumes whose files are looked for
                  seclume.space/spiffe: "true"           the SPIFFE Workload API socket
                  seclume.space/containers: app           only these containers""";
    }
}
