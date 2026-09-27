package space.seclume.kubernetes;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;

import io.kubernetes.client.openapi.ApiClient;
import okhttp3.OkHttpClient;

import space.seclume.http.SeclumeSslSocketFactory;

/**
 * The official Kubernetes Java client, with the service account token off the
 * heap.
 *
 * <pre>
 * ApiClient client = SeclumeKubernetes.inCluster();                   // in a pod
 * ApiClient client = SeclumeKubernetes.client("https://api.cluster:6443"
 *         + "?tlsRootCert=/etc/kube/ca.crt&amp;provider=file&amp;path=/etc/kube/token");
 * CoreV1Api core = new CoreV1Api(client);
 * </pre>
 *
 * <p>{@code ClientBuilder.cluster()} reads the pod's token into a
 * {@code String} and puts it into every request header - the service account
 * on the heap, and every copy of it that the rotation leaves behind. Here the
 * client holds a placeholder; its HTTP client (OkHttp) gets
 * {@link SeclumeSslSocketFactory}, whose TLS checks the API server against the
 * cluster's CA and writes the token - read from its file for each request, so
 * a rotated one is picked up at once - where the placeholder is.
 */
public final class SeclumeKubernetes {

    /** Where a pod finds its service account. */
    static final Path SERVICE_ACCOUNT = Path.of("/var/run/secrets/kubernetes.io/serviceaccount");

    private SeclumeKubernetes() {
    }

    /** In a pod: the API server from the environment, the pod's CA and token. */
    public static ApiClient inCluster() {
        String host = System.getenv("KUBERNETES_SERVICE_HOST"); // seclume-allow: the API server's address - public
        String port = System.getenv("KUBERNETES_SERVICE_PORT"); // seclume-allow: its port - public
        if (host == null || port == null) {
            throw new IllegalStateException("not in a pod: KUBERNETES_SERVICE_HOST and "
                    + "KUBERNETES_SERVICE_PORT are not set");
        }
        if (!Files.isReadable(SERVICE_ACCOUNT.resolve("token"))) {
            throw new IllegalStateException("the pod has no service account token at "
                    + SERVICE_ACCOUNT.resolve("token") + " - automountServiceAccountToken?");
        }
        String authority = host.indexOf(':') >= 0 ? "[" + host + "]" : host;
        return client("https://" + authority + ":" + port + "?tlsRootCert="
                + SERVICE_ACCOUNT.resolve("ca.crt") + "&provider=file&path="
                + SERVICE_ACCOUNT.resolve("token"));
    }

    /**
     * An API server at {@code url}: {@code https://host:port}, then
     * {@code tlsRootCert} or {@code tlsPin} for the cluster's CA, and the
     * token's secret provider.
     */
    public static ApiClient client(String url) {
        URI uri = URI.create(url);
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("the API server is reached over https://, not "
                    + uri.getScheme() + "://");
        }
        String query = uri.getRawQuery() == null ? "" : uri.getRawQuery();
        StringBuilder tls = new StringBuilder();
        StringBuilder secret = new StringBuilder();
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            boolean trust = pair.startsWith("tlsRootCert=") || pair.startsWith("tlsPin=")
                    || pair.startsWith("connectTimeout=");
            StringBuilder target = trust ? tls : secret;
            target.append(target.length() == 0 ? "" : "&").append(pair);
        }
        SeclumeSslSocketFactory sockets = SeclumeSslSocketFactory.of(tls.toString());
        String token = SeclumeSslSocketFactory.placeholder(secret.toString());
        OkHttpClient http = new OkHttpClient.Builder()
                .sslSocketFactory(sockets, sockets.trustManager())
                .hostnameVerifier(sockets.hostnameVerifier())
                .addInterceptor(chain -> chain.proceed(chain.request().newBuilder()
                        .header("Authorization", "Bearer " + token).build()))
                .build();
        String base = "https://" + uri.getRawAuthority();
        return new ApiClient(http).setBasePath(base);
    }
}
