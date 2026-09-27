package space.seclume.http;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.AbstractBufferingClientHttpRequest;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;

/**
 * Spring's {@code RestClient} and {@code RestTemplate} on a {@link SeclumeHttp}
 * - the credential added by seclume, off the heap, and never by the
 * application:
 *
 * <pre>
 * SeclumeHttp api = SeclumeHttp.of("https://api.example.com/v1?provider=file&amp;path=/run/secrets/token");
 * RestClient rest = RestClient.builder()
 *         .requestFactory(new SeclumeHttpRequestFactory(api))
 *         .baseUrl("https://api.example.com/v1")
 *         .build();
 * Order order = rest.get().uri("/orders/{id}", 42).retrieve().body(Order.class);
 * </pre>
 *
 * <p>A request to another origin is refused, and so is one that sets the
 * credential's header itself - an interceptor adding a token would have made
 * it a {@code String} already. Redirects are not followed.
 */
public final class SeclumeHttpRequestFactory implements ClientHttpRequestFactory {

    private final SeclumeHttp http;

    public SeclumeHttpRequestFactory(SeclumeHttp http) {
        this.http = http;
    }

    @Override
    public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) {
        return new Request(uri, httpMethod);
    }

    private final class Request extends AbstractBufferingClientHttpRequest {

        private final URI uri;
        private final HttpMethod method;

        Request(URI uri, HttpMethod method) {
            this.uri = uri;
            this.method = method;
        }

        @Override
        public HttpMethod getMethod() {
            return method;
        }

        @Override
        public URI getURI() {
            return uri;
        }

        @Override
        protected ClientHttpResponse executeInternal(HttpHeaders headers, byte[] bufferedOutput)
                throws IOException {
            Map<String, List<String>> plain = new LinkedHashMap<>();
            headers.forEach((name, values) -> {
                // Spring adds Content-Length for a buffered body; the client sets
                // its own from the body it is given.
                if (!name.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH)) {
                    plain.put(name, new ArrayList<>(values));
                }
            });
            byte[] body = bufferedOutput.length == 0 ? null : bufferedOutput;
            return new Response(http.send(method.name(), uri, plain, body));
        }
    }

    private static final class Response implements ClientHttpResponse {

        private final SeclumeHttp.Response response;
        private HttpHeaders headers;

        Response(SeclumeHttp.Response response) {
            this.response = response;
        }

        @Override
        public HttpStatusCode getStatusCode() {
            return HttpStatusCode.valueOf(response.status());
        }

        @Override
        public String getStatusText() {
            return response.reason();
        }

        @Override
        public HttpHeaders getHeaders() {
            if (headers == null) {
                HttpHeaders copy = new HttpHeaders();
                response.headers().forEach((name, values) -> copy.addAll(name, values));
                headers = HttpHeaders.readOnlyHttpHeaders(copy);
            }
            return headers;
        }

        @Override
        public InputStream getBody() {
            return response.body();
        }

        @Override
        public void close() {
            try {
                response.close();
            } catch (IOException ignored) {
                // the connection is closed rather than reused
            }
        }
    }
}
