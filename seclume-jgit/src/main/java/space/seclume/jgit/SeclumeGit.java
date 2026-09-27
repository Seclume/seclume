package space.seclume.jgit;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.URL;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.eclipse.jgit.transport.http.HttpConnection;
import org.eclipse.jgit.transport.http.HttpConnectionFactory;

import space.seclume.http.SeclumeSslSocketFactory;

/**
 * JGit over HTTPS - clone, fetch, push to GitHub, GitLab, Bitbucket, Gitea -
 * with the password or access token off the heap.
 *
 * <pre>
 * HttpTransport.setConnectionFactory(SeclumeGit.connections(""));   // org.eclipse.jgit.transport, once
 * Git.cloneRepository().setURI("https://git.example.com/team/app.git")
 *         .setCredentialsProvider(SeclumeGit.credentials("deploy",
 *                 "provider=file&amp;path=/run/secrets/git-token"))
 *         .setDirectory(dir).call();
 * </pre>
 *
 * <p>JGit keeps a password as a {@code char[]} in its credentials provider and
 * writes {@code Authorization: Basic ...} with it. Here it holds a
 * placeholder, and its HTTPS connections are seclume's TLS
 * ({@link SeclumeSslSocketFactory}), which writes {@code user:secret} - encoded
 * in native memory - where JGit wrote {@code user:placeholder}. Plain
 * {@code http://} is not taken: the credential would go in the clear.
 */
public final class SeclumeGit {

    private SeclumeGit() {
    }

    /**
     * A connection factory for {@code HttpTransport.setConnectionFactory};
     * {@code tlsOptions} are {@code tlsRootCert} or {@code tlsPin} for a server
     * whose CA the JVM does not know, or empty.
     */
    public static HttpConnectionFactory connections(String tlsOptions) {
        SeclumeSslSocketFactory sockets = SeclumeSslSocketFactory.of(tlsOptions);
        return new HttpConnectionFactory() {
            @Override
            public HttpConnection create(URL url) throws IOException {
                return create(url, null);
            }

            @Override
            public HttpConnection create(URL url, Proxy proxy) throws IOException {
                if (!"https".equalsIgnoreCase(url.getProtocol())) {
                    throw new IOException("seclume's Git transport is https:// only - not "
                            + url.getProtocol() + "://, where the credential would go in the "
                            + "clear");
                }
                HttpsURLConnection connection = (HttpsURLConnection) (proxy == null
                        ? url.openConnection() : url.openConnection(proxy));
                connection.setSSLSocketFactory(sockets);
                connection.setHostnameVerifier(sockets.hostnameVerifier());
                return new Connection(connection);
            }
        };
    }

    /** A credentials provider with {@code user} and a placeholder for the secret. */
    public static CredentialsProvider credentials(String user, String secretSpec) {
        return new UsernamePasswordCredentialsProvider(user,
                SeclumeSslSocketFactory.placeholder(secretSpec));
    }

    /** JGit's view of an {@code HttpsURLConnection} whose sockets are seclume's. */
    private static final class Connection implements HttpConnection {

        private final HttpsURLConnection connection;

        Connection(HttpsURLConnection connection) {
            this.connection = connection;
        }

        @Override
        public int getResponseCode() throws IOException {
            return connection.getResponseCode();
        }

        @Override
        public URL getURL() {
            return connection.getURL();
        }

        @Override
        public String getResponseMessage() throws IOException {
            return connection.getResponseMessage();
        }

        @Override
        public Map<String, List<String>> getHeaderFields() {
            return connection.getHeaderFields();
        }

        @Override
        public void setRequestProperty(String key, String value) {
            connection.setRequestProperty(key, value);
        }

        @Override
        public void setRequestMethod(String method) throws ProtocolException {
            connection.setRequestMethod(method);
        }

        @Override
        public void setUseCaches(boolean useCaches) {
            connection.setUseCaches(useCaches);
        }

        @Override
        public void setConnectTimeout(int timeout) {
            connection.setConnectTimeout(timeout);
        }

        @Override
        public void setReadTimeout(int timeout) {
            connection.setReadTimeout(timeout);
        }

        @Override
        public String getContentType() {
            return connection.getContentType();
        }

        @Override
        public InputStream getInputStream() throws IOException {
            return connection.getInputStream();
        }

        @Override
        public String getHeaderField(String name) {
            return connection.getHeaderField(name);
        }

        @Override
        public List<String> getHeaderFields(String name) {
            List<String> values = connection.getHeaderFields().get(name);
            if (values == null) {
                for (Map.Entry<String, List<String>> entry : connection.getHeaderFields()
                        .entrySet()) {
                    if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) {
                        return entry.getValue();
                    }
                }
            }
            return values == null ? List.of() : values;
        }

        @Override
        public int getContentLength() {
            return connection.getContentLength();
        }

        @Override
        public void setInstanceFollowRedirects(boolean follow) {
            connection.setInstanceFollowRedirects(follow);
        }

        @Override
        public void setDoOutput(boolean doOutput) {
            connection.setDoOutput(doOutput);
        }

        @Override
        public void setFixedLengthStreamingMode(int length) {
            connection.setFixedLengthStreamingMode(length);
        }

        @Override
        public OutputStream getOutputStream() throws IOException {
            return connection.getOutputStream();
        }

        @Override
        public void setChunkedStreamingMode(int chunkLength) {
            connection.setChunkedStreamingMode(chunkLength);
        }

        @Override
        public String getRequestMethod() {
            return connection.getRequestMethod();
        }

        @Override
        public boolean usingProxy() {
            return connection.usingProxy();
        }

        @Override
        public void connect() throws IOException {
            connection.connect();
        }

        /** JGit calls this only to switch certificate checks off; seclume's TLS keeps them. */
        @Override
        public void configure(KeyManager[] km, TrustManager[] tm, SecureRandom random) {
            // the sockets are seclume's; their trust is set on SeclumeGit.connections
        }

        @Override
        public void setHostnameVerifier(HostnameVerifier verifier) {
            // seclume's TLS checks the hostname itself
        }

        @Override
        public String toString() {
            return connection.getURL() + " (" + HttpURLConnection.class.getSimpleName()
                    + " over seclume's TLS)";
        }
    }
}
