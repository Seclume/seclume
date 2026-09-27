package space.seclume.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;

import javax.net.ssl.SSLContext;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import space.seclume.crypto.OpenSslSigningKey;
import space.seclume.tck.NoSecretInHeap;

/** An embedded Tomcat serving HTTPS with the key in OpenSSL. */
class TomcatTest {

    @TempDir
    Path directory;

    @Test
    void servesHttpsAndTheKeyStaysOffTheHeap() throws Exception {
        assumeTrue(OpenSslSigningKey.available(), "OpenSSL 3 on 64-bit Linux");
        for (String kind : new String[] {"rsa:2048", "ec:P-256"}) {
            KeyFiles files = KeyFiles.make(directory.resolve(kind.replace(':', '-')), kind);
            Tomcat tomcat = new Tomcat();
            tomcat.setBaseDir(directory.resolve("tomcat-" + kind.replace(':', '-')).toString());
            Connector connector = new Connector();
            connector.setPort(0);
            SeclumeTomcat.enableHttps(connector, files.certificate(), files.spec());
            tomcat.setConnector(connector);
            Context context = tomcat.addContext("", null);
            Tomcat.addServlet(context, "hello", new HttpServlet() {
                @Override
                protected void doGet(HttpServletRequest request, HttpServletResponse response)
                        throws IOException {
                    response.getWriter().write("secure=" + request.isSecure());
                }
            });
            context.addServletMapping("/", "hello");
            tomcat.start();
            try {
                SSLContext trust = SSLContext.getInstance("TLS");
                trust.init(null, ServerKeyTest.trusting(files.certificate()).getTrustManagers(),
                        null);
                try (HttpClient client = HttpClient.newBuilder().sslContext(trust).build()) {
                    HttpResponse<String> response = client.send(HttpRequest.newBuilder(
                            URI.create("https://localhost:" + connector.getLocalPort() + "/"))
                            .build(), HttpResponse.BodyHandlers.ofString());
                    assertEquals("secure=true", response.body());
                }
                NoSecretInHeap.assertAbsent(files.der());
                NoSecretInHeap.assertAbsent(files.secret());
            } finally {
                tomcat.stop();
                tomcat.destroy();
            }
        }
    }
}
