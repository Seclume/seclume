package space.seclume.jgit;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.http.server.GitServlet;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.transport.ReceivePack;

/**
 * A Git server over HTTPS - JGit's own servlet in Tomcat - in a process of its
 * own, asking for a Basic login whose password it reads from a file. One
 * repository, with one commit, that may be cloned and pushed to.
 */
public final class GitServerProcess {

    private GitServerProcess() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args[0]);
        String password = Files.readString(directory.resolve("password")).trim();
        Path work = directory.resolve("seed");
        try (Git seed = Git.init().setDirectory(work.toFile()).setInitialBranch("main").call()) {
            Files.writeString(work.resolve("README"), "hello from the server\n");
            seed.add().addFilepattern("README").call();
            seed.commit().setMessage("first").setAuthor("server", "server@example.com")
                    .setCommitter("server", "server@example.com").setSign(false).call();
        }
        Repository bare = Git.cloneRepository().setURI(work.toUri().toString()).setBare(true)
                .setDirectory(directory.resolve("app.git").toFile()).call().getRepository();

        Tomcat tomcat = new Tomcat();
        tomcat.setBaseDir(directory.resolve("tomcat").toString());
        Connector connector = new Connector();
        connector.setPort(0);
        connector.setScheme("https");
        connector.setSecure(true);
        connector.setProperty("SSLEnabled", "true");
        SSLHostConfig host = new SSLHostConfig();
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(host,
                SSLHostConfigCertificate.Type.RSA);
        certificate.setCertificateKeystoreFile(directory.resolve("store.p12").toString());
        certificate.setCertificateKeystorePassword("store");
        certificate.setCertificateKeystoreType("PKCS12");
        host.addCertificate(certificate);
        connector.addSslHostConfig(host);
        tomcat.setConnector(connector);

        Context context = tomcat.addContext("", null);
        GitServlet git = new GitServlet();
        git.setRepositoryResolver((request, name) -> {
            bare.incrementOpen();
            return bare;
        });
        git.setReceivePackFactory((request, repository) -> new ReceivePack(repository));
        Tomcat.addServlet(context, "git", git);
        context.addServletMapping("/*", "git");

        String expected = "Basic " + Base64.getEncoder().encodeToString(
                ("deploy:" + password).getBytes(StandardCharsets.UTF_8));
        FilterDef basic = new FilterDef();
        basic.setFilterName("basic");
        basic.setFilter(new Filter() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response,
                                 FilterChain chain) throws IOException, ServletException {
                String given = ((HttpServletRequest) request).getHeader("Authorization");
                if (expected.equals(given)) {
                    chain.doFilter(request, response);
                    return;
                }
                HttpServletResponse http = (HttpServletResponse) response;
                http.setHeader("WWW-Authenticate", "Basic realm=\"git\"");
                http.sendError(401);
            }
        });
        context.addFilterDef(basic);
        FilterMap map = new FilterMap();
        map.setFilterName("basic");
        map.addURLPattern("/*");
        context.addFilterMap(map);

        tomcat.start();
        Files.writeString(directory.resolve("port.tmp"), String.valueOf(connector.getLocalPort()));
        Files.move(directory.resolve("port.tmp"), directory.resolve("port"));
        tomcat.getServer().await();
    }
}
