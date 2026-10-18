package space.seclume.postgresql.jdbc;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * The child of {@link ProcessMemoryTest}: logs in over TLS with SCRAM, runs a
 * query, and then waits - announcing its pid - until the parent has searched
 * its memory.
 *
 * <pre>  ProcessMemoryProbe mode host port passwordFile logins</pre>
 *
 * Modes: {@code closed} closes every connection before it is searched,
 * {@code open} keeps the last one open, {@code leaking} is the negative
 * control and holds the password as a {@code String}, the way a driver that
 * takes one does.
 */
public final class ProcessMemoryProbe {

    private ProcessMemoryProbe() {
    }

    public static void main(String[] args) throws Exception {
        String mode = args[0];
        String host = args[1];
        String port = args[2];
        String passwordFile = args[3];
        int logins = Integer.parseInt(args[4]);
        Object kept = null;
        if (mode.equals("leaking")) {
            kept = Files.readString(Path.of(passwordFile), StandardCharsets.UTF_8).strip(); // seclume-allow: the negative control, which must leak
        }
        String url = "jdbc:seclume:postgresql://" + host + ":" + port + "/seclume_test"
                + "?user=seclume_test&tls=require&trustServerCertificate=true"
                + "&provider=file&path=" + passwordFile.replace('\\', '/');
        Connection open = null;
        for (int i = 0; i < logins; i++) {
            Connection connection = DriverManager.getConnection(url);
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select 1")) {
                rows.next();
            }
            if (mode.equals("open") && i == logins - 1) {
                open = connection;
            } else {
                connection.close();
            }
        }
        System.gc();
        System.gc();
        System.out.println("READY " + ProcessHandle.current().pid());
        System.out.flush();
        System.in.read();
        System.out.println(kept == null ? "done" : "kept " + kept.hashCode());
        if (open != null) {
            open.close();
        }
    }
}
