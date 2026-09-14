package space.seclume.postgresql.jdbc;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import space.seclume.tck.Heap;

/**
 * The probe for the proof at the JDBC level.
 *
 * <p>It takes exactly the path an application takes: {@code DriverManager},
 * URL, {@code PreparedStatement}. The core proof shows that the secret
 * handling is tight, the protocol proof that the handshake is - here comes the
 * added question of whether the layer above touches the password somewhere
 * after all, when taking the URL apart, say.
 */
public final class JdbcProbe {

    private JdbcProbe() {
    }

    public static void main(String[] args) throws Exception {
        String url = args[0];
        Path dumpFile = Path.of(args[1]);
        int cycles = Integer.parseInt(args[2]);

        int rows = 0;
        for (int i = 0; i < cycles; i++) {
            try (Connection connection = DriverManager.getConnection(url);
                 PreparedStatement statement = connection.prepareStatement(
                         "select ?::text, current_user")) {
                statement.setString(1, "Durchgang " + i);
                try (ResultSet result = statement.executeQuery()) {
                    while (result.next()) {
                        rows += result.getString(1).length() + result.getString(2).length();
                    }
                }
            }
        }

        // One connection stays open, the way it would stay open in a pool.
        try (Connection open = DriverManager.getConnection(url);
             Statement statement = open.createStatement();
             ResultSet result = statement.executeQuery("select 42")) {
            while (result.next()) {
                rows += result.getInt(1);
            }
            Heap.collect();
            Heap.dump(dumpFile);
            System.out.println("connected " + (cycles + 1) + " times via JDBC, sum=" + rows);
        }
    }
}
