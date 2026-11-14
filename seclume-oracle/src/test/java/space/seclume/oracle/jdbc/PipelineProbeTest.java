package space.seclume.oracle.jdbc;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.Executors;

import org.junit.jupiter.api.Test;

import space.seclume.Flight;
import space.seclume.Pipeline;

/** Throwaway: what Oracle answers to calls in flight, scenario by scenario. */
class PipelineProbeTest {

    static String url() {
        Path password = Path.of("..", ".local-oracle-password").toAbsolutePath().normalize();
        if (!Files.isReadable(password)) {
            password = Path.of(".local-oracle-password").toAbsolutePath().normalize();
        }
        return "jdbc:seclume:oracle://127.0.0.1:1521/FREEPDB1?user=seclume_test&provider=file&path="
                + password.toString().replace('\\', '/');
    }

    interface Body {
        void run(Connection c) throws Exception;
    }

    static void scenario(String name, Body body) throws Exception {
        System.setProperty("seclume.flight", "120");
        System.out.println("=== " + name);
        try (Connection c = DriverManager.getConnection(url())) {
            try (Statement s = c.createStatement()) {
                s.execute("begin execute immediate 'drop table probe_t'; exception when others then null; end;");
                s.execute("create table probe_t (id number primary key, note varchar2(40))");
            }
            c.setNetworkTimeout(Executors.newSingleThreadExecutor(), 8000);
            c.setAutoCommit(false);
            try {
                body.run(c);
                System.out.println("  ok");
            } catch (Throwable t) {
                System.out.println("  FAILED: " + t);
                for (Throwable cause = t.getCause(); cause != null; cause = cause.getCause()) {
                    System.out.println("    cause: " + cause);
                }
            }
            try {
                for (Flight.Message m : Flight.of(c).recent()) {
                    System.out.println("    " + m);
                }
            } catch (SQLException e) {
                System.out.println("  no flight: " + e);
            }
        } catch (Throwable t) {
            System.out.println("  connection: " + t);
        }
        try (Connection c = DriverManager.getConnection(url());
                Statement s = c.createStatement();
                ResultSet r = s.executeQuery("select count(*), listagg(id, ',') within group (order by id) from probe_t")) {
            r.next();
            System.out.println("  rows committed: " + r.getInt(1) + " [" + r.getString(2) + "]");
        }
    }

    static void insert(PreparedStatement p, int id) throws SQLException {
        p.setInt(1, id);
        p.setString(2, "n" + id);
        p.executeUpdate();
    }

    @Test
    @SuppressWarnings("try")
    void probe() throws Exception {
        for (String reuse : new String[] {"true"}) {
            System.setProperty("probe.reuse", reuse);
            System.out.println("##### reuse cached cursors: " + reuse);
            scenarios();
        }
    }

    @SuppressWarnings("try")
    static void scenarios() throws Exception {
        String sql = "insert into probe_t (id, note) values (?, ?)";
        scenario("G: 130 calls over 97 texts, a statement per call", c -> {
            for (int i = 1; i <= 130; i++) {
                try (PreparedStatement p = c.prepareStatement(
                        "insert into probe_t (id, note) values (?, 'text " + (i % 97) + "')")) {
                    if (i == 1) {
                        // nothing
                    }
                }
            }
            try (Pipeline u = Pipeline.open(c)) {
                for (int i = 1; i <= 130; i++) {
                    try (PreparedStatement p = c.prepareStatement(
                            "insert into probe_t (id, note) values (?, 'text " + (i % 97) + "')")) {
                        p.setInt(1, i);
                        p.executeUpdate();
                    }
                }
            }
            c.commit();
        });
        scenario("H: 130 calls over 97 texts, the statements kept open", c -> {
            PreparedStatement[] ps = new PreparedStatement[97];
            for (int t = 0; t < 97; t++) {
                ps[t] = c.prepareStatement("insert into probe_t (id, note) values (?, 'text " + t + "')");
            }
            try (Pipeline u = Pipeline.open(c)) {
                for (int i = 1; i <= 130; i++) {
                    ps[i % 97].setInt(1, i);
                    ps[i % 97].executeUpdate();
                }
            }
            c.commit();
            for (PreparedStatement p : ps) {
                p.close();
            }
        });
        scenario("I: 70 distinct texts, no cache before", c -> {
            try (Pipeline u = Pipeline.open(c)) {
                for (int i = 1; i <= 70; i++) {
                    try (PreparedStatement p = c.prepareStatement(
                            "insert into probe_t (id, note) values (?, 'other " + i + "')")) {
                        p.setInt(1, i);
                        p.executeUpdate();
                    }
                }
            }
            c.commit();
        });
        scenario("A: four fresh parses in flight, no failure", c -> {
            try (PreparedStatement p = c.prepareStatement(sql)) {
                try (Pipeline u = Pipeline.open(c)) {
                    for (int i = 1; i <= 4; i++) insert(p, i);
                }
            }
            c.commit();
        });
        scenario("B: one normal run, then two in flight on the cached cursor", c -> {
            try (PreparedStatement p = c.prepareStatement(sql)) {
                insert(p, 100);
                try (Pipeline u = Pipeline.open(c)) {
                    insert(p, 1);
                    insert(p, 2);
                }
            }
            c.commit();
        });
        scenario("C: one normal run, then ONE in flight on the cached cursor", c -> {
            try (PreparedStatement p = c.prepareStatement(sql)) {
                insert(p, 100);
                try (Pipeline u = Pipeline.open(c)) {
                    insert(p, 1);
                }
            }
            c.commit();
        });
        scenario("D: fresh parses, the second a duplicate, two after it", c -> {
            try (PreparedStatement p = c.prepareStatement(sql)) {
                try (Pipeline u = Pipeline.open(c)) {
                    insert(p, 1);
                    insert(p, 1);
                    insert(p, 2);
                    insert(p, 3);
                }
            }
            c.commit();
        });
        scenario("E: fresh parses, the last one a duplicate", c -> {
            try (PreparedStatement p = c.prepareStatement(sql)) {
                try (Pipeline u = Pipeline.open(c)) {
                    insert(p, 1);
                    insert(p, 2);
                    insert(p, 1);
                }
            }
            c.commit();
        });
        scenario("F: 130 fresh parses in flight (two groups and more)", c -> {
            try (PreparedStatement p = c.prepareStatement(sql)) {
                try (Pipeline u = Pipeline.open(c)) {
                    for (int i = 1; i <= 130; i++) insert(p, i);
                }
            }
            c.commit();
        });
    }
}
