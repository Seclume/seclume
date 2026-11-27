import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * One borrow on MariaDB: the login's role, a SET ROLE by the borrower, the
 * pool's reset, and the role the next borrower finds - see mariadb-roles.sh.
 */
public class MariaRoleProbe {
    public static void main(String[] args) throws Exception {
        String url = "jdbc:seclume:mysql://127.0.0.1:3399/information_schema?user=prober&tls=off&allowLegacyHashOverUnverifiedTls=true"
                + "&provider=file&path=/work/pw";
        try (Connection c = DriverManager.getConnection(url)) {
            System.out.println("PROOF server " + ask(c, "select version()"));
            System.out.println("PROOF login role " + ask(c, "select current_role()"));
            try (Statement s = c.createStatement()) {
                s.execute("set role " + args[0]);
            }
            System.out.println("PROOF set role " + ask(c, "select current_role()"));
            space.seclume.SessionReset reset = c.unwrap(space.seclume.SessionReset.class);
            System.out.println("PROOF reset accepted " + reset.resetSessionState());
            reset.settleReset();
            System.out.println("PROOF after reset " + ask(c, "select current_role()"));
        }
    }

    static String ask(Connection c, String sql) throws Exception {
        try (Statement s = c.createStatement(); ResultSet r = s.executeQuery(sql)) {
            r.next();
            return r.getString(1);
        }
    }
}
