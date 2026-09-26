import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

import space.seclume.crac.SeclumeCrac;
import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;
import space.seclume.postgresql.jdbc.SeclumeDataSource;

/**
 * mode register: pool registered with SeclumeCrac - checkpoint, restore, query.
 * mode bare:     the same pool, not registered - the checkpoint should be refused.
 * mode leak:     registered, and the password held as a String on purpose - the control
 *                that a search of the image would find it.
 */
public class CracProof {
    static Object leaked;

    public static void main(String[] args) throws Exception {
        String mode = args[0];
        SeclumeDataSource source = new SeclumeDataSource();
        source.setUrl("jdbc:seclume:postgresql://127.0.0.1:5442/seclume_test?user=seclume_test"
                + "&tls=off&provider=file&path=/work/pw");
        PoolSettings settings = new PoolSettings();
        settings.setName("crac");
        settings.setMaximumPoolSize(2);
        settings.setMinimumIdle(2);
        SeclumePool pool = new SeclumePool(source, settings);
        pool.warmup();
        System.out.println("PROOF before: " + one(pool) + ", pool " + pool.statistics());
        if (!mode.equals("bare")) {
            SeclumeCrac.register(pool);
        }
        if (mode.equals("leak")) {
            leaked = Files.readString(Path.of("/work/pw")).strip();
        }
        try {
            org.crac.Core.checkpointRestore();
        } catch (Exception refused) {
            System.out.println("PROOF checkpoint refused: " + refused);
            Throwable[] suppressed = refused.getSuppressed();
            for (Throwable t : suppressed) {
                System.out.println("PROOF   " + t);
            }
            return;
        }
        System.out.println("PROOF restored: " + one(pool) + ", pool " + pool.statistics());
        pool.close();
    }

    static String one(SeclumePool pool) throws Exception {
        try (Connection c = pool.getConnection(); Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select 'ok ' || pg_backend_pid()")) {
            r.next();
            return r.getString(1);
        }
    }
}
