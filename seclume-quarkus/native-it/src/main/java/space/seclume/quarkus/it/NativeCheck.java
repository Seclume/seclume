package space.seclume.quarkus.it;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

import io.agroal.api.AgroalDataSource;
import io.quarkus.agroal.DataSource;
import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.annotations.QuarkusMain;
import jakarta.inject.Inject;

/**
 * Logs in to the four databases through Agroal, keeps the connections in the
 * pools, and dumps the heap to the path given as the first argument - for a
 * search in another process, which alone knows the passwords.
 */
@QuarkusMain
public class NativeCheck implements QuarkusApplication {

    @Inject
    @DataSource("pg")
    AgroalDataSource pg;

    @Inject
    @DataSource("mysql")
    AgroalDataSource mysql;

    @Inject
    @DataSource("mssql")
    AgroalDataSource mssql;

    @Inject
    @DataSource("oracle")
    AgroalDataSource oracle;

    public static void main(String... args) {
        Quarkus.run(NativeCheck.class, args);
    }

    @Override
    public int run(String... args) throws Exception {
        int failed = 0;
        failed += ask("PostgreSQL", pg, "select current_user");
        failed += ask("MySQL", mysql, "select substring_index(current_user(), '@', 1)");
        failed += ask("SQL Server", mssql, "select suser_sname()");
        failed += ask("Oracle", oracle, "select user from dual");
        System.out.println("native image: "
                + org.graalvm.nativeimage.ImageInfo.inImageRuntimeCode());
        if (args.length > 0) {
            System.gc();
            org.graalvm.nativeimage.VMRuntime.dumpHeap(args[0], false);
            System.out.println("heap dumped to " + args[0]);
        }
        return failed;
    }

    private static int ask(String name, AgroalDataSource source, String query) {
        try (Connection connection = source.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(query)) {
            rows.next();
            System.out.println("ok   " + name + ": " + rows.getString(1) + " by "
                    + space.seclume.Secured.of(connection).authenticationMethod());
            return 0;
        } catch (Exception e) {
            System.out.println("FAIL " + name + ": " + e);
            return 1;
        }
    }
}
