package example;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.concurrent.CountDownLatch;

import javax.sql.DataSource;

import io.micronaut.context.ApplicationContext;

/**
 * Starts Micronaut, asks the database who it is through the pool that
 * application.yml describes, and keeps running - a service with an open pool,
 * which is when somebody takes a heap dump. Nothing here knows about seclume.
 */
public class Application {

    public static void main(String[] arguments) throws Exception {
        try (ApplicationContext context = ApplicationContext.run()) {
            DataSource dataSource = context.getBean(DataSource.class);
            try (Connection connection = dataSource.getConnection();
                 Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("select current_user || ' on ' || version()")) {
                rows.next();
                System.out.println("connected as " + rows.getString(1));
            }
            System.out.println("running as pid " + ProcessHandle.current().pid());
            new CountDownLatch(1).await();
        }
    }
}
