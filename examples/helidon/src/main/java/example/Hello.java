package example;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.sql.DataSource;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.Initialized;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

/**
 * When the container has started, asks the database who it is through the
 * injected {@code DataSource} - the pool that microprofile-config.properties
 * describes. Nothing here knows about seclume. The container keeps running,
 * a service with an open pool, which is when somebody takes a heap dump.
 */
@ApplicationScoped
public class Hello {

    @Inject
    DataSource dataSource;

    void started(@Observes @Initialized(ApplicationScoped.class) Object event) throws SQLException {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select current_user || ' on ' || version()")) {
            rows.next();
            System.out.println("connected as " + rows.getString(1));
        }
        System.out.println("running as pid " + ProcessHandle.current().pid());
    }
}
