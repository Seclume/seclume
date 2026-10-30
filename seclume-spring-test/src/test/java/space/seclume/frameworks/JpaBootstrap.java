package space.seclume.frameworks;

import javax.sql.DataSource;

import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.PersistenceConfiguration;

/**
 * Hibernate for {@link EncryptedPatient}, through Jakarta Persistence 3.2's
 * {@link PersistenceConfiguration} - as an application without Spring starts
 * it. A class of its own, holding no test value: the heap test's child JVM
 * uses it, and whatever it loads ends up in that child's heap dump.
 */
final class JpaBootstrap {

    private JpaBootstrap() {
    }

    /**
     * @param connection a {@link DataSource}, or a JDBC URL with its password file
     * @param action     the schema action: {@code drop-and-create}, {@code none}
     */
    static EntityManagerFactory factory(Object connection, String action) {
        PersistenceConfiguration configuration = new PersistenceConfiguration("zl-field")
                .managedClass(EncryptedPatient.class)
                .property(PersistenceConfiguration.SCHEMAGEN_DATABASE_ACTION, action);
        if (connection instanceof DataSource source) {
            configuration.property("hibernate.connection.datasource", source);
        } else {
            configuration.property(PersistenceConfiguration.JDBC_URL, connection);
        }
        return configuration.createEntityManagerFactory();
    }
}
