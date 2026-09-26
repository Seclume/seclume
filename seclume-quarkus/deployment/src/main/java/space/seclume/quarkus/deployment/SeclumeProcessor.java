package space.seclume.quarkus.deployment;

import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import io.quarkus.agroal.spi.JdbcDriverBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.runtime.configuration.ConfigurationException;

/**
 * seclume's drivers for Quarkus: four datasource kinds for Agroal, and a
 * build that refuses to put a password where Agroal would keep it.
 *
 * <pre>
 *   quarkus.datasource.db-kind=seclume-postgresql
 *   quarkus.datasource.jdbc.url=jdbc:seclume:postgresql://db/app?user=app&amp;provider=file&amp;path=/run/secrets/db
 * </pre>
 *
 * <p>The secret is configured in the URL, as a provider, and is read by the
 * driver into native memory at every login. {@code quarkus.datasource.password}
 * would be a {@code String} in Agroal's connection factory for the life of
 * the application - in every heap dump - so a seclume datasource with one
 * fails the build, naming the property.
 *
 * <p>Nothing is registered for reflection beyond the driver and XA classes
 * Agroal loads by name: the drivers use no reflection, and their native-image
 * settings (the FFM signatures, shared arenas) ship inside their own jars.
 */
class SeclumeProcessor {

    private static final String FEATURE = "seclume";

    /** db-kind, driver, XA data source. */
    private static final List<String[]> KINDS = List.of(
            new String[] {"seclume-postgresql", "space.seclume.postgresql.jdbc.SeclumeDriver",
                    "space.seclume.postgresql.jdbc.SeclumeXaDataSource"},
            new String[] {"seclume-mysql", "space.seclume.mysql.jdbc.MyDriver",
                    "space.seclume.mysql.jdbc.MyXaDataSource"},
            new String[] {"seclume-sqlserver", "space.seclume.sqlserver.jdbc.TdsDriver",
                    "space.seclume.sqlserver.jdbc.TdsXaDataSource"},
            new String[] {"seclume-oracle", "space.seclume.oracle.jdbc.OraDriver",
                    "space.seclume.oracle.jdbc.OraXaDataSource"});

    /** {@code quarkus.datasource.password} or {@code quarkus.datasource."name".password}. */
    private static final Pattern PASSWORD = Pattern.compile(
            "quarkus\\.datasource(?:\\.(\"[^\"]+\"|[^.\"]+))?\\.password");

    /**
     * The feature, and the check that comes with it: Quarkus runs only build
     * steps that produce something, so the check rides on the one that
     * always does.
     */
    @BuildStep
    FeatureBuildItem feature() {
        noPasswordInTheConfiguration();
        return new FeatureBuildItem(FEATURE);
    }

    @BuildStep
    void drivers(BuildProducer<JdbcDriverBuildItem> drivers,
                 BuildProducer<ReflectiveClassBuildItem> reflective) {
        for (String[] kind : KINDS) {
            drivers.produce(new JdbcDriverBuildItem(kind[0], kind[1], kind[2]));
            reflective.produce(ReflectiveClassBuildItem.builder(kind[1], kind[2])
                    .methods().build());
        }
    }

    /**
     * Every seclume class is initialised when the image runs, not when it is
     * built. Quarkus initialises at build time by default, and a native
     * binding made there - CNG's bcrypt.dll, OpenSSL, the lock on a secret's
     * memory - is made on the build machine for the wrong system, or fails
     * the build outright (found on the first native build, 26.09.2026).
     */
    @BuildStep
    void runtimeInit(BuildProducer<
            io.quarkus.deployment.builditem.nativeimage.RuntimeInitializedPackageBuildItem> late) {
        // The library's packages, not "space.seclume" as a whole: that prefix
        // would take in the extension's own beans, which Quarkus builds in.
        for (String name : List.of("crypto", "internal", "secret", "tls", "jfr", "pool",
                "postgresql", "mysql", "sqlserver", "oracle")) {
            late.produce(new io.quarkus.deployment.builditem.nativeimage
                    .RuntimeInitializedPackageBuildItem("space.seclume." + name));
        }
    }

    private static void noPasswordInTheConfiguration() {
        Config config = ConfigProvider.getConfig();
        for (String name : config.getPropertyNames()) {
            Matcher password = PASSWORD.matcher(name);
            if (!password.matches()) {
                continue;
            }
            String datasource = password.group(1);
            String prefix = datasource == null ? "quarkus.datasource"
                    : "quarkus.datasource." + datasource;
            Optional<String> kind = config.getOptionalValue(prefix + ".db-kind", String.class);
            if (kind.isPresent() && kind.get().startsWith("seclume-")) {
                throw new ConfigurationException(name + " is set for a " + kind.get()
                        + " datasource. Agroal would keep that password as a String for as "
                        + "long as the application runs, and it would be in every heap dump - "
                        + "the one thing seclume exists to prevent. Remove it and name the "
                        + "secret in the JDBC URL instead, e.g. provider=file&path=/run/secrets/db "
                        + "or provider=vault&address=...; the driver then reads it into "
                        + "native memory at each login.");
            }
        }
    }
}
