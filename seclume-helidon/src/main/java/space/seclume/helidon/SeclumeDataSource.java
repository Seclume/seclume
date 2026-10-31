package space.seclume.helidon;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.enterprise.util.AnnotationLiteral;
import jakarta.inject.Qualifier;

/**
 * The pool of {@code seclume.datasources.<value>}, as a qualifier:
 * {@code @Inject @SeclumeDataSource("orders") DataSource orders}.
 * {@code @Named("orders")} finds the same bean.
 *
 * <p>Every pool bean carries it, and that is not only for the injection: CDI
 * gives a bean whose only qualifiers are {@code @Named} and {@code @Any} the
 * {@code @Default} qualifier as well, so without one more qualifier every
 * named pool would be a default {@code DataSource} - and two of them would
 * make plain {@code @Inject DataSource} ambiguous.
 */
@Qualifier
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.METHOD, ElementType.TYPE})
public @interface SeclumeDataSource {

    /** The data source's name, as in {@code seclume.datasources.<name>}. */
    String value();

    /** The qualifier as a value, for a synthetic bean or {@code Instance.select}. */
    final class Literal extends AnnotationLiteral<SeclumeDataSource> implements SeclumeDataSource {

        private static final long serialVersionUID = 1L;

        private final String value;

        private Literal(String value) {
            this.value = value;
        }

        /** {@code @SeclumeDataSource(name)}. */
        public static Literal of(String name) {
            return new Literal(name);
        }

        @Override
        public String value() {
            return value;
        }
    }
}
