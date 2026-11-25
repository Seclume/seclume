package space.seclume.logging.logback;

import ch.qos.logback.core.Context;

/**
 * Whether Logback masks anything at all. {@code seclume.logging.redact=true}
 * installs the masker; the lines are masked only where a converter or encoder
 * of seclume's is in Logback's configuration - {@code redact-rules.xml} in a
 * {@code logback-spring.xml}, or a {@code RedactingEncoder}. Without either,
 * the switch looked like protection and did nothing, and nothing said so.
 */
public final class LogbackMasking {

    private static final String IN_USE = LogbackMasking.class.getName() + ".inUse";

    private LogbackMasking() {
    }

    /** Called by seclume's converters and encoder when they start in {@code context}. */
    static void inUse(Context context) {
        if (context != null) {
            context.putObject(IN_USE, Boolean.TRUE);
        }
    }

    /** Whether a converter or encoder of seclume's started in {@code context}. */
    static boolean marked(Context context) {
        return context.getObject(IN_USE) != null;
    }

    /**
     * Whether a converter or encoder of seclume's started in the Logback
     * context SLF4J logs through; {@code null} when SLF4J does not log through
     * Logback.
     */
    public static Boolean active() {
        Object factory = org.slf4j.LoggerFactory.getILoggerFactory();
        if (!(factory instanceof Context context)) {
            return null;
        }
        return context.getObject(IN_USE) != null;
    }
}
