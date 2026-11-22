package space.seclume.logging.logback;

import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;

import ch.qos.logback.core.Context;
import ch.qos.logback.core.CoreConstants;
import ch.qos.logback.core.spi.ContextAware;

/**
 * Whether the context's conversion rules for the stack trace words are still
 * seclume's: Spring Boot's {@code defaults.xml} registers its own {@code %wex}
 * and {@code %wEx}, and included after {@code redact-rules.xml} it replaces
 * them - the message masked, the stack trace not. Checked once per context
 * when a masking message converter starts, when every rule is registered.
 */
final class RuleCheck {

    /** The words {@code redact-rules.xml} registers a stack trace converter under. */
    static final Set<String> STACK_TRACE_WORDS = Set.of("ex", "exception", "throwable",
            "xEx", "xException", "xThrowable", "rEx", "rootException", "wex", "wEx");

    private static final String CHECKED = RuleCheck.class.getName() + ".checked";

    private RuleCheck() {
    }

    /** Warns through {@code converter}'s status when a stack trace word has another rule's converter. */
    static void warnAboutOtherRules(ContextAware converter) {
        Context context = converter.getContext();
        if (context == null || context.getObject(CHECKED) != null) {
            return;
        }
        context.putObject(CHECKED, Boolean.TRUE);
        Set<String> others = new TreeSet<>();
        if (context.getObject(CoreConstants.PATTERN_RULE_REGISTRY_FOR_SUPPLIERS) instanceof Map<?, ?> rules) {
            for (Map.Entry<?, ?> rule : rules.entrySet()) {
                if (STACK_TRACE_WORDS.contains(rule.getKey()) && !ours(rule.getValue())) {
                    others.add("%" + rule.getKey());
                }
            }
        }
        if (context.getObject(CoreConstants.PATTERN_RULE_REGISTRY) instanceof Map<?, ?> rules) {
            for (Map.Entry<?, ?> rule : rules.entrySet()) {
                if (STACK_TRACE_WORDS.contains(rule.getKey()) && rule.getValue() instanceof String name
                        && !name.startsWith(RuleCheck.class.getPackageName() + ".")) {
                    others.add("%" + rule.getKey());
                }
            }
        }
        if (!others.isEmpty()) {
            converter.addWarn("seclume: the stack traces of " + String.join(", ", others)
                    + " are not masked - a conversion rule registered after seclume's replaced its "
                    + "converter. Include space/seclume/logging/logback/redact-rules.xml after "
                    + "Spring Boot's defaults.xml or base.xml.");
        }
    }

    private static boolean ours(Object supplier) {
        if (!(supplier instanceof Supplier<?> made)) {
            return true;                            // not a rule this check can read
        }
        try {
            Object converter = made.get();
            return converter == null
                    || converter.getClass().getPackageName().equals(RuleCheck.class.getPackageName());
        } catch (RuntimeException | LinkageError cannot) {
            return true;
        }
    }
}
