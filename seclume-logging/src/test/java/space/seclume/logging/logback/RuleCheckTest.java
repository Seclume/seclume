package space.seclume.logging.logback;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.core.CoreConstants;
import ch.qos.logback.core.spi.ContextAwareBase;
import ch.qos.logback.core.status.Status;

/**
 * A stack trace word whose rule is no longer seclume's - registered after
 * redact-rules.xml, by class name or by supplier - is warned of, once per
 * context: its stack traces go out unmasked. seclume's own rules, and rules
 * the check cannot read, are not.
 */
class RuleCheckTest {

    @Test
    void aStackTraceRuleThatIsNotSeclumesIsWarnedOfOnce() {
        LoggerContext context = new LoggerContext();
        Map<String, String> byName = new HashMap<>();
        byName.put("wEx", "org.example.logging.PlainThrowableConverter");   // another's
        byName.put("ex", RuleCheck.class.getPackageName() + ".Masking");      // seclume's
        byName.put("msg", "org.example.logging.Message");                     // no stack trace word
        context.putObject(CoreConstants.PATTERN_RULE_REGISTRY, byName);
        Map<String, Object> bySupplier = new HashMap<>();
        bySupplier.put("wex", (Supplier<Object>) Object::new);               // another's
        bySupplier.put("rEx", "not a supplier");                             // unreadable
        bySupplier.put("xEx", (Supplier<Object>) () -> {                     // unreadable
            throw new IllegalStateException("cannot be made here");
        });
        bySupplier.put("throwable", (Supplier<Object>) () -> null);          // unreadable
        context.putObject(CoreConstants.PATTERN_RULE_REGISTRY_FOR_SUPPLIERS, bySupplier);

        ContextAwareBase converter = new ContextAwareBase();
        converter.setContext(context);
        RuleCheck.warnAboutOtherRules(converter);
        RuleCheck.warnAboutOtherRules(converter);                            // checked already

        List<String> warned = context.getStatusManager().getCopyOfStatusList().stream()
                .filter(status -> status.getLevel() == Status.WARN)
                .map(Status::getMessage).toList();
        assertEquals(1, warned.size(), warned.toString());
        String warning = warned.get(0);
        assertTrue(warning.contains("%wEx") && warning.contains("%wex"), warning);
        for (String not : new String[] {"%ex,", "%ex ", "%rEx", "%xEx", "%throwable", "%msg"}) {
            assertFalse(warning.contains(not), not + " was named: " + warning);
        }
    }

    @Test
    void onlySeclumesRulesWarnOfNothing() {
        LoggerContext context = new LoggerContext();
        context.putObject(CoreConstants.PATTERN_RULE_REGISTRY,
                Map.of("ex", RuleCheck.class.getPackageName() + ".Masking"));
        ContextAwareBase converter = new ContextAwareBase();
        converter.setContext(context);
        RuleCheck.warnAboutOtherRules(converter);
        assertTrue(context.getStatusManager().getCopyOfStatusList().stream()
                .noneMatch(status -> status.getLevel() == Status.WARN));
    }
}
