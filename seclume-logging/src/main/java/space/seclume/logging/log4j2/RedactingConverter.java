package space.seclume.logging.log4j2;

import java.util.List;

import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.apache.logging.log4j.core.pattern.ConverterKeys;
import org.apache.logging.log4j.core.pattern.LogEventPatternConverter;
import org.apache.logging.log4j.core.pattern.PatternConverter;
import org.apache.logging.log4j.core.pattern.PatternFormatter;
import org.apache.logging.log4j.core.pattern.PatternParser;
import org.apache.logging.log4j.status.StatusLogger;

import space.seclume.logging.SecretMasker;

/**
 * Log4j 2's {@code %redact{pattern}}: what the inner pattern writes, with the
 * application's secrets masked by the installed {@link SecretMasker} - the
 * message, the stack trace, whatever the pattern holds.
 *
 * <pre>
 * &lt;PatternLayout pattern="%d %-5level %logger - %redact{%msg%n%throwable}"/&gt;
 * </pre>
 *
 * <p>The plugin is found by Log4j's own index in this jar; nothing has to be
 * named in {@code packages}. With the stack trace inside the braces the layout
 * writes it once, masked - not again after the line.
 */
@Plugin(name = "redact", category = PatternConverter.CATEGORY)
@ConverterKeys({"redact"})
public final class RedactingConverter extends LogEventPatternConverter {

    private final List<PatternFormatter> formatters;
    private final boolean throwable;

    private RedactingConverter(List<PatternFormatter> formatters) {
        super("redact", "redact");
        this.formatters = List.copyOf(formatters);
        this.throwable = formatters.stream().anyMatch(PatternFormatter::handlesThrowable);
    }

    /**
     * What Log4j calls for {@code %redact{...}}.
     *
     * @param configuration the configuration the layout belongs to
     * @param options       the pattern in the braces
     * @return the converter, or {@code null} - with the reason in Log4j's status log - without a pattern
     */
    public static RedactingConverter newInstance(Configuration configuration, String[] options) {
        if (options == null || options.length != 1 || options[0] == null || options[0].isBlank()) {
            StatusLogger.getLogger().error("%redact takes one pattern: %redact{%msg%n%throwable}");
            return null;
        }
        PatternParser parser = PatternLayout.createPatternParser(configuration);
        return new RedactingConverter(parser.parse(options[0]));
    }

    @Override
    public void format(LogEvent event, StringBuilder output) {
        StringBuilder inner = new StringBuilder(128);
        for (PatternFormatter formatter : formatters) {
            formatter.format(event, inner);
        }
        output.append(SecretMasker.maskInstalled(inner.toString()));
    }

    @Override
    public boolean handlesThrowable() {
        return throwable;
    }
}
