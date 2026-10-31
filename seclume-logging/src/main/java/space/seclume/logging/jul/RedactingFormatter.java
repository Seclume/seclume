package space.seclume.logging.jul;

import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.SimpleFormatter;

import space.seclume.logging.SecretMasker;

/**
 * {@code java.util.logging} - and {@code System.Logger}, which goes there by
 * default - with the application's secrets masked by the installed
 * {@link SecretMasker}: whatever another formatter makes of a record, message,
 * parameters and stack trace alike, is masked before a handler writes it.
 *
 * <pre>
 * # logging.properties
 * java.util.logging.ConsoleHandler.formatter=space.seclume.logging.jul.RedactingFormatter
 * # optional, the formatter whose output is masked: SimpleFormatter (the default) or XMLFormatter
 * space.seclume.logging.jul.RedactingFormatter.delegate=java.util.logging.XMLFormatter
 * </pre>
 *
 * <p>Or in code: {@code handler.setFormatter(new RedactingFormatter(new MyFormatter()))},
 * or {@link #wrap(Handler)} for a handler that has its formatter already.
 * {@code getHead} and {@code getTail} - an XML document's frame - are masked
 * too.
 */
public class RedactingFormatter extends Formatter {

    private final Formatter delegate;

    /**
     * The formatter that {@code space.seclume.logging.jul.RedactingFormatter.delegate}
     * names in the logging configuration - {@code SimpleFormatter} or
     * {@code XMLFormatter}, as no class is loaded by name here - or
     * {@link SimpleFormatter}.
     */
    public RedactingFormatter() {
        this(configured());
    }

    /** Masks what {@code delegate} makes of each record. */
    public RedactingFormatter(Formatter delegate) {
        if (delegate == null) {
            throw new IllegalArgumentException("a formatter to mask the output of");
        }
        this.delegate = delegate;
    }

    /** Gives {@code handler} this formatter around the one it has; returns the handler. */
    public static <H extends Handler> H wrap(H handler) {
        Formatter current = handler.getFormatter();
        if (!(current instanceof RedactingFormatter)) {
            handler.setFormatter(new RedactingFormatter(current == null ? new SimpleFormatter() : current));
        }
        return handler;
    }

    /** The formatter whose output is masked. */
    public Formatter delegate() {
        return delegate;
    }

    @Override
    public String format(LogRecord record) {
        return SecretMasker.maskInstalled(delegate.format(record));
    }

    @Override
    public String getHead(Handler handler) {
        return SecretMasker.maskInstalled(delegate.getHead(handler));
    }

    @Override
    public String getTail(Handler handler) {
        return SecretMasker.maskInstalled(delegate.getTail(handler));
    }

    @Override
    public String formatMessage(LogRecord record) {
        return SecretMasker.maskInstalled(delegate.formatMessage(record));
    }

    private static Formatter configured() {
        String name = LogManager.getLogManager().getProperty(RedactingFormatter.class.getName() + ".delegate");
        if (name == null || name.isBlank()) {
            return new SimpleFormatter();
        }
        name = name.strip();
        Formatter formatter = switch (name) {
            case "java.util.logging.SimpleFormatter" -> new SimpleFormatter();
            case "java.util.logging.XMLFormatter" -> new java.util.logging.XMLFormatter();
            default -> null;
        };
        if (formatter == null) {
            throw new IllegalArgumentException(RedactingFormatter.class.getName() + ".delegate=" + name
                    + ": only java.util.logging.SimpleFormatter or XMLFormatter can be named here - "
                    + "for another, call new RedactingFormatter(formatter) in code");
        }
        return formatter;
    }
}
