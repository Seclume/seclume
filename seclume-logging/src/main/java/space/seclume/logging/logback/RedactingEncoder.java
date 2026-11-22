package space.seclume.logging.logback;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.encoder.Encoder;
import ch.qos.logback.core.encoder.EncoderBase;
import ch.qos.logback.core.encoder.LayoutWrappingEncoder;

import space.seclume.logging.SecretMasker;

/**
 * A Logback encoder whose whole output has the application's secrets masked
 * by the installed {@link SecretMasker}: every conversion word of a pattern,
 * the stack trace Logback adds to a pattern that has none, the MDC and key-value
 * pairs - or what another encoder writes, a JSON or other structured one,
 * which uses no conversion words at all.
 *
 * <pre>
 * &lt;encoder class="space.seclume.logging.logback.RedactingEncoder"&gt;
 *   &lt;pattern&gt;%d %-5level %logger - %msg%n&lt;/pattern&gt;
 * &lt;/encoder&gt;
 *
 * &lt;encoder class="space.seclume.logging.logback.RedactingEncoder"&gt;
 *   &lt;encoder class="ch.qos.logback.classic.encoder.JsonEncoder"/&gt;
 * &lt;/encoder&gt;
 * </pre>
 *
 * <p>Either a pattern (and optionally a charset) or one encoder to mask the
 * output of; with neither or both the encoder reports an error in Logback's
 * status and writes nothing - no line unmasked. A delegate's bytes are read in its charset when it has one - a
 * pattern encoder's - and otherwise as UTF-8; bytes that are not text in it
 * are read one character per byte, so that a secret in ASCII is still found
 * and every other byte is written as it was.
 */
public class RedactingEncoder extends EncoderBase<ILoggingEvent> {

    private Encoder<ILoggingEvent> encoder;
    private String pattern;
    private Charset charset;

    /** The encoder whose output is masked; not with a pattern. */
    public void setEncoder(Encoder<ILoggingEvent> encoder) {
        this.encoder = encoder;
    }

    /** The encoder whose output is masked. */
    public Encoder<ILoggingEvent> getEncoder() {
        return encoder;
    }

    /** A Logback pattern, written as a {@link PatternLayoutEncoder} would; not with an encoder. */
    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    /** The pattern, or {@code null}. */
    public String getPattern() {
        return pattern;
    }

    /** The charset a pattern is written in; the platform's without one. */
    public void setCharset(Charset charset) {
        this.charset = charset;
    }

    /** The charset of the pattern, or {@code null}. */
    public Charset getCharset() {
        return charset;
    }

    @Override
    public void start() {
        boolean hasPattern = pattern != null && !pattern.isBlank();
        if (hasPattern == (encoder != null)) {
            addError("RedactingEncoder takes a <pattern> or an <encoder> to mask the output of, "
                    + "one of the two");
            return;
        }
        if (hasPattern) {
            PatternLayoutEncoder patterned = new PatternLayoutEncoder();
            patterned.setContext(getContext());
            patterned.setPattern(pattern);
            patterned.setCharset(charset);
            patterned.start();
            encoder = patterned;
        } else if (!encoder.isStarted()) {
            encoder.start();
        }
        if (!encoder.isStarted()) {
            addError("RedactingEncoder: the encoder it masks did not start");
            return;
        }
        super.start();
    }

    @Override
    public void stop() {
        if (encoder != null) {
            encoder.stop();
        }
        super.stop();
    }

    /*
     * Not started - no pattern and no encoder, or both - nothing is written:
     * an appender starts and writes with an encoder that failed to start,
     * and a line it cannot mask is not written unmasked. The reason is in
     * Logback's status.
     */

    @Override
    public byte[] headerBytes() {
        return isStarted() ? masked(encoder.headerBytes()) : null;
    }

    @Override
    public byte[] encode(ILoggingEvent event) {
        return isStarted() ? masked(encoder.encode(event)) : new byte[0];
    }

    @Override
    public byte[] footerBytes() {
        return isStarted() ? masked(encoder.footerBytes()) : null;
    }

    /** {@code bytes} with the secrets masked; the same array where there was none. */
    private byte[] masked(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return bytes;
        }
        Charset read = textCharset();
        String text;
        try {
            text = read.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException notText) {
            read = StandardCharsets.ISO_8859_1;
            text = new String(bytes, read); // seclume-allow: a log line, text already - masked next
        }
        String masked = SecretMasker.maskInstalled(text);
        if (masked.equals(text)) {
            return bytes;
        }
        try {
            ByteBuffer out = read.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(masked));
            byte[] written = new byte[out.remaining()];
            out.get(written);
            return written;
        } catch (CharacterCodingException cannot) {
            // The mask itself is ASCII; a charset that cannot write it writes nothing of the line.
            return new byte[0];
        }
    }

    private Charset textCharset() {
        if (encoder instanceof LayoutWrappingEncoder<ILoggingEvent> wrapping) {
            return wrapping.getCharset() != null ? wrapping.getCharset() : Charset.defaultCharset();
        }
        return StandardCharsets.UTF_8;
    }
}
