package space.seclume.internal.jdbc;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLXML;

import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;

/**
 * A read-only {@link SQLXML} over a document that has already arrived.
 *
 * <p>The same narrowing {@link Lobs} makes for {@code Clob} and {@code Blob}:
 * accurate about the content, no claim that anything is fetched lazily. All
 * four servers send an XML column as text in the row, so the document is here
 * by the time anybody asks for it.
 *
 * <p>The write half is refused. A result set of this project is read-only, and
 * an {@code SQLXML} handed out of one that accepted {@code setString} would
 * look like it changed the row.
 *
 * <p>{@link #getSource} deliberately serves only {@link StreamSource}. The
 * other three - DOM, SAX, StAX - would each pull a parser into the driver, and
 * a caller who wants one can build it from the stream this returns in the two
 * lines they would have written anyway. Refusing is honest; returning a
 * half-configured parser with the platform's default entity resolution would
 * not be, because for XML that setting is a security decision and it is not
 * the driver's to make.
 */
public final class XmlValue implements SQLXML {

    private String document;
    private boolean freed;
    /** Made by {@code Connection.createSQLXML}: to be written once, then bound. */
    private final boolean writable;
    /** What a writer or stream handed out by the write half has collected. */
    private java.io.StringWriter text;
    private java.io.ByteArrayOutputStream bytes;

    public XmlValue(String document) {
        this.document = document;
        this.writable = false;
    }

    private XmlValue() {
        this.writable = true;
    }

    /**
     * An empty one for {@code Connection.createSQLXML}: the application
     * writes the document into it - as text, through a writer, as UTF-8
     * bytes or through a {@code StreamResult} - and binds it with
     * {@code setSQLXML}, which sends the text.
     */
    public static XmlValue writable() {
        return new XmlValue();
    }

    @Override
    public String getString() throws SQLException {
        return alive();
    }

    @Override
    public Reader getCharacterStream() throws SQLException {
        return new StringReader(alive());
    }

    /**
     * UTF-8, which is what the XML declaration in a document from any of these
     * servers says and what the servers themselves store.
     */
    @Override
    public InputStream getBinaryStream() throws SQLException {
        // seclume-allow: an XML document out of a result set is user payload, not a secret
        return new ByteArrayInputStream(alive().getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T extends Source> T getSource(Class<T> sourceClass) throws SQLException {
        StreamSource source = new StreamSource(new StringReader(alive()));
        // JDBC says null means "whatever the driver prefers", and this driver has
        // exactly one preference.
        if (sourceClass == null) {
            return (T) source;
        }
        if (sourceClass == StreamSource.class || sourceClass == Source.class) {
            return sourceClass.cast(source);
        }
        throw new SQLFeatureNotSupportedException(
                "seclume serves an SQLXML only as a StreamSource, not as " + sourceClass.getName()
                + " - build the parser you want from getCharacterStream, so that its entity "
                + "resolution is your decision rather than the driver's");
    }

    @Override
    public void free() {
        freed = true;
        document = null;
    }

    private String alive() throws SQLException {
        if (freed) {
            throw new SQLException("this SQLXML has been freed");
        }
        if (text != null) {
            document = text.toString();
        } else if (bytes != null) {
            document = bytes.toString(StandardCharsets.UTF_8);
        }
        return document;
    }

    // ---- the write half, which a read-only result set does not have -------

    @Override
    public OutputStream setBinaryStream() throws SQLException {
        requireWritable();
        bytes = new java.io.ByteArrayOutputStream();
        return bytes;
    }

    @Override
    public Writer setCharacterStream() throws SQLException {
        requireWritable();
        text = new java.io.StringWriter();
        return text;
    }

    @Override
    public void setString(String value) throws SQLException {
        requireWritable();
        document = value;
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T extends javax.xml.transform.Result> T setResult(Class<T> resultClass)
            throws SQLException {
        requireWritable();
        if (resultClass == null || resultClass == javax.xml.transform.stream.StreamResult.class
                || resultClass == javax.xml.transform.Result.class) {
            return (T) new javax.xml.transform.stream.StreamResult(setCharacterStream());
        }
        throw new SQLFeatureNotSupportedException("seclume takes an SQLXML only as a "
                + "StreamResult, not as " + resultClass.getName()
                + " - transform into a StreamResult or write the text");
    }

    /** Written once, as JDBC says, and only one that was made to be written. */
    private void requireWritable() throws SQLException {
        if (!writable) {
            throw readOnly();
        }
        if (freed) {
            throw new SQLException("this SQLXML has been freed");
        }
        if (document != null || text != null || bytes != null) {
            throw new SQLException("this SQLXML has already been written");
        }
    }

    private static SQLFeatureNotSupportedException readOnly() {
        return new SQLFeatureNotSupportedException(
                "this SQLXML came out of a read-only result set and cannot be written to");
    }
}
