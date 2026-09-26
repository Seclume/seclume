package space.seclume.springtest;

import java.sql.Blob;
import java.sql.Clob;
import java.util.Map;

import jakarta.persistence.Basic;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

import org.hibernate.annotations.Formula;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * The Hibernate mappings where a driver's answer is easy to get subtly wrong.
 *
 * <ul>
 *   <li>a <b>JSON</b> column ({@code SqlTypes.JSON}) - {@code jsonb} on
 *       PostgreSQL, {@code json} on MySQL and Oracle, {@code nvarchar(max)} on
 *       SQL Server - holding a nested map;</li>
 *   <li><b>LOBs</b> as values ({@code @Lob String}, {@code @Lob byte[]}) and as
 *       {@link Clob}/{@link Blob} objects that Hibernate writes from a stream
 *       and the application reads back as one. On PostgreSQL both are large
 *       objects - {@code oid} columns and the LO API - which is a path of its
 *       own;</li>
 *   <li>a <b>{@code @Formula}</b>, which Hibernate splices into the select
 *       list and which a query can filter on.</li>
 * </ul>
 */
@Entity
@Table(name = "zl_note")
public class Note {

    /**
     * Past MySQL's 16 MB, so its dialect picks {@code longtext} and
     * {@code longblob}; without a length Hibernate expects {@code tinytext}.
     * The other three ignore it for a LOB.
     */
    static final int LOB_LENGTH = 1_000_000_000;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "title", length = 80)
    private String title;

    @Column(name = "words", nullable = false)
    private int words;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "attributes")
    private Map<String, Object> attributes;

    @Lob
    @Column(name = "body", length = LOB_LENGTH)
    private String body;

    @Lob
    @Column(name = "data", length = LOB_LENGTH)
    private byte[] data;

    @Lob
    @Basic(fetch = FetchType.LAZY)
    @Column(name = "script", length = LOB_LENGTH)
    private Clob script;

    @Lob
    @Basic(fetch = FetchType.LAZY)
    @Column(name = "picture", length = LOB_LENGTH)
    private Blob picture;

    @Formula("words * 2")
    private int doubled;

    protected Note() {
    }

    public Note(String title, int words) {
        this.title = title;
        this.words = words;
    }

    public Long getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    public int getWords() {
        return words;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public Clob getScript() {
        return script;
    }

    public void setScript(Clob script) {
        this.script = script;
    }

    public Blob getPicture() {
        return picture;
    }

    public void setPicture(Blob picture) {
        this.picture = picture;
    }

    public int getDoubled() {
        return doubled;
    }
}
