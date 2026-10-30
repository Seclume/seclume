package space.seclume.frameworks;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Converter;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.Sealed;
import space.seclume.jpa.EncryptedBytesConverter;
import space.seclume.jpa.EncryptedStringConverter;

/**
 * An entity with every kind of encrypted attribute: a randomized name, a
 * deterministic and unique national ID, a scan as bytes, and an API token
 * that is {@link Sealed} - ciphertext in the entity, opened into native memory.
 */
@Entity
@Table(name = "zl_patient")
public class EncryptedPatient {

    @Converter
    public static class NameConverter extends EncryptedStringConverter {
        public NameConverter() {
            super("zl_patient.name", Mode.RANDOMIZED);
        }
    }

    @Converter
    public static class SsnConverter extends EncryptedStringConverter {
        public SsnConverter() {
            super("zl_patient.ssn", Mode.DETERMINISTIC);
        }
    }

    @Converter
    public static class ScanConverter extends EncryptedBytesConverter {
        public ScanConverter() {
            super("zl_patient.scan", Mode.RANDOMIZED);
        }
    }

    @Id
    private Long id;

    @Convert(converter = NameConverter.class)
    @Column(length = 400)
    private String name;

    @Convert(converter = SsnConverter.class)
    @Column(length = 100, unique = true)
    private String ssn;

    @Column(name = "api_token", length = 300)
    private Sealed apiToken;

    @Convert(converter = ScanConverter.class)
    @Column(length = 2000)
    private byte[] scan;

    protected EncryptedPatient() {
    }

    public EncryptedPatient(long id, String name, String ssn) {
        this.id = id;
        this.name = name;
        this.ssn = ssn;
    }

    public Long id() {
        return id;
    }

    public String name() {
        return name;
    }

    public String ssn() {
        return ssn;
    }

    public Sealed apiToken() {
        return apiToken;
    }

    public void apiToken(Sealed token) {
        this.apiToken = token;
    }

    public byte[] scan() {
        return scan;
    }

    public void scan(byte[] scan) {
        this.scan = scan;
    }
}
