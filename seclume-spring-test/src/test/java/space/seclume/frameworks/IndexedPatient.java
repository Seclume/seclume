package space.seclume.frameworks;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Converter;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

import space.seclume.field.BlindIndex.Transform;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.jpa.EncryptedStringConverter;
import space.seclume.jpa.StringBlindIndex;

/**
 * An entity for Jakarta Data: a randomized name searched by a blind index of
 * its first three letters, a randomized e-mail address searched by a blind
 * index whatever its case, and a deterministic, unique SSN searched as it is.
 * The index values are set where the attributes are, so that a stateless
 * session - which calls no entity callbacks - stores them too.
 */
@Entity
@Table(name = "zl_indexed_patient", indexes = {
        @Index(name = "zl_indexed_patient_ni", columnList = "name_index"),
        @Index(name = "zl_indexed_patient_ei", columnList = "email_index")})
public class IndexedPatient {

    /** Two bits: a quarter of the table shares any value - many candidates, little said. */
    static final int NAME_BITS = 2;

    static final StringBlindIndex NAME = StringBlindIndex.of("zl_indexed_patient.name", NAME_BITS,
            Transform.prefix(3).caseInsensitive());

    static final StringBlindIndex EMAIL = StringBlindIndex.of("zl_indexed_patient.email", 16,
            Transform.CASE_INSENSITIVE);

    @Converter
    public static class NameConverter extends EncryptedStringConverter {
        public NameConverter() {
            super("zl_indexed_patient.name", Mode.RANDOMIZED);
        }
    }

    @Converter
    public static class EmailConverter extends EncryptedStringConverter {
        public EmailConverter() {
            super("zl_indexed_patient.email", Mode.RANDOMIZED);
        }
    }

    @Converter
    public static class SsnConverter extends EncryptedStringConverter {
        public SsnConverter() {
            super("zl_indexed_patient.ssn", Mode.DETERMINISTIC);
        }
    }

    @Id
    private Long id;

    @Convert(converter = NameConverter.class)
    @Column(length = 400)
    private String name;

    @Column(name = "name_index")
    private Long nameIndex;

    @Convert(converter = EmailConverter.class)
    @Column(length = 400)
    private String email;

    @Column(name = "email_index")
    private Long emailIndex;

    @Convert(converter = SsnConverter.class)
    @Column(length = 100, unique = true)
    private String ssn;

    protected IndexedPatient() {
    }

    public IndexedPatient(long id, String name, String email, String ssn) {
        this.id = id;
        name(name);
        email(email);
        this.ssn = ssn;
    }

    public Long id() {
        return id;
    }

    public String name() {
        return name;
    }

    public void name(String name) {
        this.name = name;
        this.nameIndex = NAME.term(name);
    }

    public Long nameIndex() {
        return nameIndex;
    }

    public String email() {
        return email;
    }

    public void email(String email) {
        this.email = email;
        this.emailIndex = EMAIL.term(email);
    }

    public Long emailIndex() {
        return emailIndex;
    }

    public String ssn() {
        return ssn;
    }

    @Override
    public String toString() {
        return "IndexedPatient[" + id + "]";
    }
}
