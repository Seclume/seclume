package space.seclume.springtest;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

/**
 * A row with a generated key - which is what {@code getGeneratedKeys} is for -
 * and the carrier of the annotation sweep.
 *
 * <p>Everything below the key is here because an application uses it and
 * because each one asks something different of the driver:
 *
 * <ul>
 *   <li>{@code @Version} makes Hibernate write {@code where version = ?} and
 *       count the rows it changed - so the driver's update count has to be
 *       exact. One off and either nothing ever conflicts or everything
 *       does.</li>
 *   <li>{@code @CreatedDate} and {@code @LastModifiedDate} write timestamps
 *       Spring generates, which is the round trip of a {@code LocalDateTime}
 *       through four different column types.</li>
 *   <li>{@code @Enumerated(STRING)} is a short string with a check on
 *       reading: an unknown value throws rather than silently picking an
 *       ordinal.</li>
 *   <li>{@code @Embedded} spreads one object over two columns.</li>
 *   <li>{@code @Lob} is the large-text path - {@code text},
 *       {@code longtext}, {@code varchar(max)} and {@code clob}, which are
 *       four quite different things on the wire.</li>
 * </ul>
 */
@Entity
@Table(name = "zl_customer")
@EntityListeners(AuditingEntityListener.class)
public class Customer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, unique = true)
    private String email;

    @Version
    private Long version;

    @CreatedDate
    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private CustomerStatus status = CustomerStatus.ACTIVE;

    @Embedded
    private Address address;

    /**
     * A large text, and the one annotation that needs a word of its own.
     *
     * <p>{@code @Lob} alone maps to {@code oid} on PostgreSQL - a large
     * object, stored outside the row and read through a separate API that
     * this driver does not implement. That is Hibernate's default there and
     * the reason applications pair the two annotations: with the type code
     * the column is an ordinary long text on all four servers, which is what
     * {@code text}, {@code longtext}, {@code varchar(max)} and {@code clob}
     * are. Written down because "just add @Lob" is what everybody tries
     * first, and on PostgreSQL it fails at startup rather than at runtime.
     */
    @Lob
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    private String notes;

    protected Customer() {
    }

    public Customer(String name, String email) {
        this.name = name;
        this.email = email;
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public Long getVersion() {
        return version;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public CustomerStatus getStatus() {
        return status;
    }

    public void setStatus(CustomerStatus status) {
        this.status = status;
    }

    public Address getAddress() {
        return address;
    }

    public void setAddress(Address address) {
        this.address = address;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }
}
