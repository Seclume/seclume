package space.seclume.springtest;

import java.time.LocalDate;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Inheritance;
import jakarta.persistence.InheritanceType;
import jakarta.persistence.Table;
import jakarta.persistence.TableGenerator;

/**
 * Inheritance with a table per class - no shared table at all.
 *
 * <p>Reading the base type is then a {@code union all} over the subclass
 * tables with a literal column naming the type, which is a query shape none of
 * the other mappings produce: the same column comes from two different tables
 * in one result, and the driver must describe it once and consistently.
 *
 * <p>An identity column is impossible here - the keys have to be unique across
 * the tables - so this carries the fourth generation strategy, the one that
 * keeps its counter in a table of its own. That strategy is the only one that
 * needs a second connection-level round trip with a lock, which is worth
 * proving on all four.
 *
 * <p>The counter table is {@code zl_gen_keys} and not the obvious
 * {@code zl_keys}: the driver's own tests use a table of that name on two of
 * the four servers and drop it when they are done, so an application table
 * called that vanishes halfway through a build. It looked like a migration
 * that had not run.
 */
@Entity
@Table(name = "zl_doc")
@Inheritance(strategy = InheritanceType.TABLE_PER_CLASS)
@TableGenerator(name = "zl_doc_gen", table = "zl_gen_keys",
        pkColumnName = "key_name", valueColumnName = "next_value",
        pkColumnValue = "zl_doc", allocationSize = 1)
public abstract class Doc {

    @Id
    @GeneratedValue(strategy = GenerationType.TABLE, generator = "zl_doc_gen")
    private Long id;

    @Column(name = "doc_no", nullable = false, length = 40)
    private String docNo;

    @Column(name = "issued_on", nullable = false)
    private LocalDate issuedOn;

    protected Doc() {
    }

    protected Doc(String docNo, LocalDate issuedOn) {
        this.docNo = docNo;
        this.issuedOn = issuedOn;
    }

    public Long getId() {
        return id;
    }

    public String getDocNo() {
        return docNo;
    }

    public LocalDate getIssuedOn() {
        return issuedOn;
    }
}
