package space.seclume.springtest;

import org.hibernate.annotations.NaturalId;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrimaryKeyJoinColumn;
import jakarta.persistence.SecondaryTable;
import jakarta.persistence.Table;

/**
 * One entity spread over two tables, and a business key beside the technical
 * one.
 *
 * <p>{@code @SecondaryTable} means every insert is two inserts and every read
 * is a join the application never asked for - the same shape as joined
 * inheritance, but without a hierarchy to explain it, which is why it is worth
 * its own test.
 *
 * <p>{@code @NaturalId} is Hibernate's, not JPA's: it looks the row up by the
 * ISBN and then caches the mapping from that to the key. The driver sees a
 * unique index and a second select - and the second select is the one that
 * must return exactly the same key value type as the first, or the cache
 * misses forever.
 */
@Entity
@Table(name = "zl_book")
@SecondaryTable(name = "zl_book_detail", pkJoinColumns = @PrimaryKeyJoinColumn(name = "book_id"))
public class Book {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NaturalId
    @Column(name = "isbn", nullable = false, unique = true, length = 20)
    private String isbn;

    @Column(name = "title", nullable = false, length = 120)
    private String title;

    @Column(table = "zl_book_detail", name = "summary", length = 500)
    private String summary;

    protected Book() {
    }

    public Book(String isbn, String title, String summary) {
        this.isbn = isbn;
        this.title = title;
        this.summary = summary;
    }

    public Long getId() {
        return id;
    }

    public String getIsbn() {
        return isbn;
    }

    public String getTitle() {
        return title;
    }

    public String getSummary() {
        return summary;
    }
}
