package space.seclume.springtest;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.Year;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One row of every type an application maps.
 *
 * <p>Each field is here because some application has it, and because the
 * driver has to encode and decode it: a type that is written and read
 * without loss on all four servers is proven, and one that is not is a gap
 * with a name.
 *
 * <p>The identifier is a {@code UUID} on purpose - it is the one generated
 * key that does not come from the server, so it also says that
 * {@code getGeneratedKeys} is not the only way this driver can be used.
 */
@Entity
@Table(name = "zl_sample")
public class Sample {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private boolean flag;

    private short small;

    @Column(name = "number_value")
    private int number;

    @Column(name = "big_value")
    private long big;

    private double precise;

    @Column(name = "amount", precision = 18, scale = 4)
    private BigDecimal amount;

    private String text;

    /** {@code raw} is a reserved word in Oracle, so the column is named. */
    @Column(name = "raw_value")
    private byte[] raw;

    private LocalDate day;

    private LocalTime moment;

    private LocalDateTime stamp;

    private Instant instant;

    @Column(name = "offset_stamp")
    private OffsetDateTime offset;

    private Duration duration;

    @Column(name = "year_value")
    private Year year;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private CustomerStatus status;

    /** A type of the application's own, through a converter. */
    @Convert(converter = MoneyConverter.class)
    private Money price;

    protected Sample() {
    }

    public Sample(boolean flag, short small, int number, long big, double precise,
            BigDecimal amount, String text, byte[] raw, LocalDate day, LocalTime moment,
            LocalDateTime stamp, Instant instant, OffsetDateTime offset, Duration duration,
            Year year, CustomerStatus status, Money price) {
        this.flag = flag;
        this.small = small;
        this.number = number;
        this.big = big;
        this.precise = precise;
        this.amount = amount;
        this.text = text;
        this.raw = raw;
        this.day = day;
        this.moment = moment;
        this.stamp = stamp;
        this.instant = instant;
        this.offset = offset;
        this.duration = duration;
        this.year = year;
        this.status = status;
        this.price = price;
    }

    public UUID getId() {
        return id;
    }

    public boolean isFlag() {
        return flag;
    }

    public short getSmall() {
        return small;
    }

    public int getNumber() {
        return number;
    }

    public long getBig() {
        return big;
    }

    public double getPrecise() {
        return precise;
    }

    public BigDecimal getAmount() {
        return amount;
    }

    public String getText() {
        return text;
    }

    public byte[] getRaw() {
        return raw;
    }

    public LocalDate getDay() {
        return day;
    }

    public LocalTime getMoment() {
        return moment;
    }

    public LocalDateTime getStamp() {
        return stamp;
    }

    public Instant getInstant() {
        return instant;
    }

    public OffsetDateTime getOffset() {
        return offset;
    }

    public Duration getDuration() {
        return duration;
    }

    public Year getYear() {
        return year;
    }

    public CustomerStatus getStatus() {
        return status;
    }

    public Money getPrice() {
        return price;
    }
}
