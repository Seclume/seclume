package space.seclume.r2dbc;

import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;

import org.reactivestreams.Publisher;

import io.r2dbc.spi.Result;
import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import reactor.core.publisher.Flux;

/**
 * A result read in full - for a text of several statements, where JDBC hands
 * the results out one after the other and the next one closes the last. Such
 * texts are scripts and short; a query that returns many rows is a statement
 * of its own and goes through {@link SeclumeResult}, row by row.
 */
final class MaterializedResult implements Result {

    private final List<Segment> segments;
    private final Predicate<Segment> filter;
    private final AtomicBoolean consumed;

    private MaterializedResult(List<Segment> segments, Predicate<Segment> filter,
                               AtomicBoolean consumed) {
        this.segments = segments;
        this.filter = filter;
        this.consumed = consumed;
    }

    static MaterializedResult ofCount(long count) {
        return new MaterializedResult(List.of((UpdateCount) () -> count), s -> true,
                new AtomicBoolean());
    }

    /** Every row of {@code rows}, copied out as R2DBC's objects. */
    static MaterializedResult ofRows(ResultSet rows) throws SQLException {
        SeclumeRowMetadata metadata = SeclumeRowMetadata.of(rows.getMetaData());
        List<Segment> segments = new ArrayList<>();
        while (rows.next()) {
            Object[] values = new Object[metadata.size()];
            for (int i = 0; i < values.length; i++) {
                values[i] = SeclumeRow.natural(rows.getObject(i + 1));
            }
            CachedRow row = new CachedRow(values, metadata);
            segments.add((RowSegment) () -> row);
        }
        return new MaterializedResult(segments, s -> true, new AtomicBoolean());
    }

    @Override
    public Publisher<Long> getRowsUpdated() {
        return all().ofType(UpdateCount.class).map(UpdateCount::value);
    }

    @Override
    public <T> Publisher<T> map(BiFunction<Row, RowMetadata, ? extends T> mapping) {
        return all().ofType(RowSegment.class)
                .map(segment -> mapping.apply(segment.row(), segment.row().getMetadata()));
    }

    @Override
    public Result filter(Predicate<Segment> wanted) {
        return new MaterializedResult(segments, filter.and(wanted), consumed);
    }

    @Override
    public <T> Publisher<T> flatMap(Function<Segment, ? extends Publisher<? extends T>> mapping) {
        return all().concatMap(mapping::apply);
    }

    private Flux<Segment> all() {
        if (!consumed.compareAndSet(false, true)) {
            return Flux.error(new IllegalStateException("a result can be consumed only once"));
        }
        return Flux.fromIterable(segments).filter(filter);
    }

    /** A copied row: the values as R2DBC hands them out, converted when asked for another type. */
    private record CachedRow(Object[] values, SeclumeRowMetadata metadata) implements Row {

        @Override
        public RowMetadata getMetadata() {
            return metadata;
        }

        @Override
        public <T> T get(int index, Class<T> type) {
            if (index < 0 || index >= values.length) {
                throw new IndexOutOfBoundsException("column " + index + " of " + values.length);
            }
            return convert(values[index], type);
        }

        @Override
        public <T> T get(String name, Class<T> type) {
            return get(metadata.indexOf(name), type);
        }

        @SuppressWarnings("unchecked")
        private static <T> T convert(Object value, Class<T> type) {
            if (value == null || type == Object.class || type.isInstance(value)) {
                return (T) value;
            }
            if (value instanceof Number number) {
                if (type == Integer.class || type == int.class) {
                    return (T) Integer.valueOf(number.intValue());
                }
                if (type == Long.class || type == long.class) {
                    return (T) Long.valueOf(number.longValue());
                }
                if (type == Short.class || type == short.class) {
                    return (T) Short.valueOf(number.shortValue());
                }
                if (type == Double.class || type == double.class) {
                    return (T) Double.valueOf(number.doubleValue());
                }
                if (type == BigDecimal.class) {
                    return (T) new BigDecimal(number.toString());
                }
            }
            if (type == String.class) {
                return (T) String.valueOf(value);
            }
            if (type == byte[].class && value instanceof ByteBuffer buffer) {
                byte[] bytes = new byte[buffer.remaining()];
                buffer.duplicate().get(bytes);
                return (T) bytes;
            }
            throw new IllegalArgumentException("a " + value.getClass().getName()
                    + " cannot be read as " + type.getName());
        }
    }
}
