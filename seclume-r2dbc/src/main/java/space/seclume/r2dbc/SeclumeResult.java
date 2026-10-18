package space.seclume.r2dbc;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;

import org.reactivestreams.Publisher;

import io.r2dbc.spi.Result;
import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * What one execution answered: rows, read as they are asked for, or an
 * update count.
 *
 * <p>Rows are read on the connection's lane, one per request - the
 * backpressure R2DBC promises, and nothing read that nobody asked for. A
 * result can be consumed once; the JDBC statement behind it is closed when
 * the rows are done, when the subscriber cancels, or when it fails.
 */
final class SeclumeResult implements Result {

    private final Lane lane;
    private final Statement statement;
    private final ResultSet rows;
    private final long updateCount;
    private final Predicate<Segment> filter;
    private final AtomicBoolean consumed;

    private SeclumeResult(Lane lane, Statement statement, ResultSet rows, long updateCount,
                          Predicate<Segment> filter, AtomicBoolean consumed) {
        this.lane = lane;
        this.statement = statement;
        this.rows = rows;
        this.updateCount = updateCount;
        this.filter = filter;
        this.consumed = consumed;
    }

    static SeclumeResult ofRows(Lane lane, Statement statement, ResultSet rows) {
        return new SeclumeResult(lane, statement, rows, -1, segment -> true, new AtomicBoolean());
    }

    static SeclumeResult ofCount(Lane lane, Statement statement, long count) {
        return new SeclumeResult(lane, statement, null, count, segment -> true,
                new AtomicBoolean());
    }

    @Override
    public Publisher<Long> getRowsUpdated() {
        if (rows != null) {
            return close().then(Mono.empty());
        }
        return close().then(updateCount < 0 ? Mono.empty() : Mono.just(updateCount));
    }

    @Override
    public <T> Publisher<T> map(BiFunction<Row, RowMetadata, ? extends T> mapping) {
        return segments().handle((segment, sink) -> {
            if (segment instanceof RowSegment row) {
                T mapped = mapping.apply(row.row(), row.row().getMetadata());
                if (mapped == null) {
                    sink.error(new IllegalStateException("the mapping function returned null"));
                } else {
                    sink.next(mapped);
                }
            }
        });
    }

    @Override
    public Result filter(Predicate<Segment> wanted) {
        return new SeclumeResult(lane, statement, rows, updateCount, filter.and(wanted), consumed);
    }

    @Override
    public <T> Publisher<T> flatMap(Function<Segment, ? extends Publisher<? extends T>> mapping) {
        return segments().concatMap(mapping::apply);
    }

    /**
     * The segments, filtered: a row segment per row - the row valid only
     * until the next is read - or one update count.
     */
    private Flux<Segment> segments() {
        if (!consumed.compareAndSet(false, true)) {
            return Flux.error(new IllegalStateException("a result can be consumed only once"));
        }
        if (rows == null) {
            Flux<Segment> count = updateCount < 0 ? Flux.empty()
                    : Flux.just((UpdateCount) () -> updateCount);
            return count.filter(filter).concatWith(close().then(Mono.empty()));
        }
        Flux<Segment> read = Flux.<Segment, SeclumeRowMetadata>generate(
                () -> SeclumeRowMetadata.of(rows.getMetaData()),
                (metadata, sink) -> {
                    try {
                        if (rows.next()) {
                            SeclumeRow row = new SeclumeRow(rows, metadata);
                            sink.next((RowSegment) () -> row);
                        } else {
                            sink.complete();
                        }
                    } catch (SQLException e) {
                        sink.error(Errors.translate(e));
                    }
                    return metadata;
                },
                // Closed on the lane, like every other use of the connection:
                // a cancel arrives on the subscriber's thread.
                metadata -> lane.scheduler.schedule(this::closeQuietly))
                .subscribeOn(lane.scheduler);
        return read.filter(filter);
    }

    private Mono<Void> close() {
        return lane.run(this::closeQuietly);
    }

    private void closeQuietly() {
        try {
            if (rows != null) {
                rows.close();
            }
            statement.close();
        } catch (SQLException ignored) {
            // The result is done with either way.
        }
    }
}
