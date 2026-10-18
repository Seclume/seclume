package space.seclume.r2dbc;

import java.sql.Connection;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import io.r2dbc.spi.Batch;
import io.r2dbc.spi.Result;
import reactor.core.publisher.Flux;

/**
 * Several statements without parameters, one after the other - R2DBC's batch,
 * which is not JDBC's: each statement answers a result of its own, rows
 * included.
 */
final class SeclumeBatch implements Batch {

    private final Connection connection;
    private final Lane lane;
    private final List<String> statements = new ArrayList<>();

    SeclumeBatch(Connection connection, Lane lane) {
        this.connection = connection;
        this.lane = lane;
    }

    @Override
    public Batch add(String sql) {
        statements.add(sql);
        return this;
    }

    @Override
    public Flux<Result> execute() {
        List<String> toRun = List.copyOf(statements);
        statements.clear();
        return Flux.fromIterable(toRun).concatMap(sql -> lane.call(() -> {
            Statement statement = connection.createStatement();
            try {
                if (statement.execute(sql)) {
                    return (Result) SeclumeResult.ofRows(lane, statement, statement.getResultSet());
                }
                return SeclumeResult.ofCount(lane, statement, statement.getLargeUpdateCount());
            } catch (java.sql.SQLException | RuntimeException e) {
                statement.close();
                throw e;
            }
        }));
    }
}
