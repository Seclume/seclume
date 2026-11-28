package space.seclume.r2dbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import reactor.core.Disposable;
import reactor.core.publisher.Mono;

/**
 * SQL Server's and Oracle's drivers ask the server what an R2DBC connection
 * needs to say about itself, so a connection lent at once is described on the
 * lane. A subscriber that cancelled before the lane ran that left the
 * connection borrowed and never closed - IN_USE for good (#63). Every
 * connection lent is closed now, however early or late the cancel comes.
 */
@Timeout(60)
class R2dbcCancelDescribeTest {

    /** Lends at once; each connection takes {@code describeMillis} to describe itself. */
    private static final class ReadySource implements DataSource, space.seclume.ImmediateBorrow {
        final AtomicInteger lent = new AtomicInteger();
        final AtomicInteger closed = new AtomicInteger();
        final long describeMillis;

        ReadySource(long describeMillis) {
            this.describeMillis = describeMillis;
        }

        @Override
        public Connection getConnectionIfReady() {
            lent.incrementAndGet();
            boolean[] isClosed = {false};
            return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Connection.class}, (proxy, method, args) -> switch (method.getName()) {
                        case "close" -> {
                            if (!isClosed[0]) {
                                isClosed[0] = true;
                                closed.incrementAndGet();
                            }
                            yield null;
                        }
                        case "isClosed" -> isClosed[0];
                        case "getAutoCommit" -> true;
                        case "getTransactionIsolation" -> Connection.TRANSACTION_READ_COMMITTED;
                        case "getMetaData" -> {
                            Thread.sleep(describeMillis);        // the server is asked
                            yield Proxy.newProxyInstance(getClass().getClassLoader(),
                                    new Class<?>[] {java.sql.DatabaseMetaData.class},
                                    (p, m, a) -> switch (m.getName()) {
                                        case "getDatabaseProductName" -> "Microsoft SQL Server";
                                        case "getDatabaseProductVersion" -> "17.0";
                                        default -> null;
                                    });
                        }
                        case "isWrapperFor" -> false;
                        case "hashCode" -> System.identityHashCode(proxy);
                        case "equals" -> proxy == args[0];
                        default -> null;
                    });
        }

        @Override
        public Connection getConnection() throws SQLException {
            throw new SQLException("only lends at once in this test");
        }

        @Override
        public Connection getConnection(String user, String password) throws SQLException {
            return getConnection();
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
        }

        @Override
        public void setLoginTimeout(int seconds) {
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException();
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            throw new SQLException("no");
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return false;
        }
    }

    /** Takes one connection and closes whatever it is handed, cancelled or not. */
    private static final class ClosingSubscriber
            implements org.reactivestreams.Subscriber<io.r2dbc.spi.Connection> {
        private volatile org.reactivestreams.Subscription subscription;

        @Override
        public void onSubscribe(org.reactivestreams.Subscription s) {
            subscription = s;
            s.request(1);
        }

        @Override
        public void onNext(io.r2dbc.spi.Connection connection) {
            Mono.from(connection.close()).subscribe();
        }

        @Override
        public void onError(Throwable failure) {
        }

        @Override
        public void onComplete() {
        }

        void cancel() {
            org.reactivestreams.Subscription s = subscription;
            if (s != null) {
                s.cancel();
            }
        }
    }

    private static void awaitAllClosed(ReadySource source) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (source.closed.get() < source.lent.get() && deadline - System.nanoTime() > 0) {
            Thread.sleep(10);
        }
        assertEquals(source.lent.get(), source.closed.get(),
                "connections lent and never closed after a cancel");
    }

    /** Cancelled at once, many times: before the lane ran, or while it did. */
    @Test
    void aCancelAtAnyMomentClosesTheConnectionLent() throws Exception {
        ReadySource source = new ReadySource(0);
        SeclumeConnectionFactory factory = SeclumeConnectionFactory.over(source, "sqlserver");
        for (int i = 0; i < 500; i++) {
            // A connection handed on is the subscriber's, and this one does
            // what every R2DBC consumer does with it: closes it - also when it
            // arrives just as the subscriber cancels. What the test is about
            // are the ones that were never handed on.
            ClosingSubscriber subscriber = new ClosingSubscriber();
            Mono.from(factory.create()).subscribe(subscriber);
            subscriber.cancel();
        }
        assertTrue(source.lent.get() > 0);
        awaitAllClosed(source);
    }

    /** Cancelled while the server is asked: the connection, described, is closed after. */
    @Test
    void aCancelWhileDescribingClosesTheConnection() throws Exception {
        ReadySource source = new ReadySource(300);
        SeclumeConnectionFactory factory = SeclumeConnectionFactory.over(source, "sqlserver");
        CountDownLatch subscribed = new CountDownLatch(1);
        Disposable subscription = Mono.from(factory.create())
                .doOnSubscribe(s -> subscribed.countDown()).subscribe();
        assertTrue(subscribed.await(5, TimeUnit.SECONDS));
        Thread.sleep(50);                                        // the lane is in getMetaData
        subscription.dispose();
        awaitAllClosed(source);
        assertEquals(1, source.lent.get());
    }
}
