package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.nio.ByteBuffer;
import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/**
 * A login that failed without its budget lifted left the budget running; it
 * fired during the next login on the same thread, and that login's refusal -
 * a wrong password, 28000 - was reported as a login past its budget, 08001.
 * A budget speaks only for its thread's latest login.
 */
class StaleLoginBudgetTest {

    private static Transport idle() {
        return new Transport() {
            private volatile boolean open = true;

            @Override
            public int read(ByteBuffer into) {
                return 0;
            }

            @Override
            public int write(ByteBuffer from) {
                return 0;
            }

            @Override
            public boolean isOpen() {
                return open;
            }

            @Override
            public void close() {
                open = false;
            }
        };
    }

    @Test
    void anEarlierLoginsBudgetDoesNotSpeakForTheNext() throws Exception {
        // The first login fails at once; nobody lifts its budget of 100 ms.
        Transports.watch(idle(), 100, "the first login did not finish within its budget");
        Transports.late(new SQLException("refused", "28000"));
        // The second login begins on the same thread; the first budget fires meanwhile.
        Transport second = idle();
        Transports.watch(second, 60_000, "the second login did not finish within its budget");
        Thread.sleep(300);
        SQLException refused = new SQLException("access denied", "28000");
        assertSame(refused, Transports.late(refused),
                "a refusal was reported as an earlier login's budget");
        assertEquals(true, Transports.lift(second));
    }

    @Test
    void aBudgetThatRanOutForThisLoginIsSaid() throws Exception {
        Transport slow = idle();
        Transports.watch(slow, 100, "this login did not finish within its budget");
        Thread.sleep(300);
        SQLException broken = new SQLException("connection closed", "08006");
        SQLException said = Transports.late(broken);
        assertEquals("08001", said.getSQLState());
        assertSame(broken, said.getCause());
    }
}
