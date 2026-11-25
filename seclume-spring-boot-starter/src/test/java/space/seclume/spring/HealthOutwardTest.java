package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/**
 * The health indicator and the seclume endpoint handed out the SQLException's
 * text - "password authentication failed for user app", a host name - from
 * an endpoint that is often anonymous. Its kind and SQLState go out now.
 */
class HealthOutwardTest {

    @Test
    void theServersWordsStayInside() {
        SQLException refused = new java.sql.SQLInvalidAuthorizationSpecException(
                "password authentication failed for user \"app\" on db.internal", "28P01");
        String outward = SeclumePoolHealth.outward(refused);
        assertEquals("SQLInvalidAuthorizationSpecException (SQLState 28P01)", outward);
        assertFalse(outward.contains("app") || outward.contains("db.internal"));
        assertEquals("SQLException", SeclumePoolHealth.outward(new SQLException("x")));
    }
}
