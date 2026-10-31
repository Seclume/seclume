package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/**
 * MariaDB's {@code XA RECOVER FORMAT='SQL'}: the id as the XA statements take
 * it, read back byte for byte - also bytes that are not UTF-8 - and anything
 * else refused rather than misread. The live round trip is
 * {@code LocalMyXaTest}, on MariaDB as on MySQL.
 */
class MyXaRecoverFormatTest {

    @Test
    void globalIdAndBranchComeBackAsTheirBytes() {
        assertArrayEquals(new byte[] {0x41, 0x42, 0x43},
                MyXaResource.fromSqlFormat("X'4142',X'43',1", 1));
        assertArrayEquals(new byte[] {(byte) 0xff, 0x00, (byte) 0x80},
                MyXaResource.fromSqlFormat("X'ff00',x'80',  7", 7));
        assertArrayEquals(new byte[] {0x41}, MyXaResource.fromSqlFormat("X'41','',0", 0));
        assertArrayEquals(new byte[] {0x41}, MyXaResource.fromSqlFormat("X'41',X'',0", 0));
    }

    @Test
    void whatIsNotThatFormatIsNotMisread() {
        assertNull(MyXaResource.fromSqlFormat(null, 1));
        assertNull(MyXaResource.fromSqlFormat("AB", 1));
        assertNull(MyXaResource.fromSqlFormat("X'41',X'42',2", 1), "another format id");
        assertNull(MyXaResource.fromSqlFormat("X'4',X'42',1", 1), "an odd number of digits");
        assertNull(MyXaResource.fromSqlFormat("'AB',X'42',1", 1), "a string, not hex");
        assertNull(MyXaResource.fromSqlFormat("X'41',X'42',1,9", 1));
    }
}
