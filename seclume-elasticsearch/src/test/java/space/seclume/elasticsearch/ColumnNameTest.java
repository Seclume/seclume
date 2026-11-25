package space.seclume.elasticsearch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

/**
 * Index a with field b.c and index a.b with field c had one column name, so
 * one key: a value of the one opened as the other's. An index with a dot is
 * named unambiguously; one without keeps its name and its data.
 */
class ColumnNameTest {

    @Test
    void aDotInTheIndexNoLongerMakesTwoColumnsOne() {
        assertNotEquals(EncryptedDocument.columnName("a", "b.c"),
                EncryptedDocument.columnName("a.b", "c"));
    }

    @Test
    void anIndexWithoutADotKeepsItsName() {
        assertEquals("search.patients.ssn", EncryptedDocument.columnName("patients", "ssn"));
        assertEquals("search.patients.address.zip",
                EncryptedDocument.columnName("patients", "address.zip"));
    }
}
