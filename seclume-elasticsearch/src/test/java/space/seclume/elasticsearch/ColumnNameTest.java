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

    /** A nested field went to the cluster in the clear: only top-level fields are encrypted. */
    @Test
    void aNestedFieldIsRefused() throws Exception {
        try (space.seclume.field.FieldKeys keys = space.seclume.field.FieldKeys.builder()
                .key(1, EncryptedDocumentTest.key(1)).build()) {
            EncryptedDocument patients = EncryptedDocument.of(keys, "patients");
            org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                    () -> patients.field("address.street",
                            space.seclume.field.EncryptedColumn.Mode.RANDOMIZED));
        }
    }
}
