package space.seclume.heapcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * Class and field names in the report come from the heap dump, and so from
 * whoever wrote it. Escaping only {@code |} and line breaks left the rest of
 * Markdown to them: a name could put a link, an image or HTML into a report
 * that is read as evidence.
 */
class MarkdownCellTest {

    /** A Markdown construct that is not preceded by a backslash. */
    private static boolean live(String text, String construct) {
        return Pattern.compile("(?<!\\\\)" + Pattern.quote(construct)).matcher(text).find();
    }

    @Test
    void aLinkAnImageOrHtmlFromTheDumpStaysText() {
        for (String hostile : new String[] {
                "com.example.[click](https://evil.example)",
                "![pixel](https://evil.example/track.png)",
                "<img src=x onerror=alert(1)>",
                "**urgent**_field_",
                "# Heading\n| a | b |"}) {
            String cell = AuditReport.cell(hostile);
            assertFalse(live(cell, "]("), cell);
            assertFalse(live(cell, "!["), cell);
            assertFalse(live(cell, "<"), cell);
            assertFalse(live(cell, "**"), cell);
            assertFalse(live(cell, "|"), cell);
            assertFalse(cell.contains("\n"), cell);
        }
    }

    @Test
    void anOrdinaryClassNameIsUnchanged() {
        assertEquals("com.example.OrderService", AuditReport.cell("com.example.OrderService"));
        assertEquals("com.example.OrderService.password",
                AuditReport.code("com.example.OrderService.password"));
    }

    @Test
    void aBacktickCannotLeaveTheCodeSpan() {
        String code = AuditReport.code("a`](https://evil.example)`b|c\nd");
        assertFalse(code.contains("`"), code);
        assertTrue(code.contains("\\|"), code);
        assertFalse(code.contains("\n"), code);
    }
}
