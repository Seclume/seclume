package space.seclume;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The forbidden-API check reads code, not lines: of eight ways past the
 * line-by-line check, seven are reported now. The eighth - an allow marker
 * on a comment line of its own, freeing the line under it - is how 116
 * exceptions are written, and stays: it is as plain in a diff as one at the
 * end of the line. A marker inside a string literal frees nothing, on its
 * own line or the one before.
 */
class ForbiddenShapesTest {

    private static List<String> findings(String body) {
        String source = "class Sample {\n    void read(byte[] secret, java.io.Reader r) {\n"
                + body + "\n    }\n}\n";
        List<String> found = new ArrayList<>();
        ForbiddenApiTest.check("Sample.java", source, found);
        return found;
    }

    @Test
    void sevenWaysPastTheLineCheckAreReported() {
        List<String> forms = List.of(
                "        String a = new  String(secret);",
                "        String b = new java.lang.String(secret);",
                "        String c = java.nio.charset.StandardCharsets.UTF_8.decode("
                        + "java.nio.ByteBuffer.wrap(secret)).toString();",
                "        java.nio.ByteBuffer d = java.nio.ByteBuffer.wrap(secret.clone());",
                "        String e = new java.util.Scanner(r).next();",
                "        String f = \"seclume-allow: in a literal\"; String g = new String(secret);",
                "        String h = new String\n                (secret);");
        for (String form : forms) {
            assertEquals(1, findings(form).size(), "not reported: " + form);
        }
    }

    @Test
    void aMarkerInALiteralOnTheLineBeforeFreesNothing() {
        assertEquals(1, findings("        String note = \"// seclume-allow: a note\";\n"
                + "        String a = new String(secret);").size());
    }

    @Test
    void aMarkerInACommentStillAllows() {
        assertTrue(findings("        String a = new String(secret); // seclume-allow: a name")
                .isEmpty());
        assertTrue(findings("        // seclume-allow: a public salt\n"
                + "        String a = new String(secret);").isEmpty());
    }

    @Test
    void commentsAndLiteralsAreNotCode() {
        assertTrue(findings("        // new String(secret) is what not to write\n"
                + "        /* nor new String(secret) */ String s = \"new String(\";")
                .isEmpty());
        assertTrue(findings("        String t = \"\"\"\n            new String(secret)\n"
                + "            \"\"\";").isEmpty());
    }
}
