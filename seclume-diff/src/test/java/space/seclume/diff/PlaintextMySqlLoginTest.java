package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

/**
 * Every plaintext login to the real MySQL server in this module allows the
 * server's public key to be asked for.
 *
 * <p>MySQL 8's caching_sha2_password answers a login from a cache of the
 * password's hash. The cache is empty after the server starts and is filled
 * by a full login, which over plaintext needs the server's key - and seclume
 * asks for that only with {@code allowPublicKeyRetrieval=true}. A test that
 * logs in with {@code tls=off} and without it passes when another class
 * happened to log in first and fails when it ran first: the differential
 * {@code mysql} job of 13 November 2026 failed so, in FetchSizeEverywhereTest
 * and HostSelectionTest, and a fresh MySQL 8.0 refuses the same login every
 * time. The order of the classes is not the test's to rely on.
 *
 * <p>This reads the sources: a statement, an argument list or an array
 * initialiser that names MySQL and turns TLS off must allow the key too.
 */
class PlaintextMySqlLoginTest {

    private static final Path SOURCES = Path.of("src/test/java/space/seclume/diff");

    /**
     * Not logins to MySQL: HandshakeFuzzTest's go to a scripted server, which
     * never asks for a full login, and this file's are the scanner's fixtures.
     */
    private static final Set<String> NOT_MYSQL = Set.of("HandshakeFuzzTest.java", "PlaintextMySqlLoginTest.java");

    @Test
    void everyPlaintextLoginToMySqlAllowsTheServersKey() throws IOException {
        List<String> found = new ArrayList<>();
        int checked = 0;
        try (Stream<Path> files = Files.list(SOURCES)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).sorted().toList()) {
                if (NOT_MYSQL.contains(file.getFileName().toString())) {
                    continue;
                }
                String source = Files.readString(file, StandardCharsets.UTF_8);
                for (String unit : plaintextMySqlUnits(source)) {
                    checked++;
                    if (!unit.contains("allowPublicKeyRetrieval=true")) {
                        found.add(file.getFileName() + ": " + unit);
                    }
                }
            }
        }
        assertTrue(checked >= 15, "the scan saw " + checked + " plaintext MySQL logins - did the sources move?");
        assertEquals(List.of(), found, "plaintext MySQL logins that cannot fill the server's cache themselves");
    }

    // ---- the scanner, and its own tests -------------------------------------

    @Test
    void anArgumentListThatNamesMySqlAndTurnsTlsOffIsAUnit() {
        assertEquals(List.of("\"MySQL\" \"mysql\" \".local-mysql-password\" \"&tls=off\""),
                plaintextMySqlUnits("""
                        List.of(new Database("PostgreSQL", "postgresql", 5432, ".local-pg-password", "&tls=off"),
                                new Database("MySQL", "mysql", 3307, ".local-mysql-password", "&tls=off"));
                        """));
    }

    @Test
    void aConcatenatedUrlIsOneUnitUpToItsSemicolon() {
        List<String> units = plaintextMySqlUnits("""
                void m() {
                    String a = "jdbc:seclume:postgresql://" + host + "/x?tls=off";
                    String b = "jdbc:seclume:mysql://" + host + ":" + port + "/x?user=u&tls=off"
                            + "&allowPublicKeyRetrieval=true&provider=file&path=" + path;
                }
                """);
        assertEquals(1, units.size(), units.toString());
        assertTrue(units.get(0).contains("allowPublicKeyRetrieval=true"), units.toString());
    }

    @Test
    void anArrayInitialiserIsAUnit() {
        List<String> units = plaintextMySqlUnits("""
                List.of(new String[] {".local-pg-password", "jdbc:seclume:postgresql://%s/x?tls=off"},
                        new String[] {".local-mysql-password", "3307", "jdbc:seclume:mysql://%s/x?tls=off"});
                """);
        assertEquals(1, units.size(), units.toString());
        assertTrue(units.get(0).contains(".local-mysql-password"), units.toString());
    }

    @Test
    void commentsAndTextInsideStringsAreNotCode() {
        assertEquals(List.of(), plaintextMySqlUnits("""
                // new Database("MySQL", "mysql", 3307, "&tls=off");
                /* new Database("MySQL", "mysql", 3307, "&tls=off"); */
                String s = "a ( paren and a ; semicolon in a string";
                String t = "jdbc:seclume:postgresql://h/x?tls=off";
                """));
        assertEquals(1, plaintextMySqlUnits("""
                String s = "(" + "jdbc:seclume:mysql://h/x?tls=off" + ")";
                """).size());
    }

    /**
     * The string literals of every unit - statement, argument list or array
     * initialiser - that has a literal turning TLS off and one naming MySQL,
     * each unit as its literals joined by spaces.
     */
    static List<String> plaintextMySqlUnits(String source) {
        List<Token> tokens = tokens(source);
        List<String> units = new ArrayList<>();
        for (int i = 0; i < tokens.size(); i++) {
            Token token = tokens.get(i);
            if (token.literal() == null || !token.literal().contains("tls=off")) {
                continue;
            }
            int start = boundary(tokens, i, -1);
            int end = boundary(tokens, i, +1);
            List<String> literals = new ArrayList<>();
            boolean mysql = false;
            for (int j = start; j <= end; j++) {
                String literal = tokens.get(j).literal();
                if (literal != null) {
                    literals.add("\"" + literal + "\"");
                    mysql |= literal.equalsIgnoreCase("mysql") || literal.contains("mysql://")
                            || literal.contains("local-mysql-password");
                }
            }
            String unit = String.join(" ", literals);
            if (mysql && !units.contains(unit)) {
                units.add(unit);
            }
        }
        return units;
    }

    /** One token: a string literal's text, or a single character of code. */
    private record Token(String literal, char code) {
    }

    /**
     * From {@code at}, in {@code direction}, the last token of the unit: before
     * the bracket that opens or closes the group the literal is in, or before a
     * semicolon in that group.
     */
    private static int boundary(List<Token> tokens, int at, int direction) {
        int depth = 0;
        int i = at;
        while (i + direction >= 0 && i + direction < tokens.size()) {
            Token next = tokens.get(i + direction);
            if (next.literal() == null) {
                char c = next.code();
                boolean opens = c == '(' || c == '{' || c == '[';
                boolean closes = c == ')' || c == '}' || c == ']';
                if (direction < 0 ? closes : opens) {
                    depth++;
                } else if (direction < 0 ? opens : closes) {
                    if (depth == 0) {
                        return i;
                    }
                    depth--;
                } else if (c == ';' && depth == 0) {
                    return i;
                }
            }
            i += direction;
        }
        return i;
    }

    /** String literals (text blocks too) and the brackets and semicolons of the code around them. */
    private static List<Token> tokens(String source) {
        List<Token> tokens = new ArrayList<>();
        int i = 0;
        int n = source.length();
        while (i < n) {
            char c = source.charAt(i);
            if (source.startsWith("//", i)) {
                int end = source.indexOf('\n', i);
                i = end < 0 ? n : end;
            } else if (source.startsWith("/*", i)) {
                int end = source.indexOf("*/", i + 2);
                i = end < 0 ? n : end + 2;
            } else if (source.startsWith("\"\"\"", i)) {
                int end = source.indexOf("\"\"\"", i + 3);
                end = end < 0 ? n : end;
                tokens.add(new Token(source.substring(i + 3, end), '\0'));
                i = Math.min(n, end + 3);
            } else if (c == '"' || c == '\'') {
                StringBuilder text = new StringBuilder();
                int j = i + 1;
                while (j < n && source.charAt(j) != c) {
                    if (source.charAt(j) == '\\' && j + 1 < n) {
                        j++;
                    }
                    text.append(source.charAt(j));
                    j++;
                }
                if (c == '"') {
                    tokens.add(new Token(text.toString(), '\0'));
                }
                i = j + 1;
            } else {
                if ("(){}[];".indexOf(c) >= 0) {
                    tokens.add(new Token(null, c));
                }
                i++;
            }
        }
        return tokens;
    }
}
