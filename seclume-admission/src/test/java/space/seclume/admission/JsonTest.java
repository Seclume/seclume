package space.seclume.admission;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class JsonTest {

    @Test
    void whatIsReadIsWrittenAsItWas() {
        String text = "{\"a\":[1,-2.5e+3,true,false,null,\"x\\\"y\\\\z\\n\"],\"b\":{},\"c\":[],"
                + "\"\\u00e9t\\u00e9\":\"\\u20ac\"}";
        Object value = Json.parse(text);
        assertEquals("{\"a\":[1,-2.5e+3,true,false,null,\"x\\\"y\\\\z\\n\"],\"b\":{},\"c\":[],"
                + "\"\u00e9t\u00e9\":\"\u20ac\"}", Json.write(value));
        assertEquals(value, Json.parse(Json.write(value)));
        Map<String, Object> object = Json.asObject(value);
        assertEquals(new Json.Number("-2.5e+3"), Json.asArray(object.get("a")).get(1));
        assertEquals(List.of(), Json.asArray(object.get("c")));
        assertEquals(Map.of(), Json.asObject("not an object"));
    }

    @Test
    void whitespaceAndControlCharactersAreHandled() {
        assertEquals(Map.of("k", List.of()), Json.parse(" \n{ \"k\" :\t[ ] }\r\n"));
        assertEquals("\"\\u0001\"", Json.write("\u0001"));
    }

    @Test
    void whatIsNotJsonIsRefused() {
        for (String bad : List.of("", "{", "[1,]", "{\"a\" 1}", "{\"a\":1} x", "tru", "-",
                "1.", "1e", "\"\\x\"", "\"\\u12\"", "\"open", "{1:2}", "\"a\u0001\"")) {
            assertThrows(IllegalArgumentException.class, () -> Json.parse(bad), bad);
        }
    }

    @Test
    void nestingTooDeepIsRefusedRatherThanOverflowingTheStack() {
        String deep = "[".repeat(10_000) + "]".repeat(10_000);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Json.parse(deep));
        assertEquals(true, e.getMessage().contains("deeper"), e.getMessage());
        String fine = "[".repeat(Json.DEEPEST) + "]".repeat(Json.DEEPEST);
        Json.parse(fine);
    }
}
