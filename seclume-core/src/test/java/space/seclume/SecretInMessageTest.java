package space.seclume;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Five ways to put a secret into an exception message; the check found one
 * of them - password, concatenated in the throw itself. apiKey, pw, bearer and
 * a message built in a local variable first went by.
 */
class SecretInMessageTest {

    private static List<String> findings(String body) {
        String source = "class Msg {\n    void fail(String password, String apiKey, String pw,"
                + " String bearer) {\n" + body + "\n    }\n}\n";
        List<String> found = new ArrayList<>();
        ErrorMessageTest.check("Msg.java", source, found);
        return found;
    }

    @Test
    void everyFormIsReported() {
        for (String form : List.of(
                "        throw new IllegalStateException(\"the login was refused for \" + password);",
                "        throw new IllegalStateException(\"the API refused the key \" + apiKey);",
                "        throw new IllegalStateException(\"the login was refused for \" + PW);",
                "        throw new IllegalStateException(\"the token was refused: \" + bearer);",
                "        String why = \"the login was refused for \" + password;\n"
                        + "        throw new IllegalStateException(why);")) {
            assertEquals(1, findings(form).size(), "not reported: " + form);
        }
    }

    @Test
    void wordsAboutASecretAreNotTheSecret() {
        assertTrue(findings("        throw new IllegalStateException(\"the password file \""
                + " + passwordFile + \" cannot be read\");").isEmpty());
        assertTrue(findings("        throw new IllegalStateException(\"the token endpoint answered \""
                + " + bearer.status() + \" - check the client\");").isEmpty());
    }
}
