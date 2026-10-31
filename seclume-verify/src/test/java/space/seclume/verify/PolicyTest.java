package space.seclume.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@code --policy}, {@code --quantum} and {@code --cbom-diff} on the CBOM
 * fixtures in {@code src/test/resources/cbom}, which the GitHub Action's CI
 * job uses as well: {@code release-1.json} (post-quantum TLS, a KMS data key)
 * and {@code release-2.json} (the hybrid lost, an RSA-2048 key added, a data
 * key from a file).
 */
class PolicyTest {

    @TempDir
    Path directory;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private PrintStream out() {
        return new PrintStream(out, true, StandardCharsets.UTF_8);
    }

    private PrintStream err() {
        return new PrintStream(err, true, StandardCharsets.UTF_8);
    }

    private static String fixture(String name) {
        return Path.of("src/test/resources/cbom", name).toString();
    }

    private String printed() {
        return out.toString(StandardCharsets.UTF_8);
    }

    private static List<space.seclume.inventory.CryptoInventory.Asset> noConnection(String url) {
        throw new AssertionError("no connection expected for a file: " + url);
    }

    @Test
    void theFirstReleaseMeetsAStrictPolicyTheSecondDoesNot() throws Exception {
        Path policy = Files.writeString(directory.resolve("policy.properties"), """
                rsa.min-bits=3072
                tls.require-hybrid=true
                data-key.require-kms=true
                quantum=warn
                """);
        assertEquals(0, Policy.policy(List.of(policy.toString(), fixture("release-1.json")), out(), err(),
                PolicyTest::noConnection), err.toString(StandardCharsets.UTF_8));
        out.reset();
        assertEquals(1, Policy.policy(List.of(policy.toString(), fixture("release-2.json")), out(), err(),
                PolicyTest::noConnection));
        String report = printed();
        assertTrue(report.contains("`tls.require-hybrid`"), report);
        assertTrue(report.contains("`rsa.min-bits`"), report);
        assertTrue(report.contains("`data-key.require-kms`"), report);
        out.reset();
        assertEquals(1, Policy.policy(List.of(policy.toString(), fixture("release-2.json"), "--json"),
                out(), err(), PolicyTest::noConnection));
        assertTrue(printed().startsWith("{\"fails\": true"), printed());
    }

    @Test
    void theQuantumReportOfEachRelease() {
        assertEquals(0, Policy.quantum(List.of(fixture("release-1.json")), out(), err(),
                PolicyTest::noConnection));
        assertTrue(printed().contains("## Post-quantum readiness"), printed());
        out.reset();
        assertEquals(0, Policy.quantum(List.of(fixture("release-2.json"), "--json"), out(), err(),
                PolicyTest::noConnection));
        assertTrue(printed().contains("\"priority\": \"high\""), printed());
    }

    @Test
    void theSecondReleaseIsAStepBackTheReverseIsNot() {
        assertEquals(1, Policy.diff(List.of(fixture("release-1.json"), fixture("release-2.json")),
                out(), err()));
        assertTrue(printed().contains("**back**"), printed());
        out.reset();
        assertEquals(0, Policy.diff(List.of(fixture("release-2.json"), fixture("release-1.json")),
                out(), err()));
        out.reset();
        assertEquals(0, Policy.diff(List.of(fixture("release-1.json"), fixture("release-1.json")),
                out(), err()));
        assertTrue(printed().contains("No change."));
    }

    @Test
    void aJdbcUrlIsConnectedToAFileIsRead() {
        boolean[] connected = {false};
        assertEquals(0, Policy.quantum(List.of("jdbc:seclume:postgresql://db/app"), out(), err(), url -> {
            connected[0] = true;
            return List.of();
        }));
        assertTrue(connected[0]);
    }

    @Test
    void wrongCallsAndUnreadableInputAreTwo() throws Exception {
        assertEquals(2, Policy.policy(List.of("only-one"), out(), err(), PolicyTest::noConnection));
        assertEquals(2, Policy.policy(List.of(directory.resolve("absent").toString(),
                fixture("release-1.json")), out(), err(), PolicyTest::noConnection));
        Path bad = Files.writeString(directory.resolve("bad.properties"), "rsa.min-bits=lots\n");
        assertEquals(2, Policy.policy(List.of(bad.toString(), fixture("release-1.json")), out(), err(),
                PolicyTest::noConnection));
        Path notCbom = Files.writeString(directory.resolve("x.json"), "{\"bomFormat\": \"SPDX\"}");
        assertEquals(2, Policy.quantum(List.of(notCbom.toString()), out(), err(), PolicyTest::noConnection));
        assertEquals(2, Policy.diff(List.of(fixture("release-1.json")), out(), err()));
        assertEquals(2, Policy.diff(List.of(fixture("release-1.json"), notCbom.toString()), out(), err()));
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("cannot be read as a CBOM"));
    }
}
