package space.seclume.inventory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.SplittableRandom;

import org.junit.jupiter.api.Test;

import space.seclume.inventory.CryptoInventory.Asset;

/** A CBOM back into assets - whole - and anything else refused. */
class CbomReaderTest {

    private static final Instant T = Instant.parse("2026-10-30T12:00:00Z");
    private static final String PUNCTUATION = "{}[],:\"\\0e-";

    @Test
    void whatWasWrittenIsReadBackAssetForAsset() {
        List<Asset> written = CycloneDxCbomTest.everyKind();
        List<Asset> read = CbomReader.read(CycloneDxCbom.write("orders", written, T));
        assertEquals(written.size(), read.size());
        for (int i = 0; i < written.size(); i++) {
            Asset a = written.get(i);
            Asset b = read.get(i);
            assertEquals(a.ref(), b.ref());
            assertEquals(a.kind(), b.kind());
            assertEquals(a.name(), b.name());
            assertEquals(a.algorithm(), b.algorithm(), a.ref());
            assertEquals(a.bits(), b.bits(), a.ref());
            assertEquals(a.source(), b.source(), a.ref());
            assertEquals(a.firstSeen(), b.firstSeen());
            assertEquals(a.lastUsed(), b.lastUsed());
            assertEquals(a.uses(), b.uses());
            assertEquals(a.expires(), b.expires(), a.ref());
            assertEquals(a.facts(), b.facts(), a.ref());
        }
    }

    @Test
    void theAnalysesGiveTheSameAnswerOnTheFileAsOnTheProcess() {
        List<Asset> written = CycloneDxCbomTest.everyKind();
        List<Asset> read = CbomReader.read(CycloneDxCbom.write("orders", written, T));
        assertEquals(CryptoPolicy.defaults().check(written, T), CryptoPolicy.defaults().check(read, T));
        assertEquals(QuantumReadiness.assess(written), QuantumReadiness.assess(read));
        assertEquals(List.of(), CbomDiff.diff(written, read));
    }

    @Test
    void componentsSeclumeDidNotWriteAreLeftOut() {
        String json = """
                {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
                  {"type": "library", "name": "jackson"},
                  {"type": "cryptographic-asset", "bom-ref": "x", "name": "x",
                   "properties": [{"name": "seclume:kind", "value": "nonsense"}]},
                  {"type": "cryptographic-asset", "bom-ref": "k", "name": "RSA key",
                   "properties": [{"name": "seclume:kind", "value": "private_key"},
                                  {"name": "seclume:algorithm", "value": "RSA"},
                                  {"name": "seclume:bits", "value": "lots"}]}
                ]}""";
        List<Asset> assets = CbomReader.read(json);
        assertEquals(1, assets.size());
        assertEquals(0, assets.get(0).bits());
        assertEquals(Instant.EPOCH, assets.get(0).firstSeen());
        assertEquals(Map.of(), assets.get(0).facts());
        assertEquals(List.of(), CbomReader.read("{\"bomFormat\": \"CycloneDX\"}"));
    }

    @Test
    void whatIsNotACycloneDxDocumentIsRefused() {
        for (String wrong : List.of("", "[]", "{}", "{\"bomFormat\": \"SPDX\"}", "nul",
                "{\"bomFormat\": \"CycloneDX\"", "{\"bomFormat\": \"CycloneDX\"} x",
                "{\"a\": 01}", "{\"a\": 1.}", "{\"a\": -}", "{\"a\": 1e}", "{\"a\": \"\\x\"}",
                "{\"a\": \"\\u12\"}", "{\"a\": \"tab\there\"}", "{\"a\" 1}", "{a: 1}", "[1 2]",
                "{\"a\": [1,]}", "{\"a\": tru}")) {
            assertThrows(IllegalArgumentException.class, () -> CbomReader.read(wrong), wrong);
        }
        assertThrows(IllegalArgumentException.class, () -> CbomReader.read(null));
    }

    @Test
    void nestingIsBounded() {
        String deep = "[".repeat(CbomReader.MAX_DEPTH + 2) + "]".repeat(CbomReader.MAX_DEPTH + 2);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new CbomReader.Parser(deep).document());
        assertTrue(e.getMessage().contains("nested deeper"), e.getMessage());
        String fine = "[".repeat(CbomReader.MAX_DEPTH) + "]".repeat(CbomReader.MAX_DEPTH);
        new CbomReader.Parser(fine).document();
    }

    @Test
    void jsonValuesComeOutAsTheyWereMeant() {
        Object value = new CbomReader.Parser(
                "{\"s\": \"a\\\"b\\\\c\\/\\n\\u00e9\", \"n\": -12, \"f\": 1.5e2, \"t\": true, "
                + "\"z\": null, \"l\": [], \"o\": {}}").document();
        Map<?, ?> map = (Map<?, ?>) value;
        assertEquals("a\"b\\c/\n\u00e9", map.get("s"));
        assertEquals(-12L, map.get("n"));
        assertEquals(150.0, map.get("f"));
        assertEquals(Boolean.TRUE, map.get("t"));
        assertTrue(map.containsKey("z") && map.get("z") == null);
        assertEquals(List.of(), map.get("l"));
        assertEquals(Map.of(), map.get("o"));
    }

    /** Random bytes and mangled CBOMs: an answer or IllegalArgumentException, nothing else. */
    @Test
    void garbageIsRefusedNotThrownAround() {
        String good = CycloneDxCbom.write("orders", CycloneDxCbomTest.everyKind(), T);
        SplittableRandom random = new SplittableRandom(17);
        for (int round = 0; round < 2_000; round++) {
            StringBuilder text = new StringBuilder(good);
            int changes = 1 + random.nextInt(4);
            for (int c = 0; c < changes; c++) {
                int at = random.nextInt(text.length());
                switch (random.nextInt(3)) {
                    case 0 -> text.deleteCharAt(at);
                    case 1 -> text.insert(at, PUNCTUATION.charAt(random.nextInt(PUNCTUATION.length())));
                    default -> text.setCharAt(at, (char) random.nextInt(128));
                }
            }
            try {
                CbomReader.read(text.toString());
            } catch (IllegalArgumentException expected) {
                // refused
            }
        }
    }
}
