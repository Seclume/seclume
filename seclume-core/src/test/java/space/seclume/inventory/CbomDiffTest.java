package space.seclume.inventory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.inventory.CbomDiff.Change;
import space.seclume.inventory.CbomDiff.Difference;
import space.seclume.inventory.CryptoInventory.Asset;
import space.seclume.inventory.CryptoInventory.Kind;

/** Two CBOMs: what came, went, changed - and which of it is a step back. */
class CbomDiffTest {

    private static final Instant T = Instant.parse("2026-10-30T12:00:00Z");

    private static Asset tls(String peer, String version, String suite, String group) {
        Map<String, String> facts = new java.util.LinkedHashMap<>();
        facts.put("peer", peer);
        facts.put("stack", "seclume");
        facts.put("version", version);
        facts.put("cipherSuite", suite);
        if (group != null) {
            facts.put("keyExchange", group);
        }
        // A ref that differs from run to run: matching must not depend on it.
        return new Asset("protocol:" + System.nanoTime(), Kind.PROTOCOL, "TLS to " + peer, group, 0,
                "seclume", T, T, 1, null, Map.copyOf(facts));
    }

    private static Asset key(String where, String algorithm, int bits) {
        return new Asset("private-key:" + System.nanoTime(), Kind.PRIVATE_KEY, "key", algorithm, bits,
                where, T, T, 1, null, Map.of());
    }

    @Test
    void theSameCbomTwiceIsNoChange() {
        List<Asset> assets = CycloneDxCbomTest.everyKind();
        assertEquals(List.of(), CbomDiff.diff(assets, assets));
        assertTrue(CbomDiff.markdown(List.of()).contains("No change."));
    }

    @Test
    void losingTheHybridIsAStepBack() {
        List<Difference> d = CbomDiff.diff(
                List.of(tls("db", "1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768")),
                List.of(tls("db", "1.3", "TLS_AES_256_GCM_SHA384", "X25519")));
        assertEquals(1, d.size());
        assertEquals(Change.CHANGED, d.get(0).change());
        assertTrue(d.get(0).regression());
        assertTrue(d.get(0).why().contains("was post-quantum, now relies on X25519"), d.get(0).why());
        assertTrue(CbomDiff.regresses(d));
    }

    @Test
    void gainingTheHybridIsNot() {
        List<Difference> d = CbomDiff.diff(
                List.of(tls("db", "1.3", "TLS_AES_256_GCM_SHA384", "X25519")),
                List.of(tls("db", "1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768")));
        assertEquals(1, d.size());
        assertFalse(d.get(0).regression());
    }

    @Test
    void anOlderTlsVersionOrSmallerAesIsAStepBack() {
        assertTrue(CbomDiff.diff(List.of(tls("db", "1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768")),
                List.of(tls("db", "1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", null))).get(0).regression());
        List<Difference> aes = CbomDiff.diff(
                List.of(tls("db", "1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768")),
                List.of(tls("db", "1.3", "TLS_AES_128_GCM_SHA256", "X25519MLKEM768")));
        assertTrue(aes.get(0).regression());
        assertEquals("AES-256 became AES-128", aes.get(0).why());
    }

    @Test
    void aSmallerKeyIsAStepBackALargerOneIsNot() {
        assertTrue(CbomDiff.diff(List.of(key("KMS", "RSA", 3072)), List.of(key("KMS", "RSA", 2048)))
                .get(0).regression());
        assertFalse(CbomDiff.diff(List.of(key("KMS", "RSA", 2048)), List.of(key("KMS", "RSA", 4096)))
                .get(0).regression());
    }

    @Test
    void aNewVulnerableAssetIsAStepBackAndARemovedOneIsNot() {
        List<Asset> before = new ArrayList<>(List.of(key("OpenSSL", "ML-DSA-65", 0)));
        List<Asset> after = new ArrayList<>(before);
        after.add(tls("cache", "1.3", "TLS_AES_256_GCM_SHA384", "X25519"));
        after.add(tls("queue", "1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768"));
        List<Difference> d = CbomDiff.diff(before, after);
        assertEquals(2, d.size());
        assertEquals(Change.ADDED, d.get(0).change());
        assertTrue(d.get(0).regression(), d.toString());
        assertTrue(d.get(0).identity().contains("cache"));
        assertFalse(d.get(1).regression());
        List<Difference> back = CbomDiff.diff(after, before);
        assertEquals(2, back.stream().filter(x -> x.change() == Change.REMOVED).count());
        assertFalse(CbomDiff.regresses(back));
    }

    @Test
    void stepsBackComeFirstAndTheMarkdownSaysSo() {
        List<Difference> d = CbomDiff.diff(
                List.of(tls("a", "1.3", "TLS_AES_256_GCM_SHA384", "X25519"),
                        tls("b", "1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768")),
                List.of(tls("a", "1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768"),
                        tls("b", "1.3", "TLS_AES_256_GCM_SHA384", "X25519")));
        assertTrue(d.get(0).regression());
        assertTrue(d.get(0).identity().contains(" b "), d.get(0).identity());
        String markdown = CbomDiff.markdown(d);
        assertTrue(markdown.contains("2 changes, 1 of them a step back."), markdown);
        assertTrue(markdown.contains("| **back** | TLS to b on seclume |"), markdown);
    }

    @Test
    void twoAssetsThatLookAlikeAreBothKept() {
        List<Asset> before = List.of(key("OpenSSL", "EC P-256", 256));
        List<Asset> after = List.of(key("OpenSSL", "EC P-256", 256), key("OpenSSL", "EC P-256", 256));
        List<Difference> d = CbomDiff.diff(before, after);
        assertEquals(1, d.size());
        assertEquals(Change.ADDED, d.get(0).change());
        assertTrue(d.get(0).identity().endsWith("#2"));
    }
}
