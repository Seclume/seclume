package space.seclume.inventory;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

import space.seclume.inventory.CryptoInventory.Asset;

/**
 * What a quantum computer would break in this application, what to put in its
 * place, and in which order - read from the inventory, or from a CBOM.
 *
 * <p>The order follows the threat, not the algorithm:
 *
 * <ul>
 *   <li><b>High</b> - a TLS key exchange that is not post-quantum. Traffic
 *       recorded today is decrypted the day the key exchange falls ("harvest
 *       now, decrypt later"): the damage is already being done, and the fix -
 *       the X25519MLKEM768 hybrid - exists.</li>
 *   <li><b>Medium</b> - signatures: a server's certificate, our own signing
 *       keys. A signature has to be forged while it is checked, so the danger
 *       begins when the quantum computer exists, not before; but certificates
 *       and the keys behind tokens live for years and must be planned.</li>
 *   <li><b>Low</b> - 128-bit symmetric keys. Grover's search halves their
 *       strength to about 64 bits, which is a margin, not a break; 256 bits
 *       restores it.</li>
 * </ul>
 *
 * <p>Passwords and tokens are not assessed: what protects them in transit is
 * the TLS session, and that is.
 */
public final class QuantumReadiness {

    /** How urgent. */
    public enum Priority { HIGH, MEDIUM, LOW }

    /**
     * One asset to change.
     *
     * @param today       what it uses now
     * @param replacement what to use instead
     * @param how         how to get there with seclume, where seclume can
     */
    public record Item(Priority priority, String ref, String asset, String today, String threat,
            String replacement, String how) {
    }

    /**
     * @param assessed assets with an algorithm to judge
     * @param ready    of those, the ones nothing here applies to
     */
    public record Report(int assessed, int ready, List<Item> items) {

        /** The share of assessed assets that are ready, 0 to 100; 100 when there are none. */
        public int percent() {
            return assessed == 0 ? 100 : (int) Math.round(100.0 * ready / assessed);
        }

        /** As Markdown, for a job summary, a ticket, a wiki page. */
        public String markdown() {
            StringBuilder out = new StringBuilder("## Post-quantum readiness\n\n")
                    .append(ready).append(" of ").append(assessed).append(" assets ready (")
                    .append(percent()).append(" %).\n");
            if (items.isEmpty()) {
                return out.append("\nNothing here relies on what a quantum computer breaks.\n")
                        .toString();
            }
            out.append("\n| Priority | Asset | Today | Threat | Instead | How |\n")
                    .append("|---|---|---|---|---|---|\n");
            for (Item item : items) {
                out.append("| ").append(item.priority().name().toLowerCase(Locale.ROOT))
                        .append(" | ").append(CryptoPolicy.cell(item.asset()))
                        .append(" | ").append(CryptoPolicy.cell(item.today()))
                        .append(" | ").append(CryptoPolicy.cell(item.threat()))
                        .append(" | ").append(CryptoPolicy.cell(item.replacement()))
                        .append(" | ").append(CryptoPolicy.cell(item.how())).append(" |\n");
            }
            return out.toString();
        }

        /** As JSON. */
        public String json() {
            StringBuilder out = new StringBuilder("{\"assessed\": ").append(assessed)
                    .append(", \"ready\": ").append(ready).append(", \"percent\": ")
                    .append(percent()).append(", \"items\": [");
            List<String> entries = new ArrayList<>();
            for (Item item : items) {
                entries.add("{\"priority\": " + CycloneDxCbom.string(item.priority().name()
                        .toLowerCase(Locale.ROOT)) + ", \"ref\": " + s(item.ref())
                        + ", \"asset\": " + s(item.asset()) + ", \"today\": " + s(item.today())
                        + ", \"threat\": " + s(item.threat()) + ", \"replacement\": "
                        + s(item.replacement()) + ", \"how\": " + s(item.how()) + "}");
            }
            return out.append(String.join(", ", entries)).append("]}\n").toString();
        }

        private static String s(String text) {
            return CycloneDxCbom.string(text == null ? "" : text);
        }
    }

    private QuantumReadiness() {
    }

    /** The report for {@code assets}, most urgent first. */
    public static Report assess(List<Asset> assets) {
        List<Item> items = new ArrayList<>();
        int assessed = 0;
        for (Asset asset : assets) {
            List<Item> found = items(asset);
            if (found == null) {
                continue;
            }
            assessed++;
            items.addAll(found);
        }
        // Grover's halving is a margin, not a break: an asset with only that is ready.
        int notReady = (int) items.stream().filter(i -> i.priority() != Priority.LOW)
                .map(Item::ref).distinct().count();
        items.sort(Comparator.comparing(Item::priority));
        return new Report(assessed, assessed - notReady, List.copyOf(items));
    }

    /**
     * What a quantum computer would break in {@code asset} - the algorithm's
     * name - or {@code null} when nothing (Grover's halving of a symmetric key
     * is not a break).
     */
    static String vulnerable(Asset asset) {
        switch (asset.kind()) {
            case PROTOCOL -> {
                CycloneDxCbom.Algorithm kx = CycloneDxCbom.keyExchange(
                        asset.facts().get("cipherSuite"), asset.facts().get("keyExchange"));
                return kx.quantum() == 0 && !kx.primitive().equals("unknown") ? kx.name() : null;
            }
            case CERTIFICATE -> {
                CycloneDxCbom.Algorithm key = CycloneDxCbom.algorithm(asset.algorithm(), asset.bits());
                CycloneDxCbom.Algorithm signature = CycloneDxCbom.signature(
                        asset.facts().get("signatureAlgorithm"));
                if (key.quantum() == 0 && !key.primitive().equals("unknown")) {
                    return key.name();
                }
                return signature.quantum() == 0 ? signature.name() : null;
            }
            case PRIVATE_KEY -> {
                CycloneDxCbom.Algorithm key = CycloneDxCbom.algorithm(asset.algorithm(), asset.bits());
                return key.quantum() == 0 && !key.primitive().equals("unknown") ? key.name() : null;
            }
            default -> {
                return null;
            }
        }
    }

    /** The items for one asset; an empty list when it is ready, {@code null} when not assessed. */
    private static List<Item> items(Asset asset) {
        List<Item> items = new ArrayList<>();
        String name = asset.name();
        switch (asset.kind()) {
            case PROTOCOL -> {
                String broken = vulnerable(asset);
                String stack = asset.facts().getOrDefault("stack", "");
                String version = asset.facts().getOrDefault("version", "");
                if (broken != null) {
                    String how = version.startsWith("1.3")
                            ? stack.equalsIgnoreCase("JSSE")
                                    ? "tlsStack=seclume: seclume's own TLS stack offers X25519MLKEM768 "
                                    + "where OpenSSL 3.5+ or CNG has ML-KEM; the server must offer it too"
                                    : "seclume's stack offers the hybrid where OpenSSL 3.5+ or CNG has "
                                    + "ML-KEM and -Dseclume.tls.postQuantum is not false; this server "
                                    + "did not take it - enable X25519MLKEM768 on the server"
                            : "the hybrid needs TLS 1.3: move the server to TLS 1.3, then as above";
                    items.add(new Item(Priority.HIGH, asset.ref(), name, broken,
                            "harvest now, decrypt later: traffic recorded today is opened once "
                            + broken + " falls", "X25519MLKEM768 (ML-KEM-768, FIPS 203, with X25519)",
                            how));
                }
                String suite = asset.facts().getOrDefault("cipherSuite", "").toUpperCase(Locale.ROOT);
                if (suite.contains("AES_128")) {
                    items.add(grover(asset, "AES-128-GCM records",
                            "a TLS_AES_256_GCM_SHA384 suite, preferred on the server"));
                }
            }
            case CERTIFICATE -> {
                String broken = vulnerable(asset);
                if (broken != null) {
                    items.add(new Item(Priority.MEDIUM, asset.ref(), name, broken
                            + " (" + asset.facts().getOrDefault("signatureAlgorithm", "") + ")",
                            "a certificate forged once a quantum computer exists; planned now "
                            + "because certificates and CAs change slowly",
                            "ML-DSA-65 (FIPS 204), or a composite ML-DSA certificate",
                            "the server's owner and its CA; nothing to change on this side but the trust store"));
                }
            }
            case PRIVATE_KEY -> {
                String broken = vulnerable(asset);
                if (broken != null) {
                    items.add(new Item(Priority.MEDIUM, asset.ref(), name, broken,
                            "signatures - tokens, webhooks, client certificates - forged once a "
                            + "quantum computer exists",
                            "ML-DSA-65 (FIPS 204); ML-DSA-87 where CNSA 2.0 applies",
                            "a new key in the same KMS or file, published alongside the old one "
                            + "until every verifier knows it"));
                }
            }
            case DATA_KEY -> {
                String algorithm = asset.algorithm() == null ? "" : asset.algorithm();
                if (algorithm.contains("128")) {
                    items.add(grover(asset, algorithm, "AES-256 (seclume's field encryption "
                            + "uses AES-256-GCM-SIV)"));
                }
            }
            default -> {
                return null;
            }
        }
        return items;
    }

    private static Item grover(Asset asset, String today, String replacement) {
        return new Item(Priority.LOW, asset.ref(), asset.name(), today,
                "Grover's search: about 64 bits left against a quantum computer - a margin, "
                + "not a break", replacement, "");
    }
}
