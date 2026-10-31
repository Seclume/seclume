package space.seclume.inventory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import space.seclume.inventory.CryptoInventory.Asset;

/**
 * Two CBOMs compared - the last release's and this one's: what cryptography
 * came, went or changed, and which of it is a step back.
 *
 * <p>Assets are matched by what they are, not by their {@code bom-ref}, which
 * is stable within a process and nothing more: a secret by its provider and
 * source, a data key by its ring position and provider, a private key by where
 * it is held, a certificate by its subject and peer, a TLS session by its peer
 * and stack. A step back is a new asset a quantum computer would break, or an
 * old one that changed to something weaker: a lower TLS version, a smaller
 * key, a key exchange or algorithm that lost its post-quantum level.
 */
public final class CbomDiff {

    /** What happened to an asset. */
    public enum Change { ADDED, REMOVED, CHANGED }

    /**
     * One difference.
     *
     * @param identity   what the asset is, as matched
     * @param before     its description in the old CBOM, or {@code null}
     * @param after      its description in the new one, or {@code null}
     * @param regression whether this is a step back
     * @param why        why it is one, or {@code null}
     */
    public record Difference(Change change, String identity, String before, String after,
            boolean regression, String why) {
    }

    private CbomDiff() {
    }

    /** The differences from {@code before} to {@code after}, steps back first. */
    public static List<Difference> diff(List<Asset> before, List<Asset> after) {
        Map<String, Asset> old = index(before);
        Map<String, Asset> now = index(after);
        List<Difference> differences = new ArrayList<>();
        for (Map.Entry<String, Asset> entry : now.entrySet()) {
            Asset was = old.get(entry.getKey());
            Asset is = entry.getValue();
            if (was == null) {
                String broken = QuantumReadiness.vulnerable(is);
                differences.add(new Difference(Change.ADDED, entry.getKey(), null, describe(is),
                        broken != null, broken == null ? null
                                : "new, and relies on " + broken + ", which a quantum computer breaks"));
            } else if (!describe(was).equals(describe(is))) {
                String why = weaker(was, is);
                differences.add(new Difference(Change.CHANGED, entry.getKey(), describe(was),
                        describe(is), why != null, why));
            }
        }
        for (Map.Entry<String, Asset> entry : old.entrySet()) {
            if (!now.containsKey(entry.getKey())) {
                differences.add(new Difference(Change.REMOVED, entry.getKey(),
                        describe(entry.getValue()), null, false, null));
            }
        }
        differences.sort((a, b) -> Boolean.compare(b.regression(), a.regression()));
        return List.copyOf(differences);
    }

    /** Whether any difference is a step back. */
    public static boolean regresses(List<Difference> differences) {
        return differences.stream().anyMatch(Difference::regression);
    }

    static String identity(Asset asset) {
        Map<String, String> f = asset.facts();
        return switch (asset.kind()) {
            case SECRET -> "secret " + f.getOrDefault("provider", "") + " " + nonNull(asset.source());
            case DATA_KEY -> "data key " + f.getOrDefault("ring", "") + "." + f.getOrDefault("keyNumber", "")
                    + " from " + nonNull(asset.source());
            case PRIVATE_KEY -> "private key in " + nonNull(asset.source()) + " " + nonNull(asset.algorithm());
            case CERTIFICATE -> "certificate " + f.getOrDefault("subject", nonNull(asset.name()))
                    + " at " + f.getOrDefault("peer", "");
            case PROTOCOL -> "TLS to " + f.getOrDefault("peer", "") + " on " + f.getOrDefault("stack", "");
        };
    }

    static String describe(Asset asset) {
        Map<String, String> f = asset.facts();
        return switch (asset.kind()) {
            case SECRET -> "provider=" + f.getOrDefault("provider", "");
            case DATA_KEY -> nonNull(asset.algorithm()) + (Boolean.parseBoolean(f.get("primary"))
                    ? ", primary" : "");
            case PRIVATE_KEY -> nonNull(asset.algorithm()) + (asset.bits() > 0 ? "-" + asset.bits() : "");
            case CERTIFICATE -> nonNull(asset.algorithm()) + (asset.bits() > 0 ? "-" + asset.bits() : "")
                    + " signed " + f.getOrDefault("signatureAlgorithm", "");
            case PROTOCOL -> "TLS " + f.getOrDefault("version", "") + " " + f.getOrDefault("cipherSuite", "")
                    + (f.get("keyExchange") == null ? "" : " with " + f.get("keyExchange"));
        };
    }

    /** Why {@code is} is weaker than {@code was}, or {@code null} when it is not. */
    static String weaker(Asset was, Asset is) {
        if (QuantumReadiness.vulnerable(was) == null && QuantumReadiness.vulnerable(is) != null) {
            return "was post-quantum, now relies on " + QuantumReadiness.vulnerable(is);
        }
        switch (is.kind()) {
            case PROTOCOL -> {
                String a = was.facts().getOrDefault("version", "");
                String b = is.facts().getOrDefault("version", "");
                if (!a.isEmpty() && !b.isEmpty() && b.compareTo(a) < 0) {
                    return "TLS " + a + " became TLS " + b;
                }
                if (aes(was) > aes(is) && aes(is) > 0) {
                    return "AES-" + aes(was) + " became AES-" + aes(is);
                }
            }
            case PRIVATE_KEY, CERTIFICATE -> {
                CycloneDxCbom.Algorithm a = CycloneDxCbom.algorithm(was.algorithm(), was.bits());
                CycloneDxCbom.Algorithm b = CycloneDxCbom.algorithm(is.algorithm(), is.bits());
                if (b.classical() < a.classical() && b.classical() > 0) {
                    return a.name() + " (" + a.classical() + "-bit security) became " + b.name()
                            + " (" + b.classical() + ")";
                }
            }
            case DATA_KEY -> {
                CycloneDxCbom.Algorithm a = CycloneDxCbom.algorithm(was.algorithm(), was.bits());
                CycloneDxCbom.Algorithm b = CycloneDxCbom.algorithm(is.algorithm(), is.bits());
                if (b.quantum() < a.quantum()) {
                    return a.name() + " became " + b.name();
                }
            }
            default -> {
            }
        }
        return null;
    }

    private static int aes(Asset protocol) {
        String suite = protocol.facts().getOrDefault("cipherSuite", "").toUpperCase(Locale.ROOT);
        return suite.contains("AES_256") ? 256 : suite.contains("AES_128") ? 128 : 0;
    }

    private static Map<String, Asset> index(List<Asset> assets) {
        Map<String, Asset> index = new LinkedHashMap<>();
        for (Asset asset : assets) {
            String key = identity(asset);
            String unique = key;
            for (int n = 2; index.containsKey(unique); n++) {
                unique = key + " #" + n;
            }
            index.put(unique, asset);
        }
        return index;
    }

    /** As Markdown. */
    public static String markdown(List<Difference> differences) {
        StringBuilder out = new StringBuilder("## Cryptography since the last CBOM\n\n");
        if (differences.isEmpty()) {
            return out.append("No change.\n").toString();
        }
        long back = differences.stream().filter(Difference::regression).count();
        out.append(differences.size()).append(" changes, ").append(back).append(" of them a step back.\n\n")
                .append("| | Asset | Before | After | Why |\n|---|---|---|---|---|\n");
        for (Difference d : differences) {
            out.append("| ").append(d.regression() ? "**back**" : d.change().name().toLowerCase(Locale.ROOT))
                    .append(" | ").append(CryptoPolicy.cell(d.identity()))
                    .append(" | ").append(CryptoPolicy.cell(d.before() == null ? "-" : d.before()))
                    .append(" | ").append(CryptoPolicy.cell(d.after() == null ? "-" : d.after()))
                    .append(" | ").append(CryptoPolicy.cell(d.why() == null ? "" : d.why()))
                    .append(" |\n");
        }
        return out.toString();
    }

    private static String nonNull(String text) {
        return text == null ? "" : text;
    }
}
