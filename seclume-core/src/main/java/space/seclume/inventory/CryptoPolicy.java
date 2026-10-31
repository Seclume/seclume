package space.seclume.inventory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

import space.seclume.inventory.CryptoInventory.Asset;

/**
 * Rules for the cryptography an application uses, checked against its
 * inventory: at start-up, in a health check, or in a pipeline against a CBOM.
 *
 * <p>The rules, as properties - each optional, the defaults in brackets:
 *
 * <ul>
 *   <li>{@code rsa.min-bits} [2048] - RSA keys, a server's or our own;</li>
 *   <li>{@code ec.min-bits} [256] - elliptic curve keys;</li>
 *   <li>{@code tls.min-version} [1.2] - {@code 1.2} or {@code 1.3};</li>
 *   <li>{@code tls.forward-secrecy} [true] - a TLS 1.2 suite without (EC)DHE
 *       fails; TLS 1.3 always has it;</li>
 *   <li>{@code tls.require-hybrid} [false] - every key exchange post-quantum
 *       hybrid (ML-KEM);</li>
 *   <li>{@code certificate.min-days} [14] - a server certificate this close to
 *       its end fails;</li>
 *   <li>{@code signature.forbidden} [SHA1,MD5] - in a certificate's signature
 *       algorithm;</li>
 *   <li>{@code algorithm.forbidden} [] - anywhere: a key's algorithm, a cipher
 *       suite, a key exchange;</li>
 *   <li>{@code secret.forbidden-providers} [] - where secrets may not come
 *       from, for example {@code file,env-file} in production;</li>
 *   <li>{@code data-key.require-kms} [false] - field encryption keys only from
 *       a KMS ({@code kms-decrypt}, {@code vault-transit}) or {@code shamir};</li>
 *   <li>{@code data-key.forbidden-providers} [];</li>
 *   <li>{@code quantum} [warn] - an asset a quantum computer would break:
 *       {@code off}, {@code warn} or {@code fail};</li>
 *   <li>{@code warn-only} [] - rules, by name, whose findings are warnings
 *       rather than failures.</li>
 * </ul>
 *
 * <p>A finding names the rule, the asset and what is wrong with it - facts
 * from the inventory, never a secret, which the inventory does not have.
 */
public final class CryptoPolicy {

    /** What a finding means for the run. */
    public enum Severity {
        /** The policy is not met: a start fails, a health check is down, a pipeline is red. */
        FAIL,
        /** Worth knowing; nothing stops. */
        WARN
    }

    /** One rule, one asset. */
    public record Finding(Severity severity, String rule, String ref, String asset, String message) {
    }

    static final Set<String> RULES = Set.of("rsa.min-bits", "ec.min-bits", "tls.min-version",
            "tls.forward-secrecy", "tls.require-hybrid", "certificate.min-days",
            "signature.forbidden", "algorithm.forbidden", "secret.forbidden-providers",
            "data-key.require-kms", "data-key.forbidden-providers", "quantum", "warn-only");

    private final int rsaMinBits;
    private final int ecMinBits;
    private final String tlsMinVersion;
    private final boolean forwardSecrecy;
    private final boolean requireHybrid;
    private final int certificateMinDays;
    private final List<String> forbiddenSignatures;
    private final List<String> forbiddenAlgorithms;
    private final Set<String> forbiddenSecretProviders;
    private final boolean dataKeyRequireKms;
    private final Set<String> forbiddenDataKeyProviders;
    private final String quantum;
    private final Set<String> warnOnly;

    private CryptoPolicy(Map<String, String> rules) {
        for (String key : rules.keySet()) {
            if (!RULES.contains(key)) {
                throw new IllegalArgumentException("no crypto policy rule '" + key + "' - the rules "
                        + "are " + new TreeSet<>(RULES));
            }
        }
        rsaMinBits = number(rules, "rsa.min-bits", 2048);
        ecMinBits = number(rules, "ec.min-bits", 256);
        tlsMinVersion = rules.getOrDefault("tls.min-version", "1.2").trim();
        if (!tlsMinVersion.equals("1.2") && !tlsMinVersion.equals("1.3")) {
            throw new IllegalArgumentException("tls.min-version is 1.2 or 1.3, not " + tlsMinVersion);
        }
        forwardSecrecy = bool(rules, "tls.forward-secrecy", true);
        requireHybrid = bool(rules, "tls.require-hybrid", false);
        certificateMinDays = number(rules, "certificate.min-days", 14);
        forbiddenSignatures = list(rules.getOrDefault("signature.forbidden", "SHA1,MD5"));
        forbiddenAlgorithms = list(rules.getOrDefault("algorithm.forbidden", ""));
        forbiddenSecretProviders = Set.copyOf(list(rules.getOrDefault("secret.forbidden-providers", "")));
        dataKeyRequireKms = bool(rules, "data-key.require-kms", false);
        forbiddenDataKeyProviders = Set.copyOf(list(rules.getOrDefault("data-key.forbidden-providers", "")));
        quantum = rules.getOrDefault("quantum", "warn").trim().toLowerCase(Locale.ROOT);
        if (!Set.of("off", "warn", "fail").contains(quantum)) {
            throw new IllegalArgumentException("quantum is off, warn or fail, not " + quantum);
        }
        warnOnly = Set.copyOf(list(rules.getOrDefault("warn-only", "")));
        for (String rule : warnOnly) {
            if (!RULES.contains(rule)) {
                throw new IllegalArgumentException("warn-only names no rule '" + rule + "'");
            }
        }
    }

    /** The defaults. */
    public static CryptoPolicy defaults() {
        return new CryptoPolicy(Map.of());
    }

    /** From rules by name, as listed above - the rest at their defaults. */
    public static CryptoPolicy of(Map<String, String> rules) {
        Map<String, String> trimmed = new LinkedHashMap<>();
        for (Map.Entry<String, String> rule : rules.entrySet()) {
            trimmed.put(rule.getKey().trim(), rule.getValue() == null ? "" : rule.getValue().trim());
        }
        return new CryptoPolicy(trimmed);
    }

    /** From a properties file of the same rules. A policy is no secret. */
    public static CryptoPolicy load(Path file) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(file)) {
            properties.load(in);
        }
        Map<String, String> rules = new LinkedHashMap<>();
        for (String name : properties.stringPropertyNames()) {
            rules.put(name, properties.getProperty(name));
        }
        return of(rules);
    }

    /** Every finding for {@code assets}, failures first. */
    public List<Finding> check(List<Asset> assets, Instant now) {
        List<Finding> findings = new ArrayList<>();
        for (Asset asset : assets) {
            switch (asset.kind()) {
                case SECRET -> secret(asset, findings);
                case DATA_KEY -> dataKey(asset, findings);
                case PRIVATE_KEY -> key(asset, findings);
                case CERTIFICATE -> certificate(asset, now, findings);
                case PROTOCOL -> tls(asset, findings);
                default -> {
                }
            }
            quantum(asset, findings);
        }
        List<Finding> ordered = new ArrayList<>();
        for (Finding finding : findings) {
            if (finding.severity() == Severity.FAIL) {
                ordered.add(finding);
            }
        }
        for (Finding finding : findings) {
            if (finding.severity() == Severity.WARN) {
                ordered.add(finding);
            }
        }
        return List.copyOf(ordered);
    }

    /** Whether any finding fails the policy. */
    public static boolean fails(List<Finding> findings) {
        for (Finding finding : findings) {
            if (finding.severity() == Severity.FAIL) {
                return true;
            }
        }
        return false;
    }

    private void secret(Asset asset, List<Finding> findings) {
        String provider = asset.facts().get("provider");
        if (provider != null && forbiddenSecretProviders.contains(provider)) {
            add(findings, "secret.forbidden-providers", asset,
                    "comes from provider=" + provider + ", which this policy does not allow");
        }
    }

    private void dataKey(Asset asset, List<Finding> findings) {
        String source = asset.source() == null ? "" : asset.source();
        if (forbiddenDataKeyProviders.contains(source)) {
            add(findings, "data-key.forbidden-providers", asset,
                    "comes from provider=" + source + ", which this policy does not allow");
        }
        if (dataKeyRequireKms && !kmsLike(source)) {
            add(findings, "data-key.require-kms", asset, "comes from provider=" + source
                    + " - this policy wants data keys only a KMS can open (kms-decrypt, "
                    + "vault-transit) or nobody holds alone (shamir)");
        }
        forbidden(asset, asset.algorithm(), findings);
    }

    private void key(Asset asset, List<Finding> findings) {
        sizes(asset, findings);
        forbidden(asset, asset.algorithm(), findings);
    }

    private void certificate(Asset asset, Instant now, List<Finding> findings) {
        sizes(asset, findings);
        forbidden(asset, asset.algorithm(), findings);
        String signature = asset.facts().getOrDefault("signatureAlgorithm", "");
        for (String token : forbiddenSignatures) {
            if (contains(signature, token)) {
                add(findings, "signature.forbidden", asset, "is signed with " + signature);
            }
        }
        forbidden(asset, signature, findings);
        if (asset.expires() != null) {
            Duration left = Duration.between(now, asset.expires());
            if (left.isNegative()) {
                add(findings, "certificate.min-days", asset, "expired on " + asset.expires());
            } else if (left.toDays() < certificateMinDays) {
                add(findings, "certificate.min-days", asset, "expires on " + asset.expires()
                        + ", in " + left.toDays() + " days - fewer than " + certificateMinDays);
            }
        }
    }

    private void tls(Asset asset, List<Finding> findings) {
        Map<String, String> facts = asset.facts();
        String version = facts.getOrDefault("version", "");
        String suite = facts.getOrDefault("cipherSuite", "");
        String group = facts.get("keyExchange");
        if (!version.isEmpty() && version.compareTo(tlsMinVersion) < 0) {
            add(findings, "tls.min-version", asset, "runs TLS " + version + ", below "
                    + tlsMinVersion);
        }
        if (forwardSecrecy && !version.startsWith("1.3") && !suite.isEmpty()) {
            // ECDHE and DHE alike: an ephemeral key exchange.
            if (!suite.toUpperCase(Locale.ROOT).contains("DHE")) {
                add(findings, "tls.forward-secrecy", asset, "uses " + suite
                        + ", which has no forward secrecy");
            }
        }
        if (requireHybrid && (group == null || !group.toUpperCase(Locale.ROOT).contains("MLKEM"))) {
            add(findings, "tls.require-hybrid", asset, "agreed its key with "
                    + (group == null ? "a classical exchange" : group)
                    + ", not a post-quantum hybrid (X25519MLKEM768)");
        }
        forbidden(asset, suite, findings);
        forbidden(asset, group, findings);
    }

    private void sizes(Asset asset, List<Finding> findings) {
        String algorithm = asset.algorithm() == null ? "" : asset.algorithm();
        if (algorithm.equals("RSA") && asset.bits() > 0 && asset.bits() < rsaMinBits) {
            add(findings, "rsa.min-bits", asset, "is RSA-" + asset.bits() + ", below "
                    + rsaMinBits + " bits");
        }
        if (algorithm.startsWith("EC P-")) {
            int bits = CryptoInventory.number(algorithm.substring(5));
            if (bits > 0 && bits < ecMinBits) {
                add(findings, "ec.min-bits", asset, "is " + algorithm + ", below " + ecMinBits
                        + " bits");
            }
        }
    }

    private void forbidden(Asset asset, String used, List<Finding> findings) {
        if (used == null) {
            return;
        }
        for (String token : forbiddenAlgorithms) {
            if (contains(used, token)) {
                add(findings, "algorithm.forbidden", asset, "uses " + used + ", which this "
                        + "policy forbids (" + token + ")");
            }
        }
    }

    private void quantum(Asset asset, List<Finding> findings) {
        if (quantum.equals("off")) {
            return;
        }
        String broken = QuantumReadiness.vulnerable(asset);
        if (broken != null) {
            Severity severity = quantum.equals("fail") && !warnOnly.contains("quantum")
                    ? Severity.FAIL : Severity.WARN;
            findings.add(new Finding(severity, "quantum", asset.ref(), asset.name(),
                    asset.name() + " relies on " + broken + ", which a quantum computer would break"));
        }
    }

    private void add(List<Finding> findings, String rule, Asset asset, String message) {
        Severity severity = warnOnly.contains(rule) ? Severity.WARN : Severity.FAIL;
        findings.add(new Finding(severity, rule, asset.ref(), asset.name(),
                asset.name() + " " + message));
    }

    static boolean kmsLike(String provider) {
        return provider.equals("kms-decrypt") || provider.equals("vault-transit")
                || provider.equals("shamir");
    }

    private static boolean contains(String text, String token) {
        String normalized = text.toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");
        String wanted = token.toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");
        return !wanted.isEmpty() && normalized.contains(wanted);
    }

    private static List<String> list(String text) {
        List<String> items = new ArrayList<>();
        for (String item : text.split(",")) {
            if (!item.isBlank()) {
                items.add(item.trim());
            }
        }
        return items;
    }

    private static int number(Map<String, String> rules, String key, int fallback) {
        String text = rules.get(key);
        if (text == null || text.isBlank()) {
            return fallback;
        }
        int value;
        try {
            value = Integer.parseInt(text.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(key + " is a number of 0 or more, not " + text, e);
        }
        if (value < 0) {
            throw new IllegalArgumentException(key + " is a number of 0 or more, not " + text);
        }
        return value;
    }

    private static boolean bool(Map<String, String> rules, String key, boolean fallback) {
        String text = rules.get(key);
        if (text == null || text.isBlank()) {
            return fallback;
        }
        return switch (text.trim().toLowerCase(Locale.ROOT)) {
            case "true", "yes", "on" -> true;
            case "false", "no", "off" -> false;
            default -> throw new IllegalArgumentException(key + " is true or false, not " + text);
        };
    }

    /** The findings as Markdown, for a job summary or a ticket. */
    public static String markdown(List<Finding> findings) {
        StringBuilder out = new StringBuilder("## Crypto policy\n\n");
        if (findings.isEmpty()) {
            return out.append("Every asset meets the policy.\n").toString();
        }
        long failed = findings.stream().filter(f -> f.severity() == Severity.FAIL).count();
        out.append(failed).append(" failing, ").append(findings.size() - failed)
                .append(" warnings.\n\n| | Rule | Asset | Finding |\n|---|---|---|---|\n");
        for (Finding finding : findings) {
            out.append("| ").append(finding.severity() == Severity.FAIL ? "FAIL" : "warn")
                    .append(" | `").append(finding.rule()).append("` | ")
                    .append(cell(finding.asset())).append(" | ").append(cell(finding.message()))
                    .append(" |\n");
        }
        return out.toString();
    }

    /** The findings as JSON: {@code {"fails": ..., "findings": [...]}}. */
    public static String json(List<Finding> findings) {
        StringBuilder out = new StringBuilder("{\"fails\": ").append(fails(findings))
                .append(", \"findings\": [");
        List<String> entries = new ArrayList<>();
        for (Finding finding : findings) {
            entries.add("{\"severity\": " + CycloneDxCbom.string(finding.severity().name().toLowerCase(
                    Locale.ROOT)) + ", \"rule\": " + CycloneDxCbom.string(finding.rule())
                    + ", \"ref\": " + CycloneDxCbom.string(nonNull(finding.ref()))
                    + ", \"asset\": " + CycloneDxCbom.string(nonNull(finding.asset()))
                    + ", \"message\": " + CycloneDxCbom.string(finding.message()) + "}");
        }
        return out.append(String.join(", ", entries)).append("]}\n").toString();
    }

    static String cell(String text) {
        return nonNull(text).replace("|", "\\|").replace("\n", " ");
    }

    private static String nonNull(String text) {
        return text == null ? "" : text;
    }
}
