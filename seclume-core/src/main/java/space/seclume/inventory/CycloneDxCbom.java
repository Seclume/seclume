package space.seclume.inventory;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import space.seclume.Version;
import space.seclume.inventory.CryptoInventory.Asset;
import space.seclume.inventory.CryptoInventory.Kind;

/**
 * The {@link CryptoInventory} as a CycloneDX 1.6 cryptography bill of
 * materials: each secret, key, certificate and TLS session a
 * {@code cryptographic-asset} component, and each algorithm they use one too,
 * with its classical and NIST quantum security level - 0 for RSA, elliptic
 * curves and their key exchange, which a quantum computer breaks; 1 to 5 for
 * AES, ML-KEM and the hybrid X25519MLKEM768.
 *
 * <p>Written without a library, as a {@code String}: the inventory holds no
 * secret, so neither does this. Checked against the official JSON schema in
 * CI.
 */
public final class CycloneDxCbom {

    /** Algorithms by name: primitive, mode, parameter set, classical level, quantum level, functions. */
    record Algorithm(String name, String primitive, String mode, String parameters,
            int classical, int quantum, List<String> functions) {
    }

    private CycloneDxCbom() {
    }

    /** The inventory now, as CBOM JSON. */
    public static String write(String application) {
        return write(application, CryptoInventory.snapshot(), Instant.now());
    }

    /** {@code assets} as CBOM JSON, stamped {@code now}. */
    public static String write(String application, List<Asset> assets, Instant now) {
        Map<String, Algorithm> algorithms = new LinkedHashMap<>();
        List<String> components = new ArrayList<>();
        List<String[]> dependencies = new ArrayList<>();
        for (Asset asset : assets) {
            switch (asset.kind()) {
                case SECRET -> components.add(secret(asset));
                case DATA_KEY -> {
                    Algorithm algorithm = algorithm(asset.algorithm(), asset.bits());
                    algorithms.putIfAbsent(algorithm.name, algorithm);
                    components.add(material(asset, "secret-key", ref(algorithm), asset.bits()));
                }
                case PRIVATE_KEY -> {
                    Algorithm algorithm = algorithm(asset.algorithm(), asset.bits());
                    algorithms.putIfAbsent(algorithm.name, algorithm);
                    components.add(material(asset, "private-key", ref(algorithm), asset.bits()));
                }
                case CERTIFICATE -> {
                    Algorithm signature = signature(asset.facts().get("signatureAlgorithm"));
                    Algorithm key = algorithm(asset.algorithm(), asset.bits());
                    algorithms.putIfAbsent(signature.name, signature);
                    algorithms.putIfAbsent(key.name, key);
                    components.add(certificate(asset, ref(signature), ref(key)));
                }
                case PROTOCOL -> {
                    List<Algorithm> used = suite(asset.facts().get("cipherSuite"),
                            asset.facts().get("keyExchange"));
                    for (Algorithm algorithm : used) {
                        algorithms.putIfAbsent(algorithm.name, algorithm);
                    }
                    components.add(protocol(asset, used));
                    String peer = asset.facts().get("peer");
                    for (Asset other : assets) {
                        if (other.kind() == Kind.CERTIFICATE && peer != null
                                && peer.equals(other.facts().get("peer"))) {
                            dependencies.add(new String[] {asset.ref(), other.ref()});
                        }
                    }
                }
                default -> throw new IllegalStateException(asset.kind().toString());
            }
        }
        StringBuilder json = new StringBuilder(4096);
        json.append("{\n  \"bomFormat\": \"CycloneDX\",\n  \"specVersion\": \"1.6\",\n")
                .append("  \"serialNumber\": \"urn:uuid:").append(UUID.randomUUID()).append("\",\n")
                .append("  \"version\": 1,\n  \"metadata\": {\n    \"timestamp\": ")
                .append(string(now.truncatedTo(ChronoUnit.SECONDS).toString())).append(",\n")
                .append("    \"tools\": {\"components\": [{\"type\": \"library\", \"name\": ")
                .append("\"seclume\", \"version\": ").append(string(Version.current()))
                .append("}]},\n    \"component\": {\"type\": \"application\", \"name\": ")
                .append(string(application == null || application.isBlank() ? "application"
                        : application)).append("},\n    \"properties\": [")
                .append(property("seclume:quantum-vulnerable",
                        Long.toString(quantumVulnerable(assets, algorithms))))
                .append(", ").append(property("seclume:assets", Integer.toString(assets.size())))
                .append("]\n  },\n  \"components\": [\n");
        List<String> all = new ArrayList<>();
        for (Algorithm algorithm : algorithms.values()) {
            all.add(algorithm(algorithm));
        }
        all.addAll(components);
        json.append(String.join(",\n", all)).append("\n  ]");
        if (!dependencies.isEmpty()) {
            json.append(",\n  \"dependencies\": [\n");
            List<String> entries = new ArrayList<>();
            for (String[] dependency : dependencies) {
                entries.add("    {\"ref\": " + string(dependency[0]) + ", \"dependsOn\": ["
                        + string(dependency[1]) + "]}");
            }
            json.append(String.join(",\n", entries)).append("\n  ]");
        }
        return json.append("\n}\n").toString();
    }

    /**
     * How many assets a quantum computer would break: keys, certificates and
     * TLS key exchanges at NIST level 0.
     */
    static long quantumVulnerable(List<Asset> assets, Map<String, Algorithm> algorithms) {
        long count = 0;
        for (Asset asset : assets) {
            String name = switch (asset.kind()) {
                case PRIVATE_KEY, CERTIFICATE, DATA_KEY -> algorithm(asset.algorithm(),
                        asset.bits()).name;
                case PROTOCOL -> keyExchange(asset.facts().get("cipherSuite"),
                        asset.facts().get("keyExchange")).name;
                default -> null;
            };
            if (name != null && algorithms.containsKey(name) && algorithms.get(name).quantum == 0) {
                count++;
            }
        }
        return count;
    }

    // ------------------------------------------------------------- algorithms

    /** By the name the inventory has for it. */
    static Algorithm algorithm(String name, int bits) {
        String n = name == null ? "unknown" : name;
        if (n.startsWith("AES-")) {
            int size = n.contains("256") ? 256 : n.contains("192") ? 192 : 128;
            String mode = n.contains("GCM-SIV") ? "other" : n.contains("GCM") ? "gcm" : "other";
            return new Algorithm(n, "ae", mode, Integer.toString(size), size,
                    size >= 256 ? 5 : size >= 192 ? 3 : 1, List.of("encrypt", "decrypt"));
        }
        if (n.equals("RSA")) {
            int size = bits > 0 ? bits : 2048;
            int classical = size >= 15360 ? 256 : size >= 7680 ? 192 : size >= 3072 ? 128 : 112;
            return new Algorithm("RSA-" + size, "signature", null, Integer.toString(size),
                    classical, 0, List.of("sign", "verify"));
        }
        if (n.startsWith("EC P-")) {
            String curve = n.substring(3);
            int size = CryptoInventory.number(curve.substring(2));
            return new Algorithm("ECDSA " + curve, "signature", null, curve,
                    size >= 521 ? 256 : size / 2, 0, List.of("sign", "verify"));
        }
        if (n.startsWith("Ed25519") || n.startsWith("Ed448")) {
            return new Algorithm(n, "signature", null, n, n.startsWith("Ed448") ? 224 : 128, 0,
                    List.of("sign", "verify"));
        }
        if (n.startsWith("ML-DSA")) {
            int level = n.endsWith("87") ? 5 : n.endsWith("65") ? 3 : 2;
            return new Algorithm(n, "signature", null, n, 128, level, List.of("sign", "verify"));
        }
        return new Algorithm(n, "unknown", null, null, 0, 0, List.of("unknown"));
    }

    /** A certificate's signature, by its JCA name: {@code SHA256withRSA}, {@code SHA384withECDSA}. */
    static Algorithm signature(String jca) {
        String name = jca == null ? "unknown" : jca;
        String upper = name.toUpperCase(Locale.ROOT);
        if (upper.contains("ML-DSA") || upper.contains("MLDSA")) {
            return algorithm(upper.contains("87") ? "ML-DSA-87" : upper.contains("65")
                    ? "ML-DSA-65" : "ML-DSA-44", 0);
        }
        int classical = upper.contains("SHA512") ? 256 : upper.contains("SHA384") ? 192 : 128;
        return new Algorithm(name, "signature", null, null, classical, 0,
                List.of("sign", "verify"));
    }

    /** A TLS session's cipher, hash and key exchange. */
    static List<Algorithm> suite(String suite, String group) {
        List<Algorithm> used = new ArrayList<>();
        String s = suite == null ? "" : suite.toUpperCase(Locale.ROOT);
        if (s.contains("AES_256_GCM")) {
            used.add(algorithm("AES-256-GCM", 256));
        } else if (s.contains("AES_128_GCM")) {
            used.add(algorithm("AES-128-GCM", 128));
        } else if (s.contains("CHACHA20_POLY1305")) {
            used.add(new Algorithm("ChaCha20-Poly1305", "ae", "other", "256", 256, 5,
                    List.of("encrypt", "decrypt")));
        }
        if (s.endsWith("SHA384")) {
            used.add(new Algorithm("SHA-384", "hash", null, "384", 192, 3, List.of("digest")));
        } else if (s.endsWith("SHA256")) {
            used.add(new Algorithm("SHA-256", "hash", null, "256", 128, 2, List.of("digest")));
        }
        used.add(keyExchange(suite, group));
        return used;
    }

    /** The key exchange: the group the handshake named, or what a TLS 1.2 suite says. */
    static Algorithm keyExchange(String suite, String group) {
        String g = group == null ? "" : group;
        if (g.contains("MLKEM")) {
            return new Algorithm(g, "kem", null, g, 128, 3, List.of("encapsulate",
                    "decapsulate"));
        }
        if (!g.isEmpty()) {
            String name = g.equalsIgnoreCase("X25519") ? "X25519" : "ECDH " + g;
            return new Algorithm(name, "key-agree", null, g, g.contains("384") ? 192
                    : g.contains("521") ? 256 : 128, 0, List.of("keygen"));
        }
        String s = suite == null ? "" : suite.toUpperCase(Locale.ROOT);
        if (s.contains("ECDHE")) {
            return new Algorithm("ECDHE", "key-agree", null, null, 128, 0, List.of("keygen"));
        }
        return new Algorithm("TLS key exchange (not reported)", "unknown", null, null, 0, 0,
                List.of("unknown"));
    }

    // ------------------------------------------------------------- components

    private static String ref(Algorithm algorithm) {
        return "algorithm:" + algorithm.name;
    }

    private static String algorithm(Algorithm algorithm) {
        StringBuilder properties = new StringBuilder("\"primitive\": ")
                .append(string(algorithm.primitive));
        if (algorithm.parameters != null) {
            properties.append(", \"parameterSetIdentifier\": ").append(string(algorithm.parameters));
        }
        if (algorithm.mode != null) {
            properties.append(", \"mode\": ").append(string(algorithm.mode));
        }
        properties.append(", \"executionEnvironment\": \"software-plain-ram\"")
                .append(", \"cryptoFunctions\": [");
        List<String> functions = new ArrayList<>();
        for (String function : algorithm.functions) {
            functions.add(string(function));
        }
        properties.append(String.join(", ", functions)).append("]")
                .append(", \"classicalSecurityLevel\": ").append(algorithm.classical)
                .append(", \"nistQuantumSecurityLevel\": ").append(algorithm.quantum);
        return "    {\"type\": \"cryptographic-asset\", \"bom-ref\": " + string(ref(algorithm))
                + ", \"name\": " + string(algorithm.name)
                + ", \"cryptoProperties\": {\"assetType\": \"algorithm\", "
                + "\"algorithmProperties\": {" + properties + "}}}";
    }

    private static String secret(Asset asset) {
        String type = tokenLike(asset.facts().get("provider")) ? "token" : "credential";
        StringBuilder material = new StringBuilder("\"type\": ").append(string(type))
                .append(", \"state\": \"active\"")
                .append(", \"activationDate\": ").append(string(asset.firstSeen().toString()))
                .append(", \"updateDate\": ").append(string(asset.lastUsed().toString()));
        if (asset.expires() != null) {
            material.append(", \"expirationDate\": ").append(string(asset.expires().toString()));
        }
        material.append(", \"securedBy\": {\"mechanism\": \"Software\"}");
        return component(asset, "related-crypto-material",
                "\"relatedCryptoMaterialProperties\": {" + material + "}");
    }

    private static String material(Asset asset, String type, String algorithmRef, int bits) {
        StringBuilder material = new StringBuilder("\"type\": ").append(string(type))
                .append(", \"id\": ").append(string(asset.ref()))
                .append(", \"state\": \"active\"")
                .append(", \"algorithmRef\": ").append(string(algorithmRef))
                .append(", \"activationDate\": ").append(string(asset.firstSeen().toString()));
        if (bits > 0) {
            material.append(", \"size\": ").append(bits);
        }
        String held = asset.source() == null ? "Software" : asset.source();
        material.append(", \"securedBy\": {\"mechanism\": ").append(string(mechanism(held)))
                .append("}");
        return component(asset, "related-crypto-material",
                "\"relatedCryptoMaterialProperties\": {" + material + "}");
    }

    private static String certificate(Asset asset, String signatureRef, String keyRef) {
        Map<String, String> facts = asset.facts();
        String properties = "\"subjectName\": " + string(facts.get("subject"))
                + ", \"issuerName\": " + string(facts.get("issuer"))
                + ", \"notValidBefore\": " + string(facts.get("notBefore"))
                + ", \"notValidAfter\": " + string(asset.expires() == null ? ""
                        : asset.expires().toString())
                + ", \"signatureAlgorithmRef\": " + string(signatureRef)
                + ", \"subjectPublicKeyRef\": " + string(keyRef)
                + ", \"certificateFormat\": \"X.509\"";
        return component(asset, "certificate", "\"certificateProperties\": {" + properties + "}");
    }

    private static String protocol(Asset asset, List<Algorithm> used) {
        List<String> refs = new ArrayList<>();
        for (Algorithm algorithm : used) {
            refs.add(string(ref(algorithm)));
        }
        String suiteName = asset.facts().get("cipherSuite");
        String properties = "\"type\": \"tls\", \"version\": "
                + string(asset.facts().get("version"))
                + ", \"cipherSuites\": [{\"name\": " + string(suiteName == null ? "" : suiteName)
                + ", \"algorithms\": [" + String.join(", ", refs) + "]}]";
        return component(asset, "protocol", "\"protocolProperties\": {" + properties + "}");
    }

    private static String component(Asset asset, String assetType, String properties) {
        List<String> props = new ArrayList<>();
        props.add(property("seclume:kind", asset.kind().name().toLowerCase(Locale.ROOT)));
        // What the inventory itself had, so that CbomReader gets the asset back whole.
        if (asset.algorithm() != null) {
            props.add(property("seclume:algorithm", asset.algorithm()));
        }
        if (asset.bits() > 0) {
            props.add(property("seclume:bits", Integer.toString(asset.bits())));
        }
        if (asset.expires() != null) {
            props.add(property("seclume:expires", asset.expires().toString()));
        }
        if (asset.source() != null) {
            props.add(property("seclume:source", asset.source()));
        }
        props.add(property("seclume:first-seen", asset.firstSeen().toString()));
        props.add(property("seclume:last-used", asset.lastUsed().toString()));
        props.add(property("seclume:uses", Long.toString(asset.uses())));
        for (Map.Entry<String, String> fact : asset.facts().entrySet()) {
            props.add(property("seclume:" + fact.getKey(), fact.getValue()));
        }
        return "    {\"type\": \"cryptographic-asset\", \"bom-ref\": " + string(asset.ref())
                + ", \"name\": " + string(asset.name())
                + ", \"cryptoProperties\": {\"assetType\": " + string(assetType) + ", "
                + properties + "}, \"properties\": [" + String.join(", ", props) + "]}";
    }

    private static boolean tokenLike(String provider) {
        return provider != null && (provider.contains("identity") || provider.contains("metadata")
                || provider.contains("rds-iam") || provider.contains("spiffe")
                || provider.contains("jwt"));
    }

    /** Where a key is held: in a key management service, or in this process's memory. */
    private static String mechanism(String held) {
        String h = held.toLowerCase(Locale.ROOT);
        if (h.contains("kms") || h.contains("key vault") || h.contains("transit")) {
            return "KMS";
        }
        return "Software";
    }

    private static String property(String name, String value) {
        return "{\"name\": " + string(name) + ", \"value\": " + string(value == null ? "" : value)
                + "}";
    }

    /** A JSON string: quotes, backslashes and control characters escaped. */
    static String string(String value) {
        StringBuilder out = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }
}
