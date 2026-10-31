package space.seclume.secret;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;

/**
 * A secret that nobody holds alone: {@code k} of {@code n} shares, each from a
 * provider of its own, combined into the target - {@code provider=shamir}.
 *
 * <p>The case: a master key - the one that opens the field encryption ring, or
 * the database's - may not rest with a single administrator, and there is no
 * cloud KMS to hold it instead. It is split with {@link ShamirShares#split}
 * into, say, five shares of which any three are needed; each holder keeps one
 * where only they can reach it - a file on their own mount, their keychain,
 * their Vault path - and the application starts when three of them have
 * provided theirs.
 *
 * <pre>
 *   provider=shamir
 *   threshold=3                     # optional; refuses shares that need fewer
 *   share.1.provider=file
 *   share.1.path=/run/secrets/share-alice
 *   share.2.provider=vault
 *   share.2.address=https://vault:8200
 *   ...
 *   share.5.provider=keychain
 * </pre>
 *
 * <p>Shares are read in order until as many as their threshold are at hand; a
 * share that cannot be read is passed over - that a holder is away is the
 * point - and the failure names which shares were missing and why, never what
 * they contained. Shares that are there but disagree - another split, the same
 * number twice, a wrong digit - are refused outright rather than passed over:
 * that is a mistake in the configuration, and starting on the remaining shares
 * would hide it.
 *
 * <p>{@code threshold}, when given, is a floor: shares that were made with a
 * smaller one are refused, so that swapping in a weaker split is noticed.
 */
public final class ShamirSecretProvider implements SecretProvider {

    private final List<SecretProvider> shares;
    private final int threshold;

    /**
     * @param shares    the shares' providers, in the order they are tried
     * @param threshold the fewest shares a split may need, 0 for whatever the shares say
     */
    public ShamirSecretProvider(List<SecretProvider> shares, int threshold) {
        if (shares.size() < 2) {
            throw new IllegalArgumentException("provider=shamir needs at least two shares "
                    + "(share.1.*, share.2.*, ...), not " + shares.size());
        }
        if (threshold != 0 && (threshold < 2 || threshold > shares.size())) {
            throw new IllegalArgumentException("threshold=" + threshold + " needs 2 to "
                    + shares.size() + " (the shares configured)");
        }
        this.shares = List.copyOf(shares);
        this.threshold = threshold;
    }

    @Override
    public int maxSecretLength() {
        return ShamirShares.MAX_SECRET;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        List<String> missing = new ArrayList<>();
        try (Arena arena = Arena.ofConfined()) {
            List<ShamirShares.Share> found = new ArrayList<>();
            List<MemorySegment> buffers = new ArrayList<>();
            try {
                for (int i = 0; i < shares.size(); i++) {
                    if (!found.isEmpty() && found.size() == found.get(0).threshold()) {
                        break;
                    }
                    MemorySegment y = arena.allocate(ShamirShares.MAX_SECRET + ShamirShares.CHECK);
                    buffers.add(y);
                    ShamirShares.Share share;
                    try (SecretScope text = SecretScope.fromProvider(shares.get(i))) {
                        share = ShamirShares.parse(text.segment(), text.length(), y);
                    } catch (SecretUnavailableException e) {
                        if (e.getMessage() != null && e.getMessage().startsWith(
                                "a Shamir share is refused")) {
                            throw new SecretUnavailableException("share." + (i + 1) + ": "
                                    + e.getMessage());
                        }
                        missing.add("share." + (i + 1) + " (" + e.getMessage() + ")");
                        continue;
                    }
                    if (threshold != 0 && share.threshold() < threshold) {
                        throw new SecretUnavailableException("share." + (i + 1)
                                + " is of a split that needs " + share.threshold()
                                + " shares, fewer than threshold=" + threshold);
                    }
                    found.add(share);
                }
                int needed = found.isEmpty() ? Math.max(threshold, 2) : found.get(0).threshold();
                if (found.size() < needed) {
                    throw new SecretUnavailableException(needed + " Shamir shares are needed and "
                            + found.size() + " could be read; missing: "
                            + String.join(", ", missing));
                }
                return ShamirShares.combine(found, target);
            } finally {
                for (MemorySegment y : buffers) {
                    y.fill((byte) 0);
                }
            }
        }
    }

    @Override
    public void close() {
        for (SecretProvider share : shares) {
            share.close();
        }
    }

    @Override
    public String toString() {
        return "ShamirSecretProvider[" + shares.size() + " shares"
                + (threshold == 0 ? "" : ", threshold " + threshold) + "]";
    }
}
