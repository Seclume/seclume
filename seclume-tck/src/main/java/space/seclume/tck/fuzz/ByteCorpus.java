package space.seclume.tck.fuzz;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.random.RandomGenerator;

/**
 * Hostile bytes, generated the same way every time.
 *
 * <p>A corpus rather than a random stream, for the reason every fuzzing
 * write-up gives and this project has already learnt twice from its own
 * differential run: <b>starting from valid input finds more than starting from
 * noise</b>. Random bytes are rejected by the first length check and never
 * reach the state machine behind it. Valid bytes with one field spoiled reach
 * the place where somebody wrote {@code new byte[announced]}.
 *
 * <p>So a caller hands in seeds that its protocol would accept, and this class
 * damages them in the ways a wire is actually damaged - and a few ways it is
 * not, because an attacker is not a network.
 *
 * <p><b>Deterministic on purpose.</b> Every case is a pure function of the
 * seeds and an integer, so a failure is reproducible from what the test
 * printed, with no corpus file to keep and no "it was green yesterday". The
 * generator is test code and adds no runtime dependency, which is the property
 * the whole library exists to keep.
 */
public final class ByteCorpus {

    /**
     * Above this, offsets are sampled instead of exhausted.
     *
     * <p>Every case here is at least one copy of the seed, and three of the
     * generators produce one case <b>per byte</b>. That is fine for a seed of
     * a few dozen bytes and quadratic nonsense for a large one: the first run
     * of this class died of a heap exhausted by a 16 MB MySQL packet, which is
     * 16 million copies of up to 16 MB.
     *
     * <p>A limit rather than a rule about seeds, because the caller should be
     * able to hand in whatever its protocol has without doing arithmetic
     * first - and because the interesting bytes of a long packet are at its
     * ends and its boundaries, not evenly spread through its body.
     */
    private static final int EXHAUSTIVE_UP_TO = 2048;

    private final Map<String, byte[]> cases = new LinkedHashMap<>();

    private ByteCorpus() {
    }

    /**
     * Every case this corpus holds, named.
     *
     * <p>The name is what a failing test prints, so it says what was done to
     * the bytes rather than which index it was.
     */
    public Map<String, byte[]> cases() {
        return cases;
    }

    /**
     * Whether the whole corpus should run, or a sample of it.
     *
     * <p><b>A corpus that runs on every {@code mvn test} is a corpus somebody
     * deletes.</b> The full sweeps take tens of thousands of cases and minutes
     * of wall clock, which is right for a nightly job and wrong for the run a
     * developer waits on - and a suite people wait on is a suite people learn
     * to skip.
     *
     * <p>So the ordinary run takes a sample and the property turns the rest
     * on: {@code -Dseclume.fuzz.full=true}, which the {@code fuzz} profile
     * sets. The sample is not random - see {@link #sample} - so an ordinary
     * run is as repeatable as a full one.
     */
    public static boolean everything() {
        return Boolean.getBoolean("seclume.fuzz.full");
    }

    /**
     * The cases to run now: all of them, or a spread of them.
     *
     * <p>Used by the runners so that a test class says nothing about which
     * mode it is in.
     */
    public Map<String, byte[]> selected() {
        return everything() ? cases : sample(SMOKE);
    }

    /** How many cases an ordinary run takes from each corpus. */
    private static final int SMOKE = 220;

    /**
     * A spread across the corpus, and the interesting cases always.
     *
     * <p>Deterministic on purpose, and biased on purpose. The seeds
     * themselves and the shapes that need no seed - empty, one byte, all
     * ones - are the cheapest and the likeliest to break something, so they
     * are never sampled away. The rest is taken at a fixed stride, which
     * keeps a sample that is the same on every machine and every day: a
     * smoke test that varies is a smoke test whose failure nobody can
     * reproduce.
     */
    public Map<String, byte[]> sample(int most) {
        if (cases.size() <= most) {
            return cases;
        }
        Map<String, byte[]> taken = new LinkedHashMap<>();
        cases.forEach((name, bytes) -> {
            if (!name.contains(" truncated at ") && !name.contains(" byte ")
                    && !name.contains(" length at ")) {
                taken.put(name, bytes);          // seeds, splices, repeats, degenerate
            }
        });
        int stride = Math.max(1, cases.size() / Math.max(1, most - taken.size()));
        int at = 0;
        for (Map.Entry<String, byte[]> entry : cases.entrySet()) {
            if (at++ % stride == 0) {
                taken.putIfAbsent(entry.getKey(), entry.getValue());
            }
        }
        return taken;
    }

    /**
     * Builds the corpus from seeds a protocol would accept.
     *
     * @param seeds named valid byte streams - an answer, a short answer, an
     *              answer carrying rows, whatever the protocol has
     */
    public static ByteCorpus from(Map<String, byte[]> seeds) {
        ByteCorpus corpus = new ByteCorpus();
        seeds.forEach((name, seed) -> {
            corpus.add(name, seed);
            corpus.truncations(name, seed);
            corpus.spoiltLengths(name, seed);
            corpus.flips(name, seed);
            corpus.splices(name, seeds);
            corpus.repeats(name, seed);
        });
        corpus.degenerate();
        corpus.rubbish(seeds.values());
        return corpus;
    }

    private void add(String name, byte[] bytes) {
        cases.put(name, bytes);
    }

    /**
     * Cut at <b>every</b> byte, not at a few.
     *
     * <p>The interface promises a message may be split anywhere, and the state
     * a walker keeps for a half-seen header is where that promise is kept or
     * broken. There is no reason to sample: the seeds are short and the whole
     * set is cheap.
     */
    private void truncations(String name, byte[] seed) {
        for (int at : offsets(seed.length + 1)) {
            add(name + " truncated at " + at, java.util.Arrays.copyOf(seed, at));
        }
    }

    /**
     * Every offset for a short seed; the ends and a stride through the middle
     * for a long one.
     *
     * <p>The first thirty-two and the last thirty-two are always included,
     * because a header and a terminator are where a walker's state lives and a
     * stride would step over them.
     */
    private static int[] offsets(int count) {
        if (count <= EXHAUSTIVE_UP_TO) {
            int[] all = new int[count];
            for (int i = 0; i < count; i++) {
                all[i] = i;
            }
            return all;
        }
        java.util.TreeSet<Integer> picked = new java.util.TreeSet<>();
        for (int i = 0; i < 32 && i < count; i++) {
            picked.add(i);
            picked.add(count - 1 - i);
        }
        int stride = Math.max(1, count / 256);
        for (int at = 0; at < count; at += stride) {
            picked.add(at);
        }
        int[] out = new int[picked.size()];
        int i = 0;
        for (int at : picked) {
            out[i++] = at;
        }
        return out;
    }

    /**
     * Every length-shaped field set to a value that cannot be right.
     *
     * <p>Which bytes are a length is not known here, and that is the point: a
     * walker that is only tested where the author knew the length was is tested
     * by the author's own belief. So every 2-, 3- and 4-byte window is spoilt in
     * turn, and most of those do nothing, and the few that do are the interesting
     * ones.
     */
    private void spoiltLengths(String name, byte[] seed) {
        int[][] patterns = {
            {0x00, 0x00, 0x00, 0x00},
            {0xff, 0xff, 0xff, 0xff},
            {0x7f, 0xff, 0xff, 0xff},
            {0x80, 0x00, 0x00, 0x00},
            {0x00, 0x00, 0x00, 0x01},
        };
        for (int width = 2; width <= 4; width++) {
            for (int at : offsets(Math.max(0, seed.length - width + 1))) {
                for (int[] pattern : patterns) {
                    byte[] spoilt = seed.clone();
                    for (int i = 0; i < width; i++) {
                        spoilt[at + i] = (byte) pattern[i];
                    }
                    add(name + " length at " + at + " width " + width
                            + " set to " + hexOf(pattern, width), spoilt);
                }
            }
        }
    }

    /**
     * One byte turned into something else, everywhere, with the values that
     * mean something to a wire protocol.
     *
     * <p>The first version used {@code 00 ff 80 5a} - two extremes, a sign bit
     * and an arbitrary byte - and found nothing in MySQL, which was not
     * reassuring but flattering. The bytes that matter there are the markers
     * that introduce a length: {@code fb fc fd fe}. A byte saying "a
     * three-byte length follows" in a packet that holds one byte is the shape
     * that walks a reader off the end of its own buffer, and no amount of
     * {@code 0x5a} will ever produce it.
     *
     * <p>So the set is protocol-informed rather than neutral. That is a bias,
     * and the right one: a fuzzer that cannot express the input which breaks
     * the parser is a fuzzer that reports the parser is fine.
     */
    private void flips(String name, byte[] seed) {
        for (int at : offsets(seed.length)) {
            for (int value : new int[] {
                0x00, 0x01, 0x5a, 0x80, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
            }) {
                byte[] flipped = seed.clone();
                flipped[at] = (byte) value;
                add(name + " byte " + at + " = " + Integer.toHexString(value), flipped);
            }
        }
    }

    /**
     * Two answers run together, and one answer restarted in the middle of
     * another.
     *
     * <p>A relay's whole job is to find where one stops, so the case where two
     * arrive in one block is not an edge but the ordinary one - and the case
     * where the second begins before the first has finished is what a confused
     * or malicious server sends.
     */
    private void splices(String name, Map<String, byte[]> seeds) {
        byte[] seed = seeds.get(name);
        seeds.forEach((other, tail) -> {
            byte[] both = new byte[seed.length + tail.length];
            System.arraycopy(seed, 0, both, 0, seed.length);
            System.arraycopy(tail, 0, both, seed.length, tail.length);
            add(name + " then " + other, both);

            if (seed.length > 3) {
                int cut = seed.length / 2;
                byte[] interrupted = new byte[cut + tail.length];
                System.arraycopy(seed, 0, interrupted, 0, cut);
                System.arraycopy(tail, 0, interrupted, cut, tail.length);
                add(name + " cut short, then " + other, interrupted);
            }
        });
    }

    /** The same answer many times over, for a state that leaks between them. */
    private void repeats(String name, byte[] seed) {
        for (int times : new int[] {2, 3, 8}) {
            byte[] many = new byte[seed.length * times];
            for (int i = 0; i < times; i++) {
                System.arraycopy(seed, 0, many, i * seed.length, seed.length);
            }
            add(name + " repeated " + times + " times", many);
        }
    }

    /** The shapes that need no seed, and that a walker meets first. */
    private void degenerate() {
        add("empty", new byte[0]);
        add("one zero byte", new byte[] {0});
        add("one 0xff byte", new byte[] {(byte) 0xff});
        for (int size : new int[] {4, 5, 8, 9, 64, 4096}) {
            add("zeroes x" + size, new byte[size]);
            byte[] ones = new byte[size];
            java.util.Arrays.fill(ones, (byte) 0xff);
            add("0xff x" + size, ones);
        }
    }

    /**
     * Noise, and noise wearing a seed's clothes.
     *
     * <p>The low-yield half of a corpus and worth having anyway: it costs
     * nothing and it is the only part that can reach a state nobody thought
     * about, including the author of the seeds. The stream of a fixed
     * generator, so a hit is reproducible by its name.
     */
    private void rubbish(Iterable<byte[]> seeds) {
        RandomGenerator noise = java.util.random.RandomGeneratorFactory
                .of("L64X128MixRandom").create(20260923L);
        for (int round = 0; round < 64; round++) {
            byte[] block = new byte[1 + noise.nextInt(512)];
            noise.nextBytes(block);
            add("noise " + round, block);
        }
        List<byte[]> all = new ArrayList<>();
        seeds.forEach(all::add);
        for (int round = 0; round < 64 && !all.isEmpty(); round++) {
            byte[] seed = all.get(noise.nextInt(all.size())).clone();
            int howMany = 1 + noise.nextInt(Math.max(1, seed.length / 4));
            for (int i = 0; i < howMany && seed.length > 0; i++) {
                seed[noise.nextInt(seed.length)] = (byte) noise.nextInt(256);
            }
            add("seed with " + howMany + " bytes stirred, round " + round, seed);
        }
        // UTF-8 that is not: lone surrogates, overlong forms, a truncated
        // multi-byte character. Where a protocol carries a name, this is what
        // arrives when somebody wants a decoder to misbehave.
        add("broken utf-8", new byte[] {
            (byte) 0xc0, (byte) 0x80,                       // overlong NUL
            (byte) 0xed, (byte) 0xa0, (byte) 0x80,          // a lone surrogate
            (byte) 0xf4, (byte) 0x90, (byte) 0x80, (byte) 0x80,  // beyond U+10FFFF
            (byte) 0xe2, (byte) 0x82,                       // cut off mid-character
        });
    }

    private static String hexOf(int[] pattern, int width) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < width; i++) {
            out.append(String.format("%02x", pattern[i]));
        }
        return out.toString();
    }
}
