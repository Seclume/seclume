package space.seclume.spring;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import space.seclume.heapdump.OffHeapSecrets;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * The application's own secrets, for a redaction of its heap to look for -
 * without a copy of any of them on that heap.
 *
 * <p>Two kinds: the password of every {@code seclume.datasources.<name>}, from
 * the provider its pool uses, and whatever {@code seclume.heapdump.secrets.
 * <label>.*} names - an API key the application reads itself, a token a
 * library keeps - as a secret provider's settings, the way a data source's
 * {@code secret.*} are written.
 *
 * <p>For each redaction every provider writes its secret into locked native
 * memory ({@link SecretScope}); the patterns - UTF-16 both ways, Base64 - are
 * built there too, and all of it is zeroed when the redaction is over. A
 * secret that never left native memory is not in the dump; what is found is
 * a copy that did leave, in a log line or a configuration object.
 */
public final class RedactionSecrets implements OffHeapSecrets, AutoCloseable {

    private static final System.Logger LOG = System.getLogger(RedactionSecrets.class.getName());

    /** The data sources' providers, for as long as their pools hold them. */
    private static final Map<SecretProvider, String> DATA_SOURCES =
            Collections.synchronizedMap(new WeakHashMap<>());

    private final Map<String, SecretProvider> configured;

    /** @param configured {@code seclume.heapdump.secrets.*}: label to provider, which this closes */
    public RedactionSecrets(Map<String, SecretProvider> configured) {
        this.configured = new LinkedHashMap<>(configured);
    }

    /** A data source's provider, to be looked for under {@code label}. */
    static void register(String label, SecretProvider provider) {
        DATA_SOURCES.put(provider, label);
    }

    /**
     * Every provider, by label - the data sources' and the configured ones -
     * for a masker that reads them itself. Nothing is read here.
     */
    public Map<String, SecretProvider> providers() {
        Map<String, SecretProvider> providers = new LinkedHashMap<>();
        synchronized (DATA_SOURCES) {
            DATA_SOURCES.forEach((provider, label) -> providers.put(label, provider));
        }
        providers.putAll(configured);
        return providers;
    }

    /** What is looked for, by label - names only. */
    public List<String> labels() {
        List<String> labels = new ArrayList<>();
        synchronized (DATA_SOURCES) {
            labels.addAll(DATA_SOURCES.values());
        }
        labels.addAll(configured.keySet());
        return labels;
    }

    @Override
    public Opened open() {
        Map<String, SecretProvider> providers = new LinkedHashMap<>();
        synchronized (DATA_SOURCES) {
            DATA_SOURCES.forEach((provider, label) -> providers.put(label, provider));
        }
        providers.putAll(configured);
        List<SecretScope> scopes = new ArrayList<>();
        SegmentAllocator locked = (size, alignment) -> {
            SecretScope scope = SecretScope.allocate(Math.toIntExact(size));
            scopes.add(scope);
            return scope.segment().asSlice(0, size);
        };
        List<Needle> needles = new ArrayList<>();
        try {
            for (Map.Entry<String, SecretProvider> entry : providers.entrySet()) {
                SecretScope secret;
                try {
                    secret = SecretScope.fromProvider(entry.getValue());
                } catch (RuntimeException unavailable) {
                    LOG.log(System.Logger.Level.WARNING, "seclume: the secret "
                            + entry.getKey() + " could not be read, so a heap dump is not "
                            + "searched for it: " + unavailable.getMessage());
                    continue;
                }
                scopes.add(secret);
                if (secret.length() == 0) {
                    continue;                     // provider=none: a certificate is the login
                }
                MemorySegment value = secret.secret();
                needles.add(OffHeapSecrets.text(entry.getKey(), value, locked));
            }
        } catch (RuntimeException e) {
            scopes.forEach(SecretScope::close);
            throw e;
        }
        return new Opened() {
            @Override
            public List<Needle> needles() {
                return needles;
            }

            @Override
            public void close() {
                for (SecretScope scope : scopes) {
                    scope.close();
                }
            }
        };
    }

    @Override
    public void close() {
        configured.values().forEach(SecretProvider::close);
    }
}
