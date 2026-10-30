package space.seclume.frameworks;

import java.lang.foreign.ValueLayout;
import java.nio.file.Path;

import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.FieldKeys;
import space.seclume.field.Sealed;
import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretScope;
import space.seclume.tck.Heap;

/**
 * The child of {@link JpaFieldEncryptionCase}'s heap test: Hibernate on the
 * given URL, the key from its file, patient 1 loaded - its name as the String
 * attribute it is, its token opened into native memory - and the heap dumped.
 *
 * <p>Arguments: the JDBC URL, the key file, the dump.
 */
public final class JpaSealedProbe {

    private JpaSealedProbe() {
    }

    public static void main(String[] args) throws Exception {
        try (FieldKeys keys = FieldKeys.builder()
                .key(1, new FileSecretProvider(Path.of(args[1]), 128)).build()) {
            FieldKeys.install(keys);
            EntityManagerFactory factory = JpaFieldEncryptionCase.factory(args[0], "none");
            EntityManager em = factory.createEntityManager();
            EncryptedPatient patient = em.find(EncryptedPatient.class, 1L);
            Sealed token = patient.apiToken();
            try (SecretScope value = SecretScope.allocate(token.plaintextLength())) {
                value.length(keys.column("zl_patient.api_token",
                        EncryptedColumn.Mode.RANDOMIZED).open(token, value.segment()));
                long sum = 0;
                for (int i = 0; i < value.length(); i++) {
                    sum += value.secret().get(ValueLayout.JAVA_BYTE, i) & 0xff;
                }
                System.out.println("opened " + value.length() + " bytes, sum=" + sum
                        + ", name of " + patient.name().length() + " characters");
            }
            Heap.collect();
            Heap.dump(Path.of(args[2]));
            // The entity - and with it the name - is alive past the dump on purpose.
            if (patient.name().isEmpty()) {
                throw new IllegalStateException("unreachable");
            }
            em.close();
            factory.close();
        }
    }
}
