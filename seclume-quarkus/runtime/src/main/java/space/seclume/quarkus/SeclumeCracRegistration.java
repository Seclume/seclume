package space.seclume.quarkus;

import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;

import io.quarkus.runtime.StartupEvent;

/**
 * With seclume-crac on the class path, its process part - cached credentials
 * and keys wiped before a checkpoint, new secrets held back until the restore -
 * is registered at start. Nothing else loads SeclumeCrac in a Quarkus
 * application, whose pool is Agroal: without this its checkpoint image kept
 * what the process held. Without seclume-crac this does nothing.
 */
@Singleton
public class SeclumeCracRegistration {

    static final String CRAC = "space.seclume.crac.SeclumeCrac";

    void onStart(@Observes StartupEvent start) {
        java.util.Objects.requireNonNull(start, "the start-up event");
        register(Thread.currentThread().getContextClassLoader());
    }

    /** Whether seclume-crac was there and its process part is registered now. */
    public static boolean register(ClassLoader loader) {
        try {
            // Loading the class is the registration - see SeclumeCrac.registerProcess.
            Class.forName(CRAC, true, loader);
            return true;
        } catch (ClassNotFoundException absent) {
            return false;
        }
    }
}
