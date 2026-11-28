package space.seclume.spring;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;

import space.seclume.pool.SeclumePool;

/**
 * Checkpoint and restore without a line of the application's own: with
 * {@code seclume-crac} on the class path, the process's part - cached
 * credentials and keys wiped, new secrets held back until the restore - is
 * registered at start, and so is every seclume pool in the context. Without
 * it, an application with no DataSource had nothing that loaded SeclumeCrac,
 * and its image kept what the process held; one with a pool had its checkpoint
 * refused over the pool's open sockets until it registered the pool itself.
 * Registering a pool twice is nothing, so one registered by hand stays as it is.
 */
@AutoConfiguration(after = SeclumeAutoConfiguration.class)
@ConditionalOnClass(name = "space.seclume.crac.SeclumeCrac")
public class SeclumeCracAutoConfiguration {

    /** Every bean is made: the process's part, and each pool. */
    @Bean
    static SmartInitializingSingleton seclumeCracRegistration(ObjectProvider<SeclumePool> pools) {
        return () -> {
            space.seclume.crac.SeclumeCrac.registerProcess();
            pools.orderedStream().forEach(space.seclume.crac.SeclumeCrac::register);
        };
    }
}
