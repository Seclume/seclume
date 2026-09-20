package space.seclume.springtest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * The smallest application that proves the point.
 *
 * <p>The goal of this project is that one adds the dependency, configures pool
 * and driver in {@code application.properties}, and the rest works. For almost
 * everybody "the rest" means Spring Data - and Spring Data is not an
 * integration task but a compatibility question: it sits on Hibernate, which
 * sits on JDBC. If the JDBC surface is right, it works.
 *
 * <p>"If it is right" must not be assumed, which is what this module is for.
 *
 * <p>Auditing is switched on here, because {@code @CreatedDate} and
 * {@code @LastModifiedDate} do nothing without it - and a test of an
 * annotation that silently does nothing would pass for the wrong reason.
 */
@SpringBootApplication
@EnableJpaAuditing
public class ShopApplication {

    public static void main(String[] args) {
        SpringApplication.run(ShopApplication.class, args);
    }
}
