package example;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Connects, asks the database who it is, and keeps running - a service with
 * an open pool, which is when somebody takes a heap dump.
 */
@SpringBootApplication
public class GettingStarted {

    public static void main(String[] arguments) {
        SpringApplication.run(GettingStarted.class, arguments);
    }

    @Bean
    CommandLineRunner hello(JdbcTemplate jdbc) {
        return arguments -> {
            String who = jdbc.queryForObject("select current_user || ' on ' || version()",
                    String.class);
            System.out.println("connected as " + who);
            System.out.println("running as pid " + ProcessHandle.current().pid());
        };
    }
}
