package example;

import java.util.concurrent.CountDownLatch;

/**
 * Helidon MP's own main, and then stays: with no web server in this example
 * there is nothing else to keep the process alive for a heap dump.
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] arguments) throws InterruptedException {
        io.helidon.microprofile.cdi.Main.main(arguments);
        new CountDownLatch(1).await();
    }
}
