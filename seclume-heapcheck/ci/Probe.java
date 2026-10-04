import java.nio.file.Files;
import java.nio.file.Path;

/** Throwaway CI target. The credential is supplied in a file, never in argv. */
class Probe {
    private static volatile String held;

    public static void main(String[] args) throws Exception {
        if (args[0].equals("leak")) held = Files.readString(Path.of(args[1]));
        System.out.println("ready");
        Thread.sleep(120_000);
    }
}
