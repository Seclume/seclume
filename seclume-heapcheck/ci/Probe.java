import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Throwaway CI target. The credential is supplied in a file, never in argv.
 * "leak" holds it as a String; "token" holds a Vault-shaped token made from
 * it, for --discover to find without being told.
 */
class Probe {
    private static volatile String held;

    public static void main(String[] args) throws Exception {
        if (args[0].equals("leak")) held = Files.readString(Path.of(args[1]));
        if (args[0].equals("token")) held = "hvs." + Files.readString(Path.of(args[1])).strip();
        System.out.println("ready");
        Thread.sleep(120_000);
    }
}
