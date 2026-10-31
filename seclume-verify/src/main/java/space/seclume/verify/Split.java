package space.seclume.verify;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.List;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretUnavailableException;
import space.seclume.secret.ShamirShares;

/**
 * {@code --split <secret uri> <k> <n> <directory>}: a secret into {@code n}
 * Shamir shares, any {@code k} of which give it back - for
 * {@code provider=shamir}.
 *
 * <p>The secret is read through a provider like everything else, so it never
 * passes through the command line; the shares are written into
 * {@code directory}, one owner-only file each. What is printed is where they
 * went and what to do next - never a share.
 */
final class Split {

    private Split() {
    }

    static int run(List<String> arguments, PrintStream out, PrintStream err) {
        if (arguments.size() != 4) {
            err.println("usage: java -jar seclume-verify.jar --split <secret uri> <k> <n> <directory>");
            return 2;
        }
        int threshold;
        int shares;
        try {
            threshold = Integer.parseInt(arguments.get(1).strip());
            shares = Integer.parseInt(arguments.get(2).strip());
        } catch (NumberFormatException e) {
            err.println("k and n are numbers: " + arguments.get(1) + ", " + arguments.get(2));
            return 2;
        }
        Path directory = Path.of(arguments.get(3).strip());
        try (SecretProvider source = SecretProviders.fromUri(arguments.get(0).strip())) {
            List<Path> files = ShamirShares.split(source, threshold, shares, directory);
            out.println(files.size() + " shares written, any " + threshold + " of which give the "
                    + "secret back:");
            for (Path file : files) {
                out.println("  " + file);
            }
            out.println();
            out.println("Give each file to a different person, have them keep it where only they");
            out.println("can reach it, and delete it here. In the configuration:");
            out.println();
            out.println("  provider=shamir");
            out.println("  threshold=" + threshold);
            out.println("  share.1.provider=file");
            out.println("  share.1.path=<where the first holder keeps theirs>");
            out.println("  ...");
            return 0;
        } catch (IllegalArgumentException | SecretUnavailableException | IOException e) {
            err.println("no shares written: " + e.getMessage());
            return 1;
        }
    }
}
