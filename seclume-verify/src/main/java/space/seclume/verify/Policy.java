package space.seclume.verify;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.function.Function;

import space.seclume.inventory.CbomDiff;
import space.seclume.inventory.CbomReader;
import space.seclume.inventory.CryptoInventory;
import space.seclume.inventory.CryptoInventory.Asset;
import space.seclume.inventory.CryptoPolicy;
import space.seclume.inventory.QuantumReadiness;

/**
 * The inventory judged: {@code --policy}, {@code --quantum} and
 * {@code --cbom-diff}. Each takes a CBOM file a build kept, or a JDBC URL to
 * connect to and inventory as {@code --cbom} does.
 *
 * <p>Exit codes as everywhere in this tool: 0 the policy is met (no step
 * back), 1 it is not, 2 the call was wrong or the input unreadable.
 */
final class Policy {

    private Policy() {
    }

    /** {@code --policy <policy.properties> <cbom.json | jdbc url> [--json]}. */
    static int policy(List<String> arguments, PrintStream out, PrintStream err,
            Function<String, List<Asset>> connect) {
        boolean json = arguments.contains("--json");
        List<String> rest = arguments.stream().filter(a -> !a.equals("--json")).toList();
        if (rest.size() != 2) {
            err.println("usage: java -jar seclume-verify.jar --policy <policy.properties> "
                    + "<cbom.json | \"jdbc url\"> [--json]");
            return 2;
        }
        CryptoPolicy policy;
        try {
            policy = CryptoPolicy.load(Path.of(rest.get(0)));
        } catch (IOException | IllegalArgumentException e) {
            err.println("the policy cannot be read: " + e.getMessage());
            return 2;
        }
        List<Asset> assets = assets(rest.get(1), err, connect);
        if (assets == null) {
            return 2;
        }
        List<CryptoPolicy.Finding> findings = policy.check(assets, Instant.now());
        out.print(json ? CryptoPolicy.json(findings) : CryptoPolicy.markdown(findings));
        return CryptoPolicy.fails(findings) ? 1 : 0;
    }

    /** {@code --quantum <cbom.json | jdbc url> [--json]}: always 0 when it could be read. */
    static int quantum(List<String> arguments, PrintStream out, PrintStream err,
            Function<String, List<Asset>> connect) {
        boolean json = arguments.contains("--json");
        List<String> rest = arguments.stream().filter(a -> !a.equals("--json")).toList();
        if (rest.size() != 1) {
            err.println("usage: java -jar seclume-verify.jar --quantum <cbom.json | \"jdbc url\"> [--json]");
            return 2;
        }
        List<Asset> assets = assets(rest.get(0), err, connect);
        if (assets == null) {
            return 2;
        }
        QuantumReadiness.Report report = QuantumReadiness.assess(assets);
        out.print(json ? report.json() : report.markdown());
        return 0;
    }

    /** {@code --cbom-diff <before.json> <after.json>}: 1 when the second is a step back. */
    static int diff(List<String> arguments, PrintStream out, PrintStream err) {
        if (arguments.size() != 2) {
            err.println("usage: java -jar seclume-verify.jar --cbom-diff <before.json> <after.json>");
            return 2;
        }
        List<Asset> before = file(Path.of(arguments.get(0)), err);
        List<Asset> after = file(Path.of(arguments.get(1)), err);
        if (before == null || after == null) {
            return 2;
        }
        List<CbomDiff.Difference> differences = CbomDiff.diff(before, after);
        out.print(CbomDiff.markdown(differences));
        return CbomDiff.regresses(differences) ? 1 : 0;
    }

    private static List<Asset> assets(String input, PrintStream err,
            Function<String, List<Asset>> connect) {
        if (input.startsWith("jdbc:")) {
            return connect.apply(input);
        }
        return file(Path.of(input), err);
    }

    private static List<Asset> file(Path path, PrintStream err) {
        try {
            // seclume-allow: a CBOM holds facts, never a secret
            return CbomReader.read(Files.readString(path));
        } catch (IOException | IllegalArgumentException e) {
            err.println(path + " cannot be read as a CBOM: " + e.getMessage());
            return null;
        }
    }

    /** Connects as the report does, and takes the inventory after. */
    static List<Asset> connect(String url) {
        int status = Verify.run(url, new Report());
        if (status != 0) {
            System.err.println("the connection did not stand; the inventory holds what it got that far");
        }
        return CryptoInventory.snapshot();
    }
}
