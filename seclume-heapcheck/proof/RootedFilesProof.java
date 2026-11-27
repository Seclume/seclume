import java.nio.file.Files;
import java.nio.file.Path;

import space.seclume.heapcheck.RootedFiles;

/**
 * A hostile process's links, read through /proc/<pid>/root - see run-rooted.sh,
 * which plants them. Prints PROOF lines: what the plain path reaches (the
 * control) and what RootedFiles reaches.
 */
public class RootedFilesProof {

    public static void main(String[] args) throws Exception {
        String pid = args[0];
        Path plain = Path.of("/proc", pid, "root", "tmp", "evil", "marker.txt");
        System.out.println("PROOF plain path reads: " + Files.readString(plain).strip());
        try (RootedFiles rooted = RootedFiles.of(pid)) {
            Path opened = rooted.open(Path.of("/tmp/evil/marker.txt"));
            System.out.println("PROOF rooted reads: " + Files.readString(opened).strip());
            System.out.println("PROOF rooted delete of /tmp/evil/victim.txt: "
                    + rooted.delete(Path.of("/tmp/evil/victim.txt")));
            try {
                rooted.open(Path.of("/tmp/fifo"));
                System.out.println("PROOF fifo: opened");
            } catch (java.io.IOException refused) {
                System.out.println("PROOF fifo: refused - " + refused.getMessage());
            }
            try {
                Path magic = rooted.open(Path.of("/tmp/magic/etc/hostname"));
                System.out.println("PROOF magic link: " + (magic == null ? "missing"
                        : Files.readString(magic).strip()));
            } catch (java.io.IOException refused) {
                System.out.println("PROOF magic link: refused - " + refused.getMessage());
            }
            System.out.println("PROOF rooted delete of the container's own file: "
                    + rooted.delete(Path.of("/tmp/own.txt")));
        }
    }
}
