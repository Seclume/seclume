package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.foreign.Arena;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.tck.ChildJvm;

class NativeP256HeapTest {
    @TempDir Path directory;

    @ParameterizedTest
    @ValueSource(strings = {"native", "leak", "jca"})
    void measuresLivePrivateScalarAndSharedSecret(String mode) throws Exception {
        Path needles = directory.resolve(mode + ".bin");
        Path dump = directory.resolve(mode + ".hprof");
        try {
            ChildJvm.Result result = ChildJvm.run(NativeP256HeapProbe.class,
                    List.of(mode, needles.toString(), dump.toString()), 120);
            assertEquals(0, result.exitCode(), result.output());
            byte[] secrets = Files.readAllBytes(needles);
            assertEquals(64, secrets.length);
            try (Arena arena = Arena.ofConfined(); FileChannel file = FileChannel.open(dump, StandardOpenOption.READ)) {
                ByteBuffer heap = file.map(FileChannel.MapMode.READ_ONLY, 0, file.size(), arena).asByteBuffer();
                for (int offset : new int[] {0, 32}) {
                    byte[] needle = Arrays.copyOfRange(secrets, offset, offset + 32);
                    assertFalse(Arrays.equals(needle, new byte[32]), "probe produced a zero needle");
                    boolean found = contains(heap, needle);
                    byte[] reversed = needle.clone();
                    for (int i = 0; i < 32; i++) reversed[i] = needle[31 - i];
                    found |= contains(heap, reversed);
                    assertEquals(!mode.equals("native"), found,
                            mode + ": " + (offset == 0 ? "private scalar" : "shared secret"));
                }
            } finally {
                Arrays.fill(secrets, (byte) 0);
            }
        } finally {
            Files.deleteIfExists(needles);
            Files.deleteIfExists(dump);
        }
    }

    private static boolean contains(ByteBuffer data, byte[] needle) {
        outer: for (int i = 0; i <= data.limit() - needle.length; i++) {
            if (data.get(i) != needle[0]) continue;
            for (int j = 1; j < needle.length; j++) {
                if (data.get(i + j) != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }
}
