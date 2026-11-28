import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * Two restores of one checkpoint image must not draw the same random bytes.
 * OpenSSL's generator - which makes the key shares of a TLS handshake and the
 * nonce of an ECDSA signature - is in the image with its state, and CRIU
 * restores the process under the same pid, so OpenSSL's fork check does not
 * reseed it. Registered, seclume reseeds it after the restore.
 *
 * mode register: SeclumeCrac's process part registered - the two restores
 *                must print different bytes.
 * mode bare:     not registered - the control: the same bytes twice show
 *                that the comparison can tell.
 */
public class CracRandomProof {

    public static void main(String[] args) throws Throwable {
        if (args[0].equals("register")) {
            space.seclume.crac.SeclumeCrac.registerProcess();
        }
        draw();                                     // the generator is in use before the image
        org.crac.Core.checkpointRestore();
        System.out.println("PROOF random " + hex(draw()));
    }

    static byte[] draw() throws Throwable {
        Linker linker = Linker.nativeLinker();
        SymbolLookup crypto = SymbolLookup.libraryLookup("libcrypto.so.3", Arena.global());
        MethodHandle randBytes = linker.downcallHandle(crypto.find("RAND_bytes").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(32);
            if ((int) randBytes.invokeExact(out, 32) != 1) {
                throw new IllegalStateException("RAND_bytes failed");
            }
            return out.toArray(ValueLayout.JAVA_BYTE);
        }
    }

    static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        return out.toString();
    }
}
