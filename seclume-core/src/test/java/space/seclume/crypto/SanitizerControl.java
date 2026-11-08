package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * The negative control of the {@code sanitizers} job: a call into the
 * sanitized libcrypto that reads past the memory seclume handed it - eight
 * bytes allocated, sixty-four passed as their length to {@code BN_bin2bn}.
 * Run as a program, it must end with AddressSanitizer's
 * {@code heap-buffer-overflow} report; the job fails if it does not, because
 * then the sanitizer would not have seen a real fault in the tests either -
 * the library not instrumented, the allocator not intercepted, the report not
 * written.
 *
 * <p>Not a test: under a plain libcrypto it reads eight bytes too far and
 * says nothing, which is exactly what it is there to show the sanitizer does
 * not let happen.
 */
public final class SanitizerControl {

    private SanitizerControl() {
    }

    public static void main(String[] arguments) throws Throwable {
        MethodHandle bin2bn = Linker.nativeLinker().downcallHandle(
                LibCrypto.lookup().find("BN_bin2bn").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment eight = arena.allocate(8);
            MemorySegment number = (MemorySegment) bin2bn.invokeExact(eight, 64,
                    MemorySegment.NULL);
            System.out.println("BN_bin2bn read 64 bytes of 8 and nothing stopped it: "
                    + number.address());
        }
        System.exit(3);
    }
}
