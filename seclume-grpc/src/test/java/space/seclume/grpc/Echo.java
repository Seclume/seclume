package space.seclume.grpc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

import io.grpc.MethodDescriptor;

/** A unary method of strings - no protobuf needed to test the transport. */
final class Echo {

    static final MethodDescriptor<String, String> METHOD =
            MethodDescriptor.<String, String>newBuilder()
                    .setType(MethodDescriptor.MethodType.UNARY)
                    .setFullMethodName("test.Echo/Echo")
                    .setRequestMarshaller(new Strings())
                    .setResponseMarshaller(new Strings())
                    .build();

    private Echo() {
    }

    private static final class Strings implements MethodDescriptor.Marshaller<String> {
        @Override
        public InputStream stream(String value) {
            return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public String parse(InputStream stream) {
            try {
                return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }
}
