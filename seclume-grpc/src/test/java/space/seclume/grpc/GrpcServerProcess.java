package space.seclume.grpc;

import java.nio.file.Files;
import java.nio.file.Path;

import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.ServerServiceDefinition;
import io.grpc.Status;
import io.grpc.TlsServerCredentials;
import io.grpc.stub.ServerCalls;

/**
 * A gRPC server in a process of its own that knows the token - reading its
 * file for each call, so a rotation shows - and refuses calls without it.
 */
public final class GrpcServerProcess {

    private static final Metadata.Key<String> AUTHORIZATION =
            Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<String> API_KEY =
            Metadata.Key.of("x-api-key", Metadata.ASCII_STRING_MARSHALLER);

    private GrpcServerProcess() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args[0]);
        ServerServiceDefinition echo = ServerServiceDefinition.builder("test.Echo")
                .addMethod(Echo.METHOD, ServerCalls.asyncUnaryCall((request, response) -> {
                    response.onNext("ok " + request);
                    response.onCompleted();
                }))
                .build();
        ServerInterceptor check = new ServerInterceptor() {
            @Override
            public <Q, A> ServerCall.Listener<Q> interceptCall(ServerCall<Q, A> call,
                    Metadata headers, ServerCallHandler<Q, A> next) {
                String token;
                try {
                    token = Files.readString(directory.resolve("token")).trim();
                } catch (java.io.IOException e) {
                    throw new java.io.UncheckedIOException(e);
                }
                boolean ok = ("Bearer " + token).equals(headers.get(AUTHORIZATION))
                        || token.equals(headers.get(API_KEY));
                if (!ok) {
                    call.close(Status.UNAUTHENTICATED.withDescription("wrong token"),
                            new Metadata());
                    return new ServerCall.Listener<>() { };
                }
                return next.startCall(call, headers);
            }
        };
        Server server = Grpc.newServerBuilderForPort(0, TlsServerCredentials.create(
                        directory.resolve("cert.pem").toFile(), directory.resolve("key.pem").toFile()))
                .maxInboundMetadataSize(256 * 1024)
                .addService(ServerInterceptors.intercept(echo, check))
                .build()
                .start();
        Files.writeString(directory.resolve("port.tmp"), String.valueOf(server.getPort()));
        Files.move(directory.resolve("port.tmp"), directory.resolve("port"));
        server.awaitTermination();
    }
}
