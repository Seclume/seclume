package space.seclume.spring;

import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;

import space.seclume.inventory.CycloneDxCbom;

/**
 * {@code /actuator/cbom}: the cryptography this application uses, as it uses
 * it, as a CycloneDX 1.6 cryptography bill of materials - each secret a
 * provider read, each field encryption key, each private key, each TLS
 * session and its server's certificate, and every algorithm with its NIST
 * quantum security level. Facts, never a value: see
 * {@link space.seclume.inventory.CryptoInventory}.
 *
 * <p>Exposed like every endpoint: {@code management.endpoints.web.exposure.include=cbom}.
 */
@Endpoint(id = "cbom")
public final class SeclumeCbomEndpoint {

    /** The media type CycloneDX registers for its JSON. */
    public static final String MEDIA_TYPE = "application/vnd.cyclonedx+json";

    private final String application;

    public SeclumeCbomEndpoint(String application) {
        this.application = application;
    }

    @ReadOperation(produces = MEDIA_TYPE)
    public String cbom() {
        return CycloneDxCbom.write(application);
    }
}
