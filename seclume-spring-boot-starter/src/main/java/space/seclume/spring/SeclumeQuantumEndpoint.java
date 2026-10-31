package space.seclume.spring;

import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;

import space.seclume.inventory.CryptoInventory;
import space.seclume.inventory.QuantumReadiness;

/**
 * {@code /actuator/quantum}: what a quantum computer would break in this
 * application as it runs, most urgent first, and what to use instead - see
 * {@link QuantumReadiness}. Exposed like every endpoint:
 * {@code management.endpoints.web.exposure.include=quantum}.
 */
@Endpoint(id = "quantum")
public final class SeclumeQuantumEndpoint {

    @ReadOperation(produces = "application/json")
    public String quantum() {
        return QuantumReadiness.assess(CryptoInventory.snapshot()).json();
    }
}
