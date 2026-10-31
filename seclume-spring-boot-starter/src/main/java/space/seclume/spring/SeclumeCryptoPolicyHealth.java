package space.seclume.spring;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

import space.seclume.inventory.CryptoInventory;
import space.seclume.inventory.CryptoPolicy;

/**
 * {@code DOWN} while the inventory fails the crypto policy - a TLS session
 * that fell back, a certificate about to lapse, a secret from a source the
 * policy forbids - with the findings as details. Warnings go along and never
 * decide the status.
 */
public final class SeclumeCryptoPolicyHealth implements HealthIndicator {

    private final CryptoPolicy policy;

    public SeclumeCryptoPolicyHealth(CryptoPolicy policy) {
        this.policy = policy;
    }

    @Override
    public Health health() {
        List<CryptoPolicy.Finding> findings = policy.check(CryptoInventory.snapshot(), Instant.now());
        List<Map<String, String>> details = new ArrayList<>();
        for (CryptoPolicy.Finding finding : findings) {
            Map<String, String> detail = new LinkedHashMap<>();
            detail.put("severity", finding.severity().name().toLowerCase(java.util.Locale.ROOT));
            detail.put("rule", finding.rule());
            detail.put("asset", finding.asset());
            detail.put("finding", finding.message());
            details.add(detail);
        }
        Health.Builder health = CryptoPolicy.fails(findings) ? Health.down() : Health.up();
        return health.withDetail("findings", details).build();
    }
}
