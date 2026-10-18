package space.seclume.spring;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import space.seclume.pool.PoolStatistics;

/**
 * A grade for one data source - what an operator should look at, worst first.
 *
 * <p>The endpoint lists the facts: the TLS, the certificate, the login, the
 * pool's numbers. Facts need someone who knows which of them matter. This
 * says it: a certificate that expires in five days, a password sent in the
 * clear, a pool whose borrowers time out - each a finding with a level, and
 * the grade is the worst of them.
 *
 * <p><b>It never marks a data source down.</b> Health is what a load balancer
 * acts on; a certificate expiring next week taking every instance out of
 * service at once would turn a warning into the outage it warns of. Whether
 * the database can be reached stays the health check's question alone.
 *
 * <p>Nothing here names a user, a host or a value - the same rule as the
 * endpoint's.
 */
public final class SeclumeAssessment {

    /** How bad a finding is; the grade is the worst one. */
    public enum Level {
        OK, NOTE, WARNING, CRITICAL;

        String label() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** One thing worth knowing, and how much. */
    public record Finding(Level level, String check, String detail) {

        Map<String, Object> asMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("level", level.label());
            map.put("check", check);
            map.put("detail", detail);
            return map;
        }
    }

    /** Logins that send the password itself, or a hash that stands for it. */
    private static final Set<String> WEAK_LOGINS = Set.of("trust", "password", "md5",
            "mysql_native_password", "mysql_clear_password");

    static final Duration CRITICAL_EXPIRY = Duration.ofDays(7);
    static final Duration WARNING_EXPIRY = Duration.ofDays(30);

    private final List<Finding> findings = new ArrayList<>();

    private SeclumeAssessment() {
    }

    /**
     * Grades what is known about one data source.
     *
     * @param authentication the login method as {@code Secured} names it, or {@code null}
     * @param tls            the TLS description, or {@code null} for none
     * @param certificateExpires when the server's certificate expires, or {@code null}
     * @param maximum        the pool's configured maximum
     * @param resetsRefused  resets refused so far
     */
    public static SeclumeAssessment of(String authentication, String tls,
                                       Instant certificateExpires, PoolStatistics statistics,
                                       int maximum, long resetsRefused, Instant now) {
        SeclumeAssessment assessment = new SeclumeAssessment();
        assessment.transport(tls);
        assessment.certificate(certificateExpires, now);
        assessment.login(authentication);
        assessment.pool(statistics, maximum, resetsRefused);
        return assessment;
    }

    private void transport(String tls) {
        if (tls == null) {
            add(Level.CRITICAL, "tls", "the connection is in the clear");
        } else if (tls.contains("1.2") && !tls.contains("1.3")) {
            add(Level.NOTE, "tls", "TLS 1.2 - the server offers no 1.3");
        }
    }

    private void certificate(Instant expires, Instant now) {
        if (expires == null) {
            return;
        }
        Duration left = Duration.between(now, expires);
        if (left.isNegative()) {
            add(Level.CRITICAL, "certificate", "the server's certificate expired " + expires);
        } else if (left.compareTo(CRITICAL_EXPIRY) <= 0) {
            add(Level.CRITICAL, "certificate", "the server's certificate expires in "
                    + days(left) + " - " + expires);
        } else if (left.compareTo(WARNING_EXPIRY) <= 0) {
            add(Level.WARNING, "certificate", "the server's certificate expires in "
                    + days(left) + " - " + expires);
        }
    }

    private void login(String authentication) {
        if (authentication == null) {
            return;
        }
        String method = authentication.toLowerCase(Locale.ROOT);
        if (WEAK_LOGINS.contains(method)) {
            add(Level.WARNING, "authentication", "'" + method + "' sends the password or a "
                    + "hash that stands for it - the server can offer SCRAM, "
                    + "caching_sha2_password or a certificate");
        } else if (method.equals("sqlpassword")) {
            add(Level.NOTE, "authentication", "a SQL Server login with a password - "
                    + "integrated or Entra ID logins carry no password at all");
        }
    }

    private void pool(PoolStatistics statistics, int maximum, long resetsRefused) {
        if (statistics.timeouts() > 0) {
            add(Level.WARNING, "pool", statistics.timeouts()
                    + " borrow(s) timed out waiting for a connection");
        }
        if (statistics.waiting() > 0 && statistics.active() >= maximum) {
            add(Level.WARNING, "pool", "all " + maximum + " connections are in use and "
                    + statistics.waiting() + " thread(s) wait");
        }
        if (statistics.leaksReported() > 0) {
            add(Level.WARNING, "pool", statistics.leaksReported()
                    + " connection(s) were held past the leak threshold");
        }
        if (resetsRefused > 0) {
            add(Level.WARNING, "pool", resetsRefused + " session reset(s) failed - each "
                    + "connection was closed instead of lent again");
        }
    }

    private void add(Level level, String check, String detail) {
        findings.add(new Finding(level, check, detail));
    }

    private static String days(Duration left) {
        long days = left.toDays();
        return days == 1 ? "1 day" : days + " days";
    }

    /** The worst level found, {@link Level#OK} when there is nothing. */
    public Level grade() {
        Level worst = Level.OK;
        for (Finding finding : findings) {
            if (finding.level().compareTo(worst) > 0) {
                worst = finding.level();
            }
        }
        return worst;
    }

    public List<Finding> findings() {
        List<Finding> sorted = new ArrayList<>(findings);
        sorted.sort((a, b) -> b.level().compareTo(a.level()));
        return List.copyOf(sorted);
    }

    /** As the endpoint and the health details show it. */
    public Map<String, Object> asMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("grade", grade().label());
        map.put("findings", findings().stream().map(Finding::asMap).toList());
        return map;
    }
}
