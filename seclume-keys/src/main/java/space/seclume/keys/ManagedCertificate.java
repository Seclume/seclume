package space.seclume.keys;

import java.time.Instant;

/**
 * A certificate a key manager of seclume-keys keeps current by itself - one
 * from Vault's PKI, or a pair reloaded from disk - as it stands now. Public
 * facts only: the name it is configured under, the subject and validity of the
 * certificate in use, when it is to be replaced, and why the last replacement
 * failed, if it did.
 *
 * @param name        what it is configured under: a Spring SSL bundle's name,
 *                    the {@code name} setting, or the chain's file
 * @param kind        {@code vault-pki}, {@code spiffe} or {@code file}
 * @param subject     the certificate's subject
 * @param notBefore   when it began
 * @param notAfter    when it ends
 * @param nextRenewal when it is to be replaced; {@code null} when that is up
 *                    to whoever writes the file
 * @param generations how many pairs it has had, the first included
 * @param lastFailure why the last attempt to replace it failed, or {@code null}
 *                    when it did not
 * @param failedAt    when that was, or {@code null}
 */
public record ManagedCertificate(String name, String kind, String subject, Instant notBefore,
        Instant notAfter, Instant nextRenewal, int generations, String lastFailure,
        Instant failedAt) {
}
