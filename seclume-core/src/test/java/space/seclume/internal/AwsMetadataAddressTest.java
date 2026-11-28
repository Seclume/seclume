package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;

import org.junit.jupiter.api.Test;

import space.seclume.secret.AwsInstanceRole;

/**
 * EKS Pod Identity on IPv6 (fd00:ec2::23) and IMDS over IPv6 (fd00:ec2::254)
 * are unique-local, not link-local, and were refused - exactly these two are
 * taken now, no other. And a container URI's scheme was ignored: https:// was
 * asked in plain HTTP. It is refused.
 */
class AwsMetadataAddressTest {

    @Test
    void exactlyTheTwoAwsIpv6AddressesAreTaken() throws Exception {
        assertTrue(SecretFetch.awsIpv6MetadataAddress(InetAddress.getByName("fd00:ec2::23")));
        assertTrue(SecretFetch.awsIpv6MetadataAddress(InetAddress.getByName("fd00:ec2::254")));
        assertFalse(SecretFetch.awsIpv6MetadataAddress(InetAddress.getByName("fd00:ec2::24")));
        assertFalse(SecretFetch.awsIpv6MetadataAddress(InetAddress.getByName("fd00:ec3::23")));
        assertFalse(SecretFetch.awsIpv6MetadataAddress(InetAddress.getByName("10.0.0.23")));
    }

    @Test
    void aContainerUriThatIsNotHttpIsRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> AwsInstanceRole.container("https://169.254.170.2/creds", "/tmp/token"));
        AwsInstanceRole.container("http://169.254.170.2/creds", "/tmp/token");
    }
}
