package space.seclume.internal.jdbc;

import java.util.List;

/**
 * A cluster that says where its members are - asked before a connection is
 * opened, instead of waiting for DNS or a load balancer to notice a failover.
 * {@link PatroniTopology} asks Patroni's REST API; {@link AuroraTopology}
 * remembers what an Aurora instance said about its cluster.
 */
public interface ClusterTopology {

    /**
     * The servers to try for {@code wanted}, in order; empty when nothing is
     * known - the URL's own hosts are used then.
     */
    List<HostList.Host> hosts(TargetServer wanted);
}
