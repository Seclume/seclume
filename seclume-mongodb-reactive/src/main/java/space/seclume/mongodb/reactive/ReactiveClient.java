package space.seclume.mongodb.reactive;

import com.mongodb.MongoDriverInformation;
import com.mongodb.connection.ClusterDescription;

/** The reactive client: the cluster's API, and closing the sync client under it. */
final class ReactiveClient extends ReactiveCluster
        implements com.mongodb.reactivestreams.client.MongoClient {

    private final com.mongodb.client.MongoClient client;

    ReactiveClient(com.mongodb.client.MongoClient client) {
        super(client);
        this.client = client;
    }

    @Override
    public void close() {
        client.close();
    }

    @Override
    public ClusterDescription getClusterDescription() {
        return client.getClusterDescription();
    }

    @Override
    public void appendMetadata(MongoDriverInformation information) {
        client.appendMetadata(information);
    }
}
