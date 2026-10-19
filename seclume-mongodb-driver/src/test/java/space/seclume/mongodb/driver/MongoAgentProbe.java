package space.seclume.mongodb.driver;

import java.nio.file.Path;

import org.bson.Document;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;

import space.seclume.mongodb.SeclumeMongo;
import space.seclume.tck.Heap;

/**
 * Run in a child JVM under the OpenTelemetry agent by
 * {@link ApmAgentHeapDumpTest}: logs in with the official driver on
 * seclume's socket and with seclume's own driver, writes and reads with
 * both, and dumps the heap while both clients are still open. With a third
 * argument, {@code control}, the official driver alone, given the password
 * the way it wants it - the control that the search would find it.
 */
public final class MongoAgentProbe {

    private MongoAgentProbe() {
    }

    public static void main(String[] args) throws Exception {
        String url = args[0];
        Path dumpFile = Path.of(args[1]);
        if (args.length > 2 && args[2].equals("control")) {
            control(args[3], args[4], args[5], dumpFile);
            return;
        }
        try (MongoClient official = MongoClients.create(SeclumeMongo.settings(url));
             MongoClient own = SeclumeMongoClients.create(url)) {
            MongoCollection<Document> viaOfficial = official.getDatabase("seclume_test")
                    .getCollection("apm_agent");
            MongoCollection<Document> viaOwn = own.getDatabase("seclume_test")
                    .getCollection("apm_agent");
            viaOfficial.drop();
            int read = 0;
            for (int i = 0; i < 5; i++) {
                viaOfficial.insertOne(new Document("_id", "official-" + i));
                viaOwn.insertOne(new Document("_id", "own-" + i));
                read += viaOwn.countDocuments() > 0 ? 1 : 0;
                read += viaOfficial.find(new Document("_id", "own-" + i)).first() != null ? 1 : 0;
            }
            Heap.collect();
            Heap.dump(dumpFile);
            System.out.println("both clients wrote and read, " + read + " reads");
        }
    }

    private static void control(String host, String passwordFile, String caFile, Path dumpFile)
            throws Exception {
        char[] password = java.nio.file.Files.readString(Path.of(passwordFile)).strip()
                .toCharArray();
        java.security.KeyStore trust = java.security.KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        try (java.io.InputStream in = java.nio.file.Files.newInputStream(Path.of(caFile))) {
            int n = 0;
            for (java.security.cert.Certificate certificate : java.security.cert
                    .CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                trust.setCertificateEntry("ca" + n++, certificate);
            }
        }
        javax.net.ssl.TrustManagerFactory factory = javax.net.ssl.TrustManagerFactory
                .getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trust);
        javax.net.ssl.SSLContext tls = javax.net.ssl.SSLContext.getInstance("TLS");
        tls.init(null, factory.getTrustManagers(), null);
        try (MongoClient vendor = MongoClients.create(com.mongodb.MongoClientSettings.builder()
                .applyConnectionString(new com.mongodb.ConnectionString(
                        "mongodb://" + host + ":27017/?tls=true"))
                .applyToSslSettings(ssl -> ssl.context(tls))
                .credential(com.mongodb.MongoCredential.createScramSha256Credential(
                        "seclume_test", "admin", password))
                .build())) {
            vendor.getDatabase("seclume_test").getCollection("apm_agent")
                    .insertOne(new Document("_id", "control-" + System.nanoTime()));
            Heap.collect();
            Heap.dump(dumpFile);
            System.out.println("the vendor's client wrote");
        }
    }
}
