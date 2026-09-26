/**
 * SASL/SCRAM for the Kafka client with the password off the heap - see
 * {@link space.seclume.kafka.SeclumeScramLoginModule}.
 */
module seclume.kafka {

    requires transitive seclume.core;
    requires java.security.sasl;

    exports space.seclume.kafka;
}
