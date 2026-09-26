#!/bin/bash
# A Kafka broker for LocalKafkaScramTest: one KRaft node, clients on
# SASL_PLAINTEXT with SCRAM-SHA-256 and SCRAM-SHA-512, the user "orders" with a
# random password written to $DIR/password (read it with nothing but a copy).
#   broker.sh up <address clients reach> [port]    broker.sh down
set -e
NAME=seclume-kafka-test
DIR=/tmp/seclume-kafka
IMG=docker.io/apache/kafka:4.1.0
case "$1" in
up)
  ADDRESS=$2; PORT=${3:-19092}
  mkdir -p $DIR && chmod 700 $DIR
  head -c 24 /dev/urandom | base64 | tr -d '/+=' > $DIR/password; chmod 600 $DIR/password
  podman run -d --name $NAME -p $PORT:19092 \
    -e KAFKA_NODE_ID=1 -e KAFKA_PROCESS_ROLES=broker,controller \
    -e KAFKA_LISTENERS=CLIENT://:19092,INTERNAL://:9092,CONTROLLER://:9093 \
    -e KAFKA_ADVERTISED_LISTENERS=CLIENT://$ADDRESS:$PORT,INTERNAL://localhost:9092 \
    -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CLIENT:SASL_PLAINTEXT,INTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT \
    -e KAFKA_INTER_BROKER_LISTENER_NAME=INTERNAL -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
    -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
    -e KAFKA_SASL_ENABLED_MECHANISMS=SCRAM-SHA-256,SCRAM-SHA-512 \
    -e "KAFKA_LISTENER_NAME_CLIENT_SCRAM___SHA___256_SASL_JAAS_CONFIG=org.apache.kafka.common.security.scram.ScramLoginModule required;" \
    -e "KAFKA_LISTENER_NAME_CLIENT_SCRAM___SHA___512_SASL_JAAS_CONFIG=org.apache.kafka.common.security.scram.ScramLoginModule required;" \
    -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 \
    -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 -e KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0 \
    $IMG >/dev/null
  for i in $(seq 60); do
    podman exec $NAME /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list >/dev/null 2>&1 && break
    sleep 2
  done
  # The password goes in through a file inside the container, not the command line.
  podman cp $DIR/password $NAME:/tmp/pw
  # kafka-configs echoes its arguments on an error - nothing of it is shown.
  podman exec $NAME sh -c 'P=$(cat /tmp/pw); rm /tmp/pw; C="/opt/kafka/bin/kafka-configs.sh --bootstrap-server localhost:9092 --alter --entity-type users --entity-name orders"; $C --add-config "SCRAM-SHA-256=[iterations=8192,password=$P]" && $C --add-config "SCRAM-SHA-512=[password=$P]"' >/dev/null 2>&1 \
    || { echo "creating the user failed (output suppressed: it would show the password)"; exit 1; }
  echo "broker up on $ADDRESS:$PORT, user orders"
  ;;
down)
  podman rm -f $NAME >/dev/null 2>&1 || true
  shred -u $DIR/password 2>/dev/null || true
  rm -rf $DIR
  echo "broker removed"
  ;;
esac
