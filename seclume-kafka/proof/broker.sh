#!/bin/bash
# A Kafka broker for LocalKafkaScramTest and LocalKafkaSaslSslTest: one KRaft node,
#  - clients on SASL_PLAINTEXT (port, default 19092) with SCRAM-SHA-256 and -512,
#  - clients on SASL_SSL (secure port, default 19093) with SCRAM, PLAIN and OAUTHBEARER,
#    TLS 1.3 with a certificate for <address> from a CA of its own,
# the user "orders" with a random password (SCRAM and PLAIN), and for OAUTHBEARER an
# unsigned token for "orders" that the broker's default (unsecured) validator takes.
#   broker.sh up <address clients reach> [port] [secure port]    broker.sh down
# Afterwards, copied unread: $DIR/password, $DIR/token and $DIR/ca.pem.
set -e
NAME=seclume-kafka-test
DIR=/tmp/seclume-kafka
IMG=docker.io/apache/kafka:4.1.0
case "$1" in
up)
  ADDRESS=$2; PORT=${3:-19092}; SECURE=${4:-19093}
  mkdir -p $DIR && chmod 755 $DIR && cd $DIR
  head -c 24 /dev/urandom | base64 | tr -d '/+=' > password; chmod 600 password
  # An unsigned JWT ("alg":"none") for orders, valid two days - what the broker's
  # default OAUTHBEARER validator accepts. A real deployment validates signatures.
  b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
  NOW=$(date +%s)
  printf '%s.%s.' "$(printf '{"alg":"none"}' | b64url)" \
    "$(printf '{"sub":"orders","iat":%d,"exp":%d}' $NOW $((NOW + 172800)) | b64url)" > token
  chmod 600 token
  openssl ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null
  openssl req -x509 -new -key ca.key -subj /CN=seclume-kafka-test-ca -days 2 -out ca.pem 2>/dev/null
  openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -out server.key
  openssl req -new -key server.key -subj /CN=kafka -out server.csr 2>/dev/null
  printf 'subjectAltName=IP:%s,DNS:localhost\nbasicConstraints=CA:FALSE\n' "$ADDRESS" > ext
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
    -extfile ext -out server.crt 2>/dev/null
  cat server.key server.crt > server.pem
  chmod 644 ca.pem server.pem
  # PLAIN's user list holds the password: it goes in through a file, not a command line.
  printf 'KAFKA_LISTENER_NAME_SECURE_PLAIN_SASL_JAAS_CONFIG=org.apache.kafka.common.security.plain.PlainLoginModule required user_orders="%s";\n' \
    "$(cat password)" > plain.env
  chmod 600 plain.env
  SCRAM="org.apache.kafka.common.security.scram.ScramLoginModule required;"
  podman run -d --name $NAME -p $PORT:19092 -p $SECURE:19093 -v $DIR:/conf:ro,z \
    --env-file plain.env \
    -e KAFKA_NODE_ID=1 -e KAFKA_PROCESS_ROLES=broker,controller \
    -e KAFKA_LISTENERS=CLIENT://:19092,SECURE://:19093,INTERNAL://:9092,CONTROLLER://:9093 \
    -e KAFKA_ADVERTISED_LISTENERS=CLIENT://$ADDRESS:$PORT,SECURE://$ADDRESS:$SECURE,INTERNAL://localhost:9092 \
    -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CLIENT:SASL_PLAINTEXT,SECURE:SASL_SSL,INTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT \
    -e KAFKA_INTER_BROKER_LISTENER_NAME=INTERNAL -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
    -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
    -e KAFKA_SASL_ENABLED_MECHANISMS=SCRAM-SHA-256,SCRAM-SHA-512,PLAIN,OAUTHBEARER \
    -e KAFKA_LISTENER_NAME_CLIENT_SASL_ENABLED_MECHANISMS=SCRAM-SHA-256,SCRAM-SHA-512 \
    -e KAFKA_LISTENER_NAME_SECURE_SASL_ENABLED_MECHANISMS=SCRAM-SHA-256,SCRAM-SHA-512,PLAIN,OAUTHBEARER \
    -e "KAFKA_LISTENER_NAME_CLIENT_SCRAM___SHA___256_SASL_JAAS_CONFIG=$SCRAM" \
    -e "KAFKA_LISTENER_NAME_CLIENT_SCRAM___SHA___512_SASL_JAAS_CONFIG=$SCRAM" \
    -e "KAFKA_LISTENER_NAME_SECURE_SCRAM___SHA___256_SASL_JAAS_CONFIG=$SCRAM" \
    -e "KAFKA_LISTENER_NAME_SECURE_SCRAM___SHA___512_SASL_JAAS_CONFIG=$SCRAM" \
    -e "KAFKA_LISTENER_NAME_SECURE_OAUTHBEARER_SASL_JAAS_CONFIG=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required unsecuredLoginStringClaim_sub=\"broker\";" \
    -e KAFKA_LISTENER_NAME_SECURE_SSL_KEYSTORE_TYPE=PEM \
    -e KAFKA_LISTENER_NAME_SECURE_SSL_KEYSTORE_LOCATION=/conf/server.pem \
    -e KAFKA_LISTENER_NAME_SECURE_SSL_ENABLED_PROTOCOLS=TLSv1.3 \
    -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 \
    -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 -e KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0 \
    $IMG >/dev/null
  shred -u plain.env
  for i in $(seq 60); do
    podman exec $NAME /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list >/dev/null 2>&1 && break
    sleep 2
  done
  # The password goes in through a file inside the container, not the command line.
  podman cp $DIR/password $NAME:/tmp/pw
  # kafka-configs echoes its arguments on an error - nothing of it is shown.
  podman exec $NAME sh -c 'P=$(cat /tmp/pw); rm /tmp/pw; C="/opt/kafka/bin/kafka-configs.sh --bootstrap-server localhost:9092 --alter --entity-type users --entity-name orders"; $C --add-config "SCRAM-SHA-256=[iterations=8192,password=$P]" && $C --add-config "SCRAM-SHA-512=[password=$P]"' >/dev/null 2>&1 \
    || { echo "creating the user failed (output suppressed: it would show the password)"; exit 1; }
  echo "broker up on $ADDRESS: SASL_PLAINTEXT $PORT, SASL_SSL $SECURE, user orders"
  ;;
down)
  podman rm -f $NAME >/dev/null 2>&1 || true
  shred -u $DIR/password $DIR/token $DIR/*.key $DIR/server.pem 2>/dev/null || true
  rm -rf $DIR
  echo "broker removed"
  ;;
esac
