#!/usr/bin/env bash
# Starts the interop servers and writes the list of cases TlsInteropTest
# reads. Every implementation whose tool is on this machine is started; the
# workflow checks that all of them were.
#
#   tls-interop/run.sh <work directory>      then  . <work directory>/env
#   tls-interop/run.sh stop <work directory>
#
# Tools: openssl (3.x; 3.5+ adds the post-quantum case), gnutls-serv, go,
# java, miniserve (rustls). Throwaway certificates from certs.sh.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)

if [ "${1:-}" = stop ]; then
  [ -f "$2/pids" ] && xargs -r kill < "$2/pids" 2>/dev/null || true
  exit 0
fi
work=$(mkdir -p "${1:?usage: run.sh <work directory>}" && cd "$1" && pwd)
certs="$work/certs"
bash "$here/certs.sh" "$certs" >/dev/null
cases="$work/cases.txt"
: > "$cases"
: > "$work/pids"
: > "$work/implementations"

serve() { # name port expect reason -- command...
  local name=$1 port=$2 expect=$3 reason=$4
  shift 5
  "$@" > "$work/$name.log" 2>&1 &
  echo $! >> "$work/pids"
  printf '%-28s %5s %-8s %s\n' "$name" "$port" "$expect" "$reason" >> "$cases"
}

has() { command -v "$1" >/dev/null 2>&1; }

c=$certs
if has openssl; then
  echo openssl >> "$work/implementations"
  ossl() { openssl s_server -quiet -www -naccept 1000 "$@"; }
  serve openssl-1.3-x25519-ecdsa   9001 ok "" -- ossl -accept 9001 -tls1_3 -groups X25519 -cert $c/ecdsa256.pem -key $c/ecdsa256.key -cert_chain $c/ca.pem
  serve openssl-1.3-p256           9002 ok "" -- ossl -accept 9002 -tls1_3 -groups P-256 -cert $c/ecdsa256.pem -key $c/ecdsa256.key -cert_chain $c/ca.pem
  serve openssl-1.3-p384-hrr       9003 ok "" -- ossl -accept 9003 -tls1_3 -groups P-384 -cert $c/ecdsa384.pem -key $c/ecdsa384.key -cert_chain $c/ca.pem
  serve openssl-1.3-rsa            9004 ok "" -- ossl -accept 9004 -tls1_3 -cert $c/rsa2048.pem -key $c/rsa2048.key -cert_chain $c/ca.pem
  serve openssl-1.3-aes256         9005 ok "" -- ossl -accept 9005 -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -cert $c/ecdsa256.pem -key $c/ecdsa256.key -cert_chain $c/ca.pem
  serve openssl-1.2-ecdsa-gcm      9006 ok "" -- ossl -accept 9006 -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -cert $c/ecdsa256.pem -key $c/ecdsa256.key -cert_chain $c/ca.pem
  serve openssl-1.2-rsa-gcm256     9007 ok "" -- ossl -accept 9007 -tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384 -cert $c/rsa2048.pem -key $c/rsa2048.key -cert_chain $c/ca.pem
  # The flight in records of 512 bytes: the certificate alone spans several
  # (RFC 5246 6.2.1, RFC 8446 5.1). TLS-Anvil cannot show this for TLS 1.2 -
  # its fragmentation probe sends an ECDHE flight without ServerKeyExchange.
  serve openssl-1.2-fragmented     9009 ok "" -- ossl -accept 9009 -tls1_2 -max_send_frag 512 -cipher ECDHE-RSA-AES128-GCM-SHA256 -cert $c/rsa2048.pem -key $c/rsa2048.key -cert_chain $c/ca.pem
  serve openssl-1.3-fragmented     9010 ok "" -- ossl -accept 9010 -tls1_3 -max_send_frag 512 -cert $c/rsa2048.pem -key $c/rsa2048.key -cert_chain $c/ca.pem
  if openssl list -kem-algorithms 2>/dev/null | grep -qi mlkem768; then
    echo openssl-mlkem >> "$work/implementations"
    serve openssl-1.3-x25519mlkem768 9008 ok "" -- ossl -accept 9008 -tls1_3 -groups X25519MLKEM768 -cert $c/ecdsa256.pem -key $c/ecdsa256.key -cert_chain $c/ca.pem
  fi
  # Refused, each for its own reason.
  serve refuse-expired             9201 refused expired -- ossl -accept 9201 -tls1_3 -cert $c/expired.pem -key $c/expired.key -cert_chain $c/ca.pem
  serve refuse-other-name          9202 refused localhost -- ossl -accept 9202 -tls1_3 -cert $c/othername.pem -key $c/othername.key -cert_chain $c/ca.pem
  serve refuse-strangers-ca        9203 refused certification -- ossl -accept 9203 -tls1_3 -cert $c/strangers.pem -key $c/strangers.key -cert_chain $c/stranger.pem
  serve refuse-tls1.1-only         9204 refused protocol_version -- ossl -accept 9204 -tls1_1 -cipher 'DEFAULT@SECLEVEL=0' -cert $c/rsa2048.pem -key $c/rsa2048.key -cert_chain $c/ca.pem
  serve refuse-static-rsa-only     9205 refused handshake_failure -- ossl -accept 9205 -tls1_2 -cipher AES128-GCM-SHA256 -cert $c/rsa2048.pem -key $c/rsa2048.key -cert_chain $c/ca.pem
  serve refuse-cbc-only            9206 refused handshake_failure -- ossl -accept 9206 -tls1_2 -cipher ECDHE-ECDSA-AES128-SHA256 -cert $c/ecdsa256.pem -key $c/ecdsa256.key -cert_chain $c/ca.pem
  serve refuse-chacha-only         9207 refused handshake_failure -- ossl -accept 9207 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert $c/ecdsa256.pem -key $c/ecdsa256.key -cert_chain $c/ca.pem
fi
if has gnutls-serv; then
  echo gnutls >> "$work/implementations"
  gnutls() { gnutls-serv --http --disable-client-cert --x509certfile "$1" --x509keyfile "$2" -p "$3" --priority "$4"; }
  serve gnutls-1.3-ecdsa           9101 ok "" -- gnutls $c/ecdsa256.chain.pem $c/ecdsa256.key 9101 'NORMAL:-VERS-ALL:+VERS-TLS1.3'
  serve gnutls-1.3-rsa             9102 ok "" -- gnutls $c/rsa2048.chain.pem $c/rsa2048.key 9102 'NORMAL:-VERS-ALL:+VERS-TLS1.3'
  serve gnutls-1.2-ecdsa           9103 ok "" -- gnutls $c/ecdsa256.chain.pem $c/ecdsa256.key 9103 'NORMAL:-VERS-ALL:+VERS-TLS1.2'
  serve gnutls-1.2-rsa             9104 ok "" -- gnutls $c/rsa2048.chain.pem $c/rsa2048.key 9104 'NORMAL:-VERS-ALL:+VERS-TLS1.2'
fi
if has go; then
  echo go >> "$work/implementations"
  (cd "$here/goserver" && go build -o "$work/goserver" .)
  serve go-1.3-ecdsa               9301 ok "" -- "$work/goserver" -port 9301 -cert $c/ecdsa256.chain.pem -key $c/ecdsa256.key -version 1.3
  serve go-1.3-rsa                 9302 ok "" -- "$work/goserver" -port 9302 -cert $c/rsa2048.chain.pem -key $c/rsa2048.key -version 1.3
  serve go-1.2-ecdsa               9303 ok "" -- "$work/goserver" -port 9303 -cert $c/ecdsa256.chain.pem -key $c/ecdsa256.key -version 1.2
fi
if has miniserve; then
  echo rustls >> "$work/implementations"
  mkdir -p "$work/www" && echo interop > "$work/www/index.html"
  serve rustls-ecdsa               9401 ok "" -- miniserve -i 127.0.0.1 -p 9401 --tls-cert $c/ecdsa256.chain.pem --tls-key $c/ecdsa256.p8.key "$work/www"
  serve rustls-rsa                 9402 ok "" -- miniserve -i 127.0.0.1 -p 9402 --tls-cert $c/rsa2048.chain.pem --tls-key $c/rsa2048.p8.key "$work/www"
fi
if has java; then
  echo jsse >> "$work/implementations"
  serve jsse-1.3-ecdsa             9501 ok "" -- java "$here/JsseServer.java" 9501 $c/ecdsa256.p12 TLSv1.3
  serve jsse-1.2-rsa               9502 ok "" -- java "$here/JsseServer.java" 9502 $c/rsa2048.p12 TLSv1.2
fi

# Ready when every port answers.
for port in $(awk '{print $2}' "$cases"); do
  for _ in $(seq 1 60); do
    (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null && break
    sleep 0.5
  done
done
printf 'export SECLUME_TLS_INTEROP=%s\nexport SECLUME_TLS_INTEROP_CA=%s\n' "$cases" "$certs/ca.pem" > "$work/env"
echo "$(wc -l < "$cases") cases from: $(tr '\n' ' ' < "$work/implementations")"
