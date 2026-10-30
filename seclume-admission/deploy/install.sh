#!/usr/bin/env bash
# Installs the webhook with a certificate authority of its own, made here
# with openssl - for a test cluster, or where cert-manager is not used.
# usage: SECLUME_IMAGE=<image> install.sh
set -euo pipefail
image=${SECLUME_IMAGE:?set SECLUME_IMAGE to the image deploy/build-image.sh built}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
service=seclume-admission.seclume-system.svc
(
  cd "$work"
  umask 077
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
    -subj "/CN=seclume-admission CA" -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$service" \
    -keyout tls.key -out tls.csr 2>/dev/null
  printf 'subjectAltName=DNS:%s,DNS:%s.cluster.local\nextendedKeyUsage=serverAuth\n' \
    "$service" "$service" > tls.ext
  openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
    -extfile tls.ext -out tls.crt 2>/dev/null
)
kubectl apply -f - <<< 'apiVersion: v1
kind: Namespace
metadata:
  name: seclume-system'
kubectl -n seclume-system create secret tls seclume-admission-tls \
  --cert="$work/tls.crt" --key="$work/tls.key" --dry-run=client -o yaml | kubectl apply -f -
bundle=$(base64 -w0 < "$work/ca.crt")
sed -e "s|SECLUME_IMAGE|$image|g" -e "s|SECLUME_CA_BUNDLE|$bundle|" \
  "$here/seclume-admission.yaml" | kubectl apply -f -
