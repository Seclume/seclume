# seclume-admission Helm chart

The admission webhook of [seclume-admission](../../), as a chart. Pods that ask for it by
annotation get two things:
- a dump folder, with a sidecar that redacts every heap dump and Flight Recorder recording
  where it lies;
- the SPIFFE Workload API socket.

See [DIAGNOSTICS.md](../../../DIAGNOSTICS.md#injected-by-annotation-the-admission-webhook) for
what is injected and why.

```sh
./mvnw -pl seclume-admission,seclume-heapcheck -am package -DskipTests
seclume-admission/deploy/build-image.sh registry.example/seclume-admission:0.14.0
docker push registry.example/seclume-admission:0.14.0

helm install seclume-admission seclume-admission/helm/seclume-admission \
  --namespace seclume-system --create-namespace \
  --set image.repository=registry.example/seclume-admission
kubectl label namespace shop seclume.space/inject=enabled
```

## The serving certificate

| `tls.mode` | Where the certificate comes from |
|---|---|
| `selfSigned` (default) | Helm makes a CA and a certificate on install and keeps both across upgrades, so the secret and `caBundle` always agree |
| `certManager` | cert-manager issues it (`tls.certManager.issuerRef`, or a self-signed `Issuer` the chart makes) and its CA injector sets `caBundle`; renewals are picked up without a restart |
| `existingSecret` | a `kubernetes.io/tls` secret of yours (`tls.existingSecret`), with its CA in `tls.caBundle` |

The webhook reads its key with seclume-keys into native memory and checks the files every
minute.

## Values

| Value | Default | |
|---|---|---|
| `image.repository` | - | required; the image from `deploy/build-image.sh` |
| `image.tag` / `image.digest` | appVersion / - | a digest wins over the tag |
| `replicaCount` | 2 | with a PodDisruptionBudget of `minAvailable: 1` |
| `webhook.failurePolicy` | `Ignore` | a webhook that cannot be reached lets the pod through |
| `webhook.namespaceSelector` | `seclume.space/inject: enabled` | only these namespaces are sent to it |
| `webhook.timeoutSeconds` | 5 | |
| `sidecar.intervalSeconds` | 10 | how often the sidecar looks at the folder |
| `sidecar.native` | false | an init container with `restartPolicy: Always` (Kubernetes 1.29+): a Job's pod can complete |
| `sidecar.memory` | 256Mi | request and limit |
| `sidecar.dumpSizeLimit` | - | the dump folder's `sizeLimit` |
| `sidecar.image` | the webhook's image | an image with Java 25 and `seclume-heapcheck.jar` |
| `spiffe.csiDriver` | `csi.spiffe.io` | |
| `spiffe.hostPath` | - | a host directory with the socket, instead of the CSI driver |
| `spiffe.mountPath`, `spiffe.socket` | `/spiffe-workload-api`, `spire-agent.sock` | |

The pod runs as non-root with a read-only root file system and no capabilities
(`podSecurityContext`, `securityContext`).
