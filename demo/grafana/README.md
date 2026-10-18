# A Grafana dashboard for seclume

`seclume-dashboard.json` shows seclume's pools, logins, TLS handshakes and secrets from the
Spring Boot starter's Micrometer meters, scraped by Prometheus. No panel shows a user, a host
or a value: statements appear by their fingerprint, the shape without the literals.

## What it needs

- The starter with Micrometer and the Prometheus registry
  (`io.micrometer:micrometer-registry-prometheus`), and the endpoint exposed:
  `management.endpoints.web.exposure.include=prometheus`.
- For the logins, TLS, secrets and slow statements, the event meters as well:
  `seclume.metrics.events=true`, or `seclume.metrics.queries=true` for the slow statements
  too. The pool panels need neither.
- Optionally an `application` tag on every meter
  (`management.metrics.tags.application=${spring.application.name}`), so that one dashboard
  can tell several applications apart. Without it the selector shows nothing and the panels
  show everything.

## Importing

Grafana, *Dashboards*, *New*, *Import*, upload the file, and pick the Prometheus data source.

## What to look at first

- **Saturation** near 100 % with threads waiting comes before timeouts.
- **Problems in the last hour** should be all zeros. A timeout is a request that failed, a
  refused reset closed a connection, and a leak is a connection held past the threshold.
- **Waiting for a connection, p99**, against **Held by the application, p99**: long holds
  are what makes others wait.
- **Opening a connection, p99**: a rise points at the server, the network or the secret
  source, and the login and TLS panels below tell which.
