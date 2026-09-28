# Trinorin Endpoint Agent

Reference endpoint component for authorized Windows, macOS and Linux integrations.

## Lifecycle

1. Register an Endpoint integration in Trinorin.
2. Keep the one-time ingestion credential private.
3. Set `TRINORIN_URL` and `TRINORIN_TOKEN`.
4. Run `node src/index.mjs claim --platform windows --os-version "..." --agent-version "0.1.0"` once.
5. Run `node src/index.mjs heartbeat --posture healthy` periodically.
6. Send authorized security telemetry with `node src/index.mjs telemetry`.

The reference component deliberately collects only local identity/posture metadata and sends it to the Trinorin APIs. It does not claim to provide antivirus, EDR, kernel monitoring, exploit prevention, or native mobile protection.

For production packaging, platform-specific secure credential storage, code signing, update verification, least-privilege service installation, and OS-native security collectors must be added before customer deployment.
