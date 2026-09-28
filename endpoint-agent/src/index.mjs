import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";

const baseUrl = (process.env.TRINORIN_URL || "").replace(/\/$/, "");
const token = process.env.TRINORIN_TOKEN || "";
const deviceFile = process.env.TRINORIN_DEVICE_FILE || ".trinorin-device.json";

if (!baseUrl || !token) {
  console.error("Set TRINORIN_URL and TRINORIN_TOKEN before running the endpoint agent.");
  process.exit(1);
}

function loadDeviceId() {
  if (existsSync(deviceFile)) {
    try {
      const parsed = JSON.parse(readFileSync(deviceFile, "utf8"));
      if (typeof parsed.deviceId === "string" && parsed.deviceId) return parsed.deviceId;
    } catch {}
  }
  const deviceId = randomUUID();
  writeFileSync(deviceFile, JSON.stringify({ deviceId }, null, 2), { mode: 0o600 });
  return deviceId;
}

async function call(path, payload) {
  const response = await fetch(baseUrl + path, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Trinorin request failed (${response.status})`);
  return data;
}

const deviceId = loadDeviceId();
const command = process.argv[2] || "heartbeat";

if (command === "claim") {
  const platform = process.argv[process.argv.indexOf("--platform") + 1] || "unknown";
  const osVersion = process.argv[process.argv.indexOf("--os-version") + 1] || "";
  const agentVersion = process.argv[process.argv.indexOf("--agent-version") + 1] || "0.1.0";
  console.log(JSON.stringify(await call("/api/security/endpoints/claim", {
    deviceId, platform, osVersion, agentVersion,
  }), null, 2));
} else if (command === "heartbeat") {
  const posture = process.argv[process.argv.indexOf("--posture") + 1] || "unknown";
  const osVersion = process.argv[process.argv.indexOf("--os-version") + 1] || "";
  const agentVersion = process.argv[process.argv.indexOf("--agent-version") + 1] || "0.1.0";
  console.log(JSON.stringify(await call("/api/security/endpoints/heartbeat", {
    deviceId, posture, osVersion, agentVersion,
  }), null, 2));
} else if (command === "telemetry") {
  const title = process.argv[process.argv.indexOf("--title") + 1] || "Trinorin endpoint telemetry";
  const summary = process.argv[process.argv.indexOf("--summary") + 1] || "Authorized endpoint telemetry event.";
  console.log(JSON.stringify(await call("/api/security/ingest", {
    deviceId,
    evidenceType: "telemetry",
    source: "trinorin_endpoint_agent",
    title,
    summary,
    securityState: "healthy",
    data: { agentVersion: process.argv[process.argv.indexOf("--agent-version") + 1] || "0.1.0" },
  }), null, 2));
} else {
  console.error("Usage: claim | heartbeat | telemetry");
  process.exit(1);
}
