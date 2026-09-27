import { NextResponse } from "next/server";

const catalog = [
  { id: "cloud", name: "Cloud Security", integrationTypes: ["cloud_security"], actions: ["contain_asset","disable_integration","isolate_endpoint","block_indicator"] },
  { id: "identity", name: "Identity Security", integrationTypes: ["identity_provider"], actions: ["revoke_access"] },
  { id: "endpoint", name: "Endpoint Security", integrationTypes: ["endpoint_security"], actions: ["contain_asset","isolate_endpoint"] },
  { id: "network", name: "Network Security", integrationTypes: ["network_security"], actions: ["block_indicator"] },
  { id: "application", name: "Business Application Security", integrationTypes: ["business_application"], actions: ["disable_integration"] },
  { id: "database", name: "Database Telemetry", integrationTypes: ["database_telemetry"], actions: [] },
];
export async function GET() {
  return NextResponse.json({ catalog, boundary: "Catalog describes supported SentinelX integration contracts. It does not claim a provider is connected." });
}
