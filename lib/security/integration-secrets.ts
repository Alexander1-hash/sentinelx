import "server-only";

const encoder = new TextEncoder();

function getKeyMaterial() {
  const raw = process.env.TRINORIN_INTEGRATION_ENCRYPTION_KEY;
  if (!raw) throw new Error("Missing TRINORIN_INTEGRATION_ENCRYPTION_KEY.");

  const normalized = raw.trim();
  let bytes: Uint8Array;

  if (/^[0-9a-fA-F]{64}$/.test(normalized)) {
    bytes = new Uint8Array(
      normalized.match(/.{2}/g)!.map((part) => parseInt(part, 16)),
    );
  } else {
    const binary = atob(normalized);
    bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  }

  if (bytes.length !== 32) {
    throw new Error(
      "TRINORIN_INTEGRATION_ENCRYPTION_KEY must decode to exactly 32 bytes.",
    );
  }

  // Create an ArrayBuffer-backed copy so TypeScript's Web Crypto typings
  // remain compatible with newer lib.dom definitions.
  const keyBytes = new Uint8Array(32);
  keyBytes.set(bytes);

  return crypto.subtle.importKey(
    "raw",
    keyBytes.buffer,
    "AES-GCM",
    false,
    ["encrypt", "decrypt"],
  );
}

function toBase64Url(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function fromBase64Url(value: string) {
  const padded =
    value.replaceAll("-", "+").replaceAll("_", "/") +
    "=".repeat((4 - (value.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

export async function encryptIntegrationState(
  value: Record<string, unknown>,
) {
  const key = await getKeyMaterial();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encoder.encode(JSON.stringify(value)),
    ),
  );
  return `${toBase64Url(iv)}.${toBase64Url(ciphertext)}`;
}

export async function decryptIntegrationState<T>(
  value: string,
): Promise<T | null> {
  try {
    const [ivPart, ciphertextPart] = value.split(".");
    if (!ivPart || !ciphertextPart) return null;

    const key = await getKeyMaterial();
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64Url(ivPart) },
      key,
      fromBase64Url(ciphertextPart),
    );
    return JSON.parse(new TextDecoder().decode(plaintext)) as T;
  } catch {
    return null;
  }
}

export async function encryptIntegrationSecret(value: string) {
  return encryptIntegrationState({ value });
}

export async function decryptIntegrationSecret(value: string) {
  const result = await decryptIntegrationState<{ value?: unknown }>(value);
  return typeof result?.value === "string" ? result.value : null;
}
