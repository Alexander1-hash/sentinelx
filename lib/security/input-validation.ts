export function cleanText(value: unknown, max = 500) {
  if (typeof value !== "string") return "";
  return value.trim().replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "").slice(0, max);
}

export function cleanId(value: unknown) {
  const text = cleanText(value, 128);
  return /^[a-zA-Z0-9_-]+$/.test(text) ? text : "";
}

export function isSafeHttpUrl(value: unknown) {
  const text = cleanText(value, 2048);
  try {
    const url = new URL(text);
    return url.protocol === "https:";
  } catch {
    return false;
  }
}
