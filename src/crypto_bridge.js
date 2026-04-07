function toUint8Array(bytes) {
  if (bytes instanceof Uint8Array) return bytes;
  return new Uint8Array(bytes);
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }

  return btoa(binary);
}

export async function sha256_base64_from_bytes(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", toUint8Array(bytes));
  return arrayBufferToBase64(digest);
}

export async function import_pkcs8_private_key(bytes) {
  return crypto.subtle.importKey(
    "pkcs8",
    toUint8Array(bytes),
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );
}

export async function sign_string_base64(input, key) {
  const data = new TextEncoder().encode(input);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);
  return arrayBufferToBase64(sig);
}
