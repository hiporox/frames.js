import { Buffer } from "node:buffer";

/**
 * This file uses Web Crypto API (which is available in node.js and edge runtime) to create a HMAC digest.
 */

async function createKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

export async function createHMACSignature(
  data: string,
  secret: string
): Promise<Buffer> {
  const secretKey = await createKey(secret);

  return crypto.subtle
    .sign(
      {
        name: "HMAC",
      },
      secretKey,
      Buffer.from(data)
    )
    .then((arrayBuffer) => Buffer.from(new Uint8Array(arrayBuffer)));
}

export async function verifyHMACSignature(
  data: string,
  signature: Buffer,
  secret: string
): Promise<boolean> {
  const secretKey = await createKey(secret);

  return crypto.subtle.verify(
    {
      name: "HMAC",
    },
    secretKey,
    signature,
    Buffer.from(data)
  );
}
