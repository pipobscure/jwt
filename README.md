# @pipobscure/jwt

A lightweight, dependency-free JWT (JSON Web Token) utility built on the Web Crypto API.

Supports **HMAC**, **RSA**, and **ECDSA** signature algorithms (HS*, RS*, ES*, PS*).  
Implements creation, signing, verification, and extraction of JWTs with minimal overhead.

## Supported Algorithms

| Algorithm | Type   | Hash      | Notes |
|------------|--------|-----------|-------|
| HS256      | HMAC   | SHA-256   | Symmetric (shared secret) |
| HS384      | HMAC   | SHA-384   | Symmetric (shared secret) |
| HS512      | HMAC   | SHA-512   | Symmetric (shared secret) |
| RS256      | RSA    | SHA-256   | Asymmetric (RSA PKCS#1 v1.5) |
| RS384      | RSA    | SHA-384   | Asymmetric (RSA PKCS#1 v1.5) |
| RS512      | RSA    | SHA-512   | Asymmetric (RSA PKCS#1 v1.5) |
| ES256      | ECDSA  | SHA-256   | Asymmetric (P-256 curve) |
| ES384      | ECDSA  | SHA-384   | Asymmetric (P-384 curve) |
| ES512      | ECDSA  | SHA-512   | Asymmetric (P-384 curve) |
| PS256      | RSA-PSS | SHA-256  | Asymmetric (RSA PSS) |
| PS384      | RSA-PSS | SHA-384  | Asymmetric (RSA PSS) |
| PS512      | RSA-PSS | SHA-512  | Asymmetric (RSA PSS) |

## API Overview

### `generate(payload: any, key?: CryptoKey): Promise<string>`

Creates and signs a new JWT.

**Parameters**
- `payload`: Any serializable JavaScript object to embed in the JWT.
- `key`: A `CryptoKey` object usable for signing.

**Returns**
- A `Promise<string>` — the encoded and signed JWT string (`header.payload.signature`).

**Example**

```ts
import { generate } from '@pipobscure/jwt';

const jwt = await generate({ sub: 'user123', exp: 1710000000 }, secretKey);
console.log(jwt);
```

### `extract(jwt: string, key?: CryptoKey): Promise<any>`

Extracts and decodes the payload from a JWT, optionally verifying the signature.

**Parameters**
- `jwt`: The JWT string.
- `key`: *(optional)* A `CryptoKey`. If provided, the signature will be verified before extraction.

**Returns**
- The decoded payload object.

**Throws**
- `Error('invalid signature')` if verification fails when a key is supplied.

**Example**
```ts
const payload = await extract(token, publicKey);
console.log(payload.sub);
```

### `header(jwt: string): { typ: string; alg: Algorithm }`

Returns the decoded header section of a JWT.

**Example**
```ts
const { alg } = header(token);
console.log(`Algorithm used: ${alg}`);
```

### `payload(jwt: string): any`

Returns the decoded payload section of a JWT **without verifying** the signature.

**Example**
```ts
const claims = payload(token);
console.log(claims.exp);
```

### `sign(alg: Algorithm, key: CryptoKey, payload: Uint8Array) : Promise<string>`

Signs the `payload` using the `alg` and `key` and returns the Base64 encoded signature.

### `verify(alg: Algorithm, key: CryptoKey, signature: string, payload: Uint8Array) : Promise<boolean>`

Verifies the `signature` is valid for the `payload`.

## Key Management

You can create compatible keys using the Web Crypto API:

```ts
// Example: Generate HMAC key
const key = await crypto.subtle.generateKey(
  { name: 'HMAC', hash: 'SHA-256' },
  true,
  ['sign', 'verify']
);
```

Or import an existing key:
```ts
const key = await crypto.subtle.importKey(
  'raw',
  new TextEncoder().encode('supersecret'),
  { name: 'HMAC', hash: 'SHA-256' },
  false,
  ['sign', 'verify']
);
```

## License

Copyright 2025 Philipp Dunkel

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
