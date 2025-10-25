declare global {
	interface Uint8ArrayConstructor {
		fromBase64: (base64: string) => Uint8Array;
		fromHex: (hex: string) => Uint8Array;
	}

	interface Uint8Array {
		toBase64: () => string;
		toHex: () => string;
	}
}

export const ALGORITHMS = {
	HS256: {
		name: 'HMAC',
		hash: 'SHA-256',
	},
	HS384: {
		name: 'HMAC',
		hash: 'SHA-384',
	},
	HS512: {
		name: 'HMAC',
		hash: 'SHA-512',
	},
	RS256: {
		name: 'RSASSA-PKCS1-v1_5',
		hash: 'SHA-256',
	},
	RS384: {
		name: 'RSASSA-PKCS1-v1_5',
		hash: 'SHA-384',
	},
	RS512: {
		name: 'RSASSA-PKCS1-v1_5',
		hash: 'SHA-512',
	},
	ES256: {
		name: 'ECDSA',
		namedCurve: 'P-256',
		hash: 'SHA-256',
	},
	ES384: {
		name: 'ECDSA',
		namedCurve: 'P-384',
		hash: 'SHA-384',
	},
	ES512: {
		name: 'ECDSA',
		namedCurve: 'P-384',
		hash: 'SHA-512',
	},
	PS256: {
		name: 'RSA-PSS',
		hash: 'SHA-256',
		saltLength: 32,
	},
	PS384: {
		name: 'RSA-PSS',
		hash: 'SHA-384',
		saltLength: 48,
	},
	PS512: {
		name: 'RSA-PSS',
		hash: 'SHA-512',
		saltLength: 63,
	},
} as const;

export type Algorithm = keyof typeof ALGORITHMS;
export const Algorithms = Object.keys(ALGORITHMS) as Algorithm[];
type Header = { typ: 'jwt'; alg: Algorithm };

function stringifyB64(value: any) {
	return new TextEncoder().encode(JSON.stringify(value)).toBase64();
}
function parseB64(buffer: string | Uint8Array | ArrayBuffer) {
	if ('string' === typeof buffer) buffer = Uint8Array.fromBase64(buffer);
	if (buffer instanceof ArrayBuffer) buffer = new Uint8Array(buffer);
	const text = new TextDecoder().decode(buffer);
	return JSON.parse(text);
}

function parts(jwt: string) {
	const parts = jwt.split('.');
	if (parts.length < 2 || parts.length > 3) throw new TypeError('invalid token format');
	const [header, payload, signature] = parts as [string, string, string | undefined];
	return { header, payload, signature };
}

export function header(jwt: string) {
	const { typ, alg } = parseB64(parts(jwt).header);
	return { typ, alg };
}
export function payload(jwt: string) {
	return parseB64(parts(jwt).payload);
}

export async function verify(jwt: string, key: CryptoKey) {
	const { header, payload, signature } = parts(jwt);
	if (!signature) return false;
	const hdr = parseB64(header) as Header;
	const sigtxt = [header, payload].join('.');
	//console.error(`verify(${sigtxt}) == ${signature}`);
	const sigdat = new TextEncoder().encode(sigtxt);
	return await crypto.subtle.verify(ALGORITHMS[hdr.alg], key, Uint8Array.fromBase64(signature) as BufferSource, sigdat);
}

export async function generate(alg: Algorithm, key: CryptoKey, payload: any) {
	const hdr = stringifyB64({ typ: 'jwt', alg });
	const pld = stringifyB64(payload);
	const sigtxt = [hdr, pld].join('.');
	const sigdat = new TextEncoder().encode(sigtxt);
	const sig = new Uint8Array(await crypto.subtle.sign(ALGORITHMS[alg], key, sigdat)).toBase64();
	return [hdr, pld, sig].join('.');
}

export async function extract(jwt: string, key?: CryptoKey) {
	if (key && !(await verify(jwt, key))) throw new Error('invalid signature');
	return payload(jwt);
}
