import * as Assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import * as JWT from './jwt.ts';

function createParams(alg: string) {
	if (alg.startsWith('HS')) return { name: 'HMAC', hash: alg.replace(/^HS/, 'SHA-') };
	if (alg.startsWith('RS')) return { name: 'RSASSA-PKCS1-v1_5', modulusLength: 1026, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: alg.replace(/^RS/, 'SHA-') };
	if (alg.startsWith('PS')) return { name: 'RSA-PSS', modulusLength: 1026, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: alg.replace(/^PS/, 'SHA-') };
	if (alg.startsWith('ES')) return { name: 'ECDSA', namedCurve: 'P-256', hash: alg.replace(/^ES/, 'SHA-') };
	throw new Error('invalid algorithm');
}
async function createKeys(alg: JWT.Algorithm) {
	const keys = await crypto.subtle.generateKey(createParams(alg), true, ['sign', 'verify']);
	const verifyKey = (keys as CryptoKeyPair).publicKey ?? (keys as CryptoKey);
	const signKey = (keys as CryptoKeyPair).privateKey ?? (keys as CryptoKey);
	return { signKey, verifyKey };
}

(Object.keys(JWT.ALGORITHMS) as JWT.Algorithm[]).forEach((alg: JWT.Algorithm) => {
	describe(alg, () => {
		let token = '';
		const keys = createKeys(alg);

		it('can generate a token', async () => {
			token = await JWT.generate(alg, (await keys).signKey, { test: alg });
			Assert.ok(token.length);
		});
		it('can verify a token', async () => {
			Assert.ok(token.length);
			Assert.ok(await JWT.verify(token, (await keys).verifyKey));
		});
		it('can get the payload', async () => {
			Assert.ok(token.length);
			const pld = await JWT.payload(token);
			Assert.deepEqual(pld, { test: alg });
		});
		it('can get the header', async () => {
			Assert.ok(token.length);
			const hdr = await JWT.header(token);
			Assert.deepEqual(hdr, { typ: 'jwt', alg });
		});
		it('can extract', async () => {
			Assert.ok(token.length);
			Assert.deepEqual(await JWT.extract(token, (await keys).verifyKey), { test: alg });
		});
	});
});
