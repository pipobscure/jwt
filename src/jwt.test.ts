import * as Assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import * as JWT from './jwt.ts';

function createParams(alg: string) {
	if (alg.startsWith('HS')) return { name: 'HMAC', hash: alg.replace(/^HS/, 'SHA-') };
	if (alg.startsWith('RS')) return { name: 'RSASSA-PKCS1-v1_5', modulusLength: 1026, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: alg.replace(/^RS/, 'SHA-') };
	if (alg.startsWith('PS')) return { name: 'RSA-PSS', modulusLength: 1026, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: alg.replace(/^PS/, 'SHA-') };
	if (alg.startsWith('ES')) {
		if (alg === 'ES512') return { name: 'ECDSA', namedCurve: 'P-521', hash: 'SHA-512' };
		return { name: 'ECDSA', namedCurve: alg.replace(/^ES/, 'P-'), hash: alg.replace(/^ES/, 'SHA-') };
	}
	throw new Error('invalid algorithm');
}
async function createKeys(alg?: JWT.Algorithm) {
	if (!alg) return { signKey: undefined, verifyKey: undefined };
	const keys = await crypto.subtle.generateKey(createParams(alg), true, ['sign', 'verify']);
	const verifyKey = (keys as CryptoKeyPair).publicKey ?? (keys as CryptoKey);
	const signKey = (keys as CryptoKeyPair).privateKey ?? (keys as CryptoKey);
	return { signKey, verifyKey };
}
function testAlgorithm(alg?: JWT.Algorithm) {
	describe(alg ?? 'unsigned', () => {
		let token = '';
		const keys = createKeys(alg);

		it('can generate a token', async () => {
			token = await JWT.generate({ sub: 'test', test: alg ?? 'none' }, (await keys).signKey);
			Assert.ok(token.length);
		});
		it('can verify a token', async () => {
			Assert.ok(token.length);
			const { verifyKey } = await keys;
			if (!verifyKey) return;
			Assert.ok(await JWT.verify(token, verifyKey));
		});
		it('can get the payload', async () => {
			Assert.ok(token.length);
			const pld = await JWT.payload(token);
			Assert.deepEqual(pld, { sub: 'test', test: alg ?? 'none' });
		});
		it('can get the header', async () => {
			Assert.ok(token.length);
			const hdr = await JWT.header(token);
			Assert.deepEqual(hdr, { typ: 'jwt', alg });
		});
		it('can extract', async () => {
			Assert.ok(token.length);
			Assert.deepEqual(await JWT.extract(token, (await keys).verifyKey), { sub: 'test', test: alg ?? 'none' });
		});
	});
}

testAlgorithm();
(Object.keys(JWT.ALGORITHMS) as JWT.Algorithm[]).forEach((alg) => {
	//if (alg !== 'PS256') return;
	testAlgorithm(alg);
});
