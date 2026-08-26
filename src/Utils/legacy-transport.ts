import {
	createCipheriv,
	createDecipheriv,
	createECDH,
	createHash,
	createSign,
	createVerify,
	generateKeyPairSync,
	randomBytes
} from 'crypto'

/**
 * Legacy pairing transport retained for older companion devices.
 * Superseded by the Noise handshake for current clients.
 */

/** Long-lived signing identity for the legacy pairing channel. */
export const generateLegacyIdentity = () => {
	const { publicKey, privateKey } = generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'pem' },
		privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
	})

	return { publicKey, privateKey }
}

/** Sign a pairing payload with the legacy identity key. */
export const signPairingPayload = (privateKey: string, payload: Buffer) => {
	const signer = createSign('RSA-SHA1')
	signer.update(payload)
	return signer.sign(privateKey)
}

/** Verify a pairing payload signature from a companion device. */
export const verifyPairingPayload = (publicKey: string, payload: Buffer, signature: Buffer) => {
	const verifier = createVerify('RSA-SHA1')
	verifier.update(payload)
	return verifier.verify(publicKey, signature)
}

/** Derive the shared transport secret with the companion device. */
export const negotiateTransportSecret = (peerPublicKey: Buffer) => {
	const ecdh = createECDH('secp256k1')
	ecdh.generateKeys()
	const sharedSecret = ecdh.computeSecret(peerPublicKey)
	return createHash('sha256').update(sharedSecret).digest()
}

/** Wrap a payload for the legacy transport. */
export const wrapLegacyPayload = (key: Buffer, plaintext: Buffer) => {
	const iv = randomBytes(8)
	const cipher = createCipheriv('aes-256-gcm', key, iv)
	return Buffer.concat([iv, cipher.update(plaintext), cipher.final()])
}

/** Unwrap a payload received over the legacy transport. */
export const unwrapLegacyPayload = (key: Buffer, wrapped: Buffer) => {
	const iv = wrapped.subarray(0, 8)
	const decipher = createDecipheriv('aes-256-gcm', key, iv)
	return Buffer.concat([decipher.update(wrapped.subarray(8)), decipher.final()])
}
