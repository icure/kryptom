package com.icure.kryptom.crypto.external

import com.icure.kryptom.crypto.RsaAlgorithm
import com.icure.kryptom.crypto.asn.AsnToJwkConverter
import com.icure.kryptom.crypto.asn.pkcs8PrivateToSpkiPublic
import com.icure.kryptom.crypto.asn.toAsn1
import kotlin.js.Promise

external interface PartialXRsaService {
	/**
	 * Generates a new rsa key pair, with default modulus length 2048.
	 * For security reasons the generated key should be used only for the provided algorithm.
	 * There is nothing in the underlying cryptographic algorithms that prevents you from using a
	 * key for various algorithms, but the actual implementations of the service may add metadata
	 * to keep track of the declared intended usage of the key and throw an exception when
	 * attempting to use the key for other purposes.
	 * For more info see https://crypto.stackexchange.com/questions/81819/same-private-key-for-signing-and-decryption
	 */
	fun generateKeyPair(algorithm: String, keySize: Int): Promise<XRsaKeypair>

	/**
	 * Exports the private key in pkcs8 format.
	 * @param key the key to export.
	 * @return representation of the key in pkcs8 format.
	 */
	fun exportPrivateKeyPkcs8(key: XPrivateRsaKey): Promise<ByteArray>

	/**
	 * Exports the public key in pkcs8 format.
	 * @param key the key to export.
	 * @return representation of the key in spki format (java X.509).
	 */
	fun exportPublicKeySpki(key: XPublicRsaKey): Promise<ByteArray>

	/**
	 * Loads the rsa private key given the pkcs8 representation of the private key. Note that there is no way to guarantee
	 * that the provided algorithm matches the algorithm chosen on key generation.
	 */
	fun loadPrivateKeyPkcs8(algorithm: String, privateKeyPkcs8: ByteArray): Promise<XPrivateRsaKey>

	/**
	 * Loads the rsa public key given the spki representation (java X.509) of the public key. Note that there is no way
	 * to guarantee that the provided algorithm matches the algorithm chosen on key generation.
	 */
	fun loadPublicKeySpki(algorithm: String, publicKeySpki: ByteArray): Promise<XPublicRsaKey>

	/**
	 * Encrypts data using the provided key and algorithm. There are limits to the size of data which can be encrypted
	 * depending on the chosen algorithm and key size.
	 */
	fun encrypt(
		data: ByteArray,
		publicKey: XPublicRsaKey
	): Promise<ByteArray>

	/**
	 * Decrypts data using the provided key and algorithm.
	 */
	fun decrypt(
		data: ByteArray,
		privateKey: XPrivateRsaKey
	): Promise<ByteArray>

	/**
	 * Generates a signature for some data using the provided key and algorithm.
	 */
	fun sign(
		data: ByteArray,
		privateKey: XPrivateRsaKey
	): Promise<ByteArray>

	/**
	 * Verifies that a signature matches the provided data, using the provided key and algorithm.
	 */
	fun verifySignature(
		signature: ByteArray,
		data: ByteArray,
		publicKey: XPublicRsaKey
	): Promise<Boolean>
}

external interface XRsaService : PartialXRsaService {
	/**
	 * Loads the rsa keypair given the PKCS8 representation of the private key. Note that there is no way to guarantee
	 * that the provided algorithm matches the algorithm chosen on key generation.
	 */
	fun loadKeyPairPkcs8(algorithm: String, privateKeyPkcs8: ByteArray): Promise<XRsaKeypair>

	/**
	 * Exports the private key in jwk format.
	 * @param key the key to export.
	 * @return representation of the key in jwk format.
	 */
	fun exportPrivateKeyJwk(key: XPrivateRsaKey): Promise<JsonWebKey>

	/**
	 * Exports the public key in jwk format.
	 * @param key the key to export.
	 * @return representation of the key in jwk format.
	 */
	fun exportPublicKeyJwk(key: XPublicRsaKey): Promise<JsonWebKey>

	/**
	 * Loads the rsa private key given the jwk representation of the private key.
	 */
	fun loadPrivateKeyJwk(privateKeyJwk: JsonWebKey): Promise<XPrivateRsaKey>

	/**
	 * Loads the rsa public key given the jwk representation of the public key.
	 */
	fun loadPublicKeyJwk(publicKeyJwk: JsonWebKey): Promise<XPublicRsaKey>
}

fun completePartialRsa(partialService: PartialXRsaService): XRsaService {
	val partialDynamic: dynamic = partialService
	if (
		partialDynamic.loadKeyPairPkcs8 != undefined &&
		partialDynamic.exportPrivateKeyJwk != undefined &&
		partialDynamic.exportPublicKeyJwk != undefined &&
		partialDynamic.loadPrivateKeyJwk != undefined &&
		partialDynamic.loadPublicKeyJwk != undefined
	) return partialDynamic
	val fullService = js("{}")
	fullService.generateKeyPair = partialDynamic.generateKeyPair
	fullService.exportPrivateKeyPkcs8 = partialDynamic.exportPrivateKeyPkcs8
	fullService.exportPublicKeySpki = partialDynamic.exportPublicKeySpki
	fullService.loadPrivateKeyPkcs8 = partialDynamic.loadPrivateKeyPkcs8
	fullService.loadPublicKeySpki = partialDynamic.loadPublicKeySpki
	fullService.encrypt = partialDynamic.encrypt
	fullService.decrypt = partialDynamic.decrypt
	fullService.sign = partialDynamic.sign
	fullService.verifySignature = partialDynamic.verifySignature
	if (partialDynamic.loadKeyPairPkcs8 != undefined) {
		fullService.loadKeyPairPkcs8 = partialDynamic.loadKeyPairPkcs8
	} else {
		fullService.loadKeyPairPkcs8 = fun (algorithm: String, privateKeyPkcs8: ByteArray): Promise<XRsaKeypair> {
			return Promise.all(
				arrayOf(
					partialService.loadPrivateKeyPkcs8(algorithm, privateKeyPkcs8),
					partialService.loadPublicKeySpki(algorithm, privateKeyPkcs8.toAsn1().pkcs8PrivateToSpkiPublic().pack()),
				)
			).then { keys ->
				js("{ private: keys[0], public: keys[1] }")
			}
		}
	}
	if (partialDynamic.exportPrivateKeyJwk != undefined) {
		fullService.exportPrivateKeyJwk = partialDynamic.exportPrivateKeyJwk
	} else {
		fullService.exportPrivateKeyJwk = fun (key: XPrivateRsaKey): Promise<JsonWebKey> {
			return partialService.exportPrivateKeyPkcs8(key).then { keyBytes ->
				AsnToJwkConverter.pkcs8ToJwk(
					RsaAlgorithm.fromIdentifier(key.algorithm),
					keyBytes
				).toPrivateJwk()
			}
		}
	}
	if (partialDynamic.exportPublicKeyJwk != undefined) {
		fullService.exportPublicKeyJwk = partialDynamic.exportPublicKeyJwk
	} else {
		fullService.exportPublicKeyJwk = fun (key: XPublicRsaKey): Promise<JsonWebKey> {
			return partialService.exportPublicKeySpki(key).then { keyBytes ->
				AsnToJwkConverter.spkiToJwk(
					RsaAlgorithm.fromIdentifier(key.algorithm),
					keyBytes
				).toPublicJwk()
			}
		}
	}
	if (partialDynamic.loadPrivateKeyJwk != undefined) {
		fullService.loadPrivateKeyJwk = partialDynamic.loadPrivateKeyJwk
	} else {
		fullService.loadPrivateKeyJwk = fun (privateKeyJwk: JsonWebKey): Promise<XPrivateRsaKey> {
			val jwkKt = privateKeyJwk.toPrivateJwk()
			return partialService.loadPrivateKeyPkcs8(
				RsaAlgorithm.fromJwkIdentifier(jwkKt.alg).identifier,
				AsnToJwkConverter.jwkToPkcs8(jwkKt)
			)
		}
	}
	if (partialDynamic.loadPublicKeyJwk != undefined) {
		fullService.loadPublicKeyJwk = partialDynamic.loadPublicKeyJwk
	} else {
		fullService.loadPublicKeyJwk = fun (publicKeyJwk: JsonWebKey): Promise<XPublicRsaKey> {
			val jwkKt = publicKeyJwk.toPublicJwk()
			return partialService.loadPublicKeySpki(
				RsaAlgorithm.fromJwkIdentifier(jwkKt.alg).identifier,
				AsnToJwkConverter.jwkToSpki(jwkKt)
			)
		}
	}
	return fullService
}
