package com.icure.kryptom.crypto.external

import com.icure.kryptom.crypto.PrivateRsaKey
import com.icure.kryptom.crypto.PrivateRsaKeyJwk
import com.icure.kryptom.crypto.PublicRsaKey
import com.icure.kryptom.crypto.PublicRsaKeyJwk
import com.icure.kryptom.crypto.RsaAlgorithm
import com.icure.kryptom.crypto.RsaKeypair
import kotlin.js.Promise

external interface XRsaService {
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
	 * Loads the rsa keypair given the PKCS8 representation of the private key. Note that there is no way to guarantee
	 * that the provided algorithm matches the algorithm chosen on key generation.
	 */
	fun loadKeyPairPkcs8(algorithm: String, privateKeyPkcs8: ByteArray): Promise<XRsaKeypair>

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

external interface XRsaKeypair {
	val private: XPrivateRsaKey
	val public: XPublicRsaKey
}

fun <A : RsaAlgorithm> XRsaKeypair.toKryptom(algorithm: A): RsaKeypair<A> {
	return RsaKeypair(private.toKryptom(algorithm), public.toKryptom(algorithm))
}

// TODO switch to @JsPlainObject on kotlin 2
@Suppress("UNUSED_VARIABLE", "UnsafeCastFromDynamic")
fun RsaKeypair<*>.toExternal(): XRsaKeypair {
	val private = this.private.toExternal()
	val public = this.public.toExternal()
	return js("({private: private, public: public})")
}

external interface XPrivateRsaKey {
	val privateKey: dynamic
	val algorithm: String
}

fun <A : RsaAlgorithm> XPrivateRsaKey.toKryptom(algorithm: A): PrivateRsaKey<A> {
	if (this.algorithm != algorithm.identifier) {
		throw AssertionError("Algorithm mismatch: ${this.algorithm} != ${algorithm.identifier}")
	}
	return PrivateRsaKey(privateKey, algorithm)
}

fun XPrivateRsaKey.toKryptom(): PrivateRsaKey<RsaAlgorithm> {
	return PrivateRsaKey(privateKey, RsaAlgorithm.fromIdentifier(algorithm))
}

fun XPrivateRsaKey.toKryptomSignature(): PrivateRsaKey<RsaAlgorithm.RsaSignatureAlgorithm> {
	return PrivateRsaKey(privateKey, RsaAlgorithm.RsaSignatureAlgorithm.fromIdentifier(algorithm))
}

fun XPrivateRsaKey.toKryptomEncryption(): PrivateRsaKey<RsaAlgorithm.RsaEncryptionAlgorithm> {
	return PrivateRsaKey(privateKey, RsaAlgorithm.RsaEncryptionAlgorithm.fromIdentifier(algorithm))
}

// TODO switch to @JsPlainObject on kotlin 2
@Suppress("UNUSED_VARIABLE", "UNCHECKED_CAST_TO_EXTERNAL_INTERFACE")
fun PrivateRsaKey<*>.toExternal(): XPrivateRsaKey {
	val algorithmIdentifier = this.algorithm.identifier
	val thisKey = this.key
	return js("({privateKey: thisKey, algorithm: algorithmIdentifier})") as XPrivateRsaKey
}

external interface XPublicRsaKey {
	val publicKey: dynamic
	val algorithm: String
}

fun <A : RsaAlgorithm> XPublicRsaKey.toKryptom(algorithm: A): PublicRsaKey<A> {
	if (this.algorithm != algorithm.identifier) {
		throw AssertionError("Algorithm mismatch: ${this.algorithm} != ${algorithm.identifier}")
	}
	return PublicRsaKey(publicKey, algorithm)
}

fun XPublicRsaKey.toKryptom(): PublicRsaKey<RsaAlgorithm> {
	return PublicRsaKey(publicKey, RsaAlgorithm.fromIdentifier(algorithm))
}

fun XPublicRsaKey.toKryptomSignature(): PublicRsaKey<RsaAlgorithm.RsaSignatureAlgorithm> {
	return PublicRsaKey(publicKey, RsaAlgorithm.RsaSignatureAlgorithm.fromIdentifier(algorithm))
}

fun XPublicRsaKey.toKryptomEncryption(): PublicRsaKey<RsaAlgorithm.RsaEncryptionAlgorithm> {
	return PublicRsaKey(publicKey, RsaAlgorithm.RsaEncryptionAlgorithm.fromIdentifier(algorithm))
}

// TODO switch to @JsPlainObject on kotlin 2
@Suppress("UNUSED_VARIABLE", "UNCHECKED_CAST_TO_EXTERNAL_INTERFACE")
fun PublicRsaKey<*>.toExternal(): XPublicRsaKey {
	val algorithmIdentifier = this.algorithm.identifier
	val thisKey = this.key
	return js("({publicKey: thisKey, algorithm: algorithmIdentifier})") as XPublicRsaKey
}

fun JsonWebKey.toPrivateJwk() = PrivateRsaKeyJwk(
	alg = requireNotNull(alg) { "alg can't be null for a private JsonWebKey" },
	d = requireNotNull(d) { "d can't be null for a private JsonWebKey" },
	dp = requireNotNull(dp) { "dp can't be null for a private JsonWebKey" },
	dq = requireNotNull(dq) { "dq can't be null for a private JsonWebKey" },
	e = requireNotNull(e) { "e can't be null for a private JsonWebKey" },
	ext = requireNotNull(ext) { "ext can't be null for a private JsonWebKey" },
	key_ops = requireNotNull(key_ops) { "key_ops can't be null for a private JsonWebKey" }.toSet(),
	n = requireNotNull(n) { "n can't be null for a private JsonWebKey" },
	p = requireNotNull(p) { "p can't be null for a private JsonWebKey" },
	q = requireNotNull(q) { "q can't be null for a private JsonWebKey" },
	qi = requireNotNull(qi) { "qi can't be null for a private JsonWebKey" },
)

fun JsonWebKey.toPublicJwk() = PublicRsaKeyJwk(
	alg = requireNotNull(alg) { "alg can't be null for a public JsonWebKey" },
	e = requireNotNull(e) { "e can't be null for a public JsonWebKey" },
	ext = requireNotNull(ext) { "ext can't be null for a public JsonWebKey" },
	key_ops = requireNotNull(key_ops) { "key_ops can't be null for a public JsonWebKey" }.toSet(),
	n = requireNotNull(n) { "n can't be null for a public JsonWebKey" },
)

@Suppress("UNCHECKED_CAST_TO_EXTERNAL_INTERFACE", "UNUSED_VARIABLE")
fun PrivateRsaKeyJwk.toPrivateJwk(): JsonWebKey {
	val alg = alg
	val d = d
	val dp = dp
	val dq = dq
	val e = e
	val ext = ext
	val key_ops = key_ops.toTypedArray()
	val n = n
	val p = p
	val q = q
	val qi = qi
	return js("{alg:alg,d:d,dp:dp,dq:dq,e:e,ext:ext,key_ops:key_ops,n:n,p:p,q:q,qi:qi}") as JsonWebKey
}

@Suppress("UNCHECKED_CAST_TO_EXTERNAL_INTERFACE", "UNUSED_VARIABLE")
fun PublicRsaKeyJwk.toPublicJwk(): JsonWebKey {
	val alg = alg
	val e = e
	val ext = ext
	val key_ops = key_ops.toTypedArray()
	val n = n
	return js("{alg:alg,e:e,ext:ext,key_ops:key_ops,n:n}") as JsonWebKey
}

external interface JsonWebKey {
	val alg: String?
	val d: String?
	val dp: String?
	val dq: String?
	val e: String?
	val ext: Boolean?
	val key_ops: Array<String>?
	val n: String?
	val p: String?
	val q: String?
	val qi: String?
}
