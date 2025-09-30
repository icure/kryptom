package com.icure.kryptom.crypto

interface HmacService {
	/**
	 * Generates a new hmac key for a specific algorithm.
	 *
	 * @param algorithm the [HmacAlgorithm].
	 * @param keySize the key size. If null (default behaviour), [HmacAlgorithm.recommendedKeySize] will be used.
	 * Note: for general usage the key size shouldn't be less than [HmacAlgorithm.minimumRecommendedKeySize], but in
	 * some applications (e.g. TOTP shorter lengths are acceptable)
	 * @param acceptsShortKeySize if false (default) key sizes shorter than the minimum recommended key size for the algorithm will be rejected
	 */
	suspend fun <A : HmacAlgorithm> generateKey(
		algorithm: A,
		keySize: Int? = null,
		acceptsShortKeySize: Boolean = false
	): HmacKey<A>

	/**
	 * Exports a key to a byte array.
	 */
	suspend fun exportKey(key: HmacKey<*>): ByteArray

	/**
	 * Imports a key from a byte array.
	 * @param acceptsShortKey if false (default) keys shorter than the minimum recommended key size for the algorithm will be rejected
	 */
	suspend fun <A : HmacAlgorithm> loadKey(
		algorithm: A,
		bytes: ByteArray,
		acceptsShortKeys: Boolean = false
	): HmacKey<A>

	/**
	 * Generates a signature for some data using the provided key and algorithm.
	 */
	suspend fun sign(data: ByteArray, key: HmacKey<*>): ByteArray

	/**
	 * Verifies that a signature matches the provided data, using the provided key and algorithm.
	 */
	suspend fun verify(
		signature: ByteArray,
		data: ByteArray,
		key: HmacKey<*>
	): Boolean
}