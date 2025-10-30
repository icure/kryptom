package com.icure.kryptom.crypto

interface HmacService {
	/**
	 * Generates a new hmac key for a specific algorithm.
	 *
	 * @param algorithm the [HmacAlgorithm].
	 * @param keySize the key size, in bytes. If null (default behaviour), [HmacAlgorithm.recommendedKeySize] will be used.
	 * Note: for security reasons, the key size cannot be less than [HmacAlgorithm.minimumKeySize]
	 * @throws IllegalArgumentException if [keySize] is less than [HmacAlgorithm.minimumKeySize]
	 */
	suspend fun <A : HmacAlgorithm> generateKey(algorithm: A, keySize: Int? = null): HmacKey<A>

	/**
	 * Exports a key to a byte array.
	 */
	suspend fun exportKey(key: HmacKey<*>): ByteArray

	/**
	 * Imports a key from a byte array.
	 */
	suspend fun <A : HmacAlgorithm> loadKey(algorithm: A, bytes: ByteArray): HmacKey<A>

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