package com.icure.kryptom.crypto.external

import kotlin.js.Promise

external interface XHmacService {
	/**
	 * Generates a new hmac key for a specific algorithm. The key size is determined by the algorithm.
	 */
	fun generateKey(algorithm: String, keySize: Int?): Promise<XHmacKey>

	/**
	 * Exports a key to a byte array.
	 */
	fun exportKey(key: XHmacKey): Promise<ByteArray>

	/**
	 * Imports a key from a byte array. The key size must match the algorithm.
	 */
	fun loadKey(algorithm: String, bytes: ByteArray): Promise<XHmacKey>

	/**
	 * Generates a signature for some data using the provided key and algorithm.
	 */
	fun sign(data: ByteArray, key: XHmacKey): Promise<ByteArray>

	/**
	 * Verifies that a signature matches the provided data, using the provided key and algorithm.
	 */
	fun verify(
		signature: ByteArray,
		data: ByteArray,
		key: XHmacKey
	): Promise<Boolean>
}