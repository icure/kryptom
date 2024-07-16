package com.icure.kryptom.crypto

import com.icure.kryptom.js.jsCrypto
import com.icure.kryptom.js.toArrayBuffer
import com.icure.kryptom.js.toByteArray
import kotlinx.coroutines.await
import org.khronos.webgl.ArrayBuffer
import kotlin.js.json

object JsHmacService : HmacService {
	private const val ALGORITHM_NAME = "HMAC"
	private const val RAW = "raw"

	private fun paramsForAlgorithm(algorithm: HmacAlgorithm, keySize: Int) =
		json(
			"name" to ALGORITHM_NAME,
			"hash" to when (algorithm) {
				HmacAlgorithm.HmacSha512 -> "SHA-512"
				HmacAlgorithm.HmacSha256 -> "SHA-256"
			},
			"length" to keySize * 8
		)

	override suspend fun <A : HmacAlgorithm> generateKey(algorithm: A, keySize: Int?): HmacKey<A> {
		require(keySize == null || keySize >= algorithm.minimumKeySize) {
			"Invalid key size for $algorithm. A minimal length of ${algorithm.minimumKeySize} is required"
		}
		val generatedKey = jsCrypto.subtle.generateKey(
			paramsForAlgorithm(algorithm, keySize ?: algorithm.recommendedKeySize),
			true,
			arrayOf("sign", "verify")
		).await()
		val generatedKeySize = exportRawKey(generatedKey).byteLength
		if (generatedKeySize < algorithm.minimumKeySize) throw AssertionError(
			"Invalid key size for algorithm $algorithm, got $generatedKeySize"
		)
		return HmacKey(generatedKey, generatedKeySize, algorithm)
	}

	override suspend fun exportKey(key: HmacKey<*>): ByteArray =
		exportRawKey(key.key).toByteArray()

	private suspend fun exportRawKey(rawKey: dynamic) =
		jsCrypto.subtle.exportKey(RAW, rawKey).await() as ArrayBuffer

	override suspend fun <A : HmacAlgorithm> loadKey(algorithm: A, bytes: ByteArray): HmacKey<A> {
		require(bytes.size >= algorithm.minimumKeySize) { "Invalid key size for algorithm $algorithm" }
		return HmacKey(
			jsCrypto.subtle.importKey(
				RAW,
				bytes.toArrayBuffer(),
				paramsForAlgorithm(algorithm, bytes.size),
				true,
				arrayOf("sign", "verify")
			).await(),
			bytes.size,
			algorithm
		)
	}

	override suspend fun sign(data: ByteArray, key: HmacKey<*>): ByteArray {
		return jsCrypto.subtle.sign(
			paramsForAlgorithm(key.algorithm, key.keySize),
			key.key,
			data.toArrayBuffer()
		).await().toByteArray()
	}

	override suspend fun verify(
		signature: ByteArray,
		data: ByteArray,
		key: HmacKey<*>
	): Boolean {
		return jsCrypto.subtle.verify(
			paramsForAlgorithm(key.algorithm, key.keySize),
			key.key,
			signature.toArrayBuffer(),
			data.toArrayBuffer()
		).await()
	}
}