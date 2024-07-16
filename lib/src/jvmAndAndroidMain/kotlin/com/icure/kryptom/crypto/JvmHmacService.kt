package com.icure.kryptom.crypto

import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object JvmHmacService : HmacService {
	private val HmacAlgorithm.name
		get() = when (this) {
			HmacAlgorithm.HmacSha512 -> "HMac-SHA512"
			HmacAlgorithm.HmacSha256 -> "HMac-SHA256"
		}

	override suspend fun <A : HmacAlgorithm> generateKey(algorithm: A, keySize: Int?): HmacKey<A> {
		require(keySize == null || keySize >= algorithm.minimumKeySize) {
			"Invalid key size for $algorithm. A minimal length of ${algorithm.minimumKeySize} is required"
		}
		val keyGen: KeyGenerator = KeyGenerator.getInstance(algorithm.name)
		keyGen.init((keySize ?: algorithm.recommendedKeySize) * 8)
		return HmacKey(keyGen.generateKey(), algorithm)
	}

	override suspend fun exportKey(key: HmacKey<*>): ByteArray {
		return key.key.encoded
	}

	override suspend fun <A : HmacAlgorithm> loadKey(algorithm: A, bytes: ByteArray): HmacKey<A> {
		require(bytes.size >= algorithm.minimumKeySize) { "Invalid key length for algorithm $algorithm: ${bytes.size}" }
		return HmacKey(SecretKeySpec(bytes, algorithm.name), algorithm)
	}

	override suspend fun sign(data: ByteArray, key: HmacKey<*>): ByteArray {
		return Mac.getInstance(key.algorithm.name).apply { init(key.key) }.doFinal(data)
	}

	override suspend fun verify(
		signature: ByteArray,
		data: ByteArray,
		key: HmacKey<*>
	): Boolean =
		sign(data, key).contentEquals(signature)
}