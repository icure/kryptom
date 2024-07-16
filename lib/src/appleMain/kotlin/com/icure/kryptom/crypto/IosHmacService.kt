package com.icure.kryptom.crypto

import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.refTo
import platform.CoreCrypto.CCHmac
import platform.CoreCrypto.kCCHmacAlgSHA256
import platform.CoreCrypto.kCCHmacAlgSHA512

object IosHmacService : HmacService {
	override suspend fun <A : HmacAlgorithm> generateKey(algorithm: A, keySize: Int?): HmacKey<A> {
		require(keySize == null || keySize >= algorithm.minimumKeySize) {
			"Invalid key size for $algorithm. A minimal length of ${algorithm.minimumKeySize} is required"
		}
		return HmacKey(IosStrongRandom.randomBytes(keySize ?: algorithm.recommendedKeySize), algorithm)
	}


	override suspend fun exportKey(key: HmacKey<*>): ByteArray =
		key.rawKey.copyOf()

	override suspend fun <A : HmacAlgorithm> loadKey(algorithm: A, bytes: ByteArray): HmacKey<A> {
		require(bytes.size >= algorithm.minimumKeySize) {
			"Invalid key length for algorithm $algorithm: got ${bytes.size} but at least ${algorithm.minimumKeySize} expected"
		}
		return HmacKey(bytes.copyOf(), algorithm)
	}

	override suspend fun sign(data: ByteArray, key: HmacKey<*>): ByteArray {
		require(key.algorithm == HmacAlgorithm.HmacSha512 || key.algorithm == HmacAlgorithm.HmacSha256) {
			"Unsupported hmac algorithm: ${key.algorithm}"
		}
		return memScoped {
			val out = allocArray<UByteVar>(key.algorithm.digestSize)
			CCHmac(
				key.algorithm.coreCryptoAlgorithm,
				key.rawKey.refTo(0),
				key.rawKey.size.toULong(),
				data.refTo(0),
				data.size.toULong(),
				out
			)
			out.readBytes(key.algorithm.digestSize)
		}
	}

	override suspend fun verify(
		signature: ByteArray,
		data: ByteArray,
		key: HmacKey<*>
	): Boolean {
		return sign(data, key).contentEquals(signature)
	}

	private val HmacAlgorithm.coreCryptoAlgorithm: UInt get() = when (this) {
		HmacAlgorithm.HmacSha512 -> kCCHmacAlgSHA512
		HmacAlgorithm.HmacSha256 -> kCCHmacAlgSHA256
	}
}
