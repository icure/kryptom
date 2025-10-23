@file:OptIn(DelicateCoroutinesApi::class)

package com.icure.kryptom.crypto.external

import com.icure.kryptom.crypto.AesAlgorithm
import com.icure.kryptom.crypto.AesKey
import com.icure.kryptom.crypto.AesService
import com.icure.kryptom.crypto.CryptoService
import com.icure.kryptom.crypto.DigestService
import com.icure.kryptom.crypto.HmacAlgorithm
import com.icure.kryptom.crypto.HmacKey
import com.icure.kryptom.crypto.HmacService
import com.icure.kryptom.crypto.PrivateRsaKey
import com.icure.kryptom.crypto.PrivateRsaKeyJwk
import com.icure.kryptom.crypto.PublicRsaKey
import com.icure.kryptom.crypto.PublicRsaKeyJwk
import com.icure.kryptom.crypto.RsaAlgorithm
import com.icure.kryptom.crypto.RsaKeypair
import com.icure.kryptom.crypto.RsaService
import com.icure.kryptom.crypto.StrongRandom
import com.icure.kryptom.utils.PlatformMethodException
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.await
import kotlinx.coroutines.promise
import kotlin.js.Promise

/**
 * Adapts an external implementation of a crypto service to use the same interface as kryptom. This allows connecting to
 * native implementations of cryptographic operations when using kryptom-ts from react-native.
 */
fun adaptExternalCryptoService(service: PartialXCryptoService): CryptoService =
	if (service is XServiceAdapter) service.service else ServiceAdapter(completePartialCryptoService(service))

/**
 * Adapts a kotlin implementation of a crypto service to an interface suitable for Typescript.
 * This allows using the cryptographic service from plain typescript.
 */
fun adaptCryptoServiceForExternal(service: CryptoService): XCryptoService =
	if (service is ServiceAdapter) service.service else XServiceAdapter(service)

external interface PartialXCryptoService {
	val aes: XAesService
	val digest: XDigestService
	val rsa: PartialXRsaService
	val strongRandom: PartialXStrongRandom
	val hmac: XHmacService
}

external interface XCryptoService : PartialXCryptoService {
	override val rsa: XRsaService
	override val strongRandom: XStrongRandom
}

fun completePartialCryptoService(service: PartialXCryptoService): XCryptoService {
	val fullRsa = completePartialRsa(service.rsa)
	val fullStrongRandom = completePartialStrongRandom(service.strongRandom)
	return js("{ aes: service.aes, digest: service.digest, rsa: fullRsa, strongRandom: fullStrongRandom, hmac: service.hmac }")
}

private inline fun <T> wrappingNativeExceptions(block: () -> T): T =
	try {
		block()
	} catch (e: dynamic) {
		if (e is Throwable) {
			throw ExternalCryptoServiceException(
				"An external crypto service method failed",
				e
			)
		} else {
			throw ExternalCryptoServiceException(
				"An external crypto service method failed with non-throwable - $e",
				null
			)
		}
	}

private class ServiceAdapter(
	val service: XCryptoService
) : CryptoService {
	override val aes: AesService = AesServiceAdapter(service.aes)
	override val digest: DigestService = DigestServiceAdapter(service.digest)
	override val rsa: RsaService = RsaServiceAdapter(service.rsa)
	override val strongRandom: StrongRandom = StrongRandomAdapter(service.strongRandom)
	override val hmac: HmacService = HmacServiceAdapter(service.hmac)
}

private class XServiceAdapter(
	val service: CryptoService
) : XCryptoService {
	override val aes: XAesService = XAesServiceAdapter(service.aes)
	override val digest: XDigestService = XDigestServiceAdapter(service.digest)
	override val rsa: XRsaService = XRsaServiceAdapter(service.rsa)
	override val strongRandom: XStrongRandom = XStrongRandomAdapter(service.strongRandom)
	override val hmac: XHmacService = XHmacServiceAdapter(service.hmac)
}

private class AesServiceAdapter(
	private val service: XAesService
) : AesService {
	override suspend fun <A : AesAlgorithm> generateKey(algorithm: A, size: AesService.KeySize): AesKey<A> =
		wrappingNativeExceptions { service.generateKey(algorithm.identifier, size.bitSize).await().toKryptom(algorithm) }

	override suspend fun exportKey(key: AesKey<*>): ByteArray =
		wrappingNativeExceptions { service.exportKey(key.toExternal()).await() }

	override suspend fun <A : AesAlgorithm> loadKey(algorithm: A, bytes: ByteArray): AesKey<A> =
		wrappingNativeExceptions { service.loadKey(algorithm.identifier, bytes).await().toKryptom(algorithm) }

	override suspend fun encrypt(data: ByteArray, key: AesKey<*>, iv: ByteArray?): ByteArray =
		wrappingNativeExceptions { service.encrypt(data, key.toExternal(), iv).await() }

	override suspend fun decrypt(ivAndEncryptedData: ByteArray, key: AesKey<*>): ByteArray =
		wrappingNativeExceptions { service.decrypt(ivAndEncryptedData, key.toExternal()).await() }
}

private class XAesServiceAdapter(
	private val service: AesService
) : XAesService {
	override fun generateKey(algorithm: String, size: Int): Promise<XAesKey> = GlobalScope.promise {
		service.generateKey(AesAlgorithm.fromIdentifier(algorithm), AesService.KeySize.entries.first { it.bitSize == size }).toExternal()
	}

	override fun exportKey(key: XAesKey): Promise<ByteArray> = GlobalScope.promise {
		service.exportKey(key.toKryptom())
	}

	override fun loadKey(algorithm: String, bytes: ByteArray): Promise<XAesKey> = GlobalScope.promise {
		service.loadKey(AesAlgorithm.fromIdentifier(algorithm), bytes).toExternal()
	}

	override fun encrypt(data: ByteArray, key: XAesKey, iv: ByteArray?): Promise<ByteArray> = GlobalScope.promise {
		service.encrypt(data, key.toKryptom(), iv)
	}

	override fun decrypt(ivAndEncryptedData: ByteArray, key: XAesKey): Promise<ByteArray> = GlobalScope.promise {
		service.decrypt(ivAndEncryptedData, key.toKryptom())
	}
}

private class DigestServiceAdapter(
	private val service: XDigestService
) : DigestService {
	override suspend fun sha256(data: ByteArray): ByteArray =
		wrappingNativeExceptions { service.sha256(data).await() }

	override suspend fun sha512(data: ByteArray): ByteArray =
		wrappingNativeExceptions { service.sha512(data).await() }
}

private class XDigestServiceAdapter(
	private val service: DigestService
) : XDigestService {
	override fun sha256(data: ByteArray): Promise<ByteArray> = GlobalScope.promise {
		service.sha256(data)
	}

	override fun sha512(data: ByteArray): Promise<ByteArray> = GlobalScope.promise {
		service.sha512(data)
	}
}


private class HmacServiceAdapter(
	private val service: XHmacService
) : HmacService {
	override suspend fun <A : HmacAlgorithm> generateKey(algorithm: A, keySize: Int?): HmacKey<A> =
		wrappingNativeExceptions { service.generateKey(algorithm.identifier, keySize).await().toKryptom(algorithm) }

	override suspend fun exportKey(key: HmacKey<*>): ByteArray =
		wrappingNativeExceptions { service.exportKey(key.toExternal()).await() }

	override suspend fun <A : HmacAlgorithm> loadKey(algorithm: A, bytes: ByteArray): HmacKey<A> =
		wrappingNativeExceptions { service.loadKey(algorithm.identifier, bytes).await().toKryptom(algorithm) }

	override suspend fun sign(data: ByteArray, key: HmacKey<*>): ByteArray =
		wrappingNativeExceptions { service.sign(data, key.toExternal()).await() }

	override suspend fun verify(signature: ByteArray, data: ByteArray, key: HmacKey<*>): Boolean =
		wrappingNativeExceptions { service.verify(signature, data, key.toExternal()).await() }
}

private class XHmacServiceAdapter(
	private val service: HmacService
) : XHmacService {
	override fun generateKey(algorithm: String, keySize: Int?): Promise<XHmacKey> = GlobalScope.promise {
		service.generateKey(HmacAlgorithm.fromIdentifier(algorithm), keySize).toExternal()
	}

	override fun exportKey(key: XHmacKey): Promise<ByteArray> = GlobalScope.promise {
		service.exportKey(key.toKryptom())
	}

	override fun loadKey(algorithm: String, bytes: ByteArray): Promise<XHmacKey> = GlobalScope.promise {
		service.loadKey(HmacAlgorithm.fromIdentifier(algorithm), bytes).toExternal()
	}

	override fun sign(data: ByteArray, key: XHmacKey): Promise<ByteArray> = GlobalScope.promise {
		service.sign(data, key.toKryptom())
	}

	override fun verify(signature: ByteArray, data: ByteArray, key: XHmacKey): Promise<Boolean> = GlobalScope.promise {
		service.verify(signature, data, key.toKryptom())
	}
}

private class RsaServiceAdapter(
	private val service: XRsaService
) : RsaService {
	override suspend fun <A : RsaAlgorithm> generateKeyPair(algorithm: A, keySize: RsaService.KeySize): RsaKeypair<A> =
		wrappingNativeExceptions { service.generateKeyPair(algorithm.identifier, keySize.bitSize).await().toKryptom(algorithm) }

	override suspend fun exportPrivateKeyPkcs8(key: PrivateRsaKey<*>): ByteArray =
		wrappingNativeExceptions { service.exportPrivateKeyPkcs8(key.toExternal()).await() }

	override suspend fun <A : RsaAlgorithm> loadPrivateKeyPkcs8(
		algorithm: A,
		privateKeyPkcs8: ByteArray
	): PrivateRsaKey<A> =
		wrappingNativeExceptions { service.loadPrivateKeyPkcs8(algorithm.identifier, privateKeyPkcs8).await().toKryptom(algorithm) }

	override suspend fun exportPublicKeySpki(key: PublicRsaKey<*>): ByteArray =
		wrappingNativeExceptions { service.exportPublicKeySpki(key.toExternal()).await() }

	override suspend fun <A : RsaAlgorithm> loadKeyPairPkcs8(algorithm: A, privateKeyPkcs8: ByteArray): RsaKeypair<A> =
		wrappingNativeExceptions { service.loadKeyPairPkcs8(algorithm.identifier, privateKeyPkcs8).await().toKryptom(algorithm) }

	override suspend fun <A : RsaAlgorithm> loadPublicKeySpki(algorithm: A, publicKeySpki: ByteArray): PublicRsaKey<A> =
		wrappingNativeExceptions { service.loadPublicKeySpki(algorithm.identifier, publicKeySpki).await().toKryptom(algorithm) }

	override suspend fun encrypt(
		data: ByteArray,
		publicKey: PublicRsaKey<RsaAlgorithm.RsaEncryptionAlgorithm>
	): ByteArray =
		wrappingNativeExceptions { service.encrypt(data, publicKey.toExternal()).await() }

	override suspend fun decrypt(
		data: ByteArray,
		privateKey: PrivateRsaKey<RsaAlgorithm.RsaEncryptionAlgorithm>
	): ByteArray =
		wrappingNativeExceptions { service.decrypt(data, privateKey.toExternal()).await() }

	override suspend fun sign(
		data: ByteArray,
		privateKey: PrivateRsaKey<RsaAlgorithm.RsaSignatureAlgorithm>
	): ByteArray =
		wrappingNativeExceptions { service.sign(data, privateKey.toExternal()).await() }

	override suspend fun verifySignature(
		signature: ByteArray,
		data: ByteArray,
		publicKey: PublicRsaKey<RsaAlgorithm.RsaSignatureAlgorithm>
	): Boolean =
		wrappingNativeExceptions { service.verifySignature(signature, data, publicKey.toExternal()).await() }

	override suspend fun exportPrivateKeyJwk(key: PrivateRsaKey<*>): PrivateRsaKeyJwk =
		wrappingNativeExceptions { service.exportPrivateKeyJwk(key.toExternal()).await().toPrivateJwk() }

	override suspend fun exportPublicKeyJwk(key: PublicRsaKey<*>): PublicRsaKeyJwk =
		wrappingNativeExceptions { service.exportPublicKeyJwk(key.toExternal()).await().toPublicJwk() }

	override suspend fun <A : RsaAlgorithm> loadPrivateKeyJwk(
		algorithm: A,
		privateKeyJwk: PrivateRsaKeyJwk
	): PrivateRsaKey<A> =
		wrappingNativeExceptions { service.loadPrivateKeyJwk(privateKeyJwk.toPrivateJwk()).await().toKryptom(algorithm) }

	override suspend fun <A : RsaAlgorithm> loadPublicKeyJwk(
		algorithm: A,
		publicKeyJwk: PublicRsaKeyJwk
	): PublicRsaKey<A> =
		wrappingNativeExceptions { service.loadPublicKeyJwk(publicKeyJwk.toPublicJwk()).await().toKryptom(algorithm) }
}

private class XRsaServiceAdapter(
	private val service: RsaService
) : XRsaService {
	override fun generateKeyPair(algorithm: String, keySize: Int): Promise<XRsaKeypair> = GlobalScope.promise {
		service.generateKeyPair(RsaAlgorithm.fromIdentifier(algorithm), RsaService.KeySize.entries.first { it.bitSize == keySize }).toExternal()
	}

	override fun exportPrivateKeyPkcs8(key: XPrivateRsaKey): Promise<ByteArray> = GlobalScope.promise {
		service.exportPrivateKeyPkcs8(key.toKryptom())
	}

	override fun exportPublicKeySpki(key: XPublicRsaKey): Promise<ByteArray> = GlobalScope.promise {
		service.exportPublicKeySpki(key.toKryptom())
	}

	override fun loadKeyPairPkcs8(algorithm: String, privateKeyPkcs8: ByteArray): Promise<XRsaKeypair> = GlobalScope.promise {
		service.loadKeyPairPkcs8(RsaAlgorithm.fromIdentifier(algorithm), privateKeyPkcs8).toExternal()
	}

	override fun loadPrivateKeyPkcs8(algorithm: String, privateKeyPkcs8: ByteArray): Promise<XPrivateRsaKey> = GlobalScope.promise {
		service.loadPrivateKeyPkcs8(RsaAlgorithm.fromIdentifier(algorithm), privateKeyPkcs8).toExternal()
	}

	override fun loadPublicKeySpki(algorithm: String, publicKeySpki: ByteArray): Promise<XPublicRsaKey> = GlobalScope.promise {
		service.loadPublicKeySpki(RsaAlgorithm.fromIdentifier(algorithm), publicKeySpki).toExternal()
	}

	override fun encrypt(data: ByteArray, publicKey: XPublicRsaKey): Promise<ByteArray> = GlobalScope.promise {
		service.encrypt(data, publicKey.toKryptomEncryption())
	}

	override fun decrypt(data: ByteArray, privateKey: XPrivateRsaKey): Promise<ByteArray> = GlobalScope.promise {
		service.decrypt(data, privateKey.toKryptomEncryption())
	}

	override fun sign(data: ByteArray, privateKey: XPrivateRsaKey): Promise<ByteArray> = GlobalScope.promise {
		service.sign(data, privateKey.toKryptomSignature())
	}

	override fun verifySignature(signature: ByteArray, data: ByteArray, publicKey: XPublicRsaKey): Promise<Boolean> = GlobalScope.promise {
		service.verifySignature(signature, data, publicKey.toKryptomSignature())
	}

	override fun exportPrivateKeyJwk(key: XPrivateRsaKey): Promise<JsonWebKey> = GlobalScope.promise {
		service.exportPrivateKeyJwk(key.toKryptom()).toPrivateJwk()
	}

	override fun exportPublicKeyJwk(key: XPublicRsaKey): Promise<JsonWebKey> = GlobalScope.promise {
		service.exportPublicKeyJwk(key.toKryptom()).toPublicJwk()
	}

	override fun loadPrivateKeyJwk(privateKeyJwk: JsonWebKey): Promise<XPrivateRsaKey> = GlobalScope.promise {
		val convertedKey = privateKeyJwk.toPrivateJwk()
		service.loadPrivateKeyJwk(RsaAlgorithm.fromJwkIdentifier(convertedKey.alg), convertedKey).toExternal()
	}

	override fun loadPublicKeyJwk(publicKeyJwk: JsonWebKey): Promise<XPublicRsaKey> = GlobalScope.promise {
		val convertedKey = publicKeyJwk.toPublicJwk()
		service.loadPublicKeyJwk(RsaAlgorithm.fromJwkIdentifier(convertedKey.alg), convertedKey).toExternal()
	}
}

private class StrongRandomAdapter(
	private val service: XStrongRandom
) : StrongRandom {
	override fun fill(array: ByteArray) {
		wrappingNativeExceptions { service.fill(array) }
	}

	override fun randomBytes(length: Int): ByteArray =
		wrappingNativeExceptions { service.randomBytes(length) }

	override fun randomUUID(): String =
		wrappingNativeExceptions { service.randomUUID() }
}

private class XStrongRandomAdapter(
	private val service: StrongRandom
) : XStrongRandom {
	override fun fill(array: ByteArray) =
		service.fill(array)

	override fun randomBytes(length: Int): ByteArray =
		service.randomBytes(length)

	override fun randomUUID(): String =
		service.randomUUID()
}