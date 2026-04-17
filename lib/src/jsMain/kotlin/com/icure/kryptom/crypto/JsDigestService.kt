package com.icure.kryptom.crypto

import com.icure.kryptom.js.jsCrypto
import com.icure.kryptom.js.asArrayBuffer
import com.icure.kryptom.js.asByteArray
import kotlinx.coroutines.await

object JsDigestService : DigestService {
	override suspend fun sha256(data: ByteArray): ByteArray =
		jsCrypto.subtle.digest("SHA-256", data.asArrayBuffer()).await().asByteArray()

	override suspend fun sha512(data: ByteArray): ByteArray =
		jsCrypto.subtle.digest("SHA-512", data.asArrayBuffer()).await().asByteArray()
}