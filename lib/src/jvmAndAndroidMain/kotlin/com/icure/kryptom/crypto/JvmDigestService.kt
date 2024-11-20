package com.icure.kryptom.crypto

import java.security.MessageDigest

object JvmDigestService : DigestService {
	override suspend fun sha256(data: ByteArray): ByteArray =
		MessageDigest.getInstance("SHA-256").digest(data)

	override suspend fun sha512(data: ByteArray): ByteArray =
		MessageDigest.getInstance("SHA-512").digest(data)
}