package com.icure.kryptom.crypto

interface DigestService {
	suspend fun sha256(data: ByteArray): ByteArray
	suspend fun sha512(data: ByteArray): ByteArray
}