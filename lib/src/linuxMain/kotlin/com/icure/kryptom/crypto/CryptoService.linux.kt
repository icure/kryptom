package com.icure.kryptom.crypto

actual val defaultCryptoService: CryptoService = object : CryptoService {
	override val aes: AesService get() = OpensslAesService
	override val rsa: RsaService get() = OpensslRsaService
	override val strongRandom: StrongRandom get() = OpensslStrongRandom
	override val digest: DigestService get() = OpensslDigestService
	override val hmac: HmacService get() = OpensslHmacService
}

actual val defaultCryptoServiceAvailable = true