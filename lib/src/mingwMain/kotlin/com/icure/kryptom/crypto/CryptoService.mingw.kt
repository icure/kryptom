package com.icure.kryptom.crypto

/**
 * Gives access to cryptographic functions.
 */
actual val defaultCryptoService = object : CryptoService {
    override val aes: AesService get() = BCryptAesService
    override val rsa: RsaService get() = BCryptRsaService
    override val strongRandom: StrongRandom get() = BCryptStrongRandom
    override val digest: DigestService get() = BCryptDigestService
    override val hmac: HmacService get() = BCryptHmacService
}
