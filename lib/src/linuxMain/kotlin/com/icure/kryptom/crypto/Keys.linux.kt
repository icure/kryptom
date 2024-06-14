package com.icure.kryptom.crypto

/**
 * Represents a private rsa key. Each key should be used only for a specific algorithm, which is represented by [A].
 */
actual class PrivateRsaKey<out A : RsaAlgorithm> : RsaKey {
	actual val algorithm: A
		get() = TODO("Not yet implemented")
}

/**
 * Represents a public rsa key. Each key should be used only for a specific algorithm, which is represented by [A].
 */
actual class PublicRsaKey<out A : RsaAlgorithm> : RsaKey {
	actual val algorithm: A
		get() = TODO("Not yet implemented")
}

/**
 * Represents an aes key.
 */
actual class AesKey<out A : AesAlgorithm> {
	actual val algorithm: A
		get() = TODO("Not yet implemented")
}

actual class HmacKey<out A : HmacAlgorithm> {
	actual val algorithm: A
		get() = TODO("Not yet implemented")
}