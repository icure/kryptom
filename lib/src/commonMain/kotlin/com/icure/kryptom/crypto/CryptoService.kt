package com.icure.kryptom.crypto

import com.icure.kryptom.crypto.ec.PureKotlinSecp160r1Service
import com.icure.kryptom.crypto.ec.Secp160r1Service

/**
 * Gives access to cryptographic functions.
 */
expect val defaultCryptoService: CryptoService

/**
 * If the default crypto service for the current platform is available.
 * If false using defaultCryptoService may throw for some or all the methods.
 */
expect val defaultCryptoServiceAvailable: Boolean

/**
 * Interface which provides cryptographic functions.
 */
interface CryptoService {
	/**
	 * Cryptographic functions for AES.
	 */
	val aes: AesService

	/**
	 * Cryptographic functions for RSA.
	 */
	val rsa: RsaService

	/**
	 * Provides access to a cryptographically strong random generator.
	 * Thread safe.
	 */
	val strongRandom: StrongRandom

	val digest: DigestService

	val hmac: HmacService

	/**
	 * x-only elliptic-curve Diffie-Hellman over secp160r1, for short-lived secrets exchanged through codes a human
	 * types. Read the security notes on [Secp160r1Service] before using it. The default is a pure-Kotlin
	 * implementation shared by all platforms, drawing its randomness from [strongRandom].
	 */
	val secp160r1: Secp160r1Service get() = PureKotlinSecp160r1Service(strongRandom)
}
