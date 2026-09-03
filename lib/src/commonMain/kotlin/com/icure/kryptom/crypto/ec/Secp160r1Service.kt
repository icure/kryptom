package com.icure.kryptom.crypto.ec

import com.icure.kryptom.crypto.StrongRandom

/**
 * x-only elliptic-curve Diffie-Hellman over secp160r1 (SEC 2 v2, section 2.4.1).
 *
 * Public keys are exchanged as the 160-bit x-coordinate of the point alone, with no sign bit. Both ±P share an
 * x-coordinate and so do ±kP, so both parties obtain the same shared x-coordinate whichever root they
 * reconstruct. This is what lets a public key fit in exactly 20 bytes (32 base32 symbols) and is the reason this
 * curve exists in kryptom: codes that a human types from one screen into another.
 *
 * ## Security level, stated plainly
 *
 * secp160r1 provides roughly 80 bits of security: an attacker recovers a private key from its public key with
 * about 2^80 group operations (Pollard rho). That is **not** a long-term security level. Use this service only
 * for ephemeral keys protecting secrets whose value expires within minutes, generate a fresh key pair for every
 * exchange, never reuse a key, and never derive anything durable (a device key, a long-lived session key) from the
 * shared secret. For secrets that must stay confidential for longer, use a 256-bit curve instead.
 *
 * ## Implementation
 *
 * No platform crypto library available to kryptom (WebCrypto, CryptoKit, Windows CNG) supports secp160r1, so the
 * default implementation, [PureKotlinSecp160r1Service], is pure common Kotlin shared by every target. Its field
 * and curve arithmetic are branch-free with respect to secret values (see `Fp160` and `Secp160r1`), but on
 * Kotlin/JS `Long` is emulated and on the JVM the JIT may reorder, so constant-time behaviour is best effort.
 * Platform-delegating implementations (BouncyCastle, OpenSSL) can be added behind this interface later.
 *
 * Encodings: private scalars are [SCALAR_BYTES] bytes big-endian in `[1, n-1]`; public keys and shared secrets
 * are [PUBLIC_KEY_BYTES] bytes big-endian.
 */
interface Secp160r1Service {
	companion object {
		/** Size in bytes of a big-endian private scalar. The group order n has 161 bits. */
		const val SCALAR_BYTES = 21

		/** Size in bytes of a big-endian x-only public key, and of the ECDH shared x-coordinate. */
		const val PUBLIC_KEY_BYTES = 20
	}

	/**
	 * Draws a fresh private scalar, uniformly in `[1, 2^160 - 1]` (a subset of `[1, n-1]` with negligible bias).
	 * @return the scalar, [SCALAR_BYTES] bytes big-endian.
	 */
	suspend fun randomScalar(): ByteArray

	/**
	 * Computes the x-only public key for a private scalar.
	 * @param scalar a private scalar as produced by [randomScalar].
	 * @return the x-coordinate of `scalar * G`, [PUBLIC_KEY_BYTES] bytes big-endian.
	 * @throws IllegalArgumentException if [scalar] is not [SCALAR_BYTES] long or is not in `[1, n-1]`.
	 */
	suspend fun publicKeyX(scalar: ByteArray): ByteArray

	/**
	 * Checks whether some bytes are a valid x-only public key: [PUBLIC_KEY_BYTES] long, strictly less than the
	 * field prime, and the x-coordinate of a point on the curve. [ecdhX] performs this check itself; use this method
	 * when the key must be validated before doing anything else, for example when it was typed by a person.
	 */
	suspend fun isValidPublicKeyX(publicKeyX: ByteArray): Boolean

	/**
	 * x-only Diffie-Hellman.
	 * @param scalar this party's private scalar.
	 * @param peerPublicKeyX the other party's x-only public key.
	 * @return the x-coordinate of `scalar * peerPoint`, [PUBLIC_KEY_BYTES] bytes big-endian, or null if
	 * [peerPublicKeyX] is not a valid public key (see [isValidPublicKeyX]). The result is the same whichever root
	 * the peer's point is reconstructed to.
	 * @throws IllegalArgumentException if [scalar] is not [SCALAR_BYTES] long or is not in `[1, n-1]`.
	 */
	suspend fun ecdhX(scalar: ByteArray, peerPublicKeyX: ByteArray): ByteArray?
}

/**
 * Pure common-Kotlin implementation of [Secp160r1Service], used by default on every platform.
 * @param random source of randomness for [randomScalar]; the platform's strong random generator.
 */
class PureKotlinSecp160r1Service(
	private val random: StrongRandom
) : Secp160r1Service {
	override suspend fun randomScalar(): ByteArray =
		Secp160r1.randomScalar { random.randomBytes(it) }

	override suspend fun publicKeyX(scalar: ByteArray): ByteArray {
		requireValidScalar(scalar)
		return Secp160r1.publicKeyX(scalar)
	}

	override suspend fun isValidPublicKeyX(publicKeyX: ByteArray): Boolean =
		Secp160r1.decompress(publicKeyX) != null

	override suspend fun ecdhX(scalar: ByteArray, peerPublicKeyX: ByteArray): ByteArray? {
		requireValidScalar(scalar)
		return Secp160r1.ecdhX(scalar, peerPublicKeyX)
	}

	private fun requireValidScalar(scalar: ByteArray) {
		require(scalar.size == Secp160r1Service.SCALAR_BYTES) {
			"Scalar must be ${Secp160r1Service.SCALAR_BYTES} bytes, got ${scalar.size}"
		}
		require(isInScalarRange(scalar)) { "Scalar must be in [1, n-1]" }
	}

	/**
	 * -1/0 free version of `1 <= scalar < n`: a byte-wise subtraction whose final borrow tells whether the scalar is
	 * below n, plus an OR-accumulator for the zero check. No early exit on the scalar's value.
	 */
	private fun isInScalarRange(scalarBE: ByteArray): Boolean {
		var borrow = 0
		var nonZero = 0
		for (i in Secp160r1Service.SCALAR_BYTES - 1 downTo 0) {
			val s = scalarBE[i].toInt() and 0xFF
			val n = Secp160r1.N_BYTES[i].toInt() and 0xFF
			val d = s - n - borrow
			borrow = (d ushr 31) and 1
			nonZero = nonZero or s
		}
		return borrow == 1 && nonZero != 0
	}
}
