package com.icure.kryptom.crypto

/**
 * HKDF with HMAC-SHA256, as specified in RFC 5869.
 *
 * Built directly on [DigestService.sha256] with a common-Kotlin HMAC rather than on [HmacService], because HKDF's
 * salt and pseudo-random key may be of any length (a salt is often empty, a PRK is 32 bytes) while [HmacService]
 * enforces [HmacAlgorithm.minimumKeySize] on the keys it loads.
 *
 * Usage: [derive] for the common one-shot case; [extract] and [expand] separately when the same PRK must feed
 * several `info` contexts.
 *
 * @param digest the digest service providing SHA-256, typically `defaultCryptoService.digest`.
 */
class HkdfSha256(
	private val digest: DigestService
) {
	companion object {
		/** Output size of SHA-256 in bytes. */
		const val HASH_LENGTH = 32

		/** Largest output [expand] can produce: 255 * HashLen, per RFC 5869 section 2.3. */
		const val MAX_OUTPUT_LENGTH = 255 * HASH_LENGTH
	}

	/**
	 * HKDF-Extract: `PRK = HMAC-SHA256(salt, IKM)`.
	 * @param salt optional salt. Null is treated as RFC 5869 prescribes, as [HASH_LENGTH] zero bytes; an empty
	 * array yields the same PRK.
	 * @param ikm the input keying material, for example an ECDH shared secret.
	 * @return the pseudo-random key, [HASH_LENGTH] bytes.
	 */
	suspend fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray =
		digest.hmacSha256(salt ?: ByteArray(HASH_LENGTH), ikm)

	/**
	 * HKDF-Expand: `OKM = T(1) || T(2) || ...` with `T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)`.
	 * @param prk a pseudo-random key from [extract].
	 * @param info context and application-specific information, binding the output to its use.
	 * @param length number of output bytes, in `1..`[MAX_OUTPUT_LENGTH].
	 * @throws IllegalArgumentException if [length] is out of range.
	 */
	suspend fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
		require(length in 1..MAX_OUTPUT_LENGTH) { "HKDF output length must be in 1..$MAX_OUTPUT_LENGTH, got $length" }
		val blocks = (length + HASH_LENGTH - 1) / HASH_LENGTH
		val okm = ByteArray(blocks * HASH_LENGTH)
		var previous = ByteArray(0)
		for (i in 1..blocks) {
			previous = digest.hmacSha256(prk, previous + info + byteArrayOf(i.toByte()))
			previous.copyInto(okm, (i - 1) * HASH_LENGTH)
		}
		return okm.copyOf(length)
	}

	/**
	 * One-shot HKDF: [extract] followed by [expand].
	 * @param ikm the input keying material.
	 * @param salt optional salt, see [extract].
	 * @param info context information, see [expand]. Defaults to empty.
	 * @param length number of output bytes.
	 */
	suspend fun derive(
		ikm: ByteArray,
		salt: ByteArray? = null,
		info: ByteArray = ByteArray(0),
		length: Int
	): ByteArray = expand(extract(salt, ikm), info, length)
}

private const val SHA256_BLOCK_LENGTH = 64

/**
 * HMAC-SHA256 (RFC 2104) over this digest service, accepting a key of any length: keys longer than the block are
 * hashed first, shorter keys are zero-padded, exactly as the RFC prescribes.
 */
internal suspend fun DigestService.hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
	val shortKey = if (key.size > SHA256_BLOCK_LENGTH) sha256(key) else key
	val paddedKey = shortKey.copyOf(SHA256_BLOCK_LENGTH)
	val innerPad = ByteArray(SHA256_BLOCK_LENGTH) { (paddedKey[it].toInt() xor 0x36).toByte() }
	val outerPad = ByteArray(SHA256_BLOCK_LENGTH) { (paddedKey[it].toInt() xor 0x5c).toByte() }
	return sha256(outerPad + sha256(innerPad + message))
}
