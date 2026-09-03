package com.icure.kryptom.utils

/**
 * Compares two byte arrays without branching on their contents.
 *
 * Use this, never `contentEquals` or `==`, whenever one side is secret-derived: verifying an HMAC tag, a
 * commitment, a password hash. A short-circuiting comparison leaks, through its timing, how many leading bytes
 * matched, which lets an attacker forge a tag byte by byte.
 *
 * Caveat, stated plainly: on the JVM and on Kotlin/JS this is *best effort*. Neither platform guarantees that the
 * JIT will not reintroduce an early exit, and Kotlin has no equivalent of C's volatile barriers. The loop below
 * is the portable formulation used by JVM crypto libraries (it accumulates differences rather than testing them),
 * and it is what can be done in common code. A platform-delegating version could later route to
 * `MessageDigest.isEqual` (JVM), `crypto.timingSafeEqual` (Node) or `CRYPTO_memcmp` (OpenSSL).
 *
 * The length check does leak the lengths. That is fine for the intended use, where both sides are fixed-size
 * digests; do not rely on this function to hide the length of a variable-length secret.
 */
fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
	if (a.size != b.size) return false
	var accumulator = 0
	for (i in a.indices) {
		accumulator = accumulator or (a[i].toInt() xor b[i].toInt())
	}
	return accumulator == 0
}
