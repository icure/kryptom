package com.icure.kryptom.crypto.ec

import com.icure.kryptom.utils.hexToByteArray

/**
 * secp160r1 (SEC 2 v2 §2.4.1), with x-only public keys.
 *
 * ```
 * p = 2^160 - 2^31 - 1
 * a = p - 3
 * b = 1c97befc54bd7a8b65acf89f81d4d4adc565fa45
 * n = 0100000000000000000001f4c8f927aed3ca752257   (161 bits, cofactor 1)
 * ```
 *
 * ## Why x-only is safe here
 *
 * A public key is transmitted as the 160-bit x-coordinate alone, with no sign bit. Both ±P share
 * an x, and for scalar k the points ±kP also share an x, so the ECDH shared x-coordinate is
 * identical whichever root each side reconstructs. That is what makes the key fit in exactly 32
 * Crockford symbols.
 *
 * ## Why the formulas below are trustworthy
 *
 * The Jacobian doubling (dbl-2001-b, which requires a = -3) and addition (add-1998-cmo-2) are
 * incomplete on their own: addition is wrong when the inputs are equal, negatives of each other,
 * or at infinity. [addComplete] repairs that by computing both candidate results and selecting
 * with masks, never branching. That selection logic was validated against an independent Python
 * reference over 200 randomised cases with random projective rescaling, plus every degenerate case
 * (∞+∞, ∞+G, G+∞, G+G, G+(-G), 2G+(-2G), dbl(∞)), before being written here. The Kotlin port is
 * pinned to the same reference by the vectors in `Secp160r1Vectors`.
 *
 * The cofactor is 1 and the order is prime, so there are no small-subgroup or order-2 concerns
 * once [decompress] has confirmed the point is on the curve — which is the check that must never be
 * skipped, since the x-coordinate arrives from a human typing at a keyboard.
 */
internal object Secp160r1 {

    /** Curve coefficient b. */
    val B: LongArray = Fp160.fromBytes(hexToByteArray("1c97befc54bd7a8b65acf89f81d4d4adc565fa45"))

    /** Base point G, affine. */
    private val GX = Fp160.fromBytes(hexToByteArray("4a96b5688ef573284664698968c38bb913cbfc82"))
    private val GY = Fp160.fromBytes(hexToByteArray("23a628553168947d59dcc912042351377ac5fb32"))

    /** Group order n, big-endian, 21 bytes. */
    val N_BYTES: ByteArray = hexToByteArray("0100000000000000000001f4c8f927aed3ca752257")

    /** Bits of scalar processed by the ladder. n has 161 bits. */
    const val SCALAR_BITS = 161

    /** Bytes in a scalar's big-endian encoding. */
    const val SCALAR_BYTES = 21

    /** Bytes in an encoded x-only public key. */
    const val KEY_BYTES = Fp160.BYTES

    /** A point in Jacobian coordinates. Infinity is any point with z = 0. */
    class Jac(val x: LongArray, val y: LongArray, val z: LongArray)

    private val INFINITY: Jac get() = Jac(Fp160.ONE, Fp160.ONE, Fp160.ZERO)

    val G: Jac get() = Jac(GX.copyOf(), GY.copyOf(), Fp160.ONE)

    // ------------------------------------------------------------------ point primitives

    private fun selectPoint(mask: Long, a: Jac, b: Jac): Jac = Jac(
        Fp160.select(mask, a.x, b.x),
        Fp160.select(mask, a.y, b.y),
        Fp160.select(mask, a.z, b.z),
    )

    private fun neg(p: Jac): Jac = Jac(p.x, Fp160.neg(p.y), p.z)

    /** dbl-2001-b. Requires a = -3. Correctly yields infinity from infinity and from y = 0. */
    private fun jDouble(p: Jac): Jac {
        val delta = Fp160.sqr(p.z)
        val gamma = Fp160.sqr(p.y)
        val beta = Fp160.mul(p.x, gamma)
        val alpha = Fp160.mulSmall(
            Fp160.mul(Fp160.sub(p.x, delta), Fp160.add(p.x, delta)), 3
        )
        val x3 = Fp160.sub(Fp160.sqr(alpha), Fp160.mulSmall(beta, 8))
        val z3 = Fp160.sub(
            Fp160.sub(Fp160.sqr(Fp160.add(p.y, p.z)), gamma), delta
        )
        val y3 = Fp160.sub(
            Fp160.mul(alpha, Fp160.sub(Fp160.mulSmall(beta, 4), x3)),
            Fp160.mulSmall(Fp160.sqr(gamma), 8),
        )
        return Jac(x3, y3, z3)
    }

    /** add-1998-cmo-2. Invalid when p == ±q or either input is infinity; see [addComplete]. */
    private fun jAdd(p: Jac, q: Jac): Jac {
        val z1z1 = Fp160.sqr(p.z)
        val z2z2 = Fp160.sqr(q.z)
        val u1 = Fp160.mul(p.x, z2z2)
        val u2 = Fp160.mul(q.x, z1z1)
        val s1 = Fp160.mul(Fp160.mul(p.y, z2z2), q.z)
        val s2 = Fp160.mul(Fp160.mul(q.y, z1z1), p.z)
        val h = Fp160.sub(u2, u1)
        val r = Fp160.sub(s2, s1)
        val hh = Fp160.sqr(h)
        val hhh = Fp160.mul(hh, h)
        val u1hh = Fp160.mul(u1, hh)
        val x3 = Fp160.sub(Fp160.sub(Fp160.sqr(r), hhh), Fp160.mulSmall(u1hh, 2))
        val y3 = Fp160.sub(
            Fp160.mul(r, Fp160.sub(u1hh, x3)),
            Fp160.mul(s1, hhh),
        )
        val z3 = Fp160.mul(Fp160.mul(h, p.z), q.z)
        return Jac(x3, y3, z3)
    }

    /** -1 if the two Jacobian points represent the same affine point. */
    private fun jEq(p: Jac, q: Jac): Long {
        val z1z1 = Fp160.sqr(p.z)
        val z2z2 = Fp160.sqr(q.z)
        val xEq = Fp160.equalsMask(Fp160.mul(p.x, z2z2), Fp160.mul(q.x, z1z1))
        val yEq = Fp160.equalsMask(
            Fp160.mul(Fp160.mul(p.y, z2z2), q.z),
            Fp160.mul(Fp160.mul(q.y, z1z1), p.z),
        )
        return xEq and yEq
    }

    /**
     * Addition valid for every pair of inputs, branch-free.
     *
     * Both candidate formulas are always evaluated and the answer selected by mask, so the work
     * done does not reveal which case occurred. Later selections take priority, so the precedence
     * is: p infinite, then q infinite, then p == q, then p == -q, then the generic case.
     */
    private fun addComplete(p: Jac, q: Jac): Jac {
        val pInf = Fp160.isZeroMask(p.z)
        val qInf = Fp160.isZeroMask(q.z)
        val same = jEq(p, q)
        val opposite = jEq(p, neg(q))

        var out = jAdd(p, q)
        out = selectPoint(opposite, INFINITY, out)
        out = selectPoint(same, jDouble(p), out)
        out = selectPoint(qInf, p, out)
        out = selectPoint(pInf, q, out)
        return out
    }

    /**
     * Double-and-add-always over a fixed [SCALAR_BITS] iterations.
     *
     * The iteration count and the operations performed are identical for every scalar; only a
     * masked selection differs per bit. Costs one doubling and one complete addition per bit
     * regardless of the bit's value, which is the point.
     */
    fun scalarMul(scalarBE: ByteArray, point: Jac): Jac {
        require(scalarBE.size == SCALAR_BYTES) { "scalar must be $SCALAR_BYTES bytes" }
        var acc = INFINITY
        for (bit in SCALAR_BITS - 1 downTo 0) {
            acc = jDouble(acc)
            val candidate = addComplete(acc, point)
            val byteIdx = SCALAR_BYTES - 1 - (bit / 8)
            val mask = -(((scalarBE[byteIdx].toInt() ushr (bit % 8)) and 1).toLong())
            acc = selectPoint(mask, candidate, acc)
        }
        return acc
    }

    /** The affine x-coordinate, or null if the point is at infinity. */
    fun affineX(p: Jac): ByteArray? {
        if (Fp160.isZeroMask(p.z) != 0L) return null
        val zInv = Fp160.inverse(p.z)
        return Fp160.toBytes(Fp160.mul(p.x, Fp160.sqr(zInv)))
    }

    /**
     * Reconstructs the point with the given x-coordinate, choosing the even-y root.
     *
     * Returns null when [xBytes] is not a valid encoding — either not less than p, or not the
     * x-coordinate of any curve point. **This is the input validation for a value typed by a
     * human, and skipping it would accept arbitrary attacker-chosen field elements.**
     *
     * The choice of root is irrelevant to the shared secret (see the class documentation) but is
     * made deterministic so that both sides agree on the transcript.
     */
    fun decompress(xBytes: ByteArray): Jac? {
        if (xBytes.size != KEY_BYTES) return null
        val x = Fp160.fromBytes(xBytes)
        if (Fp160.lessThanPMask(x) == 0L) return null // x >= p is not a canonical encoding

        // y^2 = x^3 - 3x + b
        val rhs = Fp160.add(
            Fp160.sub(Fp160.mul(Fp160.sqr(x), x), Fp160.mulSmall(x, 3)),
            B,
        )
        val y = Fp160.sqrtOrNull(rhs) ?: return null
        // A prime-order curve has no point of order two, so y = 0 cannot occur; reject anyway
        // rather than rely on that reasoning holding after someone edits the parameters.
        if (Fp160.isZeroMask(y) != 0L) return null

        val yEven = Fp160.select(Fp160.isOddMask(y), Fp160.neg(y), y)
        return Jac(x, yEven, Fp160.ONE)
    }

    /** x-only ECDH. Null if the peer's key is invalid or the result is degenerate. */
    fun ecdhX(scalarBE: ByteArray, peerXBytes: ByteArray): ByteArray? {
        val peer = decompress(peerXBytes) ?: return null
        return affineX(scalarMul(scalarBE, peer))
    }

    /** The x-only public key for a scalar. */
    fun publicKeyX(scalarBE: ByteArray): ByteArray =
        affineX(scalarMul(scalarBE, G))
            ?: throw IllegalStateException("scalar multiplication yielded infinity")

    /**
     * Draws a private scalar.
     *
     * Takes 160 random bits and rejects only zero. Because n = 2^160 + ~2^81 is barely above 2^160,
     * every non-zero 160-bit value is a valid scalar in [1, n-1]; the resulting distribution is
     * uniform on [1, 2^160-1] rather than [1, n-1], a bias of about 2^-79 which is far below any
     * threat. Doing it this way avoids a rejection loop whose iteration count could be observed.
     */
    fun randomScalar(randomBytes: (Int) -> ByteArray): ByteArray {
        while (true) {
            val raw = randomBytes(Fp160.BYTES)
            var acc = 0
            for (b in raw) acc = acc or b.toInt()
            if (acc == 0) continue // probability 2^-160; loop for completeness, not for security
            val out = ByteArray(SCALAR_BYTES)
            raw.copyInto(out, SCALAR_BYTES - Fp160.BYTES)
            return out
        }
    }
}
