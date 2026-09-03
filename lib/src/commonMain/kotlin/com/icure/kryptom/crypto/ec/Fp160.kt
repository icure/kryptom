package com.icure.kryptom.crypto.ec

import com.icure.kryptom.utils.hexToByteArray

/**
 * Arithmetic in the field F_p, p = 2^160 - 2^31 - 1 (the secp160r1 prime).
 *
 * ## Representation
 *
 * Eight limbs of 20 bits each, held in a `LongArray`, least significant limb first. Canonical
 * elements are fully reduced (value < p) with every limb in `[0, 2^20)`.
 *
 * 20-bit limbs are chosen for two reasons. First, products fit comfortably: a limb product is under
 * 2^40 and a schoolbook column accumulates at most eight of them, so a column stays under 2^43 and
 * nothing can overflow a signed `Long`. Kotlin common code has no 128-bit type and no
 * `multiplyHigh`, so 32-bit limbs are not an option — (2^32-1)^2 already overflows `Long`. Second,
 * bit 160 lands exactly on a limb boundary, which makes the modular reduction a clean split.
 *
 * ## Reduction
 *
 * 2^160 ≡ 2^31 + 1 (mod p), so a 320-bit product `t` folds as
 * `low160(t) + high(t) + (high(t) << 31)`. Two folds suffice:
 *
 * - after the first, the value is under 2^192;
 * - after the second, under 2^160 + 2^64, which is less than 2p;
 *
 * so a single conditional subtraction of p yields a canonical result. Both folds and the
 * subtraction are branch-free.
 *
 * ## Constant-time claim, stated honestly
 *
 * Every operation here is branch-free with respect to its operand *values*: selections use masks,
 * not `if`. [pow] does branch, but only on the bits of a **public compile-time exponent** (p-2 for
 * inversion, (p+1)/4 for square roots), so its operation sequence is fixed and independent of the
 * secret.
 *
 * That said, on Kotlin/JS `Long` is emulated and on JVM the JIT may do as it pleases, so this is
 * best effort rather than a guarantee — the same caveat that applies to [com.icure.kryptom.utils.constantTimeEquals].
 * What it does buy you is the absence of *algorithmic* timing dependence, which is the part that
 * leaks whole key bits rather than fractions of a nanosecond.
 */
internal object Fp160 {

    const val LIMBS = 8
    const val LIMB_BITS = 20
    const val LIMB_MASK = 0xFFFFFL
    const val BYTES = 20

    /** p = 2^160 - 2^31 - 1. Derived from bytes rather than hand-written limbs, to avoid a typo. */
    val P: LongArray = fromBytes(
        hexToByteArray("ffffffffffffffffffffffffffffffff7fffffff")
    )

    /** p - 2, the inversion exponent. Public constant. */
    private val P_MINUS_2 = hexToByteArray("ffffffffffffffffffffffffffffffff7ffffffd")

    /** (p + 1) / 4, the square-root exponent. Valid because p ≡ 3 (mod 4). */
    private val P_PLUS_1_OVER_4 = hexToByteArray("3fffffffffffffffffffffffffffffffe0000000")

    val ZERO: LongArray get() = LongArray(LIMBS)
    val ONE: LongArray get() = LongArray(LIMBS).also { it[0] = 1L }

    // ------------------------------------------------------------------ encoding

    /**
     * Big-endian 20 bytes to limbs. Written as a bit loop rather than clever block shuffling:
     * this runs a handful of times per pairing, and clarity is worth more than speed here.
     */
    fun fromBytes(be: ByteArray): LongArray {
        require(be.size == BYTES) { "expected $BYTES bytes, got ${be.size}" }
        val out = LongArray(LIMBS)
        for (bit in 0 until LIMBS * LIMB_BITS) {
            val byteIdx = BYTES - 1 - (bit / 8)
            val b = (be[byteIdx].toInt() ushr (bit % 8)) and 1
            out[bit / LIMB_BITS] = out[bit / LIMB_BITS] or (b.toLong() shl (bit % LIMB_BITS))
        }
        return out
    }

    fun toBytes(x: LongArray): ByteArray {
        val out = ByteArray(BYTES)
        for (bit in 0 until LIMBS * LIMB_BITS) {
            val b = ((x[bit / LIMB_BITS] ushr (bit % LIMB_BITS)) and 1L).toInt()
            val byteIdx = BYTES - 1 - (bit / 8)
            out[byteIdx] = (out[byteIdx].toInt() or (b shl (bit % 8))).toByte()
        }
        return out
    }

    // ------------------------------------------------------------------ masks and selection

    /** -1 if every limb is zero, else 0. */
    fun isZeroMask(x: LongArray): Long {
        var acc = 0L
        for (i in 0 until LIMBS) acc = acc or x[i]
        return ((acc or -acc) shr 63).inv()
    }

    /** -1 if the two elements are equal, else 0. */
    fun equalsMask(x: LongArray, y: LongArray): Long {
        var acc = 0L
        for (i in 0 until LIMBS) acc = acc or (x[i] xor y[i])
        return ((acc or -acc) shr 63).inv()
    }

    /** [a] where [mask] is -1, [b] where it is 0. */
    fun select(mask: Long, a: LongArray, b: LongArray): LongArray {
        val out = LongArray(LIMBS)
        for (i in 0 until LIMBS) out[i] = (a[i] and mask) or (b[i] and mask.inv())
        return out
    }

    /** -1 if the low bit of the canonical value is set. */
    fun isOddMask(x: LongArray): Long = -(x[0] and 1L)

    /**
     * -1 if the limb array, read as an integer, is strictly less than p.
     *
     * Used to reject a non-canonical x-coordinate: the 160-bit encoding can represent values in
     * [p, 2^160), which are not valid field elements, and accepting them would let a peer smuggle
     * in a value that reduces to something they control.
     */
    fun lessThanPMask(x: LongArray): Long {
        var borrow = 0L
        for (i in 0 until LIMBS) {
            val v = x[i] - P[i] - borrow
            borrow = (v ushr 63) and 1L
        }
        return -borrow
    }

    // ------------------------------------------------------------------ add / sub

    fun add(x: LongArray, y: LongArray): LongArray {
        val t = LongArray(LIMBS + 1)
        var carry = 0L
        for (i in 0 until LIMBS) {
            val v = x[i] + y[i] + carry
            t[i] = v and LIMB_MASK
            carry = v ushr LIMB_BITS
        }
        t[LIMBS] = carry
        return conditionalSubP(t)
    }

    fun sub(x: LongArray, y: LongArray): LongArray {
        val d = LongArray(LIMBS)
        var borrow = 0L
        for (i in 0 until LIMBS) {
            val v = x[i] - y[i] - borrow
            d[i] = v and LIMB_MASK
            borrow = (v ushr 63) and 1L
        }
        // Underflowed, so add p back. Branch-free: the addend is masked, not skipped.
        val mask = -borrow
        val out = LongArray(LIMBS)
        var carry = 0L
        for (i in 0 until LIMBS) {
            val v = d[i] + (P[i] and mask) + carry
            out[i] = v and LIMB_MASK
            carry = v ushr LIMB_BITS
        }
        return out
    }

    fun neg(x: LongArray): LongArray = sub(ZERO, x)

    /** Doubles, tripling etc. via repeated [add] — clarity over micro-optimisation. */
    fun mulSmall(x: LongArray, k: Int): LongArray {
        var acc = ZERO
        repeat(k) { acc = add(acc, x) }
        return acc
    }

    // ------------------------------------------------------------------ multiply

    fun mul(x: LongArray, y: LongArray): LongArray {
        val t = LongArray(2 * LIMBS)
        for (i in 0 until LIMBS) {
            val xi = x[i]
            for (j in 0 until LIMBS) {
                // Each column takes at most 8 products of < 2^40, so stays under 2^43.
                t[i + j] += xi * y[j]
            }
        }
        normalise(t)
        return reduce(t)
    }

    fun sqr(x: LongArray): LongArray = mul(x, x)

    fun inverse(x: LongArray): LongArray = pow(x, P_MINUS_2)

    /**
     * A square root of [x], or null if [x] is not a quadratic residue.
     *
     * p ≡ 3 (mod 4), so a candidate root is x^((p+1)/4) and one squaring confirms it. Returning
     * null is how [Secp160r1.decompress] rejects an x-coordinate that is not on the curve.
     */
    fun sqrtOrNull(x: LongArray): LongArray? {
        val candidate = pow(x, P_PLUS_1_OVER_4)
        return if (equalsMask(sqr(candidate), x) != 0L) candidate else null
    }

    /**
     * Left-to-right square-and-multiply. [exp] must be a **public** constant — the branches below
     * follow its bits.
     */
    private fun pow(base: LongArray, exp: ByteArray): LongArray {
        var acc = ONE
        var started = false
        for (byte in exp) {
            for (bit in 7 downTo 0) {
                if (started) acc = sqr(acc)
                if (((byte.toInt() ushr bit) and 1) == 1) {
                    acc = if (started) mul(acc, base) else base.copyOf()
                    started = true
                }
            }
        }
        return acc
    }

    // ------------------------------------------------------------------ reduction internals

    /** Carry-propagates an accumulator into 20-bit limbs, in place. */
    private fun normalise(t: LongArray) {
        var carry = 0L
        for (i in t.indices) {
            val v = t[i] + carry
            t[i] = v and LIMB_MASK
            carry = v ushr LIMB_BITS
        }
        // The caller sizes the array so that nothing is left over.
        require(carry == 0L) { "reduction accumulator overflow" }
    }

    /** dst += src << bits. Accumulates without normalising; the caller normalises after. */
    private fun addShiftedInto(dst: LongArray, src: LongArray, bits: Int) {
        val limbShift = bits / LIMB_BITS
        val bitShift = bits % LIMB_BITS
        for (k in src.indices) {
            val v = src[k] shl bitShift
            val idx = k + limbShift
            if (idx < dst.size) dst[idx] += v and LIMB_MASK
            if (idx + 1 < dst.size) dst[idx + 1] += v ushr LIMB_BITS
        }
    }

    /**
     * Folds a 2*LIMBS accumulator down to a canonical element using 2^160 ≡ 2^31 + 1.
     *
     * See the class documentation for the bounds that make two folds plus one conditional
     * subtraction sufficient. `FoldTest` pins those bounds with explicit worst-case inputs.
     */
    private fun reduce(t: LongArray): LongArray {
        // Fold 1: value < 2^192, so 10 limbs (200 bits) of headroom.
        val r1 = LongArray(10)
        for (i in 0 until LIMBS) r1[i] = t[i]
        val h1 = LongArray(LIMBS) { t[LIMBS + it] }
        for (i in h1.indices) if (i < r1.size) r1[i] += h1[i]
        addShiftedInto(r1, h1, 31)
        normalise(r1)

        // Fold 2: value < 2^160 + 2^64 < 2p, so 9 limbs suffice.
        val r2 = LongArray(LIMBS + 1)
        for (i in 0 until LIMBS) r2[i] = r1[i]
        val h2 = longArrayOf(r1[8], r1[9])
        r2[0] += h2[0]
        r2[1] += h2[1]
        addShiftedInto(r2, h2, 31)
        normalise(r2)

        return conditionalSubP(r2)
    }

    /** [a] must be < 2p and have LIMBS+1 limbs. Returns the canonical representative. */
    private fun conditionalSubP(a: LongArray): LongArray {
        val d = LongArray(LIMBS + 1)
        var borrow = 0L
        for (i in 0 until LIMBS) {
            val v = a[i] - P[i] - borrow
            d[i] = v and LIMB_MASK
            borrow = (v ushr 63) and 1L
        }
        val vTop = a[LIMBS] - borrow
        borrow = (vTop ushr 63) and 1L

        // borrow == 1 means a < p, so keep a; otherwise take the difference.
        val keepA = -borrow
        val out = LongArray(LIMBS)
        for (i in 0 until LIMBS) out[i] = (a[i] and keepA) or (d[i] and keepA.inv())
        return out
    }
}
