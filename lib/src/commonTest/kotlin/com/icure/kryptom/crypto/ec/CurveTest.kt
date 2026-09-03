package com.icure.kryptom.crypto.ec

import com.icure.kryptom.utils.hexToByteArray
import com.icure.kryptom.utils.toHexString
import io.kotest.core.spec.style.StringSpec
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Field and curve arithmetic, pinned to the independently generated vectors. */
class CurveTest : StringSpec({

    fun fp(hex: String) = Fp160.fromBytes(hexToByteArray(hex))
    fun hex(x: LongArray) = Fp160.toBytes(x).toHexString()

    // ------------------------------------------------------------------ domain parameters

        "primeIsTwoTo160MinusTwoTo31MinusOne" {
        // Reconstruct p from its definition using only field-independent byte math, then compare
        // to the constant actually used. A typo in the constant is the kind of error that produces
        // a curve that still "works" but is not secp160r1.
        val expected = ByteArray(20) { 0xFF.toByte() }
        // clear bit 31: byte index 19 - 3 = 16, bit 7 of that byte
        expected[16] = (expected[16].toInt() and 0x7F).toByte()
        assertEquals(expected.toHexString(), Fp160.toBytes(Fp160.P).toHexString())
        assertEquals(Secp160r1Vectors.P, Fp160.toBytes(Fp160.P).toHexString())
    }

        "curveConstantsMatchSec2" {
        assertEquals(Secp160r1Vectors.B, hex(Secp160r1.B))
        assertEquals(Secp160r1Vectors.N, Secp160r1.N_BYTES.toHexString())
        val g = Secp160r1.G
        assertEquals(Secp160r1Vectors.GX, hex(g.x))
        assertEquals(Secp160r1Vectors.GY, hex(g.y))
    }

        "generatorIsOnTheCurve" {
        val g = Secp160r1.G
        val lhs = Fp160.sqr(g.y)
        val rhs = Fp160.add(
            Fp160.sub(Fp160.mul(Fp160.sqr(g.x), g.x), Fp160.mulSmall(g.x, 3)),
            Secp160r1.B,
        )
        assertEquals(hex(lhs), hex(rhs))
    }

    // ------------------------------------------------------------------ field

        "fieldOperationsMatchVectors" {
        for ((i, row) in Secp160r1Vectors.field.withIndex()) {
            val u = fp(row[0])
            val v = fp(row[1])
            assertEquals(row[2], hex(Fp160.add(u, v)), "add, row $i")
            assertEquals(row[3], hex(Fp160.sub(u, v)), "sub, row $i")
            assertEquals(row[4], hex(Fp160.mul(u, v)), "mul, row $i")
            assertEquals(row[5], hex(Fp160.sqr(u)), "sqr, row $i")
            if (row[6].isNotEmpty()) {
                assertEquals(row[6], hex(Fp160.inverse(u)), "inv, row $i")
            }
        }
    }

        "byteRoundTripIsExact" {
        for (row in Secp160r1Vectors.field) {
            assertEquals(row[0], hex(fp(row[0])))
        }
        assertEquals("0".repeat(40), hex(Fp160.ZERO))
        assertEquals("0".repeat(39) + "1", hex(Fp160.ONE))
    }

        "inverseTimesValueIsOne" {
        for (row in Secp160r1Vectors.field) {
            val u = fp(row[0])
            if (Fp160.isZeroMask(u) != 0L) continue
            assertEquals(hex(Fp160.ONE), hex(Fp160.mul(u, Fp160.inverse(u))))
        }
    }

        "additionAndSubtractionAreInverse" {
        for (row in Secp160r1Vectors.field) {
            val u = fp(row[0])
            val v = fp(row[1])
            assertEquals(hex(u), hex(Fp160.sub(Fp160.add(u, v), v)))
            assertEquals(hex(u), hex(Fp160.add(Fp160.sub(u, v), v)))
        }
    }

    /**
     * The reduction bounds argument (see [Fp160]) rests on worst-case magnitudes. These are the
     * inputs that stress it: p-1 squared is the largest product reachable from canonical inputs.
     */
        "reductionHandlesWorstCaseMagnitudes" {
        val pMinus1 = Fp160.sub(Fp160.ZERO, Fp160.ONE)
        assertEquals(hex(Fp160.ONE), hex(Fp160.sqr(pMinus1)), "(p-1)^2 must be 1")
        assertEquals(hex(Fp160.sub(Fp160.ZERO, Fp160.ONE)), hex(pMinus1))
        // p-1 + p-1 = p-2
        assertEquals(hex(Fp160.sub(Fp160.ZERO, Fp160.mulSmall(Fp160.ONE, 2))),
            hex(Fp160.add(pMinus1, pMinus1)))
        // (p-1)*(p-1) again via mul rather than sqr, and p-1 times 1
        assertEquals(hex(Fp160.ONE), hex(Fp160.mul(pMinus1, pMinus1)))
        assertEquals(hex(pMinus1), hex(Fp160.mul(pMinus1, Fp160.ONE)))
    }

        "nonCanonicalEncodingsAreRejected" {
        // p, p+1 and 2^160-1 all fit in 20 bytes but are not field elements.
        assertEquals(0L, Fp160.lessThanPMask(Fp160.P))
        assertEquals(0L, Fp160.lessThanPMask(fp("f".repeat(40))))
        assertTrue(Fp160.lessThanPMask(Fp160.sub(Fp160.ZERO, Fp160.ONE)) != 0L, "p-1 < p")
        assertTrue(Fp160.lessThanPMask(Fp160.ZERO) != 0L, "0 < p")
    }

        "squareRootAgreesWithSquaring" {
        for (row in Secp160r1Vectors.field) {
            val u = fp(row[0])
            val sq = Fp160.sqr(u)
            val root = Fp160.sqrtOrNull(sq)
            assertNotNull(root, "a square must have a root")
            // Either root is acceptable; the square must come back.
            assertEquals(hex(sq), hex(Fp160.sqr(root)))
        }
    }

        "squareRootRejectsNonResidues" {
        var nonResidues = 0
        var candidate = Fp160.mulSmall(Fp160.ONE, 2)
        repeat(60) {
            if (Fp160.sqrtOrNull(candidate) == null) nonResidues++
            candidate = Fp160.add(candidate, Fp160.ONE)
        }
        // Roughly half of all field elements are non-residues; assert we see a healthy share
        // rather than zero, which is what a broken sqrt that never rejects would give.
        assertTrue(nonResidues in 15..45, "found $nonResidues non-residues in 60, expected ~30")
    }

    // ------------------------------------------------------------------ curve

        "scalarMultiplicationMatchesVectors" {
        for ((i, row) in Secp160r1Vectors.scalarMul.withIndex()) {
            val k = hexToByteArray(row[0])
            val r = Secp160r1.scalarMul(k, Secp160r1.G)
            assertEquals(row[1], Secp160r1.affineX(r)?.toHexString(), "x, row $i (k=${row[0]})")
        }
    }

        "publicKeyDerivationMatchesVectors" {
        for (row in Secp160r1Vectors.scalarMul) {
            assertEquals(row[1], Secp160r1.publicKeyX(hexToByteArray(row[0])).toHexString())
        }
    }

        "decompressionMatchesVectors" {
        for ((i, v) in Secp160r1Vectors.decompress.withIndex()) {
            val (xHex, valid, yEven) = v
            val p = Secp160r1.decompress(hexToByteArray(xHex))
            if (valid) {
                assertNotNull(p, "row $i: x=$xHex should be on the curve")
                assertEquals(xHex, Fp160.toBytes(p.x).toHexString())
                assertEquals(yEven, Fp160.toBytes(p.y).toHexString(), "row $i: even root")
                assertEquals(0L, Fp160.isOddMask(p.y), "row $i: chosen root must be even")
            } else {
                assertNull(p, "row $i: x=$xHex must be rejected")
            }
        }
    }

        "decompressionRejectsWrongLength" {
        assertNull(Secp160r1.decompress(ByteArray(19)))
        assertNull(Secp160r1.decompress(ByteArray(21)))
        assertNull(Secp160r1.decompress(ByteArray(0)))
    }

        "decompressedPointsSatisfyTheCurveEquation" {
        for ((xHex, valid, _) in Secp160r1Vectors.decompress) {
            val p = Secp160r1.decompress(hexToByteArray(xHex)) ?: continue
            assertTrue(valid)
            val lhs = Fp160.sqr(p.y)
            val rhs = Fp160.add(
                Fp160.sub(Fp160.mul(Fp160.sqr(p.x), p.x), Fp160.mulSmall(p.x, 3)),
                Secp160r1.B,
            )
            assertEquals(hex(lhs), hex(rhs), "x=$xHex")
        }
    }

        "ecdhMatchesVectorsAndBothSidesAgree" {
        for ((i, row) in Secp160r1Vectors.ecdh.withIndex()) {
            val (dA, xA, dB, xB, shared) = row
            assertEquals(xA, Secp160r1.publicKeyX(hexToByteArray(dA)).toHexString(), "xA, row $i")
            assertEquals(xB, Secp160r1.publicKeyX(hexToByteArray(dB)).toHexString(), "xB, row $i")
            val fromA = Secp160r1.ecdhX(hexToByteArray(dA), hexToByteArray(xB))
            val fromB = Secp160r1.ecdhX(hexToByteArray(dB), hexToByteArray(xA))
            assertEquals(shared, fromA?.toHexString(), "A's view, row $i")
            assertEquals(shared, fromB?.toHexString(), "B's view, row $i")
        }
    }

        "ecdhRejectsAnInvalidPeerKey" {
        val d = hexToByteArray(Secp160r1Vectors.ecdh[0][0])
        for ((xHex, valid, _) in Secp160r1Vectors.decompress) {
            if (valid) continue
            assertNull(Secp160r1.ecdhX(d, hexToByteArray(xHex)), "must reject x=$xHex")
        }
    }

    /**
     * x-only means both parties may reconstruct opposite roots. The shared secret must be
     * unaffected — if it were not, roughly half of all pairings would fail in production, which is
     * exactly the kind of bug that survives a happy-path test suite.
     */
        "oppositeRootsYieldTheSameSharedSecret" {
        for (row in Secp160r1Vectors.ecdh) {
            val dA = hexToByteArray(row[0])
            val xB = hexToByteArray(row[3])
            val pB = Secp160r1.decompress(xB)!!
            val negB = Secp160r1.Jac(pB.x, Fp160.neg(pB.y), pB.z)
            val viaEven = Secp160r1.affineX(Secp160r1.scalarMul(dA, pB))
            val viaOdd = Secp160r1.affineX(Secp160r1.scalarMul(dA, negB))
            assertEquals(viaEven?.toHexString(), viaOdd?.toHexString())
            assertEquals(row[4], viaEven?.toHexString())
        }
    }

    // ------------------------------------------------------------------ degenerate cases

        "scalarMultiplicationByZeroIsInfinity" {
        assertNull(Secp160r1.affineX(Secp160r1.scalarMul(ByteArray(21), Secp160r1.G)))
    }

        "scalarMultiplicationByOrderIsInfinity" {
        // nG = infinity. This exercises the p == -q branch of addComplete at the final step,
        // which an incomplete addition formula would get wrong.
        assertNull(Secp160r1.affineX(Secp160r1.scalarMul(Secp160r1.N_BYTES, Secp160r1.G)))
    }

        "scalarOneYieldsTheGenerator" {
        val one = ByteArray(Secp160r1.SCALAR_BYTES).also { it[20] = 1 }
        assertEquals(Secp160r1Vectors.GX, Secp160r1.publicKeyX(one).toHexString())
    }

    /**
     * Diffie-Hellman symmetry over freshly drawn scalars, not just the recorded vectors. The
     * vectors prove agreement with the reference; this proves the property holds generally, which
     * is what catches a ladder that is subtly wrong only for some bit patterns.
     */
        "ecdhIsSymmetricForArbitraryScalars" {
        var seed = 0x9E3779B97F4A7C15uL
        val next = { n: Int ->
            ByteArray(n) {
                seed = seed * 6364136223846793005uL + 1442695040888963407uL
                (seed shr 33).toByte()
            }
        }
        repeat(12) {
            val dA = Secp160r1.randomScalar(next)
            val dB = Secp160r1.randomScalar(next)
            val xA = Secp160r1.publicKeyX(dA)
            val xB = Secp160r1.publicKeyX(dB)
            val sA = Secp160r1.ecdhX(dA, xB)
            val sB = Secp160r1.ecdhX(dB, xA)
            assertNotNull(sA)
            assertNotNull(sB)
            assertEquals(sA.toHexString(), sB.toHexString())
            // and the shared value must not simply be one of the public keys
            assertFalse(sA.contentEquals(xA) || sA.contentEquals(xB))
        }
    }

        "randomScalarIsInRangeAndNonZero" {
        var counter = 0
        val notRandom = { n: Int -> ByteArray(n) { (counter++ % 251 + 1).toByte() } }
        repeat(50) {
            val s = Secp160r1.randomScalar(notRandom)
            assertEquals(Secp160r1.SCALAR_BYTES, s.size)
            assertEquals(0, s[0].toInt(), "top byte must be zero: scalar < 2^160")
            var acc = 0
            for (b in s) acc = acc or b.toInt()
            assertFalse(acc == 0, "scalar must not be zero")
        }
    }

        "allZeroRandomnessIsRejectedNotReturned" {
        var calls = 0
        val random = { n: Int ->
            calls++
            if (calls <= 2) ByteArray(n) else ByteArray(n) { 7 }
        }
        val s = Secp160r1.randomScalar(random)
        assertEquals(3, calls, "two all-zero draws must be rejected")
        assertEquals(7, s[Secp160r1.SCALAR_BYTES - 1].toInt())
    }

    // ------------------------------------------------------------------ constant-time helpers

        "masksBehaveAsAllOnesOrAllZeros" {
        assertEquals(-1L, Fp160.isZeroMask(Fp160.ZERO))
        assertEquals(0L, Fp160.isZeroMask(Fp160.ONE))
        assertEquals(-1L, Fp160.equalsMask(Fp160.ONE, Fp160.ONE))
        assertEquals(0L, Fp160.equalsMask(Fp160.ONE, Fp160.ZERO))
        assertEquals(-1L, Fp160.isOddMask(Fp160.ONE))
        assertEquals(0L, Fp160.isOddMask(Fp160.mulSmall(Fp160.ONE, 2)))
        // select must be total, not "mostly right"
        assertEquals(Secp160r1Vectors.GX, Fp160.toBytes(Fp160.select(-1L, Secp160r1.G.x, Fp160.ZERO)).toHexString())
        assertEquals("0".repeat(40), Fp160.toBytes(Fp160.select(0L, Secp160r1.G.x, Fp160.ZERO)).toHexString())
    }
})
