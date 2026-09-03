package com.icure.kryptom.crypto.ec

import com.icure.kryptom.crypto.defaultCryptoService
import com.icure.kryptom.utils.hexToByteArray
import com.icure.kryptom.utils.toHexString
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

/** The public service surface, as exposed through [defaultCryptoService]. Curve internals are covered by [CurveTest]. */
class Secp160r1ServiceTest : StringSpec({
	val service = defaultCryptoService.secp160r1

	"random scalars have the right size, a zero top byte and are never zero" {
		repeat(20) {
			val s = service.randomScalar()
			s.size shouldBe Secp160r1Service.SCALAR_BYTES
			s[0] shouldBe 0.toByte()
			s.any { it != 0.toByte() } shouldBe true
		}
	}

	"random scalars use all 160 bits: no byte position is stuck at zero" {
		// The x-coordinate of kG looks random whatever the range of k, so uniformity of public keys or codes cannot
		// reveal a narrowed scalar range; only the scalars themselves can.
		val scalars = (1..40).map { service.randomScalar() }
		for (i in 1 until Secp160r1Service.SCALAR_BYTES) {
			scalars.count { it[i] != 0.toByte() } shouldBe io.kotest.matchers.ints.beGreaterThan(30)
		}
	}

	"fresh key pairs agree on the shared secret from both sides" {
		repeat(8) {
			val dA = service.randomScalar()
			val dB = service.randomScalar()
			val xA = service.publicKeyX(dA)
			val xB = service.publicKeyX(dB)
			xA.size shouldBe Secp160r1Service.PUBLIC_KEY_BYTES
			val fromA = service.ecdhX(dA, xB).shouldNotBeNull()
			val fromB = service.ecdhX(dB, xA).shouldNotBeNull()
			fromA.toHexString() shouldBe fromB.toHexString()
			fromA.contentEquals(xA) shouldBe false
			fromA.contentEquals(xB) shouldBe false
		}
	}

	"public keys and shared secrets match the reference vectors" {
		Secp160r1Vectors.ecdh.forEach { (dA, xA, dB, xB, shared) ->
			service.publicKeyX(hexToByteArray(dA)).toHexString() shouldBe xA
			service.publicKeyX(hexToByteArray(dB)).toHexString() shouldBe xB
			service.ecdhX(hexToByteArray(dA), hexToByteArray(xB))?.toHexString() shouldBe shared
			service.ecdhX(hexToByteArray(dB), hexToByteArray(xA))?.toHexString() shouldBe shared
		}
	}

	"public key validation agrees with the reference decisions" {
		Secp160r1Vectors.decompress.forEach { (x, valid, _) ->
			service.isValidPublicKeyX(hexToByteArray(x)) shouldBe valid
		}
		service.isValidPublicKeyX(ByteArray(19)) shouldBe false
		service.isValidPublicKeyX(ByteArray(21)) shouldBe false
	}

	"ecdh with an invalid peer key yields null rather than a secret" {
		val d = service.randomScalar()
		Secp160r1Vectors.decompress.filter { !it.second }.forEach { (x, _, _) ->
			service.ecdhX(d, hexToByteArray(x)).shouldBeNull()
		}
		service.ecdhX(d, ByteArray(0)).shouldBeNull()
	}

	"scalars outside [1, n-1] or of the wrong size are rejected" {
		val peer = service.publicKeyX(service.randomScalar())
		val zero = ByteArray(Secp160r1Service.SCALAR_BYTES)
		val n = Secp160r1.N_BYTES
		val nPlusOne = n.copyOf().also { it[it.lastIndex] = (it[it.lastIndex] + 1).toByte() }
		val allOnes = ByteArray(Secp160r1Service.SCALAR_BYTES) { 0xFF.toByte() }
		listOf(zero, n, nPlusOne, allOnes, ByteArray(20), ByteArray(22)).forEach { bad ->
			shouldThrow<IllegalArgumentException> { service.publicKeyX(bad) }
			shouldThrow<IllegalArgumentException> { service.ecdhX(bad, peer) }
		}
		// n - 1 is the largest valid scalar and yields -G, whose x is G's x
		val nMinusOne = n.copyOf().also { it[it.lastIndex] = (it[it.lastIndex] - 1).toByte() }
		service.publicKeyX(nMinusOne).toHexString() shouldBe Secp160r1Vectors.GX
	}

	"consecutive key pairs are distinct" {
		val keys = (1..30).map { service.publicKeyX(service.randomScalar()).toHexString() }
		keys.toSet().size shouldBe keys.size
	}
})
