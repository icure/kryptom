package com.icure.kryptom.utils

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe

class ConstantTimeEqualsTest : StringSpec({
	"identical arrays are equal, including empty ones" {
		constantTimeEquals(ByteArray(0), ByteArray(0)) shouldBe true
		val a = ByteArray(32) { it.toByte() }
		constantTimeEquals(a, a.copyOf()) shouldBe true
	}

	"arrays of different length are never equal, even when one is a prefix of the other" {
		val a = ByteArray(32) { it.toByte() }
		constantTimeEquals(a, a.copyOf(31)) shouldBe false
		constantTimeEquals(a.copyOf(31), a) shouldBe false
		constantTimeEquals(a, ByteArray(0)) shouldBe false
	}

	"a single flipped bit at any position is detected" {
		val a = ByteArray(32) { it.toByte() }
		for (i in a.indices) for (bit in 0 until 8) {
			val b = a.copyOf().also { it[i] = (it[i].toInt() xor (1 shl bit)).toByte() }
			constantTimeEquals(a, b) shouldBe false
		}
	}
})
