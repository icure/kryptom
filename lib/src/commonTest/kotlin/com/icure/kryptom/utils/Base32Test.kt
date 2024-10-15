package com.icure.kryptom.utils

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe

val base32CanonicalData: List<Pair<String, ByteArray>> = listOf(
	"MY======" to "f",
	"MZXQ====" to "fo",
	"MZXW6===" to "foo",
	"MZXW6YQ=" to "foob",
	"MZXW6YTB" to "fooba",
	"MZXW6YTBOI======" to "foobar",
	"JRXXEZLNEBUXA43VNUQGI33MN5ZCA43JOQ======" to "Lorem ipsum dolor sit",
	"I5UW65TBNZXGSICHNFXXEZ3JN4======" to "Giovanni Giorgio",
	"HY7T4PZ6H4======" to ">?>?>?",
	Pair(
		"KNXW2ZLUNBUW4ZZAOZSXE6JANRXW4ZZANJ2XG5BAORXSA3LBNNSSA43VOJSSA5DIMVZGKIDJOMQG43ZANRUW4ZJAO5ZGC4DQNFXGO===",
		"Something very long just to make sure there is no line wrapping"
	)
).map { it.first to it.second.encodeToByteArray() }

val invalidPaddingBase32: List<String> = listOf(
	"MZXW6YQ==",
	"MZXW6YTB=",
	"MZXW6=YTB",
	"MZXW6YTB==",
	"MZXW6YTB===",
	"MZXW6YTB====",
	"MZXW6YTB=====",
	"MZXW6YTB======",
	"MZXW6YTB======="
)

val missingPaddingBase32: List<Pair<String, ByteArray>> = listOf(
	"MZXW6" to "foo",
	"I5UW65TBNZXGSICHNFXXEZ3JN4" to "Giovanni Giorgio",
).map { it.first to it.second.encodeToByteArray() }

val invalidBase32: List<String> = listOf(
	"MZXW6Y\nTB",
	"MZXW6\\nYTB",
	"MZXW1YTB",
	"mZXW6YTB",
)

class Base32Test : StringSpec({
	"Base 32 strings should be encoded to the expected values" {
		base32CanonicalData.forEach { base32Encode(it.second) shouldBe it.first }
	}

	"Base 32 strings should be decoded to the expected values" {
		base32CanonicalData.forEach {
			println("Converting: ${it.first}")
			base32Decode(it.first).toList() shouldBe it.second.toList()
		}
	}

	"Base 32 decode should work with missing padding" {
		missingPaddingBase32.forEach { base32Decode(it.first).toList() shouldBe it.second.toList() }
	}

	"Base 32 strings with invalid padding (not missing but not correct amount of =) should not be decoded" {
		invalidPaddingBase32.forEach { shouldThrow<IllegalArgumentException> { base32Decode(it) } }
	}

	"Base 32 strings with invalid characters should not be decoded" {
		invalidBase32.forEach { shouldThrow<IllegalArgumentException> { base32Decode(it) } }
	}

	"Empty base 32 string should be decoded to an empty byte array" {
		base32Decode("") shouldBe ByteArray(0)
	}

	"Empty byte array should be encoded to an empty base 32 string" {
		base32Encode(ByteArray(0)) shouldBe ""
	}

})