package com.icure.kryptom.utils

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe

val base64CanonicalData: List<Pair<String, ByteArray>> = listOf(
	"Zg==" to "f",
	"Zm8=" to "fo",
	"Zm9v" to "foo",
	"Zm9vYg==" to "foob",
	"Zm9vYmE=" to "fooba",
	"Zm9vYmFy" to "foobar",
	"TG9yZW0=" to "Lorem",
	"TG9yZW0gaXBzdW0gZG9sb3Igc2l0" to "Lorem ipsum dolor sit",
	"R2lvdmFubmkgR2lvcmdpbw==" to "Giovanni Giorgio",
	"Pj8+Pz4/" to ">?>?>?",
	Pair(
		"U29tZXRoaW5nIHZlcnkgbG9uZyBqdXN0IHRvIG1ha2Ugc3VyZSB0aGVyZSBpcyBubyBsaW5lIHdyYXBwaW5n",
		"Something very long just to make sure there is no line wrapping"
	),
).map { it.first to it.second.encodeToByteArray() }

val invalidPaddingBase64: List<String> = listOf(
	"TG9yZW0==",
	"TG9yZW0gaXBzdW0gZG9sb3Igc2l0=",
	"TG9yZW0gaXBzdW0gZG9sb3Igc2l0==",
	"R2lvdmFubmkgR2lvcmdpbw=",
	"R2lvdmFubmkgR2lvcmdpbw==="
)

val missingPadding: List<Pair<String, ByteArray>> = listOf(
	"TG9yZW0" to "Lorem",
	"R2lvdmFubmkgR2lvcmdpbw" to "Giovanni Giorgio",
).map { it.first to it.second.encodeToByteArray() }

val invalidBase64: List<String> = listOf(
	"TG9yZW0\ngaXBzdW0K",
	"TG9yZW0gaXB\\nzdW0K",
	"Pj8-Pz4_",
	"Pj8?Pz4?",
)

class Base64Test : StringSpec({
	"Base 64 strings should be encoded to the expected values" {
		base64CanonicalData.forEach { base64Encode(it.second) shouldBe it.first }
	}

	"Base 64 strings should be decoded to the expected values" {
		base64CanonicalData.forEach {
			base64Decode(it.first).also { println(it.decodeToString()) }.toList() shouldBe it.second.toList()
		}
	}

	"Base 64 decode should work with missing padding" {
		missingPadding.forEach { base64Decode(it.first).toList() shouldBe it.second.toList() }
	}

	"Base 64 strings with invalid padding (not missing but not correct amount of =) should not be decoded" {
		invalidPaddingBase64.forEach { shouldThrow<IllegalArgumentException> { base64Decode(it) } }
	}

	"Base 64 strings with invalid characters should not be decoded" {
		invalidBase64.forEach { shouldThrow<IllegalArgumentException> { base64Decode(it) } }
	}

	"Base 64 with URL safe alphabet should work" {
		val data = ">?>?>?".encodeToByteArray()
		val expectedEncoded = "Pj8-Pz4_"
		base64UrlEncode(data) shouldBe expectedEncoded
		base64UrlDecode(expectedEncoded).toList() shouldBe data.toList()
	}

	"Empty base 64 string should be decoded to an empty byte array" {
		base64Decode("") shouldBe ByteArray(0)
	}

	"Empty byte array should be encoded to an empty base 64 string" {
		base64Encode(ByteArray(0)) shouldBe ""
	}
})