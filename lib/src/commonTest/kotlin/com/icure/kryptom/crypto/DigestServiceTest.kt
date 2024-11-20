package com.icure.kryptom.crypto

import com.icure.kryptom.utils.toHexString
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe

private val dataHashesSha256 = listOf(
	"b4b7ccdb3223f407fa3bd0a6451453d774a14bf3208111a6e523ec6dce2af64c",
	"55fc641a0b2729692a7f3ffe84ef9b60c0ec6f29cbd91d96c52f7d1ae2046848",
	"16aba5393ad72c0041f5600ad3c2c52ec437a2f0c7fc08fadfc3c0fe9641d7a3",
	"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
	"b51ebfba6018c0e9c4700da49b0db9b398de89ad0613e2031a1bb3b0eb351bea",
	"bc762c3f9118e2b024676ec9ca6b2f264ac97dd2ccd026efef829fa2b1bd1a7b",
)

private val dataHashesSha512 = listOf(
	"e9886887a97e372086cb3fc0f12af49f28d54ce8fa7b17649c7ebae7abf47aacf42241b877bef1b915c1e60297e38c4b9a6314d20484486f6864621fa2dd0045",
	"220f725f99988952ead43f764752cf4b63749305b89b5ba628feb4fe9a9e46ee982c5e49a102e7aafd144ddc79d4063091afc04ac04abc41ed5d1806e010d7ad",
	"b1f4aaa6b51c19ffbe4b1b6fa107be09c8acafd7c768106a3faf475b1e27a940d3c075fda671eadf46c68f93d7eabcf604bcbf7055da0dc4eae6743607a2fc3f",
	"07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
	"5a3d39bf9ba70bfeb466c39a5cf1383cf541b686b8a957dad4767819fb5e2781aa4d251f6de8ae0f3078559eeb96b4115a7600f7cfac9cc8e781d8b8d51e9daa",
	"dc7df11585bfcbe22b83e457ece29a5fd8764acfea0a730ec050ca24a6521057f635f1243f15ce846a237a60e72f11550e9862a389b109abb8980ad1964b355b",
)

class DigestServiceTest : StringSpec({
	"Sha256 digest should match expected" {
		data.zip(dataHashesSha256).forEach { (data, hash) ->
			defaultCryptoService.digest.sha256(data.encodeToByteArray()).toHexString() shouldBe hash
		}
	}

	"Sha512 digest should match expected" {
		data.zip(dataHashesSha512).forEach { (data, hash) ->
			defaultCryptoService.digest.sha512(data.encodeToByteArray()).toHexString() shouldBe hash
		}
	}
})