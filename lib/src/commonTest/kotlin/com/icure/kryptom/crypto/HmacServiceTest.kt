package com.icure.kryptom.crypto

import com.icure.kryptom.utils.base64Decode
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import kotlin.random.Random


private val keys = mapOf<HmacAlgorithm, List<String>>(
	HmacAlgorithm.HmacSha512 to listOf(
		"E8Kij04n2hg/j3y/d7M8RRmQLQHA+oCR7Uldec/f+kZH17nE0i7haenaM8tFrUljA+p0F/sHOLw+HPtmtcCl8xnqajmjcTtfImZZD67uaIt30UkoMUQqOb62oR3cQ/fdWgIZTMk811HfE91UweqfalT6kAg5yh5wTc+xY5FGkLk=",
		"AW4gGO9BKZCSxZ7sYUJHzuRBAJOawt+FE3geEik9dbQ0+Q9svc7jCXSKH9bHmeDfh+Wtuo+3GdKKZO8WzGLOMK470+scybPnEqV8eMpa2evV6moCrzUp4u2H+HpY8MTavSFSz/+V4ZWNQyJQ968bwlC7tSglNnoYBQi/4DQ8uzo="
	),
	HmacAlgorithm.HmacSha256 to listOf(
		"avqBDjVyWAUN9rAf3I+dKvD0kZ6lXHrZggexsk4+x8NwYq7ig1/BRfZhLJThQnRK4ZeUHNZ2uj+KiY75GgHv7A==",
		"Gp6MlgtH4CN0Esif3lQGk8VHt6p3PRqiIcUQIcbrWv/eGqQCotWCpm065iNM5luH2BaAjow1gCo637Zt00vvjA=="
	)
)

private val shortKeys = mapOf<HmacAlgorithm, String>(
	HmacAlgorithm.HmacSha512 to "qftdnQyVIbK7MbJfBpQHRkGX7FSI+ilwuIPLt9M9ycWPYbDvJZsneEpbYTpMZRpoYR+A53O99LyhQAlJfZ4a",
	HmacAlgorithm.HmacSha256 to "anX77NJQoWlJl8TogLQqGaxK7tIwj134BEB3Ws/rqA=="
)

private val signatures = mapOf<HmacAlgorithm, List<Pair<Pair<Int, Int>, String>>>(
	HmacAlgorithm.HmacSha512 to listOf(
		Pair(0, 0) to "tuSBTthZtICyFCn6MePfHBq5Ai+MjkFYBAKxXbkBOOTe58+jixTh1dcgvgJ6YIeA1uFVLOkpcWxB2mBbF5AjEA==",
		Pair(1, 0) to "g52+8DTHo0PV1OAYrYVNwHpULEjVAoI6qTS5Zov0vT3QyZuPYCXpeEm3xyuE63aog9IphKGHLMlr3Ir80Hirqg==",
		Pair(2, 0) to "uUENcn0wIjGoHkOGZ6Bimpd4XEd5Sd9B8HmC0VlJpWDEQtEYtDCsNGk095C3EdphyWk4rLYjv30nEnqTsVjDMg==",
		Pair(3, 0) to "mCU9EWH5nXV58sDhUGfKYT45UGU5D3LyTtmsVqcobnbui2cg2e/muzegtDR3x5amAyb+4tpXXXPh/3M7ngblZA==",
		Pair(4, 0) to "TxwX8KSSlMK70zyHRBEu4ILRroQEDKKje9CnYxEDRvqRgp5ZhWdHY2nPm07a0WyLhHHIjU3euFdsMx1HMoVlRA==",
		Pair(5, 0) to "W3h75WaCNUU+7ZQM3wTKLeklxu5W9s09SVBNaTZlFwjfgitWeiFeB5G97qVaBDuMguW5V6pob4KNYiOaN8EZKA==",
		Pair(0, 1) to "wrXsV09J8DF6JmH0XM5ZbO///oDsOKe7MfAXpMFNTy4iwkGDkkrnecT3/LIBOD3eZl8TnotU4Uj+nuPg/TvjIg==",
		Pair(1, 1) to "4tLl7NJtMujA1A2CA5cmvs5s1GLJOXCeLuuzzVOSAzHqc1WSgl+LfuasJCZMk8zjpbi8SeYuUF/BRI+CtnTbEg==",
		Pair(2, 1) to "G0mUriNqa1Q+e80vMxsqufsXreaVfgHyAGuNEa1OcSffsGze35VTpd98LQAv1Wb2VNcGeCNl4+tbqg5ZwhgnrQ==",
		Pair(3, 1) to "qriWAQ10f5hsnWhSvsyyJnwJsDCLgAZmH/wZ2Xn8OFzijNERrnBI3F1aAhI5xxdg8AuHx/rjOnPu/ARd2OrawA==",
		Pair(4, 1) to "Dx1sK7dpbuNwFEkxi1hZULPQYQR29F/niMD8XsRF2Y/SuonDeYNPynnsqSCMvblihDmpyRDN1bH/gc21aAjKqw==",
		Pair(5, 1) to "Se2o/YDuil+CWDeAcM7Z8Vl3JSFtFFayAb1k84XvirS3fKNWp6N6PKs+tXC3qljx42ZLKax0eTG95UltL7ZxVA==",
	),
	HmacAlgorithm.HmacSha256 to listOf(
		Pair(0, 0) to "uDa9fe9/vYp24I9kHEbYyc0L8oZOTOzRfrq9uQ5csvg=",
		Pair(1, 0) to "Qm+S3MQEDD+d1z7GbzoOsR1TA5anlQyXbEZ/XVmhMcs=",
		Pair(2, 0) to "b/o9uN/IDMp7rWbUS6uONgxKOfVbSNnC8a78N7IbOEA=",
		Pair(3, 0) to "M6hzVW1Z/VpZPlBhrF8vNf/kjzwzvxQMJ1nEe8ELlHY=",
		Pair(4, 0) to "odbU9K2mv6zmfCYRINHpqNXAT+lnFkGLCpnjsSrUkRQ=",
		Pair(5, 0) to "zBHSP+5XFIev8dyzbpKCFicxL/njKf/R1TM5EjYJBOk=",
		Pair(0, 1) to "BIdAzENjXq4xI/KRQbTqDmjTrg9N6yqzJPQJq9hFFB8=",
		Pair(1, 1) to "rVH2zWoUICgNJIhZewWZKRAIUfJP9C7HPvVoTFdwNy0=",
		Pair(2, 1) to "2EBOLIa6Xn9MsNEJup3HsnCXZbtKF0wplyIYUABHom8=",
		Pair(3, 1) to "yt0nS9LoSSHhPqGitlNOaM6lYaaD0IQubyZFAf99RDM=",
		Pair(4, 1) to "ns+3d+tOS5HW/Tz5s7CMGZBbdF7My7s0K0EFH7prgOc=",
		Pair(5, 1) to "IkQt6zUUaGPShElalV8DSTjt3MfnWs1qdJ3kqQeom2I=",
	)
)

class HmacServiceTest : StringSpec({
	fun <A : HmacAlgorithm> doTest(algorithm: A) {
		"$algorithm - key should have recommended size if no custom size is passed" {
			val key = defaultCryptoService.hmac.generateKey(algorithm)
			defaultCryptoService.hmac.exportKey(key).size shouldBe algorithm.recommendedKeySize
		}

		"$algorithm - can generate a key with a custom size" {
			val size = algorithm.minimumRecommendedKeySize
			val key = defaultCryptoService.hmac.generateKey(algorithm, size)
			defaultCryptoService.hmac.exportKey(key).size shouldBe size
		}

		"$algorithm - cannot specify a key size less than the minimum key size" {
			shouldThrow<IllegalArgumentException> {
				defaultCryptoService.hmac.generateKey(algorithm, algorithm.minimumRecommendedKeySize - 1)
			}
		}

		"$algorithm - cannot import a key shorter then the minimum key size" {
			shouldThrow<IllegalArgumentException> {
				defaultCryptoService.hmac.loadKey(algorithm, base64Decode(shortKeys.getValue(algorithm)))
			}
		}

		"$algorithm - Signature generation and verification should match expected" {
			val key = defaultCryptoService.hmac.generateKey(algorithm)
			val wrongKey = defaultCryptoService.hmac.generateKey(algorithm)
			data.forEach { data ->
				val dataBytes = data.encodeToByteArray()
				val signature = defaultCryptoService.hmac.sign(dataBytes, key)
				defaultCryptoService.hmac.verify(signature, dataBytes, key) shouldBe true
				defaultCryptoService.hmac.verify(signature, dataBytes, wrongKey) shouldBe false
				data.mutations().forEach { mutatedData ->
					defaultCryptoService.hmac.verify(
						signature,
						mutatedData.encodeToByteArray(),
						key
					) shouldBe false
				}
			}
		}

		"$algorithm - Exported and reimported key should work" {
			val keyBytes = defaultCryptoService.hmac.exportKey(defaultCryptoService.hmac.generateKey(algorithm))
			val key = defaultCryptoService.hmac.loadKey(algorithm, keyBytes)
			data.forEach { data ->
				val dataBytes = data.encodeToByteArray()
				val signature = defaultCryptoService.hmac.sign(dataBytes, key)
				defaultCryptoService.hmac.verify(signature, dataBytes, key) shouldBe true
				data.mutations().forEach { mutatedData ->
					defaultCryptoService.hmac.verify(
						signature,
						mutatedData.encodeToByteArray(),
						key
					) shouldBe false
				}
			}
		}

		"$algorithm - Signature verification should match expected - signature from other sources" {
			val importedKeys =
				keys.getValue(algorithm).map { defaultCryptoService.hmac.loadKey(algorithm, base64Decode(it)) }
			signatures.getValue(algorithm).forEach { (dataAndKeyIndex, signature) ->
				val (dataIndex, keyIndex) = dataAndKeyIndex
				val key = importedKeys[keyIndex]
				val dataString = data[dataIndex]
				val signatureBytes = base64Decode(signature)
				defaultCryptoService.hmac.verify(
					signatureBytes,
					dataString.encodeToByteArray(),
					key
				) shouldBe true
				dataString.mutations().forEach { mutatedData ->
					defaultCryptoService.hmac.verify(
						signatureBytes,
						mutatedData.encodeToByteArray(),
						key
					) shouldBe false
				}
				val wrongKey = importedKeys[(keyIndex + 1) % importedKeys.size]
				defaultCryptoService.hmac.verify(
					signatureBytes,
					dataString.encodeToByteArray(),
					wrongKey
				) shouldBe false
			}
		}

		"$algorithm - methods should not modify input buffer" {
			val data = Random.nextBytes(30)
			val dataCopy = data.copyOf()
			val key = Random.nextBytes(algorithm.recommendedKeySize)
			val keyCopy = key.copyOf()
			try {
				val loadedKey = defaultCryptoService.hmac.loadKey(algorithm, key)
				val signature = defaultCryptoService.hmac.sign(data, loadedKey)
				defaultCryptoService.hmac.verify(signature, data, loadedKey)
			} catch(e: Exception) {
				// This test does not care if the methods complete successfully, as long as the buffers are unmodified this test should pass
			} finally {
				data.toList() shouldBe dataCopy.toList()
				key.toList() shouldBe keyCopy.toList()
			}
		}
	}

	doTest(HmacAlgorithm.HmacSha512)
	doTest(HmacAlgorithm.HmacSha256)
})
