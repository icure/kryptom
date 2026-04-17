package com.icure.kryptom.js

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlin.random.Random

class ArrayBufferUtilsTest : StringSpec({
	"Should be capable of converting large byte arrays to array buffer and back" {
		Random.nextBytes(128 * 1024 * 1024).asArrayBuffer().asByteArray()
	}

	"Round trip conversion should give equivalent data" {
		val original = Random.nextBytes(128)
		original.toList() shouldBe original.asArrayBuffer().asByteArray().toList()
	}

	"Round trip conversion should give the same buffer if possible" {
		val original = Random.nextBytes(128).asArrayBuffer()
		original shouldBeSameInstanceAs original.asByteArray().asArrayBuffer()
	}
})