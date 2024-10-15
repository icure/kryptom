package com.icure.kryptom.utils

import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlinx.io.writeString


// Encoding implementation comes from ktor utils https://raw.githubusercontent.com/ktorio/ktor/5f27f303bd26a361430b45fe173434d35986f52a/ktor-utils/common/src/io/ktor/util/Base64.kt
// with minimal changes to allow for custom alphabet
// Decoding is also based on ktor but with added strong validation of the input.

private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
private const val BASE32_PAD = '='
private const val BASE32_MASK_INT: Int = 0x1F

private val BASE32_INVERSE_ALPHABET_STANDARD = LongArray(256) {
	BASE32_ALPHABET.indexOf(it.toChar()).toLong()
}

/**
 * Encode bytes as a base 32 string.
 * - Uses the encoding scheme as specified in RFC 4648 table 3.
 * - The output string uses UTF-8 encoding.
 * - Does not perform any line wrapping
 * - Inserts padding '=' if necessary.
 * @param bytes the bytes to encode
 * @return the base32 representation of the bytes.
 */
fun base32Encode(bytes: ByteArray): String =
	encodeBase32(bytes, BASE32_ALPHABET)

/**
 * Decodes a base 32 string.
 * - Uses the encoding scheme as specified in RFC 4648 table 3.
 * - The input string uses UTF-8 encoding.
 * - Fails if there are invalid characters (including line wrappings)
 * - Does not require padding '=' but if they are present they must be in correct amount
 * @param base32String a base 32 string.
 * @return the bytes represented by the provided string.
 * @throws IllegalArgumentException if the input string is not a valid base64 string.
 */
fun base32Decode(base32String: String): ByteArray =
	decodeBase32(base32String, BASE32_INVERSE_ALPHABET_STANDARD)

/**
 * Encode [ByteArray] in base32 format.
 */
private fun encodeBase32(data: ByteArray, alphabet: String): String {
	var position = 0
	var writeOffset = 0
	val charArray = CharArray(data.size * 8 / 5 + 7)

	while (position + 5 < data.size) {
		val octets = Array(5) { data[position + it].toLong() }
		position += 5

		val chunk = octets.foldIndexed(0L) { idx, acc, octet ->
			acc or ((octet and 0xFF) shl (32 - 8 * idx))
		}
		for (index in 7 downTo 0) {
			val char = (chunk shr (5 * index)).toInt() and BASE32_MASK_INT
			charArray[writeOffset++] = alphabet[char]
		}
	}

	val remaining = data.size - position
	if (remaining == 0) return charArray.concatToString(0, writeOffset)

	val chunk = (0 until 5).fold(0L) { acc, idx ->
		val octet = if(idx < remaining) {
			data[position + idx].toLong()
		} else {
			0
		}
		acc or ((octet and 0xFF) shl (32 - 8 * idx))
	}

	val padSize = (5 - remaining) * 8 / 5
	for (index in 7 downTo padSize) {
		val char = (chunk shr (5 * index)).toInt() and BASE32_MASK_INT
		charArray[writeOffset++] = alphabet[char]
	}

	repeat(padSize) { charArray[writeOffset++] = BASE32_PAD }

	return charArray.concatToString(0, writeOffset)
}

private fun decodeBase32(input: String, lookupTable: LongArray): ByteArray {
	if (input.isEmpty()) {
		return byteArrayOf()
	}

	val unpaddedData = if (input.last() == BASE32_PAD) {
		require(input.length % 8 == 0) { "Invalid padded base32 string length: ${input.length}" }
		require(input[input.length - 7] != BASE32_PAD) { "Too much padding" }
		val lastPadIndex = input.indexOfFirst { it == BASE32_PAD }
		require(lastPadIndex > (input.length - 7)) { "Invalid base32 string, padding before last octets" }
		input.substring(0, lastPadIndex)
	} else input

	val packet = Buffer().apply {
		writeString(unpaddedData)
	}
	val bufferSize = 8
	val data = ByteArray(bufferSize)
	return Buffer().apply {
		while (!packet.exhausted()) {
			val read = packet.readAtMostTo(data)

			val chunk = data.let {
				if(read < bufferSize) {
					it.sliceArray(0 until read)
				} else it
			}.foldIndexed(0L) { index, result, current ->
				val found = lookupTable.getOrNull(current.toInt())?.takeIf { it >= 0 }
					?: throw IllegalArgumentException("Invalid base32 character: $current")
				result or (found shl ((7 - index) * 5))
			}

			val bytesToLoad = when(read) {
				2 -> 4
				4 -> 3
				5 -> 2
				7 -> 1
				8 -> 0
				else -> throw IllegalArgumentException("Invalid base 32 character, loaded $read bytes")
			}

			for (index in 4 downTo bytesToLoad) {
				val origin = (chunk shr (8 * index)) and 0xff
				writeByte(origin.toByte())
			}
		}
	}.readByteArray()
}