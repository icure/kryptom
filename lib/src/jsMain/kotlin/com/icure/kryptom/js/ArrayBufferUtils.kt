package com.icure.kryptom.js

import org.khronos.webgl.ArrayBuffer
import org.khronos.webgl.Int8Array

/**
 * Convert an [ArrayBuffer] to a [ByteArray] without copying (https://youtrack.jetbrains.com/issue/KT-30098).
 */
fun ArrayBuffer.asByteArray(): ByteArray = Int8Array(this).unsafeCast<ByteArray>()

/**
 * Get the [ArrayBuffer] associated with this ByteArray without copying if possible
 */
fun ByteArray.asArrayBuffer(): ArrayBuffer {
	val thiz: dynamic = this
	check(js("thiz instanceof Int8Array")) {
		"Unexpected type for ByteArray, expected Int8Array, got ${js("thiz.constructor.name")}"
	}
	return js("""
		const buffer = thiz.buffer
		const byteOffset = thiz.byteOffset
		const byteLength = thiz.byteLength
		if (buffer instanceof ArrayBuffer) {
			if (byteOffset === 0 && byteLength === buffer.byteLength) {
				return buffer
			}
			return buffer.slice(byteOffset, byteOffset + byteLength)
		}
		const copy = new Int8Array(byteLength)
		copy.set(thiz)
		return copy.buffer
	""")
}
