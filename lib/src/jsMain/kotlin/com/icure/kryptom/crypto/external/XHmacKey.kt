package com.icure.kryptom.crypto.external

import com.icure.kryptom.crypto.HmacAlgorithm
import com.icure.kryptom.crypto.HmacKey

external interface XHmacKey {
	val hmacKey: dynamic
	val keySize: Int
	val algorithm: String
}

fun <A : HmacAlgorithm> XHmacKey.toKryptom(algorithm: A): HmacKey<A> {
	if (this.algorithm != algorithm.identifier) {
		throw AssertionError("Algorithm mismatch: ${this.algorithm} != ${algorithm.identifier}")
	}
	return HmacKey(hmacKey, keySize, algorithm)
}

fun XHmacKey.toKryptom(): HmacKey<HmacAlgorithm> {
	return HmacKey(hmacKey, keySize, HmacAlgorithm.fromIdentifier(algorithm))
}

// TODO switch to @JsPlainObject on kotlin 2
@Suppress("UNUSED_VARIABLE", "UNCHECKED_CAST_TO_EXTERNAL_INTERFACE")
fun HmacKey<*>.toExternal(): XHmacKey {
	val thisKey = this.key
	val algorithmIdentifier = this.algorithm.identifier
	return js("({hmacKey: thisKey, algorithm: algorithmIdentifier})") as XHmacKey
}