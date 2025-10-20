package com.icure.kryptom.crypto.external

import com.icure.kryptom.crypto.AesAlgorithm
import com.icure.kryptom.crypto.AesKey

external interface XAesKey {
	val aesKey: dynamic
	val algorithm: String
}

fun <A : AesAlgorithm> XAesKey.toKryptom(algorithm: A): AesKey<A> {
	if (this.algorithm != algorithm.identifier) {
		throw AssertionError("Algorithm mismatch: ${this.algorithm} != ${algorithm.identifier}")
	}
	return AesKey(aesKey, algorithm)
}

fun XAesKey.toKryptom(): AesKey<AesAlgorithm> {
	return AesKey(aesKey, AesAlgorithm.fromIdentifier(algorithm))
}

// TODO switch to @JsPlainObject on kotlin 2
@Suppress("UNUSED_VARIABLE", "UNCHECKED_CAST_TO_EXTERNAL_INTERFACE")
fun AesKey<*>.toExternal(): XAesKey {
	val thisKey = this.cryptoKey
	val algorithmIdentifier = this.algorithm.identifier
	return js("({aesKey: thisKey, algorithm: algorithmIdentifier})") as XAesKey
}