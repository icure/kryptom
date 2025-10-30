package com.icure.kryptom.js

import org.khronos.webgl.ArrayBuffer
import kotlin.js.Json
import kotlin.js.Promise

// https://raw.githubusercontent.com/ktorio/ktor/810b8134963820d634e4d4e852854afc6b7de417/ktor-utils/jsAndWasmShared/src/io/ktor/util/PlatformUtilsJs.kt
//language=JavaScript
private fun hasNodeApi(): Boolean = js(
	"""
(typeof process !== 'undefined' 
    && process.versions != null 
    && process.versions.node != null) ||
(typeof window !== 'undefined' 
    && typeof window.process !== 'undefined' 
    && window.process.versions != null 
    && window.process.versions.node != null)
"""
)

internal val jsCrypto: Crypto get() = checkNotNull(jsCryptoOrNull) {
	"""
	Js crypto or crypto.subtle is not available.
	To use kryptom with node and ES modules you need to use node 19 or later.
	To use kryptom in expo / react native use the @icure/nitro-kryptom npm package.
	""".trimIndent()
}

/**
 * Implementation based on
 * [ktor](https://github.com/ktorio/ktor/blob/8efb61fcc2/ktor-utils/js/src/io/ktor/util/CryptoJs.kt#L47)
 * Global instance of [Crypto].
 */
private val jsCryptoOrNull: Crypto? by lazy {
	val crypto = if (hasNodeApi()) {
		//language=JavaScript
		js("""
			typeof crypto != 'undefined' 
				? crypto
				: typeof require != 'undefined'
					? eval('require')('crypto')
					: undefined
		""")
	} else {
		//language=JavaScript
		js("(window ? (window.crypto ? window.crypto : window.msCrypto) : self.crypto)")
	}
	// Note: crypto is dynamic, can't use takeIf
	if (crypto?.subtle != null) crypto else null
}

fun defaultJsCryptoAvailable(): Boolean =
	jsCryptoOrNull != null

/**
 * https://developer.mozilla.org/en-US/docs/Web/API/Crypto
 */
internal external class Crypto {
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle
	 */
	val subtle: SubtleCrypto

	/**
	 * https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
	 */
	fun getRandomValues(array: ByteArray): ByteArray

	/**
	 * https://developer.mozilla.org/en-US/docs/Web/API/Crypto/randomUUID
	 */
	fun randomUUID(): String
}

/**
 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
 */
internal external class SubtleCrypto {
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey#syntax
	 */
	fun generateKey(algorithm: Json, extractable: Boolean, keyUsages: Array<String>): Promise<dynamic>

	/**
	 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/exportKey
	 */
	fun exportKey(format: String, key: dynamic): Promise<dynamic>

	/**
	 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
	 */
	fun importKey(
		format: String,
		keyData: dynamic,
		algorithm: Json,
		extractable: Boolean,
		keyUsages: Array<String>
	): Promise<dynamic>

	/**
	 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
	 */
	fun encrypt(algorithm: Json, key: dynamic, data: ArrayBuffer): Promise<ArrayBuffer>

	/**
	 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt
	 */
	fun decrypt(algorithm: Json, key: dynamic, data: ArrayBuffer): Promise<ArrayBuffer>

	/**
	 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign
	 */
	fun sign(algorithm: Json, key: dynamic, data: ArrayBuffer): Promise<ArrayBuffer>

	/**
	 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
	 */
	fun verify(algorithm: Json, key: dynamic, signature: ArrayBuffer, data: ArrayBuffer): Promise<Boolean>

	/**
	 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
	 */
	fun digest(algorithm: String, data: ArrayBuffer): Promise<ArrayBuffer>
}
