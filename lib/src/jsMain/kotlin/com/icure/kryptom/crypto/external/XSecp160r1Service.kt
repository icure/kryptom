package com.icure.kryptom.crypto.external

import kotlin.js.Promise

/**
 * Typescript-facing counterpart of [com.icure.kryptom.crypto.ec.Secp160r1Service]: x-only ECDH over secp160r1.
 * Scalars are 21 bytes big-endian, public keys and shared secrets 20 bytes big-endian. See the Kotlin interface for
 * the security notes: this curve is for ephemeral keys and secrets that expire within minutes.
 *
 * External implementations may omit this service entirely; kryptom then falls back to its pure-Kotlin
 * implementation, fed by the external strong random generator.
 */
external interface XSecp160r1Service {
	fun randomScalar(): Promise<ByteArray>
	fun publicKeyX(scalar: ByteArray): Promise<ByteArray>
	fun isValidPublicKeyX(publicKeyX: ByteArray): Promise<Boolean>
	/** Resolves to null (or undefined) when the peer key is invalid. */
	fun ecdhX(scalar: ByteArray, peerPublicKeyX: ByteArray): Promise<ByteArray?>
}
